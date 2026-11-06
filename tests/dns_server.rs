use dns_guard::server::{Server, ServerConfig};
use dns_guard::{Action, Category, Index, Limits, Rule, Scope, compile};
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::oneshot,
    time::timeout,
};

fn run(future: impl Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future);
}
fn index() -> Arc<Index> {
    Arc::new(
        compile(
            &[
                Rule::new("ads.example", Scope::Domain, Action::Block, Category::ADS).unwrap(),
                Rule::new(
                    "safe.ads.example",
                    Scope::Domain,
                    Action::Allow,
                    Category::ADS,
                )
                .unwrap(),
                Rule::new(
                    "adult.example",
                    Scope::Domain,
                    Action::Enforce,
                    Category::ADULT,
                )
                .unwrap(),
                Rule::new("exact.example", Scope::Exact, Action::Block, Category::ADS).unwrap(),
            ],
            Limits::default(),
        )
        .unwrap(),
    )
}
fn query(name: &str) -> Message {
    let mut message = Message::new(1234, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    message
}
fn answer(request: &Message) -> Message {
    let mut message = Message::response(request.metadata.id, OpCode::Query);
    message.queries = request.queries.clone();
    message.metadata.recursion_available = true;
    message.metadata.recursion_desired = request.metadata.recursion_desired;
    message.metadata.authentic_data = true;
    message.add_answer(Record::from_rdata(
        request.queries[0].name.clone(),
        30,
        RData::A(A::new(192, 0, 2, 10)),
    ));
    message
}
async fn start(
    mut config: ServerConfig,
) -> (
    SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<std::io::Result<()>>,
    Arc<dns_guard::server::Stats>,
) {
    config.listen = "127.0.0.1:0".parse().unwrap();
    let server = Server::bind(config, index()).await.unwrap();
    let address = server.local_addr().unwrap();
    let stats = server.stats();
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(server.run(async {
        let _ = stopped.await;
    }));
    (address, stop, task, stats)
}
fn config(upstream: SocketAddr) -> ServerConfig {
    ServerConfig {
        upstream,
        timeout: Duration::from_millis(250),
        ..Default::default()
    }
}
async fn udp(address: SocketAddr, request: &Message) -> Message {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(address).await.unwrap();
    socket.send(&request.to_vec().unwrap()).await.unwrap();
    let mut bytes = [0; 4096];
    let n = timeout(Duration::from_secs(2), socket.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    Message::from_vec(&bytes[..n]).unwrap()
}
async fn frame(socket: &mut TcpStream) -> Message {
    let n = timeout(Duration::from_secs(2), socket.read_u16())
        .await
        .unwrap()
        .unwrap() as usize;
    let mut bytes = vec![0; n];
    socket.read_exact(&mut bytes).await.unwrap();
    Message::from_vec(&bytes).unwrap()
}
async fn write_frame(socket: &mut TcpStream, message: &Message) {
    let bytes = message.to_vec().unwrap();
    socket.write_u16(bytes.len() as u16).await.unwrap();
    socket.write_all(&bytes).await.unwrap();
}

#[test]
fn blocks_locally_preserves_edns_and_forwards_exceptions() {
    run(async {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (address, stop, task, stats) = start(config(upstream.local_addr().unwrap())).await;
        for name in [
            "ads.example",
            "X.ADS.EXAMPLE.",
            "_sip._tcp.ads.example",
            "adult.example",
        ] {
            let mut request = query(name);
            request.set_edns(
                Edns::new()
                    .set_max_payload(4096)
                    .set_dnssec_ok(true)
                    .clone(),
            );
            request.metadata.authentic_data = true;
            let response = udp(address, &request).await;
            assert_eq!(response.metadata.response_code, ResponseCode::Refused);
            assert_eq!(response.metadata.id, 1234);
            assert_eq!(
                response.queries,
                Message::from_vec(&request.to_vec().unwrap())
                    .unwrap()
                    .queries
            );
            assert!(!response.metadata.authentic_data);
            assert!(!response.metadata.authoritative);
            assert!(response.metadata.recursion_available);
            assert_eq!(response.edns.unwrap().max_payload(), 1232);
        }
        let mut bytes = [0; 4096];
        assert_eq!(
            upstream.try_recv_from(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let mock = tokio::spawn(async move {
            for _ in 0..3 {
                let (n, client) = upstream.recv_from(&mut bytes).await.unwrap();
                let request = Message::from_vec(&bytes[..n]).unwrap();
                upstream
                    .send_to(&answer(&request).to_vec().unwrap(), client)
                    .await
                    .unwrap();
            }
        });
        for name in ["safe.ads.example", "_srv.exact.example", "."] {
            let response = udp(address, &query(name)).await;
            assert_eq!(response.metadata.response_code, ResponseCode::NoError);
            assert_eq!(response.metadata.id, 1234);
            assert_eq!(response.answers.len(), 1);
            assert!(!response.metadata.authentic_data);
        }
        mock.await.unwrap();
        assert_eq!(stats.snapshot().blocked, 4);
        assert_eq!(stats.snapshot().forwarded, 3);
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
    });
}

#[test]
fn tcp_accepts_fragmented_and_pipelined_frames() {
    run(async {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (address, stop, task, _) = start(config(upstream.local_addr().unwrap())).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        let first = query("ads.example").to_vec().unwrap();
        let mut bytes = (first.len() as u16).to_be_bytes().to_vec();
        bytes.extend(&first);
        let mut second = query("adult.example");
        second.metadata.id = 2345;
        let second = second.to_vec().unwrap();
        bytes.extend((second.len() as u16).to_be_bytes());
        bytes.extend(second);
        client.write_all(&bytes[..1]).await.unwrap();
        client.write_all(&bytes[1..7]).await.unwrap();
        client.write_all(&bytes[7..]).await.unwrap();
        for id in [1234, 2345] {
            let reply = frame(&mut client).await;
            assert_eq!(reply.metadata.id, id);
            assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
        }
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
        let mut byte = [0];
        assert_eq!(
            timeout(Duration::from_secs(1), client.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    });
}

#[test]
fn truncated_udp_retries_tcp_and_respects_client_udp_size() {
    run(async {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = UdpSocket::bind(tcp.local_addr().unwrap()).await.unwrap();
        let (address, stop, task, _) = start(config(tcp.local_addr().unwrap())).await;
        let mock = tokio::spawn(async move {
            let mut bytes = [0; 4096];
            let (n, client) = upstream.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..n]).unwrap();
            let mut truncated = answer(&request);
            truncated.answers.clear();
            truncated.metadata.truncation = true;
            upstream
                .send_to(&truncated.to_vec().unwrap(), client)
                .await
                .unwrap();
            for _ in 0..2 {
                let (mut socket, _) = tcp.accept().await.unwrap();
                let request = frame(&mut socket).await;
                let mut reply = answer(&request);
                let record = reply.answers[0].clone();
                reply.answers.extend(std::iter::repeat_n(record, 79));
                write_frame(&mut socket, &reply).await;
            }
        });
        let reply = udp(address, &query("large.example")).await;
        assert!(reply.metadata.truncation);
        assert_eq!(reply.metadata.id, 1234);
        let mut client = TcpStream::connect(address).await.unwrap();
        write_frame(&mut client, &query("large.example")).await;
        let reply = frame(&mut client).await;
        assert!(!reply.metadata.truncation);
        assert_eq!(reply.answers.len(), 80);
        mock.await.unwrap();
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
    });
}

#[test]
fn rejects_wrong_upstream_id_question_and_source() {
    run(async {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (address, stop, task, _) = start(config(upstream.local_addr().unwrap())).await;
        let mock = tokio::spawn(async move {
            let mut bytes = [0; 4096];
            let (n, client) = upstream.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..n]).unwrap();
            let valid = answer(&request);
            let mut bad = valid.clone();
            bad.metadata.id ^= 1;
            upstream
                .send_to(&bad.to_vec().unwrap(), client)
                .await
                .unwrap();
            bad = valid.clone();
            bad.queries[0] = query("wrong.example").queries.remove(0);
            upstream
                .send_to(&bad.to_vec().unwrap(), client)
                .await
                .unwrap();
            let spoof = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            bad = valid.clone();
            bad.answers.clear();
            spoof.send_to(&bad.to_vec().unwrap(), client).await.unwrap();
            upstream
                .send_to(&valid.to_vec().unwrap(), client)
                .await
                .unwrap();
        });
        let reply = udp(address, &query("clean.example")).await;
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(reply.metadata.id, 1234);
        mock.await.unwrap();
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
    });
}

#[test]
fn upstream_timeout_servfails_without_blocking_other_queries() {
    run(async {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (address, stop, task, stats) = start(config(upstream.local_addr().unwrap())).await;
        let first = tokio::spawn(async move { udp(address, &query("timeout.example")).await });
        let mut bytes = [0; 4096];
        timeout(Duration::from_secs(1), upstream.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            udp(address, &query("ads.example"))
                .await
                .metadata
                .response_code,
            ResponseCode::Refused
        );
        assert_eq!(
            first.await.unwrap().metadata.response_code,
            ResponseCode::ServFail
        );
        assert_eq!(stats.snapshot().upstream_errors, 1);
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
    });
}

#[test]
fn malformed_and_unsupported_queries_never_reach_upstream() {
    run(async {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (address, stop, task, _) = start(config(upstream.local_addr().unwrap())).await;
        let mut multiple = query("clean.example");
        multiple.add_query(Query::query(
            Name::from_ascii("two.example").unwrap(),
            RecordType::A,
        ));
        assert_eq!(
            udp(address, &multiple).await.metadata.response_code,
            ResponseCode::FormErr
        );
        let mut transfer = query("clean.example");
        transfer.queries[0].query_type = RecordType::AXFR;
        assert_eq!(
            udp(address, &transfer).await.metadata.response_code,
            ResponseCode::Refused
        );
        let mut version = query("clean.example");
        version.set_edns(Edns::new().set_version(1).clone());
        // BADVERS and BADSIG share wire RCODE 16; Hickory decodes it as BADSIG.
        assert_eq!(
            u16::from(udp(address, &version).await.metadata.response_code),
            16
        );
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for bytes in [vec![1, 2], vec![0; 12], vec![0; 4097]] {
            client.send_to(&bytes, address).await.unwrap();
        }
        assert_eq!(
            udp(address, &query("ads.example"))
                .await
                .metadata
                .response_code,
            ResponseCode::Refused
        );
        let mut bytes = [0; 4096];
        assert_eq!(
            upstream.try_recv_from(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
    });
}

#[test]
fn validates_configuration_before_binding() {
    run(async {
        for c in [
            ServerConfig {
                max_inflight: 0,
                ..Default::default()
            },
            ServerConfig {
                max_tcp_connections: 0,
                ..Default::default()
            },
            ServerConfig {
                timeout: Duration::ZERO,
                ..Default::default()
            },
            ServerConfig {
                allowed_clients: vec![],
                ..Default::default()
            },
            ServerConfig {
                upstream: "0.0.0.0:53".parse().unwrap(),
                ..Default::default()
            },
            ServerConfig {
                categories: 128,
                ..Default::default()
            },
        ] {
            assert!(Server::bind(c, index()).await.is_err());
        }
    });
}

#[test]
fn overload_is_bounded_and_permits_are_recovered() {
    run(async {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut c = config(upstream.local_addr().unwrap());
        c.max_inflight = 1;
        c.timeout = Duration::from_secs(2);
        let (address, stop, task, stats) = start(c).await;
        let first = tokio::spawn(async move { udp(address, &query("pending.example")).await });
        let mut bytes = [0; 4096];
        let (n, peer) = timeout(Duration::from_secs(1), upstream.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        let request = Message::from_vec(&bytes[..n]).unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        second
            .send_to(&query("ads.example").to_vec().unwrap(), address)
            .await
            .unwrap();
        timeout(Duration::from_secs(1), async {
            while stats.snapshot().overloaded == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(stats.snapshot().peak_inflight, 1);
        upstream
            .send_to(&answer(&request).to_vec().unwrap(), peer)
            .await
            .unwrap();
        assert_eq!(
            first.await.unwrap().metadata.response_code,
            ResponseCode::NoError
        );
        assert_eq!(
            udp(address, &query("ads.example"))
                .await
                .metadata
                .response_code,
            ResponseCode::Refused
        );
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(stats.snapshot().inflight, 0);
    });
}

#[test]
fn access_list_denies_before_processing_and_shutdown_cancels_pending_work() {
    run(async {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut c = config(upstream.local_addr().unwrap());
        c.allowed_clients = vec!["192.0.2.0/24".parse().unwrap()];
        let (address, stop, task, stats) = start(c).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&query("clean.example").to_vec().unwrap(), address)
            .await
            .unwrap();
        timeout(Duration::from_secs(1), async {
            while stats.snapshot().denied == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(stats.snapshot().forwarded, 0);
        let mut tcp = TcpStream::connect(address).await.unwrap();
        let mut bytes = [0; 1];
        assert_eq!(
            timeout(Duration::from_secs(1), tcp.read(&mut bytes))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
        let mut c = config(upstream.local_addr().unwrap());
        c.timeout = Duration::from_secs(10);
        let (address, stop, task, stats) = start(c).await;
        client
            .send_to(&query("pending.example").to_vec().unwrap(), address)
            .await
            .unwrap();
        let mut bytes = [0; 4096];
        timeout(Duration::from_secs(1), upstream.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        stop.send(()).unwrap();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(stats.snapshot().inflight, 0);
    });
}

#[test]
fn blocks_cname_targets_and_disabled_categories_do_not_block() {
    run(async {
        use hickory_proto::rr::rdata::CNAME;
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut c = config(upstream.local_addr().unwrap());
        c.categories = Category::ADS;
        let (address, stop, task, stats) = start(c).await;
        let mock = tokio::spawn(async move {
            let mut bytes = [0; 4096];
            for _ in 0..2 {
                let (n, peer) = upstream.recv_from(&mut bytes).await.unwrap();
                let request = Message::from_vec(&bytes[..n]).unwrap();
                let mut reply = answer(&request);
                if request.queries[0].name.to_ascii() == "alias.example." {
                    reply.answers.clear();
                    reply.add_answer(Record::from_rdata(
                        request.queries[0].name.clone(),
                        30,
                        RData::CNAME(CNAME(Name::from_ascii("ads.example.").unwrap())),
                    ));
                }
                upstream
                    .send_to(&reply.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        assert_eq!(
            udp(address, &query("alias.example"))
                .await
                .metadata
                .response_code,
            ResponseCode::Refused
        );
        assert_eq!(
            udp(address, &query("adult.example"))
                .await
                .metadata
                .response_code,
            ResponseCode::NoError
        );
        mock.await.unwrap();
        assert_eq!(stats.snapshot().blocked, 1);
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
    });
}
