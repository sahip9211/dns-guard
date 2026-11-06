#![forbid(unsafe_code)]
mod config_cli;
use dns_guard::{Budget, Category, FeedFormat, Index, Limits, compile, parse_feed};
use std::{fs::File, io::Read, path::Path, sync::Arc, time::Duration};

const CEILING: u64 = 10_000_000;
const HELP: &str = "dns-guard — compact DNS filtering prototype

  dns-guard compile OUTPUT --other-bytes N --feed FORMAT CATEGORIES INPUT [--feed ...]
  dns-guard check INDEX CATEGORIES DOMAIN [DOMAIN ...]
  dns-guard inspect INDEX
  dns-guard serve INDEX --upstream IP:PORT [OPTIONS]
  dns-guard serve --config DATABASE
  dns-guard config init DATABASE INDEX --upstream IP:PORT [OPTIONS]
  dns-guard config show DATABASE
  dns-guard config set DATABASE --revision N [--index INDEX] [OPTIONS]

Serve options:
  --listen IP:PORT          UDP and TCP listener (default 127.0.0.1:5353)
  --allow-client CIDR       Repeatable; replaces the default loopback-only ACL
  --categories CATEGORIES   Default all
  --max-inflight N          Outstanding queries, default 64, maximum 4096
  --max-tcp-connections N   TCP clients, default 32, maximum 1024
  --timeout-ms N           Whole upstream exchange deadline, default 2000
  --cache-bytes N          Cache table/payload limit, default 262144; 0 disables

The listener uses one runtime thread. No OS DNS settings are changed.
Saved configuration changes apply after restarting the service.
Configuration is read and closed before starting the DNS runtime.

FORMAT: domains | hosts | adblock
CATEGORIES: comma-separated ads,adult,malware,tracking,phishing,gambling,social; all; none

--other-bytes must include every installed byte except the current output index:
executables, added runtimes, assets, raw feeds, configuration, DB/WAL, logs and
reserved growth. Old index plus staged replacement count against the strict
10,000,000-byte ceiling. This supplied estimate is not an installation audit.
Only locally compiled snapshots are supported; checksums are not signatures.";

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}

fn run() -> CliResult<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else {
        return Err(HELP.into());
    };
    match command {
        "--help" | "-h" | "help" => println!("{HELP}"),
        "--version" => println!("dns-guard {}", env!("CARGO_PKG_VERSION")),
        "compile" => compile_command(&args[1..])?,
        "serve" => serve_command(&args[1..])?,
        "config" => config_cli::run(&args[1..])?,
        "check" if args.len() >= 4 => {
            let enabled = categories(&args[2])?;
            let index = Index::load(Path::new(&args[1]), Limits::default().max_index_bytes)?;
            // Validate all names before emitting partial results.
            for domain in &args[3..] {
                index.check(domain, enabled)?;
            }
            for domain in &args[3..] {
                let decision = index.check(domain, enabled)?;
                println!(
                    "{} {domain} blocked={} allowed={} enforced={}",
                    if decision.is_blocked() {
                        "BLOCK"
                    } else {
                        "ALLOW"
                    },
                    decision.blocked,
                    decision.allowed,
                    decision.enforced
                );
            }
        }
        "inspect" if args.len() == 2 => {
            let index = Index::load(Path::new(&args[1]), Limits::default().max_index_bytes)?;
            println!(
                "format={} rules={} bytes={}",
                index.format_version(),
                index.rule_count(),
                index.as_bytes().len()
            );
        }
        _ => return Err(HELP.into()),
    }
    Ok(())
}

fn serve_command(args: &[String]) -> CliResult<()> {
    use dns_guard::server::{Server, ServerConfig};
    let (input, config) = if args.first().is_some_and(|arg| arg == "--config") {
        if args.len() != 2 {
            return Err(
                "serve --config requires exactly one database path and no overrides".into(),
            );
        }
        let saved = dns_guard::config::ConfigStore::open(Path::new(&args[1]))?.load()?;
        eprintln!("Using configuration revision {}", saved.revision);
        (saved.settings.index_path, saved.settings.dns)
    } else {
        let input = args
            .first()
            .ok_or("serve requires INDEX and --upstream IP:PORT")?;
        let mut config = ServerConfig::default();
        parse_serve_options(&args[1..], &mut config, true)?;
        (Path::new(input).to_path_buf(), config)
    };
    let index = Arc::new(Index::load(&input, Limits::default().max_index_bytes)?);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            let server = Server::bind(config, index).await?;
            let stats = server.stats();
            // Install termination handlers before announcing readiness.
            #[cfg(unix)]
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            let stop = async move {
                #[cfg(unix)]
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
                #[cfg(not(unix))]
                let _ = tokio::signal::ctrl_c().await;
            };
            eprintln!(
                "DNS listening on {} (UDP/TCP, workers=1)",
                server.local_addr()?
            );
            server.run(stop).await?;
            eprintln!("DNS stopped: {:?}", stats.snapshot());
            Ok::<(), Box<dyn std::error::Error>>(())
        })
}

fn parse_serve_options(
    args: &[String],
    config: &mut dns_guard::server::ServerConfig,
    require_upstream: bool,
) -> CliResult<()> {
    let mut seen = std::collections::HashSet::new();
    let mut clients = Vec::new();
    let (options, remainder) = args.as_chunks::<2>();
    for option in options {
        let key = option[0].as_str();
        let value = &option[1];
        if key != "--allow-client" && !seen.insert(key) {
            return Err(format!("duplicate serve option: {key}").into());
        }
        match key {
            "--listen" => config.listen = value.parse()?,
            "--upstream" => config.upstream = value.parse()?,
            "--allow-client" => clients.push(value.parse()?),
            "--categories" => config.categories = categories(value)?,
            "--max-inflight" => config.max_inflight = value.parse()?,
            "--max-tcp-connections" => config.max_tcp_connections = value.parse()?,
            "--timeout-ms" => config.timeout = Duration::from_millis(value.parse()?),
            "--cache-bytes" => config.cache_bytes = value.parse()?,
            _ => return Err(format!("unknown serve option: {key}").into()),
        }
    }
    if !remainder.is_empty() || (require_upstream && !seen.contains("--upstream")) {
        return Err("serve requires complete options and an explicit --upstream IP:PORT".into());
    }
    if !clients.is_empty() {
        config.allowed_clients = clients;
    }
    Ok(())
}

fn compile_command(args: &[String]) -> CliResult<()> {
    let output = args
        .first()
        .ok_or("compile requires an output path, --other-bytes, and --feed")?;
    let mut other_bytes = None;
    let mut feeds = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--other-bytes" if i + 1 < args.len() && other_bytes.is_none() => {
                other_bytes = Some(args[i + 1].parse::<u64>()?);
                i += 2;
            }
            "--feed" if i + 3 < args.len() => {
                let format = match args[i + 1].as_str() {
                    "domains" => FeedFormat::Domains,
                    "hosts" => FeedFormat::Hosts,
                    "adblock" => FeedFormat::Adblock,
                    _ => return Err("unknown feed format".into()),
                };
                feeds.push((format, categories(&args[i + 2])?, &args[i + 3]));
                i += 4;
            }
            argument => {
                return Err(format!("invalid or incomplete compile option: {argument}").into());
            }
        }
    }
    let other_bytes =
        other_bytes.ok_or("--other-bytes is required for explicit storage accounting")?;
    if feeds.is_empty() {
        return Err("at least one --feed is required".into());
    }
    if other_bytes >= CEILING {
        return Err("other installed bytes already exhaust the budget".into());
    }
    let limits = Limits::default();
    let mut remaining = limits.max_input_bytes;
    let mut rules = Vec::new();
    for (format, enabled, input) in feeds {
        let file = File::open(input).map_err(|e| format!("{input}: {e}"))?;
        if file.metadata()?.len() > remaining as u64 {
            return Err(format!("{input}: total feed input byte limit exceeded").into());
        }
        let mut text = String::new();
        file.take(remaining as u64 + 1).read_to_string(&mut text)?;
        if text.len() > remaining {
            return Err("total feed input byte limit exceeded".into());
        }
        remaining -= text.len();
        let feed_limits = Limits {
            max_rules: limits.max_rules - rules.len(),
            ..limits
        };
        rules.extend(
            parse_feed(&text, format, enabled, feed_limits).map_err(|e| format!("{input}: {e}"))?,
        );
    }
    let index = compile(&rules, limits)?;
    index.publish(
        Path::new(output),
        Budget {
            ceiling_bytes: CEILING,
            other_bytes,
        },
    )?;
    println!(
        "compiled input_rules={} rules={} bytes={} output={output}",
        rules.len(),
        index.rule_count(),
        index.as_bytes().len()
    );
    Ok(())
}

fn categories(value: &str) -> CliResult<u32> {
    if value == "none" {
        return Ok(0);
    }
    if value == "all" {
        return Ok(Category::ALL);
    }
    let mut result = 0;
    for name in value.split(',') {
        result |= match name {
            "ads" => Category::ADS,
            "adult" => Category::ADULT,
            "malware" => Category::MALWARE,
            "tracking" => Category::TRACKING,
            "phishing" => Category::PHISHING,
            "gambling" => Category::GAMBLING,
            "social" => Category::SOCIAL,
            _ => return Err(format!("unknown category: {name}").into()),
        };
    }
    Ok(result)
}
