#[path = "../examples/support/mod.rs"]
mod support;
#[path = "../examples/support/wire.rs"]
mod wire;
use dns_guard::{Action, Category, Limits, Rule, Scope, compile};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct Counting;
static TRACK: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
// Instrument only this test executable; production code forbids unsafe Rust.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACK.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if TRACK.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;

#[test]
fn successful_hot_path_never_allocates() {
    let index = compile(
        &[Rule::new("example.com", Scope::Domain, Action::Block, Category::ADS).unwrap()],
        Limits::default(),
    )
    .unwrap();
    let packed = compile(
        &[
            Rule::new("example.com", Scope::Domain, Action::Block, Category::ADS).unwrap(),
            Rule::new(
                "safe.example.com",
                Scope::Exact,
                Action::Allow,
                Category::ADS,
            )
            .unwrap(),
        ],
        Limits::default(),
    )
    .unwrap();
    let request =
        wire::parse_request(b"GET /check/127/example.com HTTP/1.1\r\nHost: local\r\n\r\n")
            .unwrap()
            .unwrap();
    assert_eq!(
        request.used,
        b"GET /check/127/example.com HTTP/1.1\r\nHost: local\r\n\r\n".len()
    );
    let mut reply = wire::Buffer::<512>::new();
    TRACK.store(true, Ordering::SeqCst);
    for _ in 0..10_000 {
        for domain in [
            "EXAMPLE.COM.",
            "sub.example.com",
            "clean.test",
            "badexample.com",
        ] {
            for index in [&index, &packed] {
                wire::encode_reply(index, &request, &mut reply).unwrap();
                std::hint::black_box(
                    index
                        .check(std::hint::black_box(domain), Category::ALL)
                        .unwrap(),
                );
            }
        }
    }
    TRACK.store(false, Ordering::SeqCst);
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed), 0);
}
