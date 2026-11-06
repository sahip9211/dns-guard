use dns_guard::{Action, Category, FeedFormat, Limits, Scope, compile, parse_feed};

#[test]
fn supported_feeds_produce_equivalent_domain_rules() {
    let inputs = [
        (
            FeedFormat::Domains,
            "# domains\nAds.Example.\ntracker.example\n",
        ),
        (
            FeedFormat::Hosts,
            "# hosts\n127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n0.0.0.0 ads.example tracker.example # aliases\n",
        ),
        (
            FeedFormat::Adblock,
            "[Adblock Plus 2.0]\n! title\n||ads.example^\n||tracker.example^\n",
        ),
    ];
    let indexes: Vec<_> = inputs
        .iter()
        .map(|(format, text)| {
            compile(
                &parse_feed(text, *format, Category::ADS, Limits::default()).unwrap(),
                Limits::default(),
            )
            .unwrap()
        })
        .collect();
    assert_eq!(indexes[0].as_bytes(), indexes[1].as_bytes());
    assert_eq!(indexes[1].as_bytes(), indexes[2].as_bytes());
}

#[test]
fn adblock_exceptions_keep_their_semantics() {
    let rules = parse_feed(
        "||example.com^\n@@||safe.example.com^\n",
        FeedFormat::Adblock,
        Category::ADS,
        Limits::default(),
    )
    .unwrap();
    assert_eq!(rules[1].action(), Action::Allow);
    assert_eq!(rules[1].scope(), Scope::Domain);
    let index = compile(&rules, Limits::default()).unwrap();
    assert!(
        index
            .check("x.example.com", Category::ALL)
            .unwrap()
            .is_blocked()
    );
    assert!(
        !index
            .check("safe.example.com", Category::ALL)
            .unwrap()
            .is_blocked()
    );
}

#[test]
fn unsupported_syntax_is_an_error_never_silently_broadened() {
    for text in [
        "||ads.example^$third-party",
        "example.com##.ad",
        "||*.example.com^",
        "/advert/",
        "|https://example.com/",
        "@@example.com",
    ] {
        let error =
            parse_feed(text, FeedFormat::Adblock, Category::ADS, Limits::default()).unwrap_err();
        assert!(error.to_string().contains("line 1"), "{error}");
    }
    assert!(
        parse_feed(
            "192.0.2.1 example.com",
            FeedFormat::Hosts,
            Category::ADS,
            Limits::default()
        )
        .is_err()
    );
    assert!(
        parse_feed(
            "0.0.0.0",
            FeedFormat::Hosts,
            Category::ADS,
            Limits::default()
        )
        .is_err()
    );
    assert!(
        parse_feed(
            "# empty",
            FeedFormat::Domains,
            Category::ADS,
            Limits::default()
        )
        .is_err()
    );
}

#[test]
fn parser_limits_apply_before_deduplication() {
    let text = "example.com\nexample.com\n";
    assert!(
        parse_feed(
            text,
            FeedFormat::Domains,
            Category::ADS,
            Limits {
                max_rules: 1,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        parse_feed(
            text,
            FeedFormat::Domains,
            Category::ADS,
            Limits {
                max_input_bytes: 3,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        parse_feed(
            text,
            FeedFormat::Domains,
            Category::ADS,
            Limits {
                max_line_bytes: 4,
                ..Limits::default()
            }
        )
        .is_err()
    );
}

#[test]
fn hagezi_header_is_supported_but_cosmetic_rules_are_not_comments() {
    let rules = parse_feed(
        "[Adblock Plus]\n! Title: fixture\n||ads.example^\n",
        FeedFormat::Adblock,
        Category::ADS,
        Limits::default(),
    )
    .unwrap();
    assert_eq!(rules.len(), 1);
    for unsupported in ["##.advert", "#@#.advert"] {
        let text = format!("||ads.example^\n{unsupported}\n");
        assert!(parse_feed(&text, FeedFormat::Adblock, Category::ADS, Limits::default()).is_err());
    }
}
