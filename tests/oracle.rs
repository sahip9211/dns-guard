use dns_guard::{Action, Category, Limits, Rule, Scope, compile};

#[test]
fn short_suffixes_and_all_actions_remain_exact_at_prefix_jump_boundaries() {
    let mut rules = Vec::new();
    for (i, name) in ["a", "ab", "a-b", "x.a", "x.ab", "y.x.ab", "x.123"]
        .iter()
        .enumerate()
    {
        for (s, scope) in [Scope::Exact, Scope::Domain, Scope::Subdomains]
            .into_iter()
            .enumerate()
        {
            for (a, action) in [Action::Block, Action::Allow, Action::Enforce]
                .into_iter()
                .enumerate()
            {
                rules.push(Rule::new(name, scope, action, 1 << ((i + s + a) % 7)).unwrap());
            }
        }
    }
    let index = compile(&rules, Limits::default()).unwrap();
    for query in [
        "a", "ab", "a-b", "x.a", "x.ab", "y.x.ab", "z.y.x.ab", "X.AB.", "notab", "ab.x", "x.123",
        "0", "0.a", "x.z",
    ] {
        let canonical = query.trim_end_matches('.').to_ascii_lowercase();
        for enabled in 0..=Category::ALL {
            let mut found = [0; 3];
            for r in &rules {
                let exact = canonical == r.domain();
                let child = canonical
                    .strip_suffix(r.domain())
                    .is_some_and(|p| p.ends_with('.'));
                if match r.scope() {
                    Scope::Exact => exact,
                    Scope::Domain => exact || child,
                    Scope::Subdomains => child,
                } {
                    found[r.action() as usize] |= r.categories();
                }
            }
            let d = index.check(query, enabled).unwrap();
            assert_eq!(
                (d.blocked, d.allowed, d.enforced),
                (
                    ((found[0] & !found[1]) | found[2]) & enabled,
                    found[1] & enabled,
                    found[2] & enabled
                ),
                "{query}/{enabled}"
            );
        }
    }
}

#[test]
fn compact_matcher_agrees_with_independent_linear_policy_oracle() {
    let mut rules = Vec::new();
    for n in 0..300 {
        let domain = format!("d{}.zone{}.test", n % 23, n % 7);
        let scope = [Scope::Exact, Scope::Domain, Scope::Subdomains][n % 3];
        let action = [Action::Allow, Action::Block, Action::Enforce][n / 3 % 3];
        let categories = 1 << (n / 9 % 4);
        rules.push((domain, scope, action, categories));
    }
    let compiled: Vec<_> = rules
        .iter()
        .map(|(d, s, a, c)| Rule::new(d, *s, *a, *c).unwrap())
        .collect();
    let index = compile(&compiled, Limits::default()).unwrap();
    for n in 0..2400 {
        let domain = match n % 4 {
            0 => format!("d{}.zone{}.test", n % 29, n % 9),
            1 => format!("sub.d{}.zone{}.test", n % 29, n % 9),
            2 => format!("badd{}.zone{}.test", n % 29, n % 9),
            _ => format!("d{}.zone{}.test.evil", n % 29, n % 9),
        };
        let enabled = n as u32 & Category::ALL;
        let (mut block, mut allow, mut enforce) = (0, 0, 0);
        for (rule, scope, action, categories) in &rules {
            let exact = domain == *rule;
            let child = domain
                .strip_suffix(rule)
                .is_some_and(|prefix| prefix.ends_with('.'));
            let matches = match scope {
                Scope::Exact => exact,
                Scope::Domain => exact || child,
                Scope::Subdomains => child,
            };
            if matches {
                match action {
                    Action::Block => block |= categories,
                    Action::Allow => allow |= categories,
                    Action::Enforce => enforce |= categories,
                }
            }
        }
        let actual = index.check(&domain, enabled).unwrap();
        assert_eq!(
            actual.blocked,
            ((block & !allow) | enforce) & enabled,
            "{domain}"
        );
        assert_eq!(actual.allowed, allow & enabled, "{domain}");
        assert_eq!(actual.enforced, enforce & enabled, "{domain}");
    }
}
