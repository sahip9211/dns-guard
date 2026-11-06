use crate::{Action, Error, Limits, Result, Rule, Scope, validate_categories};

#[derive(Clone, Copy, Debug)]
pub enum FeedFormat {
    Domains,
    Hosts,
    Adblock,
}

/// Strict import: unsupported syntax fails the feed, preserving the active index.
/// Plain domains and sinkhole hosts entries block the domain and its descendants.
pub fn parse_feed(
    text: &str,
    format: FeedFormat,
    categories: u32,
    limits: Limits,
) -> Result<Vec<Rule>> {
    validate_categories(categories)?;
    if categories == 0 {
        return Err(Error::new("feed categories cannot be empty"));
    }
    if text.len() > limits.max_input_bytes {
        return Err(Error::new("feed exceeds input byte limit"));
    }
    let mut rules = Vec::new();
    for (line_number, raw) in text.lines().enumerate() {
        let parse_line = |rules: &mut Vec<Rule>| -> Result<()> {
            if raw.len() > limits.max_line_bytes {
                return Err(Error::new("line exceeds byte limit"));
            }
            let line = raw.trim();
            if line.is_empty() || (!matches!(format, FeedFormat::Adblock) && line.starts_with('#'))
            {
                return Ok(());
            }
            let mut push = |domain: &str, action: Action| -> Result<()> {
                if rules.len() >= limits.max_rules {
                    return Err(Error::new("feed exceeds rule limit"));
                }
                rules.push(Rule::new(domain, Scope::Domain, action, categories)?);
                Ok(())
            };
            match format {
                FeedFormat::Domains => push(line, Action::Block)?,
                FeedFormat::Adblock => {
                    if line.starts_with('!')
                        || matches!(line, "[Adblock Plus]" | "[Adblock Plus 2.0]")
                    {
                        return Ok(());
                    }
                    let (line, action) = match line.strip_prefix("@@") {
                        Some(rule) => (rule, Action::Allow),
                        None => (line, Action::Block),
                    };
                    let domain = line
                        .strip_prefix("||")
                        .and_then(|s| s.strip_suffix('^'))
                        .ok_or_else(|| {
                            Error::new(
                                "unsupported Adblock syntax; expected ||hostname^ or @@||hostname^",
                            )
                        })?;
                    push(domain, action)?;
                }
                FeedFormat::Hosts => {
                    let mut fields = line.split('#').next().unwrap_or("").split_whitespace();
                    let address = fields
                        .next()
                        .ok_or_else(|| Error::new("missing hosts address"))?;
                    if !matches!(address, "0.0.0.0" | "127.0.0.1" | "::" | "::1") {
                        return Err(Error::new("hosts entry must use a sinkhole address"));
                    }
                    let mut had_host = false;
                    for host in fields {
                        had_host = true;
                        if [
                            "localhost",
                            "localhost.localdomain",
                            "local",
                            "ip6-localhost",
                            "ip6-loopback",
                            "broadcasthost",
                        ]
                        .iter()
                        .any(|name| host.eq_ignore_ascii_case(name))
                        {
                            continue;
                        }
                        push(host, Action::Block)?;
                    }
                    if !had_host {
                        return Err(Error::new("hosts entry has no hostname"));
                    }
                }
            }
            Ok(())
        };
        parse_line(&mut rules)
            .map_err(|error| Error::new(format!("line {}: {error}", line_number + 1)))?;
    }
    if rules.is_empty() {
        return Err(Error::new("feed contains no supported rules"));
    }
    Ok(rules)
}
