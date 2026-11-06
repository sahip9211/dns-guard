//! Benchmark tooling: recompile a validated v1 snapshot, or generate matched
//! v1/v2 synthetic fixtures. Does not replace the budgeted production publisher.
use dns_guard::{Action, Category, Index, Limits, Rule, Scope, compile};
use fst::Streamer;
use std::{collections::BTreeMap, path::Path};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn legacy(rules: &[Rule]) -> Result<Vec<u8>> {
    let mut records = BTreeMap::<Vec<u8>, u64>::new();
    for rule in rules {
        let mut key = vec![rule.scope() as u8 * 3 + rule.action() as u8];
        key.extend(rule.domain().bytes().rev());
        *records.entry(key).or_default() |= rule.categories() as u64;
    }
    let mut builder = fst::MapBuilder::memory();
    for (key, value) in &records {
        builder.insert(key, *value)?;
    }
    let payload = builder.into_inner()?;
    let mut bytes = b"DNGIDX01".to_vec();
    bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&(records.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn mixed(path: &Path) -> Result<()> {
    std::fs::create_dir(path)?;
    let mut rules = Vec::new();
    let mut queries = String::new();
    // 20,000 distinct hosts, every scope/action kind, 180,000 logical policies.
    // Distinct category masks keep precedence observable. This deliberately
    // stresses mixed policy traversal; it is not a sampled traffic distribution.
    for n in 0..20_000_u32 {
        let name = format!("d{:08x}.zone{}.test", n.wrapping_mul(2654435761), n % 31);
        let mut full = [0; 3];
        let mut child = [0; 3];
        for scope in [Scope::Exact, Scope::Domain, Scope::Subdomains] {
            for action in [Action::Block, Action::Allow, Action::Enforce] {
                let bits = 1 << ((n + scope as u32 * 3 + action as u32) % 7);
                rules.push(Rule::new(&name, scope, action, bits)?);
                if scope != Scope::Subdomains {
                    full[action as usize] |= bits;
                }
                if scope != Scope::Exact {
                    child[action as usize] |= bits;
                }
            }
        }
        if n < 4000 {
            let decision = |m: [u32; 3]| (m[0] & !m[1]) | m[2];
            queries.push_str(&format!(
                "{name}\t127\t{}\nx.{name}\t127\t{}\nnegative{n}.invalid\t127\t0\n",
                decision(full),
                decision(child)
            ));
        }
    }
    let v1 = legacy(&rules)?;
    let v2 = compile(&rules, Limits::default())?;
    let old = Index::from_bytes(v1.clone(), Limits::default().max_index_bytes)?;
    for rule in &rules {
        assert_eq!(
            old.check(rule.domain(), Category::ALL)?,
            v2.check(rule.domain(), Category::ALL)?
        );
    }
    std::fs::write(path.join("v1.dngi"), v1)?;
    std::fs::write(path.join("v2.dngi"), v2.as_bytes())?;
    std::fs::write(path.join("queries.tsv"), queries)?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: repack V1_INDEX NEW_INDEX | repack --mixed NEW_DIRECTORY".into());
    }
    if args[0] == "--mixed" {
        return mixed(Path::new(&args[1]));
    }
    let old = Index::load(Path::new(&args[0]), Limits::default().max_index_bytes)?;
    if &old.as_bytes()[..8] != b"DNGIDX01" {
        return Err("expected v1 snapshot".into());
    }
    let map = fst::Map::new(&old.as_bytes()[32..])?;
    let mut stream = map.stream();
    let mut rules = Vec::with_capacity(old.rule_count());
    while let Some((key, categories)) = stream.next() {
        let name = String::from_utf8(key[1..].iter().rev().copied().collect())?;
        rules.push(Rule::new(
            &name,
            [Scope::Exact, Scope::Domain, Scope::Subdomains][key[0] as usize / 3],
            [Action::Block, Action::Allow, Action::Enforce][key[0] as usize % 3],
            categories as u32,
        )?);
    }
    // The compiler selects v1 for one kind and v2 for mixed kinds.
    let new = compile(&rules, Limits::default())?;
    assert_eq!(old.rule_count(), new.rule_count());
    for rule in &rules {
        assert_eq!(
            old.check(rule.domain(), Category::ALL)?,
            new.check(rule.domain(), Category::ALL)?
        );
    }
    // Never overwrite a corpus used by previous reports.
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[1])?;
    file.write_all(new.as_bytes())?;
    println!(
        "{{\"rules\":{},\"before_bytes\":{},\"after_bytes\":{}}}",
        new.rule_count(),
        old.as_bytes().len(),
        new.as_bytes().len()
    );
    Ok(())
}
