use super::{CliResult, parse_serve_options};
use dns_guard::{
    Index, Limits,
    config::{ConfigStore, Settings},
    server::ServerConfig,
};
use std::path::Path;

pub fn run(args: &[String]) -> CliResult<()> {
    match args.first().map(String::as_str) {
        Some("init") if args.len() >= 3 => {
            let mut settings = Settings {
                index_path: std::fs::canonicalize(&args[2])?,
                dns: ServerConfig::default(),
            };
            parse_serve_options(&args[3..], &mut settings.dns, true)?;
            validate_index(&settings)?;
            ConfigStore::create(Path::new(&args[1]), &settings)?;
            println!("created configuration revision=1; restart service to apply");
        }
        Some("show") if args.len() == 2 => {
            let saved = ConfigStore::open(Path::new(&args[1]))?.load()?;
            let s = &saved.settings;
            println!("schema=1 revision={}\nindex={}\nlisten={}\nupstream={}\ncategories={}\nmax_inflight={}\nmax_tcp_connections={}\ncache_bytes={}\ntimeout_ms={}", saved.revision, s.index_path.display(), s.dns.listen, s.dns.upstream, s.dns.categories, s.dns.max_inflight, s.dns.max_tcp_connections, s.dns.cache_bytes, s.dns.timeout.as_millis());
            for client in &s.dns.allowed_clients { println!("allow_client={client}"); }
        }
        Some("set") if args.len() >= 4 => {
            let mut store = ConfigStore::open(Path::new(&args[1]))?;
            let mut settings = store.load()?.settings;
            let mut revision = None;
            let mut index = None;
            let mut options = Vec::new();
            let (pairs, remainder) = args[2..].as_chunks::<2>();
            if !remainder.is_empty() { return Err("incomplete configuration option".into()); }
            for [key, value] in pairs {
                match key.as_str() {
                    "--revision" if revision.is_none() => revision = Some(value.parse::<u64>()?),
                    "--index" if index.is_none() => index = Some(std::fs::canonicalize(value)?),
                    "--revision" | "--index" => return Err(format!("duplicate option: {key}").into()),
                    _ => { options.push(key.clone()); options.push(value.clone()); }
                }
            }
            let revision = revision.ok_or("config set requires --revision from config show")?;
            if index.is_none() && options.is_empty() { return Err("config set requires at least one setting".into()); }
            if let Some(path) = index { settings.index_path = path; }
            parse_serve_options(&options, &mut settings.dns, false)?;
            validate_index(&settings)?;
            let next = store.replace(revision, &settings)?;
            println!("saved configuration revision={next}; restart service to apply");
        }
        _ => return Err("use config init DATABASE INDEX --upstream IP:PORT, config show DATABASE, or config set DATABASE --revision N [OPTIONS]".into()),
    }
    Ok(())
}

fn validate_index(settings: &Settings) -> CliResult<()> {
    settings.validate()?;
    Index::load(&settings.index_path, Limits::default().max_index_bytes)?;
    Ok(())
}
