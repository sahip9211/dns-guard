use super::{CliResult, parse_serve_options};
use dns_guard::{
    Index, Limits,
    config::{ConfigStore, Settings},
    keys::DataKey,
    server::ServerConfig,
};
use std::path::Path;

pub fn run(args: &[String]) -> CliResult<()> {
    if args.first().is_some_and(|arg| arg == "keygen") {
        if args.len() == 2 && args[1] == "--keyring" {
            println!("{}", DataKey::create_in_keyring()?);
            return Ok(());
        }
        if args.len() != 2 {
            return Err("use config keygen KEY_FILE or config keygen --keyring".into());
        }
        DataKey::create_file(Path::new(&args[1]))?;
        println!("created private instance key; keep it separate from database backups");
        return Ok(());
    }
    let (args, key) = with_key(args)?;
    match args.first().map(String::as_str) {
        Some("encrypt") if args.len()==3 => {
            ConfigStore::import_plaintext(Path::new(&args[1]),Path::new(&args[2]),&key)?;
            println!("created encrypted configuration revision=1; source remains plaintext and was not removed");
        }
        Some("init") if args.len() >= 3 => {
            let mut settings = Settings {
                index_path: std::fs::canonicalize(&args[2])?,
                dns: ServerConfig::default(),
            };
            parse_serve_options(&args[3..], &mut settings.dns, true)?;
            validate_index(&settings)?;
            ConfigStore::create(Path::new(&args[1]), &settings, &key)?;
            println!("created configuration revision=1; restart service to apply");
        }
        Some("show") if args.len() == 2 => {
            let saved = ConfigStore::open(Path::new(&args[1]), &key)?.load()?;
            let s = &saved.settings;
            println!("schema=1 revision={}\nindex={}\nlisten={}\nupstream={}\ncategories={}\nmax_inflight={}\nmax_tcp_connections={}\ncache_bytes={}\ntimeout_ms={}", saved.revision, s.index_path.display(), s.dns.listen, s.dns.upstream, s.dns.categories, s.dns.max_inflight, s.dns.max_tcp_connections, s.dns.cache_bytes, s.dns.timeout.as_millis());
            for client in &s.dns.allowed_clients { println!("allow_client={client}"); }
        }
        Some("set") if args.len() >= 4 => {
            let mut store = ConfigStore::open(Path::new(&args[1]), &key)?;
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

pub fn with_key(args: &[String]) -> CliResult<(Vec<String>, DataKey)> {
    let mut rest = Vec::new();
    let mut source = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--key-file" || args[i] == "--keyring" {
            if source.is_some() || i + 1 == args.len() {
                return Err(
                    "supply exactly one key source: --key-file PATH or --keyring ID".into(),
                );
            }
            source = Some((args[i].as_str(), &args[i + 1]));
            i += 2;
        } else {
            rest.push(args[i].clone());
            i += 1;
        }
    }
    let (kind, value)=source.ok_or("encrypted configuration requires --key-file PATH or --keyring ID; create a new instance key with config keygen")?;
    let key = if kind == "--keyring" {
        DataKey::read_keyring(value)?
    } else {
        DataKey::read_file(Path::new(value))?
    };
    Ok((rest, key))
}

fn validate_index(settings: &Settings) -> CliResult<()> {
    settings.validate()?;
    Index::load(&settings.index_path, Limits::default().max_index_bytes)?;
    Ok(())
}
