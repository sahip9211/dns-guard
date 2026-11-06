use crate::CliResult;
use dns_guard::keys::ManagementToken;
use std::{net::SocketAddr, path::Path};

pub fn run(args: &[String]) -> CliResult<()> {
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["token-create", "--keyring"] => {
            let id = ManagementToken::create_in_keyring()?;
            // Public identifier on stderr; secret on stdout only for this
            // explicit provisioning/export command, never ordinary startup.
            eprintln!("management credential ID: {id}");
            println!("{}", ManagementToken::read_keyring(&id)?.expose_bearer().as_str());
        }
        ["token-create", path] if !path.starts_with('-') => {
            let token = ManagementToken::create_file(Path::new(path))?;
            eprintln!("created private management credential; stdout contains the secret bearer token");
            println!("{}", token.expose_bearer().as_str());
        }
        ["token-show", "--token-file", path] => println!("{}", ManagementToken::read_file(Path::new(path))?.expose_bearer().as_str()),
        ["token-show", "--token-keyring", id] => println!("{}", ManagementToken::read_keyring(id)?.expose_bearer().as_str()),
        _ => return Err("management requires token-create PATH|--keyring or token-show --token-file PATH|--token-keyring ID".into()),
    }
    Ok(())
}

pub struct Options {
    pub address: SocketAddr,
    pub token: ManagementToken,
}

pub fn extract(args: &[String]) -> CliResult<(Vec<String>, Option<Options>)> {
    let mut remaining = Vec::new();
    let (mut listen, mut file, mut keyring) = (None, None, None);
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let slot = match arg.as_str() {
            "--management-listen" => &mut listen,
            "--management-token-file" => &mut file,
            "--management-token-keyring" => &mut keyring,
            _ => {
                remaining.push(arg.clone());
                continue;
            }
        };
        if slot.is_some() {
            return Err("duplicate management option".into());
        }
        *slot = Some(args.next().ok_or("management option requires a value")?);
    }
    if listen.is_none() && file.is_none() && keyring.is_none() {
        return Ok((remaining, None));
    }
    let address: SocketAddr = listen
        .ok_or("management credential requires --management-listen")?
        .parse()
        .map_err(|_| "management address must be a numeric loopback IP:PORT")?;
    if !address.ip().is_loopback() {
        return Err("management must bind a numeric loopback address".into());
    }
    let token = match (file, keyring) {
        (Some(path), None) => ManagementToken::read_file(Path::new(path))?,
        (None, Some(id)) => ManagementToken::read_keyring(id)?,
        _ => return Err(
            "management requires exactly one --management-token-file or --management-token-keyring"
                .into(),
        ),
    };
    Ok((remaining, Some(Options { address, token })))
}
