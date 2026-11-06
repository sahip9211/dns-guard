use dns_guard::Index;
use std::time::Instant;

#[allow(dead_code)] // The poll adapter writes directly into its fixed buffer.
pub fn route(index: &Index, method: &str, url: &str) -> (u16, String, Option<u128>) {
    let mut body = String::with_capacity(64);
    let (status, elapsed) =
        route_into(index, method, url, &mut body).expect("String write cannot fail");
    (status, body, elapsed)
}

pub fn route_into(
    index: &Index,
    method: &str,
    url: &str,
    body: &mut impl std::fmt::Write,
) -> Result<(u16, Option<u128>), std::fmt::Error> {
    fn plain(
        body: &mut impl std::fmt::Write,
        status: u16,
        text: &str,
    ) -> Result<(u16, Option<u128>), std::fmt::Error> {
        body.write_str(text)?;
        Ok((status, None))
    }
    if method != "GET" {
        return plain(body, 405, "method not allowed");
    }
    if url == "/health" {
        return plain(body, 200, "ok");
    }
    let Some(rest) = url.strip_prefix("/check/") else {
        return plain(body, 404, "not found");
    };
    let Some((categories, domain)) = rest.split_once('/') else {
        return plain(body, 400, "missing domain");
    };
    let Ok(categories) = categories.parse::<u32>() else {
        return plain(body, 400, "invalid category mask");
    };
    let start = Instant::now();
    let decision = index.check(domain, categories);
    let elapsed = start.elapsed().as_nanos();
    match decision {
        Ok(d) => {
            write!(
                body,
                "{{\"blocked\":{},\"allowed\":{},\"enforced\":{}}}",
                d.blocked, d.allowed, d.enforced
            )?;
            Ok((200, Some(elapsed)))
        }
        Err(error) => {
            write!(body, "{error}")?;
            Ok((400, None))
        }
    }
}
