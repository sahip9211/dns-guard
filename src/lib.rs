//! Exact, immutable domain policy indexes shared by all client profiles.
//!
//! A bounded DNS forwarding service is available in [`server`].
#![forbid(unsafe_code)]

mod cache;
pub mod config;
mod domain;
mod feeds;
mod index;
pub mod server;
mod storage;

pub use feeds::{FeedFormat, parse_feed};
pub use index::{Index, compile, compile_sources};
pub use storage::Budget;

/// Stable category bits in snapshot format versions 1 and 2.
pub struct Category;
impl Category {
    pub const ADS: u32 = 1;
    pub const ADULT: u32 = 2;
    pub const MALWARE: u32 = 4;
    pub const TRACKING: u32 = 8;
    pub const PHISHING: u32 = 16;
    pub const GAMBLING: u32 = 32;
    pub const SOCIAL: u32 = 64;
    pub const ALL: u32 = 127;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Scope {
    /// Only this hostname.
    Exact = 0,
    /// This hostname and its descendants, at DNS label boundaries.
    Domain = 1,
    /// Descendants only; excludes the hostname itself.
    Subdomains = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Action {
    Block = 0,
    Allow = 1,
    /// Cannot be overridden by an allow rule; still requires an enabled category.
    Enforce = 2,
}

#[derive(Clone, Debug)]
pub struct Rule {
    domain: String,
    scope: Scope,
    action: Action,
    categories: u32,
}
impl Rule {
    pub fn new(domain: &str, scope: Scope, action: Action, categories: u32) -> Result<Self> {
        validate_categories(categories)?;
        if categories == 0 {
            return Err(Error::new("a rule must have at least one category"));
        }
        Ok(Self {
            domain: domain::Domain::parse(domain)?.as_str().to_owned(),
            scope,
            action,
            categories,
        })
    }
    pub fn domain(&self) -> &str {
        &self.domain
    }
    pub fn scope(&self) -> Scope {
        self.scope
    }
    pub fn action(&self) -> Action {
        self.action
    }
    pub fn categories(&self) -> u32 {
        self.categories
    }
}

/// Borrowed input to an offline rebuild. Disabled sources contribute no rules.
/// Source identity/configuration and file retention belong to the caller.
#[derive(Clone, Copy, Debug)]
pub struct RuleSource<'a> {
    pub enabled: bool,
    pub rules: &'a [Rule],
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Raw feed bytes, separately from installed footprint.
    pub max_input_bytes: usize,
    pub max_line_bytes: usize,
    /// Before deduplication, to bound compiler work.
    pub max_rules: usize,
    /// Includes the snapshot header. The complete app has a separate budget.
    pub max_index_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024 * 1024,
            max_line_bytes: 4096,
            max_rules: 1_000_000,
            max_index_bytes: 9_999_999,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Decision {
    /// Effective blocked categories after allow/enforce precedence.
    pub blocked: u32,
    /// Categories matched by allow rules (may also be enforced).
    pub allowed: u32,
    pub enforced: u32,
}
impl Decision {
    pub fn is_blocked(self) -> bool {
        self.blocked != 0
    }
}

#[derive(Debug)]
pub struct Error(String);
impl Error {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}
impl From<fst::Error> for Error {
    fn from(error: fst::Error) -> Self {
        Self(error.to_string())
    }
}
pub type Result<T> = std::result::Result<T, Error>;

fn validate_categories(categories: u32) -> Result<()> {
    if categories & !Category::ALL != 0 {
        return Err(Error::new("unknown category bits"));
    }
    Ok(())
}
