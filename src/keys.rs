//! Per-instance database keys. File custody is a development interface, not an
//! OS credential vault or a boundary against other processes with the same UID.
use crate::{Error, Result};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

#[cfg(feature = "os-keyring")]
mod os_store;

pub struct DataKey(Zeroizing<[u8; 32]>);
impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey([REDACTED])")
    }
}
impl DataKey {
    /// Create a new OS-store entry under a random public identifier, never a
    /// caller-selected name that could accidentally replace an existing key.
    pub fn create_in_keyring() -> Result<String> {
        #[cfg(feature = "os-keyring")]
        {
            os_store::create("dns-guard.instance-key.v1")
        }
        #[cfg(not(feature = "os-keyring"))]
        {
            Err(Error::new(
                "OS credential store support is not enabled in this build",
            ))
        }
    }

    /// Read only: missing, locked or corrupt credentials are never regenerated.
    pub fn read_keyring(id: &str) -> Result<Self> {
        #[cfg(feature = "os-keyring")]
        {
            os_store::read("dns-guard.instance-key.v1", id)
        }
        #[cfg(not(feature = "os-keyring"))]
        {
            let _ = id;
            Err(Error::new(
                "OS credential store support is not enabled in this build",
            ))
        }
    }

    /// Raw high-entropy key supplied by a credential provider. Not a password KDF.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::fill(bytes.as_mut())
            .map_err(|e| Error::new(format!("OS key generation failed: {e}")))?;
        Ok(Self(bytes))
    }
    /// Never overwrite a previous key: doing so would orphan its encrypted data.
    pub fn create_file(path: &Path) -> Result<Self> {
        let key = Self::generate()?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(key.0.as_ref())?;
        file.sync_all()?;
        #[cfg(unix)]
        File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
        Ok(key)
    }
    pub fn read_file(path: &Path) -> Result<Self> {
        validate_file(&fs::symlink_metadata(path)?)?;
        let mut file = File::open(path)?;
        validate_file(&file.metadata()?)?;
        let mut bytes = Zeroizing::new([0; 32]);
        file.read_exact(bytes.as_mut())?;
        if file.read(&mut [0; 1])? != 0 {
            return Err(Error::new("key file must contain exactly 32 bytes"));
        }
        Ok(Self(bytes))
    }
    pub(crate) fn sqlcipher_literal(&self) -> Zeroizing<String> {
        use std::fmt::Write;
        let mut text = Zeroizing::new(String::with_capacity(67));
        text.push_str("x'");
        for byte in self.0.iter() {
            write!(&mut *text, "{byte:02x}").expect("writing to String");
        }
        text.push('\'');
        text
    }
}
/// Independent, randomly generated read-only management credential. Never use a
/// database key as a bearer token. The native store has a separate namespace.
pub struct ManagementToken(DataKey);

impl std::fmt::Debug for ManagementToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ManagementToken([REDACTED])")
    }
}

impl ManagementToken {
    pub fn generate() -> Result<Self> {
        DataKey::generate().map(Self)
    }
    pub fn create_file(path: &Path) -> Result<Self> {
        DataKey::create_file(path).map(Self)
    }
    pub fn read_file(path: &Path) -> Result<Self> {
        DataKey::read_file(path).map(Self)
    }
    pub fn create_in_keyring() -> Result<String> {
        #[cfg(feature = "os-keyring")]
        {
            os_store::create("dns-guard.management-token.v1")
        }
        #[cfg(not(feature = "os-keyring"))]
        {
            Err(Error::new(
                "OS credential store support is not enabled in this build",
            ))
        }
    }
    pub fn read_keyring(id: &str) -> Result<Self> {
        #[cfg(feature = "os-keyring")]
        {
            os_store::read("dns-guard.management-token.v1", id).map(Self)
        }
        #[cfg(not(feature = "os-keyring"))]
        {
            let _ = id;
            Err(Error::new(
                "OS credential store support is not enabled in this build",
            ))
        }
    }
    /// Explicit bootstrap/export only. Do not log this value or place it in URLs.
    pub fn expose_bearer(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.0.0.as_ref()))
    }
    pub fn ensure_separate_from(&self, data_key: &DataKey) -> Result<()> {
        use subtle::ConstantTimeEq;
        if bool::from(self.0.0.as_ref().ct_eq(data_key.0.as_ref())) {
            return Err(Error::new(
                "management token must not reuse the database key",
            ));
        }
        Ok(())
    }
}

fn validate_file(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_file() || metadata.len() != 32 {
        return Err(Error::new(
            "key must be a regular 32-byte file, not a symlink",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::new(
                "key file must deny group and other access (chmod 600)",
            ));
        }
    }
    Ok(())
}
