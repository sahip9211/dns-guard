//! Per-instance database keys. File custody is a development interface, not an
//! OS credential vault or a boundary against other processes with the same UID.
use crate::{Error, Result};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

pub struct DataKey(Zeroizing<[u8; 32]>);
impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey([REDACTED])")
    }
}
impl DataKey {
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
