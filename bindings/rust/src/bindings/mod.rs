#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[cfg(feature = "serde")]
mod serde;
#[cfg(test)]
mod test_formats;

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::fmt;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};

#[cfg(feature = "std")]
use alloc::ffi::CString;
#[cfg(feature = "std")]
use std::path::Path;

pub const FIELD_ELEMENTS_PER_BLOB_MAINNET: usize = 4096;
pub const BYTES_PER_BLOB_MAINNET: usize = FIELD_ELEMENTS_PER_BLOB_MAINNET * BYTES_PER_FIELD_ELEMENT;
pub const FIELD_ELEMENTS_PER_BLOB_MINIMAL: usize = 4;
pub const BYTES_PER_BLOB_MINIMAL: usize = FIELD_ELEMENTS_PER_BLOB_MINIMAL * BYTES_PER_FIELD_ELEMENT;

pub const BYTES_PER_G1_POINT: usize = 48;
pub const BYTES_PER_G2_POINT: usize = 96;

/// Number of G2 points required for the kzg trusted setup.
/// 65 is fixed and is used for providing multiproofs up to 64 field elements.
pub const NUM_G2_POINTS: usize = 65;

/// A trusted (valid) KZG commitment.
// NOTE: this is a type alias to the struct Bytes48, same as [`KZGProof`] in the C header files. To
//       facilitate type safety: proofs and commitments should not be interchangeable, we use a
//       custom implementation.
#[repr(C)]
pub struct KZGCommitment {
    bytes: [u8; BYTES_PER_COMMITMENT],
}

/// A trusted (valid) KZG proof.
// NOTE: this is a type alias to the struct Bytes48, same as [`KZGCommitment`] in the C header
//       files. To facilitate type safety: proofs and commitments should not be interchangeable, we
//       use a custom implementation.
#[repr(C)]
pub struct KZGProof {
    bytes: [u8; BYTES_PER_PROOF],
}

#[derive(Debug, Clone, PartialEq)]
pub struct Blob<const BYTES_PER_BLOB: usize> {
    bytes: [u8; BYTES_PER_BLOB],
}

pub type MainnetBlob = Blob<BYTES_PER_BLOB_MAINNET>;
pub type MinimalBlob = Blob<BYTES_PER_BLOB_MINIMAL>;

#[derive(Debug, Clone, PartialEq)]
pub struct GenericBlob {
    bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct KzgSettings<
    const FIELD_ELEMENTS_PER_BLOB: usize,
    const BYTES_PER_BLOB: usize,
    B: ValidatedBlob,
> {
    kzg_settings: KZGSettings,
    _phantom: PhantomData<B>,
}

pub type MainnetKzgSettings =
    KzgSettings<FIELD_ELEMENTS_PER_BLOB_MAINNET, BYTES_PER_BLOB_MAINNET, MainnetBlob>;
pub type MinimalKzgSettings =
    KzgSettings<FIELD_ELEMENTS_PER_BLOB_MINIMAL, BYTES_PER_BLOB_MINIMAL, MinimalBlob>;
pub type GenericMainnetKzgSettings =
    KzgSettings<FIELD_ELEMENTS_PER_BLOB_MAINNET, BYTES_PER_BLOB_MAINNET, GenericBlob>;
pub type GenericMinimalKzgSettings =
    KzgSettings<FIELD_ELEMENTS_PER_BLOB_MINIMAL, BYTES_PER_BLOB_MINIMAL, GenericBlob>;

impl<const FIELD_ELEMENTS_PER_BLOB: usize, const BYTES_PER_BLOB: usize>
    KzgSettings<FIELD_ELEMENTS_PER_BLOB, BYTES_PER_BLOB, GenericBlob>
{
    pub fn validate_blob(bytes: &[u8]) -> Result<GenericBlob, Error> {
        let blob = slice_to_blob::<BYTES_PER_BLOB>(bytes)?;
        Ok(GenericBlob {
            bytes: blob.to_vec(),
        })
    }
}

pub trait ValidatedBlob: AsRef<[u8]> {}

impl ValidatedBlob for MainnetBlob {}
impl ValidatedBlob for MinimalBlob {}
impl ValidatedBlob for GenericBlob {}

pub trait KzgSettingsTrait {
    type Blob;

    fn new(kzg_settings: KZGSettings) -> Result<Self, Error>
    where
        Self: Sized;

    fn load_trusted_setup_file(trusted_setup_file: &Path) -> Result<Self, Error>
    where
        Self: Sized;

    fn load_trusted_setup(
        g1_bytes: &[[u8; BYTES_PER_G1_POINT]],
        g2_bytes: &[[u8; BYTES_PER_G2_POINT]],
    ) -> Result<Self, Error>
    where
        Self: Sized;

    fn blob_to_kzg_commitment(&self, blob: &Self::Blob) -> Result<KZGCommitment, Error>;

    fn compute_kzg_proof(
        &self,
        blob: &Self::Blob,
        z_bytes: &Bytes32,
    ) -> Result<(KZGProof, Bytes32), Error>;

    fn compute_blob_kzg_proof(
        &self,
        blob: &Self::Blob,
        commitment_bytes: &Bytes48,
    ) -> Result<KZGProof, Error>;

    fn verify_kzg_proof(
        &self,
        commitment_bytes: &Bytes48,
        z_bytes: &Bytes32,
        y_bytes: &Bytes32,
        proof_bytes: &Bytes48,
    ) -> Result<bool, Error>;

    fn verify_blob_kzg_proof(
        &self,
        blob: &Self::Blob,
        commitment_bytes: &Bytes48,
        proof_bytes: &Bytes48,
    ) -> Result<bool, Error>;

    fn verify_blob_kzg_proof_batch(
        &self,
        blobs: &[Self::Blob],
        commitments_bytes: &[Bytes48],
        proofs_bytes: &[Bytes48],
    ) -> Result<bool, Error>;
}

impl<const FIELD_ELEMENTS_PER_BLOB: usize, const BYTES_PER_BLOB: usize, B: ValidatedBlob>
    KzgSettingsTrait for KzgSettings<FIELD_ELEMENTS_PER_BLOB, BYTES_PER_BLOB, B>
{
    type Blob = B;

    fn new(kzg_settings: KZGSettings) -> Result<Self, Error> {
        if kzg_settings.field_elements_per_blob() != FIELD_ELEMENTS_PER_BLOB {
            return Err(Error::InvalidTrustedSetup("length mismatch".to_string()));
        }
        Ok(Self {
            kzg_settings,
            _phantom: PhantomData,
        })
    }

    /// Loads a trusted setup in the format described below and
    /// returns a `KzgSettings` struct.
    ///
    /// The file format is as follows:
    ///
    /// FIELD_ELEMENTS_PER_BLOB
    /// 65 # This is fixed and is used for providing multiproofs up to 64 field elements.
    /// `FIELD_ELEMENT_PER_BLOB` lines with each line containing a hex encoded g1 byte value.
    /// 65 lines with each line containing a hex encoded g2 byte value.
    fn load_trusted_setup_file(trusted_setup_file: &Path) -> Result<Self, Error> {
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file)?;
        Self::new(kzg_settings)
    }

    /// Loads a trusted setup and returns a `KzgSettings` struct.
    ///
    /// The `g1_bytes` and `g2_bytes` need to be extracted and parsed from a file
    /// and then passed into this function.
    fn load_trusted_setup(
        g1_bytes: &[[u8; BYTES_PER_G1_POINT]],
        g2_bytes: &[[u8; BYTES_PER_G2_POINT]],
    ) -> Result<Self, Error> {
        let kzg_settings = KZGSettings::load_trusted_setup(g1_bytes, g2_bytes)?;
        Self::new(kzg_settings)
    }

    /// Return the `KzgCommitment` corresponding to the `Blob`.
    fn blob_to_kzg_commitment(&self, blob: &B) -> Result<KZGCommitment, Error> {
        let mut kzg_commitment: MaybeUninit<KZGCommitment> = MaybeUninit::uninit();
        unsafe {
            let res = blob_to_kzg_commitment(
                kzg_commitment.as_mut_ptr(),
                blob.as_ref().as_ptr(),
                &self.kzg_settings,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(kzg_commitment.assume_init())
            } else {
                Err(Error::CError(res))
            }
        }
    }

    /// Compute the `KZGProof` given the `Blob` at the point corresponding to field element `z`.
    fn compute_kzg_proof(&self, blob: &B, z_bytes: &Bytes32) -> Result<(KZGProof, Bytes32), Error> {
        let mut kzg_proof = MaybeUninit::<KZGProof>::uninit();
        let mut y_out = MaybeUninit::<Bytes32>::uninit();
        unsafe {
            let res = compute_kzg_proof(
                kzg_proof.as_mut_ptr(),
                y_out.as_mut_ptr(),
                blob.as_ref().as_ptr(),
                z_bytes,
                &self.kzg_settings,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok((kzg_proof.assume_init(), y_out.assume_init()))
            } else {
                Err(Error::CError(res))
            }
        }
    }

    /// Compute the `KZGProof` given the `Blob` and `KzgCommitment`.
    fn compute_blob_kzg_proof(
        &self,
        blob: &B,
        commitment_bytes: &Bytes48,
    ) -> Result<KZGProof, Error> {
        let mut kzg_proof = MaybeUninit::<KZGProof>::uninit();
        unsafe {
            let res = compute_blob_kzg_proof(
                kzg_proof.as_mut_ptr(),
                blob.as_ref().as_ptr(),
                commitment_bytes,
                &self.kzg_settings,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(kzg_proof.assume_init())
            } else {
                Err(Error::CError(res))
            }
        }
    }

    /// Verify a KZG proof claiming that `p(z) == y`.
    fn verify_kzg_proof(
        &self,
        commitment_bytes: &Bytes48,
        z_bytes: &Bytes32,
        y_bytes: &Bytes32,
        proof_bytes: &Bytes48,
    ) -> Result<bool, Error> {
        let mut verified: MaybeUninit<bool> = MaybeUninit::uninit();
        unsafe {
            let res = verify_kzg_proof(
                verified.as_mut_ptr(),
                commitment_bytes,
                z_bytes,
                y_bytes,
                proof_bytes,
                &self.kzg_settings,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(verified.assume_init())
            } else {
                Err(Error::CError(res))
            }
        }
    }

    /// Given a blob and its proof, verify that it corresponds to the provided commitment.
    fn verify_blob_kzg_proof(
        &self,
        blob: &B,
        commitment_bytes: &Bytes48,
        proof_bytes: &Bytes48,
    ) -> Result<bool, Error> {
        let mut verified: MaybeUninit<bool> = MaybeUninit::uninit();
        unsafe {
            let res = verify_blob_kzg_proof(
                verified.as_mut_ptr(),
                blob.as_ref().as_ptr(),
                commitment_bytes,
                proof_bytes,
                &self.kzg_settings,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(verified.assume_init())
            } else {
                Err(Error::CError(res))
            }
        }
    }

    /// Given a list of blobs and blob KZG proofs, verify that they correspond to the
    /// provided commitments.
    fn verify_blob_kzg_proof_batch(
        &self,
        blobs: &[B],
        commitments_bytes: &[Bytes48],
        proofs_bytes: &[Bytes48],
    ) -> Result<bool, Error> {
        if blobs.len() != commitments_bytes.len() {
            return Err(Error::MismatchLength(format!(
                "There are {} blobs and {} commitments",
                blobs.len(),
                commitments_bytes.len()
            )));
        }
        if blobs.len() != proofs_bytes.len() {
            return Err(Error::MismatchLength(format!(
                "There are {} blobs and {} proofs",
                blobs.len(),
                proofs_bytes.len()
            )));
        }

        let mut flat_blobs: Vec<u8> = Vec::with_capacity(blobs.len() * FIELD_ELEMENTS_PER_BLOB);
        for blob in blobs {
            flat_blobs.extend_from_slice(blob.as_ref());
        }

        let mut verified: MaybeUninit<bool> = MaybeUninit::uninit();
        unsafe {
            let res = verify_blob_kzg_proof_batch(
                verified.as_mut_ptr(),
                flat_blobs.as_ptr(),
                commitments_bytes.as_ptr(),
                proofs_bytes.as_ptr(),
                blobs.len(),
                &self.kzg_settings,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(verified.assume_init())
            } else {
                Err(Error::CError(res))
            }
        }
    }
}

impl<const BYTES_PER_BLOB: usize> Blob<BYTES_PER_BLOB> {
    pub fn new(bytes: [u8; BYTES_PER_BLOB]) -> Self {
        Self { bytes }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let blob = slice_to_blob::<BYTES_PER_BLOB>(bytes)?;
        Ok(Self { bytes: blob })
    }
}

impl<const BYTES_PER_BLOB: usize> Deref for Blob<BYTES_PER_BLOB> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.bytes.as_slice()
    }
}

impl<const BYTES_PER_BLOB: usize> std::convert::AsRef<[u8]> for Blob<BYTES_PER_BLOB> {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl Deref for GenericBlob {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.bytes.as_slice()
    }
}

impl std::convert::AsRef<[u8]> for GenericBlob {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

fn slice_to_blob<const BYTES_PER_BLOB: usize>(bytes: &[u8]) -> Result<[u8; BYTES_PER_BLOB], Error> {
    if bytes.len() != BYTES_PER_BLOB {
        return Err(Error::MismatchLength(format!(
            "Blob length invalid {}",
            bytes.len()
        )));
    }
    let mut blob = [0; BYTES_PER_BLOB];
    blob.copy_from_slice(bytes);
    Ok(blob)
}

#[derive(Debug)]
pub enum Error {
    /// Wrong number of bytes.
    InvalidBytesLength(String),
    /// The hex string is invalid.
    InvalidHexFormat(String),
    /// The KZG proof is invalid.
    InvalidKzgProof(String),
    /// The KZG commitment is invalid.
    InvalidKzgCommitment(String),
    /// The provided trusted setup is invalid.
    InvalidTrustedSetup(String),
    /// Paired arguments have different lengths.
    MismatchLength(String),
    /// The underlying c-kzg library returned an error.
    CError(C_KZG_RET),
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBytesLength(s)
            | Self::InvalidHexFormat(s)
            | Self::InvalidKzgProof(s)
            | Self::InvalidKzgCommitment(s)
            | Self::InvalidTrustedSetup(s)
            | Self::MismatchLength(s) => f.write_str(s),
            Self::CError(s) => fmt::Debug::fmt(s, f),
        }
    }
}

/// Converts a hex string (with or without the 0x prefix) to bytes.
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, Error> {
    let trimmed_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(trimmed_str)
        .map_err(|e| Error::InvalidHexFormat(format!("Failed to decode hex: {}", e)))
}

/// Holds the parameters of a kzg trusted setup ceremony.
impl KZGSettings {
    /// Initializes a trusted setup from `FIELD_ELEMENTS_PER_BLOB` g1 points
    /// and 65 g2 points in byte format.
    fn load_trusted_setup(
        g1_bytes: &[[u8; BYTES_PER_G1_POINT]],
        g2_bytes: &[[u8; BYTES_PER_G2_POINT]],
    ) -> Result<Self, Error> {
        let mut kzg_settings = MaybeUninit::<KZGSettings>::uninit();
        unsafe {
            let res = load_trusted_setup(
                kzg_settings.as_mut_ptr(),
                g1_bytes.as_ptr().cast(),
                g1_bytes.len(),
                g2_bytes.as_ptr().cast(),
                g2_bytes.len(),
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(kzg_settings.assume_init())
            } else {
                Err(Error::InvalidTrustedSetup(format!(
                    "Invalid trusted setup: {res:?}",
                )))
            }
        }
    }

    /// Loads the trusted setup parameters from a file. The file format is as follows:
    ///
    /// FIELD_ELEMENTS_PER_BLOB
    /// 65 # This is fixed and is used for providing multiproofs up to 64 field elements.
    /// FIELD_ELEMENT_PER_BLOB g1 byte values
    /// 65 g2 byte values
    #[cfg(feature = "std")]
    fn load_trusted_setup_file(file_path: &Path) -> Result<Self, Error> {
        #[cfg(unix)]
        let file_path_bytes = {
            use std::os::unix::prelude::OsStrExt;
            file_path.as_os_str().as_bytes()
        };

        #[cfg(windows)]
        let file_path_bytes = file_path
            .as_os_str()
            .to_str()
            .ok_or_else(|| Error::InvalidTrustedSetup("Unsupported non unicode file path".into()))?
            .as_bytes();

        let file_path = CString::new(file_path_bytes)
            .map_err(|e| Error::InvalidTrustedSetup(format!("Invalid trusted setup file: {e}")))?;

        Self::load_trusted_setup_file_inner(&file_path)
    }

    /// Loads the trusted setup parameters from a file. The file format is as follows:
    ///
    /// FIELD_ELEMENTS_PER_BLOB
    /// 65 # This is fixed and is used for providing multiproofs up to 64 field elements.
    /// FIELD_ELEMENT_PER_BLOB g1 byte values
    /// 65 g2 byte values
    #[cfg(not(feature = "std"))]
    fn load_trusted_setup_file(file_path: &CStr) -> Result<Self, Error> {
        Self::load_trusted_setup_file_inner(file_path)
    }

    /// Loads the trusted setup parameters from a file.
    ///
    /// Same as [`load_trusted_setup_file`](Self::load_trusted_setup_file)
    #[cfg_attr(not(feature = "std"), doc = ", but takes a `CStr` instead of a `Path`")]
    /// .
    fn load_trusted_setup_file_inner(file_path: &CStr) -> Result<Self, Error> {
        // SAFETY: `b"r\0"` is a valid null-terminated string.
        const MODE: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"r\0") };

        // SAFETY:
        // - .as_ptr(): pointer is not dangling because file_path has not been dropped.
        //    Usage or ptr: File will not be written to it by the c code.
        let file_ptr = unsafe { libc::fopen(file_path.as_ptr(), MODE.as_ptr()) };
        if file_ptr.is_null() {
            #[cfg(not(feature = "std"))]
            return Err(Error::InvalidTrustedSetup(format!(
                "Failed to open trusted setup file {file_path:?}"
            )));

            #[cfg(feature = "std")]
            return Err(Error::InvalidTrustedSetup(format!(
                "Failed to open trusted setup file {file_path:?}: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut kzg_settings = MaybeUninit::<KZGSettings>::uninit();
        let result = unsafe {
            let res = load_trusted_setup_file(kzg_settings.as_mut_ptr(), file_ptr);
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(kzg_settings.assume_init())
            } else {
                Err(Error::InvalidTrustedSetup(format!(
                    "Invalid trusted setup: {res:?}"
                )))
            }
        };

        // We don't really care if this fails.
        let _unchecked_close_result = unsafe { libc::fclose(file_ptr) };

        result
    }
}

impl Drop for KZGSettings {
    fn drop(&mut self) {
        unsafe { free_trusted_setup(self) }
    }
}

impl Bytes32 {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 32 {
            return Err(Error::InvalidBytesLength(format!(
                "Invalid byte length. Expected {} got {}",
                32,
                bytes.len(),
            )));
        }
        let mut new_bytes = [0; 32];
        new_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: new_bytes })
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        Self::from_bytes(&hex_to_bytes(hex_str)?)
    }
}

impl Bytes48 {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 48 {
            return Err(Error::InvalidBytesLength(format!(
                "Invalid byte length. Expected {} got {}",
                48,
                bytes.len(),
            )));
        }
        let mut new_bytes = [0; 48];
        new_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: new_bytes })
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        Self::from_bytes(&hex_to_bytes(hex_str)?)
    }

    pub fn into_inner(self) -> [u8; 48] {
        self.bytes
    }
}

impl KZGProof {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BYTES_PER_PROOF {
            return Err(Error::InvalidKzgProof(format!(
                "Invalid byte length. Expected {} got {}",
                BYTES_PER_PROOF,
                bytes.len(),
            )));
        }
        let mut proof_bytes = [0; BYTES_PER_PROOF];
        proof_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: proof_bytes })
    }

    pub fn to_bytes(&self) -> Bytes48 {
        Bytes48 { bytes: self.bytes }
    }

    pub fn as_hex_string(&self) -> String {
        hex::encode(self.bytes)
    }
}

impl KZGCommitment {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BYTES_PER_COMMITMENT {
            return Err(Error::InvalidKzgCommitment(format!(
                "Invalid byte length. Expected {} got {}",
                BYTES_PER_PROOF,
                bytes.len(),
            )));
        }
        let mut commitment = [0; BYTES_PER_COMMITMENT];
        commitment.copy_from_slice(bytes);
        Ok(Self { bytes: commitment })
    }

    pub fn to_bytes(&self) -> Bytes48 {
        Bytes48 { bytes: self.bytes }
    }

    pub fn as_hex_string(&self) -> String {
        hex::encode(self.bytes)
    }
}

impl From<[u8; BYTES_PER_COMMITMENT]> for KZGCommitment {
    fn from(value: [u8; BYTES_PER_COMMITMENT]) -> Self {
        Self { bytes: value }
    }
}

impl From<[u8; BYTES_PER_PROOF]> for KZGProof {
    fn from(value: [u8; BYTES_PER_PROOF]) -> Self {
        Self { bytes: value }
    }
}

impl From<[u8; 32]> for Bytes32 {
    fn from(value: [u8; 32]) -> Self {
        Self { bytes: value }
    }
}

impl From<[u8; 48]> for Bytes48 {
    fn from(value: [u8; 48]) -> Self {
        Self { bytes: value }
    }
}

impl Deref for Bytes32 {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl Deref for Bytes48 {
    type Target = [u8; 48];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl DerefMut for Bytes48 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

impl Deref for KZGProof {
    type Target = [u8; BYTES_PER_PROOF];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl Deref for KZGCommitment {
    type Target = [u8; BYTES_PER_COMMITMENT];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

/// Safety: The memory for `roots_of_unity` and `g1_values` and `g2_values` are only freed on
/// calling `free_trusted_setup` which only happens when we drop the struct.
unsafe impl Sync for KZGSettings {}
unsafe impl Send for KZGSettings {}

#[cfg(test)]
#[allow(unused_imports, dead_code)]
mod tests {
    use super::*;
    use kzg_mainnet::{Blob, Kzg, KzgSettings, BYTES_PER_BLOB, FIELD_ELEMENTS_PER_BLOB};
    use rand::{rngs::ThreadRng, Rng};
    use std::{fs, path::PathBuf};
    use test_formats::{
        blob_to_kzg_commitment_test, compute_blob_kzg_proof, compute_kzg_proof,
        verify_blob_kzg_proof, verify_blob_kzg_proof_batch, verify_kzg_proof,
    };

    fn generate_random_blob(rng: &mut ThreadRng) -> Blob {
        let mut arr = [0; BYTES_PER_BLOB];
        rng.fill(&mut arr[..]);
        // Ensure that the blob is canonical by ensuring that
        // each field element contained in the blob is < BLS_MODULUS
        for i in 0..FIELD_ELEMENTS_PER_BLOB {
            arr[i * BYTES_PER_FIELD_ELEMENT] = 0;
        }
        arr.into()
    }

    fn test_simple(trusted_setup_file: &Path) {
        let mut rng = rand::thread_rng();
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

        let num_blobs: usize = rng.gen_range(1..16);
        let mut blobs: Vec<Blob> = (0..num_blobs)
            .map(|_| generate_random_blob(&mut rng))
            .collect();

        let commitments: Vec<Bytes48> = blobs
            .iter()
            .map(|blob| KZGCommitment::blob_to_kzg_commitment(blob, &kzg_settings).unwrap())
            .map(|commitment| commitment.to_bytes())
            .collect();

        let proofs: Vec<Bytes48> = blobs
            .iter()
            .zip(commitments.iter())
            .map(|(blob, commitment)| {
                Kzg::compute_blob_kzg_proof(blob, commitment, &kzg_settings).unwrap()
            })
            .map(|proof| proof.to_bytes())
            .collect();

        assert!(
            Kzg::verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs, &kzg_settings).unwrap()
        );

        blobs.pop();

        let error = Kzg::verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs, &kzg_settings)
            .unwrap_err();
        assert!(matches!(error, Error::MismatchLength(_)));

        let incorrect_blob = generate_random_blob(&mut rng);
        blobs.push(incorrect_blob);

        assert!(
            !Kzg::verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs, &kzg_settings)
                .unwrap()
        );
    }

    #[test]
    fn test_end_to_end() {
        let trusted_setup_file = Path::new("../../src/trusted_setup.txt");
        test_simple(trusted_setup_file);
    }

    const BLOB_TO_KZG_COMMITMENT_TESTS: &str = "../../tests/blob_to_kzg_commitment/*/*/*";
    const COMPUTE_KZG_PROOF_TESTS: &str = "../../tests/compute_kzg_proof/*/*/*";
    const COMPUTE_BLOB_KZG_PROOF_TESTS: &str = "../../tests/compute_blob_kzg_proof/*/*/*";
    const VERIFY_KZG_PROOF_TESTS: &str = "../../tests/verify_kzg_proof/*/*/*";
    const VERIFY_BLOB_KZG_PROOF_TESTS: &str = "../../tests/verify_blob_kzg_proof/*/*/*";
    const VERIFY_BLOB_KZG_PROOF_BATCH_TESTS: &str = "../../tests/verify_blob_kzg_proof_batch/*/*/*";

    #[test]
    fn test_blob_to_kzg_commitment() {
        let trusted_setup_file = Path::new("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();
        let test_files: Vec<PathBuf> = glob::glob(BLOB_TO_KZG_COMMITMENT_TESTS)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!test_files.is_empty());

        for test_file in test_files {
            let yaml_data = fs::read_to_string(test_file).unwrap();
            let test: blob_to_kzg_commitment_test::Test = serde_yaml::from_str(&yaml_data).unwrap();
            let Ok(blob) = test.input.get_blob() else {
                assert!(test.get_output().is_none());
                continue;
            };

            match KZGCommitment::blob_to_kzg_commitment(&blob, &kzg_settings) {
                Ok(res) => assert_eq!(res.bytes, test.get_output().unwrap().bytes),
                _ => assert!(test.get_output().is_none()),
            }
        }
    }

    #[test]
    fn test_compute_kzg_proof() {
        let trusted_setup_file = Path::new("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();
        let test_files: Vec<PathBuf> = glob::glob(COMPUTE_KZG_PROOF_TESTS)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!test_files.is_empty());

        for test_file in test_files {
            let yaml_data = fs::read_to_string(test_file).unwrap();
            let test: compute_kzg_proof::Test = serde_yaml::from_str(&yaml_data).unwrap();
            let (Ok(blob), Ok(z)) = (test.input.get_blob(), test.input.get_z()) else {
                assert!(test.get_output().is_none());
                continue;
            };

            match KZGProof::compute_kzg_proof(&blob, &z, &kzg_settings) {
                Ok((proof, y)) => {
                    assert_eq!(proof.bytes, test.get_output().unwrap().0.bytes);
                    assert_eq!(y.bytes, test.get_output().unwrap().1.bytes);
                }
                _ => assert!(test.get_output().is_none()),
            }
        }
    }

    #[test]
    fn test_compute_blob_kzg_proof() {
        let trusted_setup_file = Path::new("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();
        let test_files: Vec<PathBuf> = glob::glob(COMPUTE_BLOB_KZG_PROOF_TESTS)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!test_files.is_empty());

        for test_file in test_files {
            let yaml_data = fs::read_to_string(test_file).unwrap();
            let test: compute_blob_kzg_proof::Test = serde_yaml::from_str(&yaml_data).unwrap();
            let (Ok(blob), Ok(commitment)) = (test.input.get_blob(), test.input.get_commitment())
            else {
                assert!(test.get_output().is_none());
                continue;
            };

            match KZGProof::compute_blob_kzg_proof(&blob, &commitment, &kzg_settings) {
                Ok(res) => assert_eq!(res.bytes, test.get_output().unwrap().bytes),
                _ => assert!(test.get_output().is_none()),
            }
        }
    }

    #[test]
    fn test_verify_kzg_proof() {
        let trusted_setup_file = Path::new("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();
        let test_files: Vec<PathBuf> = glob::glob(VERIFY_KZG_PROOF_TESTS)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!test_files.is_empty());

        for test_file in test_files {
            let yaml_data = fs::read_to_string(test_file).unwrap();
            let test: verify_kzg_proof::Test = serde_yaml::from_str(&yaml_data).unwrap();
            let (Ok(commitment), Ok(z), Ok(y), Ok(proof)) = (
                test.input.get_commitment(),
                test.input.get_z(),
                test.input.get_y(),
                test.input.get_proof(),
            ) else {
                assert!(test.get_output().is_none());
                continue;
            };

            match KZGProof::verify_kzg_proof(&commitment, &z, &y, &proof, &kzg_settings) {
                Ok(res) => assert_eq!(res, test.get_output().unwrap()),
                _ => assert!(test.get_output().is_none()),
            }
        }
    }

    #[test]
    fn test_verify_blob_kzg_proof() {
        let trusted_setup_file = Path::new("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();
        let test_files: Vec<PathBuf> = glob::glob(VERIFY_BLOB_KZG_PROOF_TESTS)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!test_files.is_empty());

        for test_file in test_files {
            let yaml_data = fs::read_to_string(test_file).unwrap();
            let test: verify_blob_kzg_proof::Test = serde_yaml::from_str(&yaml_data).unwrap();
            let (Ok(blob), Ok(commitment), Ok(proof)) = (
                test.input.get_blob(),
                test.input.get_commitment(),
                test.input.get_proof(),
            ) else {
                assert!(test.get_output().is_none());
                continue;
            };

            match Kzg::verify_blob_kzg_proof(&blob, &commitment, &proof, &kzg_settings) {
                Ok(res) => assert_eq!(res, test.get_output().unwrap()),
                _ => assert!(test.get_output().is_none()),
            }
        }
    }

    #[test]
    fn test_verify_blob_kzg_proof_batch() {
        let trusted_setup_file = Path::new("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();
        let test_files: Vec<PathBuf> = glob::glob(VERIFY_BLOB_KZG_PROOF_BATCH_TESTS)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!test_files.is_empty());

        for test_file in test_files {
            let yaml_data = fs::read_to_string(test_file).unwrap();
            let test: verify_blob_kzg_proof_batch::Test = serde_yaml::from_str(&yaml_data).unwrap();
            let (Ok(blobs), Ok(commitments), Ok(proofs)) = (
                test.input.get_blobs(),
                test.input.get_commitments(),
                test.input.get_proofs(),
            ) else {
                assert!(test.get_output().is_none());
                continue;
            };

            match Kzg::verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs, &kzg_settings) {
                Ok(res) => assert_eq!(res, test.get_output().unwrap()),
                _ => assert!(test.get_output().is_none()),
            }
        }
    }
}
