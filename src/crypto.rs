//! Kerberos cryptographic primitives.
//!
//! The implemented encryption families cover RFC3962
//! `aes128-cts-hmac-sha1-96` / `aes256-cts-hmac-sha1-96` and RFC8009
//! `aes128-cts-hmac-sha256-128` / `aes256-cts-hmac-sha384-192`, RFC3961
//! `des3-cbc-sha1-kd`, and RFC4757 `arcfour-hmac-md5` / `rc4-hmac`,
//! matching the gokrb5 v8 surface used by key derivation, checksums, and
//! encrypted message handling.

use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use des::TdesEde3;
use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use rc4::{Rc4, StreamCipher};
use sha1::Sha1;
use sha2::{Sha256, Sha384};

const AES_BLOCK_SIZE: usize = 16;
const DES3_BLOCK_SIZE: usize = 8;
const DES3_KEY_SIZE: usize = 24;
const DES3_SEED_SIZE: usize = 21;
const RC4_HMAC_KEY_SIZE: usize = 16;
const RC4_HMAC_CONFOUNDER_SIZE: usize = 8;
const HMAC_SHA1_96_SIZE: usize = 12;
const HMAC_SHA1_SIZE: usize = 20;
const HMAC_SHA256_128_SIZE: usize = 16;
const HMAC_SHA384_192_SIZE: usize = 24;
const HMAC_MD5_SIZE: usize = 16;
const DEFAULT_RFC3962_S2KPARAMS: &str = "00001000";
const DEFAULT_RFC8009_S2KPARAMS: &str = "00008000";
const DEFAULT_DES3_S2KPARAMS: &str = "";
const DEFAULT_RC4_HMAC_S2KPARAMS: &str = "";
const KERBEROS_CONSTANT: &[u8] = b"kerberos";
const RC4_HMAC_SIGNATURE_KEY: &[u8] = b"signaturekey\0";

/// Kerberos AES CTS-HMAC-SHA1-96 encryption type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AesSha1Etype {
    /// `aes128-cts-hmac-sha1-96`, etype 17.
    Aes128,
    /// `aes256-cts-hmac-sha1-96`, etype 18.
    Aes256,
}

impl AesSha1Etype {
    /// Return the AES-SHA1 encryption type for a Kerberos etype id.
    pub fn from_etype_id(etype_id: i32) -> Option<Self> {
        match etype_id {
            17 => Some(Self::Aes128),
            18 => Some(Self::Aes256),
            _ => None,
        }
    }

    /// Kerberos encryption type ID.
    pub fn etype_id(self) -> i32 {
        match self {
            Self::Aes128 => 17,
            Self::Aes256 => 18,
        }
    }

    /// Kerberos checksum type ID.
    pub fn checksum_type_id(self) -> i32 {
        match self {
            Self::Aes128 => 15,
            Self::Aes256 => 16,
        }
    }

    /// Protocol key size in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 => 32,
        }
    }

    /// Confounder size in bytes.
    pub fn confounder_len(self) -> usize {
        AES_BLOCK_SIZE
    }

    /// Truncated SHA-1 HMAC size in bytes.
    pub fn hmac_len(self) -> usize {
        HMAC_SHA1_96_SIZE
    }

    /// Default RFC3962 string-to-key parameters, encoded as big-endian hex.
    pub fn default_s2kparams(self) -> &'static str {
        DEFAULT_RFC3962_S2KPARAMS
    }

    /// Derive the PBKDF2 intermediate key for RFC3962 string-to-key.
    pub fn string_to_pbkdf2(self, secret: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
        let mut out = vec![0; self.key_len()];
        pbkdf2::pbkdf2_hmac::<Sha1>(secret, salt, iterations, &mut out);
        out
    }

    /// Derive an AES protocol key from a password and salt.
    ///
    /// `s2kparams` must be the Kerberos four-byte iteration count encoded as
    /// eight hex characters. The RFC3962 zero value means 2^32 iterations; this
    /// implementation rejects it rather than attempting an impractical derive.
    pub fn string_to_key(
        self,
        secret: &[u8],
        salt: &[u8],
        s2kparams: &str,
    ) -> Result<Vec<u8>, Error> {
        let iterations = s2kparams_to_iterations(s2kparams)?;
        let tkey = self.string_to_pbkdf2(secret, salt, iterations);
        self.derive_key(&tkey, KERBEROS_CONSTANT)
    }

    /// Derive a usage-specific key from a protocol key.
    pub fn derive_key(self, protocol_key: &[u8], usage: &[u8]) -> Result<Vec<u8>, Error> {
        self.validate_key(protocol_key)?;
        let random = self.derive_random(protocol_key, usage)?;
        Ok(random)
    }

    /// RFC3961 DR function for AES.
    pub fn derive_random(self, protocol_key: &[u8], usage: &[u8]) -> Result<Vec<u8>, Error> {
        self.validate_key(protocol_key)?;
        if usage.is_empty() {
            return Err(Error::EmptyUsage);
        }

        let folded_usage = nfold(usage, AES_BLOCK_SIZE * 8)?;
        let mut out = Vec::with_capacity(self.key_len());
        let (_, mut block) = self.encrypt_data(protocol_key, &folded_usage)?;

        while out.len() < self.key_len() {
            let remaining = self.key_len() - out.len();
            out.extend_from_slice(&block[..remaining.min(block.len())]);
            if out.len() < self.key_len() {
                let (_, next) = self.encrypt_data(protocol_key, &block)?;
                block = next;
            }
        }

        Ok(out)
    }

    /// Calculate the keyed checksum for message bytes and a Kerberos key usage.
    pub fn checksum(self, protocol_key: &[u8], data: &[u8], usage: u32) -> Result<Vec<u8>, Error> {
        let key = self.derive_key(protocol_key, &usage_constant(usage, 0x99))?;
        Ok(hmac_sha1_96(&key, data))
    }

    /// Verify a keyed checksum.
    pub fn verify_checksum(
        self,
        protocol_key: &[u8],
        data: &[u8],
        checksum: &[u8],
        usage: u32,
    ) -> bool {
        self.checksum(protocol_key, data, usage)
            .is_ok_and(|expected| constant_time_eq(&expected, checksum))
    }

    /// Encrypt raw bytes with RFC3962 AES-CTS and a zero initial IV.
    ///
    /// Returns `(next_iv, ciphertext)`, matching gokrb5's AES-CTS helper.
    pub fn encrypt_data(self, key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        self.validate_key(key)?;
        aes_cts_encrypt(key, plaintext)
    }

    /// Decrypt raw bytes with RFC3962 AES-CTS and a zero initial IV.
    pub fn decrypt_data(self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.validate_key(key)?;
        aes_cts_decrypt(key, ciphertext)
    }

    /// Encrypt a Kerberos message with an explicit confounder.
    ///
    /// The explicit confounder keeps tests deterministic and lets callers wire
    /// in their own randomness policy. The returned bytes are ciphertext plus
    /// the RFC3962 integrity hash.
    pub fn encrypt_message_with_confounder(
        self,
        protocol_key: &[u8],
        message: &[u8],
        usage: u32,
        confounder: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.validate_key(protocol_key)?;
        if confounder.len() != self.confounder_len() {
            return Err(Error::InvalidConfounderLength {
                expected: self.confounder_len(),
                actual: confounder.len(),
            });
        }

        let mut plain = Vec::with_capacity(confounder.len() + message.len());
        plain.extend_from_slice(confounder);
        plain.extend_from_slice(message);

        let encryption_key = self.derive_key(protocol_key, &usage_constant(usage, 0xaa))?;
        let (_, mut encrypted) = self.encrypt_data(&encryption_key, &plain)?;
        let integrity_key = self.derive_key(protocol_key, &usage_constant(usage, 0x55))?;
        encrypted.extend_from_slice(&hmac_sha1_96(&integrity_key, &plain));
        Ok(encrypted)
    }

    /// Decrypt a Kerberos message and verify its RFC3962 integrity hash.
    pub fn decrypt_message(
        self,
        protocol_key: &[u8],
        ciphertext: &[u8],
        usage: u32,
    ) -> Result<Vec<u8>, Error> {
        self.validate_key(protocol_key)?;
        if ciphertext.len() < self.hmac_len() + self.confounder_len() {
            return Err(Error::CiphertextTooShort {
                minimum: self.hmac_len() + self.confounder_len(),
                actual: ciphertext.len(),
            });
        }

        let (encrypted, mac) = ciphertext.split_at(ciphertext.len() - self.hmac_len());
        let encryption_key = self.derive_key(protocol_key, &usage_constant(usage, 0xaa))?;
        let plain = self.decrypt_data(&encryption_key, encrypted)?;

        if plain.len() < self.confounder_len() {
            return Err(Error::PlaintextTooShort {
                minimum: self.confounder_len(),
                actual: plain.len(),
            });
        }

        let integrity_key = self.derive_key(protocol_key, &usage_constant(usage, 0x55))?;
        let expected = hmac_sha1_96(&integrity_key, &plain);
        if !constant_time_eq(&expected, mac) {
            return Err(Error::IntegrityCheckFailed);
        }

        Ok(plain[self.confounder_len()..].to_vec())
    }

    fn validate_key(self, key: &[u8]) -> Result<(), Error> {
        if key.len() != self.key_len() {
            return Err(Error::InvalidKeyLength {
                expected: self.key_len(),
                actual: key.len(),
            });
        }
        Ok(())
    }
}

/// Kerberos RFC8009 AES CTS-HMAC-SHA2 encryption type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AesSha2Etype {
    /// `aes128-cts-hmac-sha256-128`, etype 19.
    Aes128,
    /// `aes256-cts-hmac-sha384-192`, etype 20.
    Aes256,
}

impl AesSha2Etype {
    /// Return the AES-SHA2 encryption type for a Kerberos etype id.
    pub fn from_etype_id(etype_id: i32) -> Option<Self> {
        match etype_id {
            19 => Some(Self::Aes128),
            20 => Some(Self::Aes256),
            _ => None,
        }
    }

    /// Kerberos encryption type ID.
    pub fn etype_id(self) -> i32 {
        match self {
            Self::Aes128 => 19,
            Self::Aes256 => 20,
        }
    }

    /// Kerberos checksum type ID.
    pub fn checksum_type_id(self) -> i32 {
        match self {
            Self::Aes128 => 19,
            Self::Aes256 => 20,
        }
    }

    /// RFC8009 encryption type name used when building saltp.
    pub fn ename(self) -> &'static str {
        match self {
            Self::Aes128 => "aes128-cts-hmac-sha256-128",
            Self::Aes256 => "aes256-cts-hmac-sha384-192",
        }
    }

    /// Protocol base key size in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 => 32,
        }
    }

    /// Confounder size in bytes.
    pub fn confounder_len(self) -> usize {
        AES_BLOCK_SIZE
    }

    /// Truncated HMAC size in bytes.
    pub fn hmac_len(self) -> usize {
        match self {
            Self::Aes128 => HMAC_SHA256_128_SIZE,
            Self::Aes256 => HMAC_SHA384_192_SIZE,
        }
    }

    /// Default RFC8009 string-to-key parameters, encoded as big-endian hex.
    pub fn default_s2kparams(self) -> &'static str {
        DEFAULT_RFC8009_S2KPARAMS
    }

    /// Return the RFC8009 saltp value for this encryption type.
    pub fn saltp(self, salt: &[u8]) -> Vec<u8> {
        let mut saltp = Vec::with_capacity(self.ename().len() + 1 + salt.len());
        saltp.extend_from_slice(self.ename().as_bytes());
        saltp.push(0);
        saltp.extend_from_slice(salt);
        saltp
    }

    /// Derive the PBKDF2 intermediate key for RFC8009 string-to-key.
    pub fn string_to_pbkdf2(self, secret: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
        let mut out = vec![0; self.key_len()];
        match self {
            Self::Aes128 => pbkdf2::pbkdf2_hmac::<Sha256>(secret, salt, iterations, &mut out),
            Self::Aes256 => pbkdf2::pbkdf2_hmac::<Sha384>(secret, salt, iterations, &mut out),
        }
        out
    }

    /// Derive an AES protocol key from a password and salt.
    ///
    /// RFC8009 prepends the encryption type name and a NUL byte to the supplied
    /// salt before PBKDF2.
    pub fn string_to_key(
        self,
        secret: &[u8],
        salt: &[u8],
        s2kparams: &str,
    ) -> Result<Vec<u8>, Error> {
        let iterations = s2kparams_to_iterations(s2kparams)?;
        let saltp = self.saltp(salt);
        let tkey = self.string_to_pbkdf2(secret, &saltp, iterations);
        self.derive_key(&tkey, KERBEROS_CONSTANT)
    }

    /// Derive a usage-specific key from a protocol key.
    pub fn derive_key(self, protocol_key: &[u8], label: &[u8]) -> Result<Vec<u8>, Error> {
        self.validate_protocol_key(protocol_key)?;
        if label.is_empty() {
            return Err(Error::EmptyUsage);
        }

        Ok(self.kdf_hmac_sha2(protocol_key, label, &[], self.derive_key_bits(label)))
    }

    /// RFC8009 PRF derivation.
    pub fn derive_random(self, protocol_key: &[u8], usage: &[u8]) -> Result<Vec<u8>, Error> {
        self.validate_protocol_key(protocol_key)?;
        if usage.is_empty() {
            return Err(Error::EmptyUsage);
        }

        Ok(self.kdf_hmac_sha2(protocol_key, b"prf", usage, self.hash_len() * 8))
    }

    /// Calculate the keyed checksum for message bytes and a Kerberos key usage.
    pub fn checksum(self, protocol_key: &[u8], data: &[u8], usage: u32) -> Result<Vec<u8>, Error> {
        let key = self.derive_key(protocol_key, &usage_constant(usage, 0x99))?;
        Ok(self.truncated_hmac(&key, data))
    }

    /// Verify a keyed checksum.
    pub fn verify_checksum(
        self,
        protocol_key: &[u8],
        data: &[u8],
        checksum: &[u8],
        usage: u32,
    ) -> bool {
        self.checksum(protocol_key, data, usage)
            .is_ok_and(|expected| constant_time_eq(&expected, checksum))
    }

    /// Encrypt raw bytes with RFC8009 AES-CTS and a zero initial IV.
    ///
    /// The key is the derived encryption key, not the protocol base key.
    pub fn encrypt_data(self, key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        self.validate_encrypt_key(key)?;
        aes_cts_encrypt(key, plaintext)
    }

    /// Decrypt raw bytes with RFC8009 AES-CTS and a zero initial IV.
    pub fn decrypt_data(self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.validate_encrypt_key(key)?;
        aes_cts_decrypt(key, ciphertext)
    }

    /// Encrypt a Kerberos message with an explicit confounder.
    ///
    /// RFC8009 calculates integrity over a zero IV followed by the AES output,
    /// rather than over confounder-plus-plaintext as RFC3962 does.
    pub fn encrypt_message_with_confounder(
        self,
        protocol_key: &[u8],
        message: &[u8],
        usage: u32,
        confounder: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.validate_protocol_key(protocol_key)?;
        if confounder.len() != self.confounder_len() {
            return Err(Error::InvalidConfounderLength {
                expected: self.confounder_len(),
                actual: confounder.len(),
            });
        }

        let mut plain = Vec::with_capacity(confounder.len() + message.len());
        plain.extend_from_slice(confounder);
        plain.extend_from_slice(message);

        let encryption_key = self.derive_key(protocol_key, &usage_constant(usage, 0xaa))?;
        let (_, mut encrypted) = self.encrypt_data(&encryption_key, &plain)?;
        let mac = self.integrity_hash(protocol_key, usage, &encrypted)?;
        encrypted.extend_from_slice(&mac);
        Ok(encrypted)
    }

    /// Decrypt a Kerberos message and verify its RFC8009 integrity hash.
    pub fn decrypt_message(
        self,
        protocol_key: &[u8],
        ciphertext: &[u8],
        usage: u32,
    ) -> Result<Vec<u8>, Error> {
        self.validate_protocol_key(protocol_key)?;
        if ciphertext.len() < self.hmac_len() + self.confounder_len() {
            return Err(Error::CiphertextTooShort {
                minimum: self.hmac_len() + self.confounder_len(),
                actual: ciphertext.len(),
            });
        }

        let (encrypted, mac) = ciphertext.split_at(ciphertext.len() - self.hmac_len());
        let encryption_key = self.derive_key(protocol_key, &usage_constant(usage, 0xaa))?;
        let plain = self.decrypt_data(&encryption_key, encrypted)?;

        if plain.len() < self.confounder_len() {
            return Err(Error::PlaintextTooShort {
                minimum: self.confounder_len(),
                actual: plain.len(),
            });
        }

        let expected = self.integrity_hash(protocol_key, usage, encrypted)?;
        if !constant_time_eq(&expected, mac) {
            return Err(Error::IntegrityCheckFailed);
        }

        Ok(plain[self.confounder_len()..].to_vec())
    }

    fn derive_key_bits(self, label: &[u8]) -> usize {
        match self {
            Self::Aes128 => 128,
            Self::Aes256 if label == KERBEROS_CONSTANT => 256,
            Self::Aes256 if label.last() == Some(&0xaa) => 256,
            Self::Aes256 => 192,
        }
    }

    fn hash_len(self) -> usize {
        match self {
            Self::Aes128 => 32,
            Self::Aes256 => 48,
        }
    }

    fn kdf_hmac_sha2(
        self,
        protocol_key: &[u8],
        label: &[u8],
        context: &[u8],
        output_bits: usize,
    ) -> Vec<u8> {
        let mut input = Vec::with_capacity(4 + label.len() + 1 + context.len() + 4);
        input.extend_from_slice(&1u32.to_be_bytes());
        input.extend_from_slice(label);
        input.push(0);
        input.extend_from_slice(context);
        input.extend_from_slice(&(output_bits as u32).to_be_bytes());

        let output = match self {
            Self::Aes128 => hmac_sha256(protocol_key, &input),
            Self::Aes256 => hmac_sha384(protocol_key, &input),
        };
        output[..output_bits / 8].to_vec()
    }

    fn integrity_hash(
        self,
        protocol_key: &[u8],
        usage: u32,
        encrypted: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let integrity_key = self.derive_key(protocol_key, &usage_constant(usage, 0x55))?;
        let mut data = Vec::with_capacity(AES_BLOCK_SIZE + encrypted.len());
        data.resize(AES_BLOCK_SIZE, 0);
        data.extend_from_slice(encrypted);
        Ok(self.truncated_hmac(&integrity_key, &data))
    }

    fn truncated_hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Self::Aes128 => hmac_sha256(key, data)[..self.hmac_len()].to_vec(),
            Self::Aes256 => hmac_sha384(key, data)[..self.hmac_len()].to_vec(),
        }
    }

    fn validate_protocol_key(self, key: &[u8]) -> Result<(), Error> {
        if key.len() != self.key_len() {
            return Err(Error::InvalidKeyLength {
                expected: self.key_len(),
                actual: key.len(),
            });
        }
        Ok(())
    }

    fn validate_encrypt_key(self, key: &[u8]) -> Result<(), Error> {
        self.validate_protocol_key(key)
    }
}

/// Kerberos RFC3961 DES3-CBC-SHA1-KD encryption type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Des3CbcSha1KdEtype;

impl Des3CbcSha1KdEtype {
    /// Return the DES3 encryption type for a Kerberos etype id.
    pub fn from_etype_id(etype_id: i32) -> Option<Self> {
        match etype_id {
            16 => Some(Self),
            _ => None,
        }
    }

    /// Return the DES3 encryption type for a Kerberos checksum type id.
    pub fn from_checksum_type_id(checksum_type_id: i32) -> Option<Self> {
        match checksum_type_id {
            12 => Some(Self),
            _ => None,
        }
    }

    /// Kerberos encryption type ID.
    pub fn etype_id(self) -> i32 {
        16
    }

    /// Kerberos checksum type ID.
    pub fn checksum_type_id(self) -> i32 {
        12
    }

    /// Protocol key size in bytes.
    pub fn key_len(self) -> usize {
        DES3_KEY_SIZE
    }

    /// Confounder size in bytes.
    pub fn confounder_len(self) -> usize {
        DES3_BLOCK_SIZE
    }

    /// HMAC-SHA1 size in bytes.
    pub fn hmac_len(self) -> usize {
        HMAC_SHA1_SIZE
    }

    /// DES3 string-to-key parameters must be empty.
    pub fn default_s2kparams(self) -> &'static str {
        DEFAULT_DES3_S2KPARAMS
    }

    /// Derive a DES3 protocol key from a password and salt.
    pub fn string_to_key(
        self,
        secret: &[u8],
        salt: &[u8],
        s2kparams: &str,
    ) -> Result<Vec<u8>, Error> {
        if !s2kparams.is_empty() {
            return Err(Error::NonEmptyDes3S2kParams);
        }

        let mut input = Vec::with_capacity(secret.len() + salt.len());
        input.extend_from_slice(secret);
        input.extend_from_slice(salt);

        let folded = nfold(&input, DES3_SEED_SIZE * 8)?;
        let tkey = self.random_to_key(&folded)?;
        self.derive_key(&tkey, KERBEROS_CONSTANT)
    }

    /// Convert 21 seed bytes into a DES3 key with DES parity and weak-key fixups.
    pub fn random_to_key(self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        des3_random_to_key(bytes)
    }

    /// Derive a usage-specific key from a protocol key.
    pub fn derive_key(self, protocol_key: &[u8], usage: &[u8]) -> Result<Vec<u8>, Error> {
        let random = self.derive_random(protocol_key, usage)?;
        self.random_to_key(&random)
    }

    /// RFC3961 DR function for DES3.
    pub fn derive_random(self, protocol_key: &[u8], usage: &[u8]) -> Result<Vec<u8>, Error> {
        self.validate_key(protocol_key)?;
        if usage.is_empty() {
            return Err(Error::EmptyUsage);
        }

        let folded_usage = nfold(usage, DES3_BLOCK_SIZE * 8)?;
        let mut out = Vec::with_capacity(DES3_SEED_SIZE);
        let (_, mut block) = self.encrypt_data(protocol_key, &folded_usage)?;

        while out.len() < DES3_SEED_SIZE {
            let remaining = DES3_SEED_SIZE - out.len();
            out.extend_from_slice(&block[..remaining.min(block.len())]);
            if out.len() < DES3_SEED_SIZE {
                let (_, next) = self.encrypt_data(protocol_key, &block)?;
                block = next;
            }
        }

        Ok(out)
    }

    /// Calculate the keyed checksum for message bytes and a Kerberos key usage.
    pub fn checksum(self, protocol_key: &[u8], data: &[u8], usage: u32) -> Result<Vec<u8>, Error> {
        let key = self.derive_key(protocol_key, &usage_constant(usage, 0x99))?;
        Ok(hmac_sha1(&key, data))
    }

    /// Verify a keyed checksum.
    pub fn verify_checksum(
        self,
        protocol_key: &[u8],
        data: &[u8],
        checksum: &[u8],
        usage: u32,
    ) -> bool {
        self.checksum(protocol_key, data, usage)
            .is_ok_and(|expected| constant_time_eq(&expected, checksum))
    }

    /// Encrypt raw bytes with DES3-CBC and a zero initial IV.
    ///
    /// Returns `(next_iv, ciphertext)`, matching gokrb5's DES3-CBC helper.
    pub fn encrypt_data(self, key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        self.validate_key(key)?;
        des3_cbc_encrypt(key, plaintext)
    }

    /// Decrypt raw bytes with DES3-CBC and a zero initial IV.
    pub fn decrypt_data(self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.validate_key(key)?;
        des3_cbc_decrypt(key, ciphertext)
    }

    /// Encrypt a Kerberos message with an explicit confounder.
    ///
    /// The returned bytes are zero-padded DES3-CBC ciphertext plus the RFC3961
    /// HMAC-SHA1 integrity hash over the padded confounder-plus-message bytes.
    pub fn encrypt_message_with_confounder(
        self,
        protocol_key: &[u8],
        message: &[u8],
        usage: u32,
        confounder: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.validate_key(protocol_key)?;
        if confounder.len() != self.confounder_len() {
            return Err(Error::InvalidConfounderLength {
                expected: self.confounder_len(),
                actual: confounder.len(),
            });
        }

        let mut plain = Vec::with_capacity(confounder.len() + message.len());
        plain.extend_from_slice(confounder);
        plain.extend_from_slice(message);
        zero_pad(&mut plain, DES3_BLOCK_SIZE);

        let encryption_key = self.derive_key(protocol_key, &usage_constant(usage, 0xaa))?;
        let (_, mut encrypted) = self.encrypt_data(&encryption_key, &plain)?;
        let integrity_key = self.derive_key(protocol_key, &usage_constant(usage, 0x55))?;
        encrypted.extend_from_slice(&hmac_sha1(&integrity_key, &plain));
        Ok(encrypted)
    }

    /// Decrypt a Kerberos message and verify its RFC3961 integrity hash.
    ///
    /// Like gokrb5, this returns the decrypted message after the confounder and
    /// preserves any zero padding added before encryption.
    pub fn decrypt_message(
        self,
        protocol_key: &[u8],
        ciphertext: &[u8],
        usage: u32,
    ) -> Result<Vec<u8>, Error> {
        self.validate_key(protocol_key)?;
        if ciphertext.len() < self.hmac_len() + self.confounder_len() {
            return Err(Error::CiphertextTooShort {
                minimum: self.hmac_len() + self.confounder_len(),
                actual: ciphertext.len(),
            });
        }

        let (encrypted, mac) = ciphertext.split_at(ciphertext.len() - self.hmac_len());
        let encryption_key = self.derive_key(protocol_key, &usage_constant(usage, 0xaa))?;
        let plain = self.decrypt_data(&encryption_key, encrypted)?;

        if plain.len() < self.confounder_len() {
            return Err(Error::PlaintextTooShort {
                minimum: self.confounder_len(),
                actual: plain.len(),
            });
        }

        let integrity_key = self.derive_key(protocol_key, &usage_constant(usage, 0x55))?;
        let expected = hmac_sha1(&integrity_key, &plain);
        if !constant_time_eq(&expected, mac) {
            return Err(Error::IntegrityCheckFailed);
        }

        Ok(plain[self.confounder_len()..].to_vec())
    }

    fn validate_key(self, key: &[u8]) -> Result<(), Error> {
        if key.len() != self.key_len() {
            return Err(Error::InvalidKeyLength {
                expected: self.key_len(),
                actual: key.len(),
            });
        }
        Ok(())
    }
}

/// Kerberos RFC4757 RC4-HMAC encryption type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rc4HmacEtype;

impl Rc4HmacEtype {
    /// Return the RC4-HMAC encryption type for a Kerberos etype id.
    pub fn from_etype_id(etype_id: i32) -> Option<Self> {
        match etype_id {
            23 => Some(Self),
            _ => None,
        }
    }

    /// Return the RC4-HMAC encryption type for a Kerberos checksum type id.
    pub fn from_checksum_type_id(checksum_type_id: i32) -> Option<Self> {
        match checksum_type_id {
            -138 => Some(Self),
            _ => None,
        }
    }

    /// Kerberos encryption type ID.
    pub fn etype_id(self) -> i32 {
        23
    }

    /// Kerberos checksum type ID.
    pub fn checksum_type_id(self) -> i32 {
        -138
    }

    /// Protocol key size in bytes.
    pub fn key_len(self) -> usize {
        RC4_HMAC_KEY_SIZE
    }

    /// Confounder size in bytes.
    pub fn confounder_len(self) -> usize {
        RC4_HMAC_CONFOUNDER_SIZE
    }

    /// HMAC-MD5 size in bytes.
    pub fn hmac_len(self) -> usize {
        HMAC_MD5_SIZE
    }

    /// Default RFC4757 string-to-key parameters.
    pub fn default_s2kparams(self) -> &'static str {
        DEFAULT_RC4_HMAC_S2KPARAMS
    }

    /// Derive an RC4-HMAC protocol key from a password.
    ///
    /// RFC4757 ignores salt and string-to-key parameters and hashes the
    /// password's UTF-16LE form with MD4.
    pub fn string_to_key(
        self,
        secret: &[u8],
        _salt: &[u8],
        _s2kparams: &str,
    ) -> Result<Vec<u8>, Error> {
        let password = std::str::from_utf8(secret).map_err(|_| Error::InvalidStringToKeySecret)?;
        let mut utf16le = Vec::with_capacity(password.len() * 2);
        for unit in password.encode_utf16() {
            utf16le.extend_from_slice(&unit.to_le_bytes());
        }
        Ok(Md4::digest(&utf16le).to_vec())
    }

    /// Convert random bytes into an RC4-HMAC key.
    pub fn random_to_key(self, bytes: &[u8]) -> Vec<u8> {
        Md4::digest(bytes).to_vec()
    }

    /// Derive a usage-specific key from a protocol key.
    pub fn derive_key(self, protocol_key: &[u8], usage: &[u8]) -> Result<Vec<u8>, Error> {
        self.validate_key(protocol_key)?;
        if usage.is_empty() {
            return Err(Error::EmptyUsage);
        }
        Ok(hmac_md5(protocol_key, usage))
    }

    /// Calculate the RFC4757 keyed checksum for message bytes and a key usage.
    pub fn checksum(self, protocol_key: &[u8], data: &[u8], usage: u32) -> Result<Vec<u8>, Error> {
        self.validate_key(protocol_key)?;
        Ok(kerb_checksum_hmac_md5(protocol_key, data, usage))
    }

    /// Verify an RFC4757 keyed checksum.
    pub fn verify_checksum(
        self,
        protocol_key: &[u8],
        data: &[u8],
        checksum: &[u8],
        usage: u32,
    ) -> bool {
        self.checksum(protocol_key, data, usage)
            .is_ok_and(|expected| constant_time_eq(&expected, checksum))
    }

    /// Encrypt raw bytes with RC4.
    pub fn encrypt_data(self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.validate_key(key)?;
        rc4_hmac_crypt(key, plaintext)
    }

    /// Decrypt raw bytes with RC4.
    pub fn decrypt_data(self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.validate_key(key)?;
        rc4_hmac_crypt(key, ciphertext)
    }

    /// Encrypt a Kerberos message with an explicit confounder.
    ///
    /// The returned bytes are the 16-byte HMAC-MD5 checksum followed by the
    /// RC4 encrypted confounder-plus-message payload.
    pub fn encrypt_message_with_confounder(
        self,
        protocol_key: &[u8],
        message: &[u8],
        usage: u32,
        confounder: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.validate_key(protocol_key)?;
        if confounder.len() != self.confounder_len() {
            return Err(Error::InvalidConfounderLength {
                expected: self.confounder_len(),
                actual: confounder.len(),
            });
        }

        let mut plain = Vec::with_capacity(confounder.len() + message.len());
        plain.extend_from_slice(confounder);
        plain.extend_from_slice(message);

        let usage_key = hmac_md5(protocol_key, &rc4_hmac_usage_to_ms_msg_type(usage));
        let checksum = hmac_md5(&usage_key, &plain);
        let encryption_key = hmac_md5(&usage_key, &checksum);
        let encrypted = rc4_hmac_crypt(&encryption_key, &plain)?;

        let mut out = Vec::with_capacity(checksum.len() + encrypted.len());
        out.extend_from_slice(&checksum);
        out.extend_from_slice(&encrypted);
        Ok(out)
    }

    /// Decrypt a Kerberos message and verify its RFC4757 integrity checksum.
    pub fn decrypt_message(
        self,
        protocol_key: &[u8],
        ciphertext: &[u8],
        usage: u32,
    ) -> Result<Vec<u8>, Error> {
        self.validate_key(protocol_key)?;
        if ciphertext.len() < self.hmac_len() + self.confounder_len() {
            return Err(Error::CiphertextTooShort {
                minimum: self.hmac_len() + self.confounder_len(),
                actual: ciphertext.len(),
            });
        }

        let (checksum, encrypted) = ciphertext.split_at(self.hmac_len());
        let usage_key = hmac_md5(protocol_key, &rc4_hmac_usage_to_ms_msg_type(usage));
        let encryption_key = hmac_md5(&usage_key, checksum);
        let plain = rc4_hmac_crypt(&encryption_key, encrypted)?;

        if plain.len() < self.confounder_len() {
            return Err(Error::PlaintextTooShort {
                minimum: self.confounder_len(),
                actual: plain.len(),
            });
        }

        let expected = hmac_md5(&usage_key, &plain);
        if !constant_time_eq(&expected, checksum) {
            return Err(Error::IntegrityCheckFailed);
        }

        Ok(plain[self.confounder_len()..].to_vec())
    }

    fn validate_key(self, key: &[u8]) -> Result<(), Error> {
        if key.len() != self.key_len() {
            return Err(Error::InvalidKeyLength {
                expected: self.key_len(),
                actual: key.len(),
            });
        }
        Ok(())
    }
}

/// Kerberos encryption type supported by this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KerberosEtype {
    /// RFC3962 AES-SHA1 etype.
    Sha1(AesSha1Etype),
    /// RFC8009 AES-SHA2 etype.
    Sha2(AesSha2Etype),
    /// RFC3961 DES3-CBC-SHA1-KD etype.
    Des3CbcSha1Kd(Des3CbcSha1KdEtype),
    /// RFC4757 RC4-HMAC etype.
    Rc4Hmac(Rc4HmacEtype),
}

impl KerberosEtype {
    /// Return a supported encryption type for a Kerberos etype id.
    pub fn from_etype_id(etype_id: i32) -> Option<Self> {
        AesSha1Etype::from_etype_id(etype_id)
            .map(Self::Sha1)
            .or_else(|| AesSha2Etype::from_etype_id(etype_id).map(Self::Sha2))
            .or_else(|| Des3CbcSha1KdEtype::from_etype_id(etype_id).map(Self::Des3CbcSha1Kd))
            .or_else(|| Rc4HmacEtype::from_etype_id(etype_id).map(Self::Rc4Hmac))
    }

    /// Return a supported encryption type for a Kerberos checksum type id.
    pub fn from_checksum_type_id(checksum_type_id: i32) -> Option<Self> {
        match checksum_type_id {
            12 => Some(Self::Des3CbcSha1Kd(Des3CbcSha1KdEtype)),
            15 => Some(Self::Sha1(AesSha1Etype::Aes128)),
            16 => Some(Self::Sha1(AesSha1Etype::Aes256)),
            19 => Some(Self::Sha2(AesSha2Etype::Aes128)),
            20 => Some(Self::Sha2(AesSha2Etype::Aes256)),
            _ => Rc4HmacEtype::from_checksum_type_id(checksum_type_id).map(Self::Rc4Hmac),
        }
    }

    /// Kerberos encryption type ID.
    pub fn etype_id(self) -> i32 {
        match self {
            Self::Sha1(etype) => etype.etype_id(),
            Self::Sha2(etype) => etype.etype_id(),
            Self::Des3CbcSha1Kd(etype) => etype.etype_id(),
            Self::Rc4Hmac(etype) => etype.etype_id(),
        }
    }

    /// Kerberos checksum type ID.
    pub fn checksum_type_id(self) -> i32 {
        match self {
            Self::Sha1(etype) => etype.checksum_type_id(),
            Self::Sha2(etype) => etype.checksum_type_id(),
            Self::Des3CbcSha1Kd(etype) => etype.checksum_type_id(),
            Self::Rc4Hmac(etype) => etype.checksum_type_id(),
        }
    }

    /// Protocol base key size in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Self::Sha1(etype) => etype.key_len(),
            Self::Sha2(etype) => etype.key_len(),
            Self::Des3CbcSha1Kd(etype) => etype.key_len(),
            Self::Rc4Hmac(etype) => etype.key_len(),
        }
    }

    /// Confounder size in bytes.
    pub fn confounder_len(self) -> usize {
        match self {
            Self::Sha1(etype) => etype.confounder_len(),
            Self::Sha2(etype) => etype.confounder_len(),
            Self::Des3CbcSha1Kd(etype) => etype.confounder_len(),
            Self::Rc4Hmac(etype) => etype.confounder_len(),
        }
    }

    /// Truncated HMAC size in bytes.
    pub fn hmac_len(self) -> usize {
        match self {
            Self::Sha1(etype) => etype.hmac_len(),
            Self::Sha2(etype) => etype.hmac_len(),
            Self::Des3CbcSha1Kd(etype) => etype.hmac_len(),
            Self::Rc4Hmac(etype) => etype.hmac_len(),
        }
    }

    /// Default string-to-key parameters, encoded as big-endian hex.
    pub fn default_s2kparams(self) -> &'static str {
        match self {
            Self::Sha1(etype) => etype.default_s2kparams(),
            Self::Sha2(etype) => etype.default_s2kparams(),
            Self::Des3CbcSha1Kd(etype) => etype.default_s2kparams(),
            Self::Rc4Hmac(etype) => etype.default_s2kparams(),
        }
    }

    /// Derive a protocol key from a password and salt.
    pub fn string_to_key(
        self,
        secret: &[u8],
        salt: &[u8],
        s2kparams: &str,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Sha1(etype) => etype.string_to_key(secret, salt, s2kparams),
            Self::Sha2(etype) => etype.string_to_key(secret, salt, s2kparams),
            Self::Des3CbcSha1Kd(etype) => etype.string_to_key(secret, salt, s2kparams),
            Self::Rc4Hmac(etype) => etype.string_to_key(secret, salt, s2kparams),
        }
    }

    /// Calculate the keyed checksum for message bytes and a Kerberos key usage.
    pub fn checksum(self, protocol_key: &[u8], data: &[u8], usage: u32) -> Result<Vec<u8>, Error> {
        match self {
            Self::Sha1(etype) => etype.checksum(protocol_key, data, usage),
            Self::Sha2(etype) => etype.checksum(protocol_key, data, usage),
            Self::Des3CbcSha1Kd(etype) => etype.checksum(protocol_key, data, usage),
            Self::Rc4Hmac(etype) => etype.checksum(protocol_key, data, usage),
        }
    }

    /// Verify a keyed checksum.
    pub fn verify_checksum(
        self,
        protocol_key: &[u8],
        data: &[u8],
        checksum: &[u8],
        usage: u32,
    ) -> bool {
        match self {
            Self::Sha1(etype) => etype.verify_checksum(protocol_key, data, checksum, usage),
            Self::Sha2(etype) => etype.verify_checksum(protocol_key, data, checksum, usage),
            Self::Des3CbcSha1Kd(etype) => {
                etype.verify_checksum(protocol_key, data, checksum, usage)
            }
            Self::Rc4Hmac(etype) => etype.verify_checksum(protocol_key, data, checksum, usage),
        }
    }

    /// Encrypt a Kerberos message with an explicit confounder.
    pub fn encrypt_message_with_confounder(
        self,
        protocol_key: &[u8],
        message: &[u8],
        usage: u32,
        confounder: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Sha1(etype) => {
                etype.encrypt_message_with_confounder(protocol_key, message, usage, confounder)
            }
            Self::Sha2(etype) => {
                etype.encrypt_message_with_confounder(protocol_key, message, usage, confounder)
            }
            Self::Des3CbcSha1Kd(etype) => {
                etype.encrypt_message_with_confounder(protocol_key, message, usage, confounder)
            }
            Self::Rc4Hmac(etype) => {
                etype.encrypt_message_with_confounder(protocol_key, message, usage, confounder)
            }
        }
    }

    /// Decrypt a Kerberos message and verify its integrity hash.
    pub fn decrypt_message(
        self,
        protocol_key: &[u8],
        ciphertext: &[u8],
        usage: u32,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Sha1(etype) => etype.decrypt_message(protocol_key, ciphertext, usage),
            Self::Sha2(etype) => etype.decrypt_message(protocol_key, ciphertext, usage),
            Self::Des3CbcSha1Kd(etype) => etype.decrypt_message(protocol_key, ciphertext, usage),
            Self::Rc4Hmac(etype) => etype.decrypt_message(protocol_key, ciphertext, usage),
        }
    }
}

/// Convert a Kerberos iteration count to RFC3962 string-to-key parameters.
pub fn iterations_to_s2kparams(iterations: u32) -> String {
    hex_encode(&iterations.to_be_bytes())
}

/// Parse RFC3962 string-to-key parameters into an iteration count.
pub fn s2kparams_to_iterations(s2kparams: &str) -> Result<u32, Error> {
    if s2kparams.len() != 8 {
        return Err(Error::InvalidS2kParamsLength(s2kparams.len()));
    }

    let mut bytes = [0; 4];
    for (idx, pair) in s2kparams.as_bytes().chunks_exact(2).enumerate() {
        bytes[idx] = hex_pair(pair[0], pair[1])?;
    }

    let iterations = u32::from_be_bytes(bytes);
    if iterations == 0 {
        return Err(Error::UnsupportedIterationCountZero);
    }
    Ok(iterations)
}

/// Calculate the RFC4757 `KERB_CHECKSUM_HMAC_MD5` checksum.
///
/// This checksum is used by RC4-HMAC and by Microsoft S4U PA-FOR-USER data.
/// Unlike [`Rc4HmacEtype::checksum`], this accepts arbitrary Kerberos session
/// key lengths because PA-FOR-USER signs with the TGT session key directly.
pub fn kerb_checksum_hmac_md5(protocol_key: &[u8], data: &[u8], usage: u32) -> Vec<u8> {
    let signing_key = hmac_md5(protocol_key, RC4_HMAC_SIGNATURE_KEY);
    let msg_type = rc4_hmac_usage_to_ms_msg_type(usage);
    let mut md5_input = Vec::with_capacity(msg_type.len() + data.len());
    md5_input.extend_from_slice(&msg_type);
    md5_input.extend_from_slice(data);
    let digest = Md5::digest(&md5_input);
    hmac_md5(&signing_key, &digest)
}

/// RFC3961 n-fold operation.
pub fn nfold(input: &[u8], output_bits: usize) -> Result<Vec<u8>, Error> {
    if input.is_empty() {
        return Err(Error::EmptyNfoldInput);
    }
    if output_bits == 0 || !output_bits.is_multiple_of(8) {
        return Err(Error::InvalidNfoldOutputBits(output_bits));
    }

    let input_bits = input.len() * 8;
    let lcm_bits = lcm(output_bits, input_bits);
    let replicate = lcm_bits / input_bits;
    let mut sum_bytes = Vec::with_capacity(input.len() * replicate);

    for i in 0..replicate {
        sum_bytes.extend_from_slice(&rotate_right(input, 13 * i));
    }

    let output_len = output_bits / 8;
    let mut folded = vec![0; output_len];
    for chunk in sum_bytes.chunks_exact(output_len) {
        folded = ones_complement_addition(&folded, chunk);
    }

    Ok(folded)
}

/// Errors produced by Kerberos cryptographic operations.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// AES key material length did not match the selected encryption type.
    #[error("invalid key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength {
        /// Expected key length.
        expected: usize,
        /// Actual key length.
        actual: usize,
    },

    /// Confounder length did not match the selected encryption type.
    #[error("invalid confounder length: expected {expected} bytes, got {actual}")]
    InvalidConfounderLength {
        /// Expected confounder length.
        expected: usize,
        /// Actual confounder length.
        actual: usize,
    },

    /// Ciphertext was too short for the requested operation.
    #[error("ciphertext too short: expected at least {minimum} bytes, got {actual}")]
    CiphertextTooShort {
        /// Minimum accepted byte length.
        minimum: usize,
        /// Actual byte length.
        actual: usize,
    },

    /// Decrypted plaintext was too short to remove a confounder.
    #[error("plaintext too short: expected at least {minimum} bytes, got {actual}")]
    PlaintextTooShort {
        /// Minimum accepted byte length.
        minimum: usize,
        /// Actual byte length.
        actual: usize,
    },

    /// Message integrity verification failed.
    #[error("integrity verification failed")]
    IntegrityCheckFailed,

    /// String-to-key parameters were not four bytes of hex.
    #[error("invalid s2kparams length: expected 8 hex characters, got {0}")]
    InvalidS2kParamsLength(usize),

    /// String-to-key parameter hex was invalid.
    #[error("invalid s2kparams hex byte: {0}")]
    InvalidS2kParamsHex(char),

    /// RFC3962's zero iteration value means 2^32 iterations and is not run.
    #[error("s2kparams iteration count zero is not supported")]
    UnsupportedIterationCountZero,

    /// RC4-HMAC string-to-key requires a UTF-8 password byte string.
    #[error("RC4-HMAC string-to-key secret must be valid UTF-8")]
    InvalidStringToKeySecret,

    /// DES3 string-to-key parameters are required to be empty.
    #[error("DES3 string-to-key parameters must be empty")]
    NonEmptyDes3S2kParams,

    /// DES3 random-to-key seed material length did not match RFC3961.
    #[error("invalid random-to-key seed length: expected {expected} bytes, got {actual}")]
    InvalidSeedLength {
        /// Expected seed length.
        expected: usize,
        /// Actual seed length.
        actual: usize,
    },

    /// The n-fold input was empty.
    #[error("n-fold input must not be empty")]
    EmptyNfoldInput,

    /// The n-fold usage constant was empty.
    #[error("key usage constant must not be empty")]
    EmptyUsage,

    /// The n-fold output size was not a positive whole number of bytes.
    #[error("invalid n-fold output bit count: {0}")]
    InvalidNfoldOutputBits(usize),

    /// Data encryption needs at least one plaintext byte.
    #[error("plaintext must not be empty")]
    EmptyPlaintext,

    /// CBC ciphertext was not an exact multiple of the selected block size.
    #[error("ciphertext length {actual} is not a multiple of {block_size}")]
    InvalidCiphertextBlockSize {
        /// Required block size.
        block_size: usize,
        /// Actual ciphertext length.
        actual: usize,
    },
}

fn aes_cts_encrypt(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    let iv = [0; AES_BLOCK_SIZE];
    if plaintext.len() <= AES_BLOCK_SIZE {
        let mut padded = plaintext.to_vec();
        zero_pad(&mut padded, AES_BLOCK_SIZE);
        let encrypted = cbc_encrypt(key, &iv, &padded);
        return Ok((encrypted.clone(), encrypted));
    }

    if plaintext.len().is_multiple_of(AES_BLOCK_SIZE) {
        let mut encrypted = cbc_encrypt(key, &iv, plaintext);
        let next_iv = encrypted[encrypted.len() - AES_BLOCK_SIZE..].to_vec();
        swap_last_two_blocks(&mut encrypted);
        return Ok((next_iv, encrypted));
    }

    let original_len = plaintext.len();
    let mut padded = plaintext.to_vec();
    zero_pad(&mut padded, AES_BLOCK_SIZE);

    let padded_len = padded.len();
    let regular_len = padded_len - (2 * AES_BLOCK_SIZE);
    let (regular_plain, tail) = padded.split_at(regular_len);
    let (penultimate_plain, last_plain) = tail.split_at(AES_BLOCK_SIZE);

    let mut ciphertext = Vec::with_capacity(padded_len);
    let mut chained_iv = iv;

    if !regular_plain.is_empty() {
        let regular_cipher = cbc_encrypt(key, &chained_iv, regular_plain);
        chained_iv.copy_from_slice(&regular_cipher[regular_cipher.len() - AES_BLOCK_SIZE..]);
        ciphertext.extend_from_slice(&regular_cipher);
    }

    let penultimate_cipher = cbc_encrypt(key, &chained_iv, penultimate_plain);
    let mut penultimate_block = [0; AES_BLOCK_SIZE];
    penultimate_block.copy_from_slice(&penultimate_cipher);

    let last_cipher = cbc_encrypt(key, &penultimate_block, last_plain);
    let mut last_block = [0; AES_BLOCK_SIZE];
    last_block.copy_from_slice(&last_cipher);

    ciphertext.extend_from_slice(&last_block);
    ciphertext.extend_from_slice(&penultimate_block);
    ciphertext.truncate(original_len);

    Ok((last_block.to_vec(), ciphertext))
}

fn aes_cts_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < AES_BLOCK_SIZE {
        return Err(Error::CiphertextTooShort {
            minimum: AES_BLOCK_SIZE,
            actual: ciphertext.len(),
        });
    }

    let iv = [0; AES_BLOCK_SIZE];
    if ciphertext.len().is_multiple_of(AES_BLOCK_SIZE) {
        if ciphertext.len() == AES_BLOCK_SIZE {
            return Ok(cbc_decrypt(key, &iv, ciphertext));
        }

        let mut swapped = ciphertext.to_vec();
        swap_last_two_blocks(&mut swapped);
        return Ok(cbc_decrypt(key, &iv, &swapped));
    }

    let short_len = ciphertext.len() % AES_BLOCK_SIZE;
    let regular_len = ciphertext.len() - AES_BLOCK_SIZE - short_len;
    let (regular_cipher, tail) = ciphertext.split_at(regular_len);
    let (penultimate_cipher, last_cipher) = tail.split_at(AES_BLOCK_SIZE);

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut chain_iv = iv;
    if !regular_cipher.is_empty() {
        let regular_plain = cbc_decrypt(key, &chain_iv, regular_cipher);
        plaintext.extend_from_slice(&regular_plain);
        chain_iv.copy_from_slice(&regular_cipher[regular_cipher.len() - AES_BLOCK_SIZE..]);
    }

    let penultimate_plain = cbc_decrypt(key, &iv, penultimate_cipher);
    let pad_len = AES_BLOCK_SIZE - short_len;
    let mut completed_last_cipher = [0; AES_BLOCK_SIZE];
    completed_last_cipher[..short_len].copy_from_slice(last_cipher);
    completed_last_cipher[short_len..]
        .copy_from_slice(&penultimate_plain[AES_BLOCK_SIZE - pad_len..]);

    let last_plain = cbc_decrypt(key, &chain_iv, &completed_last_cipher);
    plaintext.extend_from_slice(&last_plain);

    let penultimate_plain = cbc_decrypt(key, &completed_last_cipher, penultimate_cipher);
    plaintext.extend_from_slice(&penultimate_plain);
    plaintext.truncate(ciphertext.len());

    Ok(plaintext)
}

fn cbc_encrypt(key: &[u8], iv: &[u8; AES_BLOCK_SIZE], plaintext: &[u8]) -> Vec<u8> {
    debug_assert!(plaintext.len().is_multiple_of(AES_BLOCK_SIZE));

    let mut previous = *iv;
    let mut out = Vec::with_capacity(plaintext.len());
    for chunk in plaintext.chunks_exact(AES_BLOCK_SIZE) {
        let mut block = [0; AES_BLOCK_SIZE];
        for i in 0..AES_BLOCK_SIZE {
            block[i] = chunk[i] ^ previous[i];
        }
        encrypt_block(key, &mut block);
        previous = block;
        out.extend_from_slice(&block);
    }
    out
}

fn cbc_decrypt(key: &[u8], iv: &[u8; AES_BLOCK_SIZE], ciphertext: &[u8]) -> Vec<u8> {
    debug_assert!(ciphertext.len().is_multiple_of(AES_BLOCK_SIZE));

    let mut previous = *iv;
    let mut out = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks_exact(AES_BLOCK_SIZE) {
        let mut block = [0; AES_BLOCK_SIZE];
        block.copy_from_slice(chunk);
        let cipher_block = block;
        decrypt_block(key, &mut block);
        for i in 0..AES_BLOCK_SIZE {
            block[i] ^= previous[i];
        }
        previous = cipher_block;
        out.extend_from_slice(&block);
    }
    out
}

fn encrypt_block(key: &[u8], block: &mut [u8; AES_BLOCK_SIZE]) {
    let mut block_array = Array::from(*block);
    match key.len() {
        16 => {
            let key_bytes: [u8; 16] = key
                .try_into()
                .expect("key length is validated before AES-128 encryption");
            let key_array = Array::from(key_bytes);
            let cipher = aes::Aes128::new(&key_array);
            cipher.encrypt_block(&mut block_array);
        }
        32 => {
            let key_bytes: [u8; 32] = key
                .try_into()
                .expect("key length is validated before AES-256 encryption");
            let key_array = Array::from(key_bytes);
            let cipher = aes::Aes256::new(&key_array);
            cipher.encrypt_block(&mut block_array);
        }
        _ => unreachable!("key length is validated before block encryption"),
    }
    block.copy_from_slice(&block_array);
}

fn decrypt_block(key: &[u8], block: &mut [u8; AES_BLOCK_SIZE]) {
    let mut block_array = Array::from(*block);
    match key.len() {
        16 => {
            let key_bytes: [u8; 16] = key
                .try_into()
                .expect("key length is validated before AES-128 decryption");
            let key_array = Array::from(key_bytes);
            let cipher = aes::Aes128::new(&key_array);
            cipher.decrypt_block(&mut block_array);
        }
        32 => {
            let key_bytes: [u8; 32] = key
                .try_into()
                .expect("key length is validated before AES-256 decryption");
            let key_array = Array::from(key_bytes);
            let cipher = aes::Aes256::new(&key_array);
            cipher.decrypt_block(&mut block_array);
        }
        _ => unreachable!("key length is validated before block decryption"),
    }
    block.copy_from_slice(&block_array);
}

fn des3_cbc_encrypt(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    let mut padded = plaintext.to_vec();
    zero_pad(&mut padded, DES3_BLOCK_SIZE);

    let mut previous = [0; DES3_BLOCK_SIZE];
    let mut out = Vec::with_capacity(padded.len());
    for chunk in padded.chunks_exact(DES3_BLOCK_SIZE) {
        let mut block = [0; DES3_BLOCK_SIZE];
        for i in 0..DES3_BLOCK_SIZE {
            block[i] = chunk[i] ^ previous[i];
        }
        des3_encrypt_block(key, &mut block);
        previous = block;
        out.extend_from_slice(&block);
    }

    Ok((previous.to_vec(), out))
}

fn des3_cbc_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < DES3_BLOCK_SIZE {
        return Err(Error::CiphertextTooShort {
            minimum: DES3_BLOCK_SIZE,
            actual: ciphertext.len(),
        });
    }
    if !ciphertext.len().is_multiple_of(DES3_BLOCK_SIZE) {
        return Err(Error::InvalidCiphertextBlockSize {
            block_size: DES3_BLOCK_SIZE,
            actual: ciphertext.len(),
        });
    }

    let mut previous = [0; DES3_BLOCK_SIZE];
    let mut out = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks_exact(DES3_BLOCK_SIZE) {
        let mut block = [0; DES3_BLOCK_SIZE];
        block.copy_from_slice(chunk);
        let cipher_block = block;
        des3_decrypt_block(key, &mut block);
        for i in 0..DES3_BLOCK_SIZE {
            block[i] ^= previous[i];
        }
        previous = cipher_block;
        out.extend_from_slice(&block);
    }

    Ok(out)
}

fn des3_encrypt_block(key: &[u8], block: &mut [u8; DES3_BLOCK_SIZE]) {
    let key_bytes: [u8; DES3_KEY_SIZE] = key
        .try_into()
        .expect("key length is validated before DES3 encryption");
    let key_array = Array::from(key_bytes);
    let cipher = TdesEde3::new(&key_array);
    let mut block_array = Array::from(*block);
    cipher.encrypt_block(&mut block_array);
    block.copy_from_slice(&block_array);
}

fn des3_decrypt_block(key: &[u8], block: &mut [u8; DES3_BLOCK_SIZE]) {
    let key_bytes: [u8; DES3_KEY_SIZE] = key
        .try_into()
        .expect("key length is validated before DES3 decryption");
    let key_array = Array::from(key_bytes);
    let cipher = TdesEde3::new(&key_array);
    let mut block_array = Array::from(*block);
    cipher.decrypt_block(&mut block_array);
    block.copy_from_slice(&block_array);
}

fn des3_random_to_key(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if bytes.len() != DES3_SEED_SIZE {
        return Err(Error::InvalidSeedLength {
            expected: DES3_SEED_SIZE,
            actual: bytes.len(),
        });
    }

    let mut key = Vec::with_capacity(DES3_KEY_SIZE);
    for seed in bytes.chunks_exact(7) {
        let mut block = des3_stretch_56_bits(seed);
        des3_fix_weak_key(&mut block);
        key.extend_from_slice(&block);
    }
    Ok(key)
}

fn des3_stretch_56_bits(bytes: &[u8]) -> [u8; DES3_BLOCK_SIZE] {
    debug_assert_eq!(bytes.len(), 7);

    let mut out = [0; DES3_BLOCK_SIZE];
    let mut last_byte = 0;
    for (idx, byte) in bytes.iter().enumerate() {
        let (lowest_bit, adjusted) = des3_calc_odd_parity(*byte);
        out[idx] = adjusted;
        if lowest_bit != 0 {
            last_byte |= 1 << (idx + 1);
        }
    }

    let (_, adjusted_last) = des3_calc_odd_parity(last_byte);
    out[DES3_BLOCK_SIZE - 1] = adjusted_last;
    out
}

fn des3_calc_odd_parity(mut byte: u8) -> (u8, u8) {
    let lowest_bit = byte & 0x01;
    let mut count = 0;
    for position in 1..8 {
        if byte & (1 << position) != 0 {
            count += 1;
        }
    }

    if count % 2 == 0 {
        byte |= 1;
    } else {
        byte &= !1;
    }
    (lowest_bit, byte)
}

fn des3_fix_weak_key(block: &mut [u8; DES3_BLOCK_SIZE]) {
    if des3_is_weak_key(block) {
        block[DES3_BLOCK_SIZE - 1] ^= 0xf0;
    }
}

fn des3_is_weak_key(block: &[u8; DES3_BLOCK_SIZE]) -> bool {
    const WEAK_KEYS: [[u8; DES3_BLOCK_SIZE]; 16] = [
        [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
        [0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe],
        [0xe0, 0xe0, 0xe0, 0xe0, 0xf1, 0xf1, 0xf1, 0xf1],
        [0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e],
        [0x01, 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e],
        [0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e, 0x01],
        [0x01, 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1],
        [0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1, 0x01],
        [0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe],
        [0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01],
        [0x1f, 0xe0, 0x1f, 0xe0, 0x0e, 0xf1, 0x0e, 0xf1],
        [0xe0, 0x1f, 0xe0, 0x1f, 0xf1, 0x0e, 0xf1, 0x0e],
        [0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e, 0xfe],
        [0xfe, 0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e],
        [0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1, 0xfe],
        [0xfe, 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1],
    ];

    WEAK_KEYS.contains(block)
}

fn zero_pad(bytes: &mut Vec<u8>, block_size: usize) {
    let remainder = bytes.len() % block_size;
    if remainder != 0 {
        bytes.resize(bytes.len() + block_size - remainder, 0);
    }
}

fn swap_last_two_blocks(bytes: &mut [u8]) {
    let len = bytes.len();
    for i in 0..AES_BLOCK_SIZE {
        bytes.swap(len - (2 * AES_BLOCK_SIZE) + i, len - AES_BLOCK_SIZE + i);
    }
}

fn usage_constant(usage: u32, suffix: u8) -> [u8; 5] {
    let usage = usage.to_be_bytes();
    [usage[0], usage[1], usage[2], usage[3], suffix]
}

fn rc4_hmac_usage_to_ms_msg_type(usage: u32) -> [u8; 4] {
    let mut usage = match usage {
        3 | 9 => 8,
        23 => 13,
        _ => usage,
    };

    let mut out = [0; 4];
    for byte in &mut out {
        if usage < 0x80 {
            *byte = usage as u8;
            break;
        }
        *byte = ((usage as u8) & 0x7f) | 0x80;
        usage >>= 7;
    }
    out
}

fn rc4_hmac_crypt(key: &[u8], input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut cipher =
        <Rc4 as rc4::KeyInit>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength {
            expected: RC4_HMAC_KEY_SIZE,
            actual: key.len(),
        })?;
    let mut out = input.to_vec();
    cipher.apply_keystream(&mut out);
    Ok(out)
}

fn hmac_sha1_96(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac_sha1(key, data)[..HMAC_SHA1_96_SIZE].to_vec()
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC-SHA1 accepts keys of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC-MD5 accepts keys of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha384(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        Hmac::<Sha384>::new_from_slice(key).expect("HMAC-SHA384 accepts keys of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0;
    for (left, right) in a.iter().zip(b) {
        diff |= left ^ right;
    }
    diff == 0
}

fn rotate_right(bytes: &[u8], steps: usize) -> Vec<u8> {
    let bit_len = bytes.len() * 8;
    let mut out = vec![0; bytes.len()];
    for i in 0..bit_len {
        let bit = get_bit(bytes, i);
        set_bit(&mut out, (i + steps) % bit_len, bit);
    }
    out
}

fn ones_complement_addition(left: &[u8], right: &[u8]) -> Vec<u8> {
    debug_assert_eq!(left.len(), right.len());

    let num_bits = left.len() * 8;
    let mut out = vec![0; left.len()];
    let mut carry = 0;

    for bit_index in (0..num_bits).rev() {
        let sum = get_bit(left, bit_index) + get_bit(right, bit_index) + carry;
        match sum {
            0 => carry = 0,
            1 => {
                set_bit(&mut out, bit_index, 1);
                carry = 0;
            }
            2 => carry = 1,
            3 => {
                set_bit(&mut out, bit_index, 1);
                carry = 1;
            }
            _ => unreachable!(),
        }
    }

    if carry == 1 {
        let mut carry_array = vec![0; left.len()];
        let last = carry_array.len() - 1;
        carry_array[last] = 1;
        return ones_complement_addition(&out, &carry_array);
    }

    out
}

fn get_bit(bytes: &[u8], position: usize) -> u8 {
    let byte_index = position / 8;
    let bit_index = position % 8;
    (bytes[byte_index] >> (7 - bit_index)) & 1
}

fn set_bit(bytes: &mut [u8], position: usize, value: u8) {
    let byte_index = position / 8;
    let bit_index = position % 8;
    bytes[byte_index] |= value << (7 - bit_index);
}

fn lcm(left: usize, right: usize) -> usize {
    (left * right) / gcd(left, right)
}

fn gcd(mut left: usize, mut right: usize) -> usize {
    while right != 0 {
        let next = left % right;
        left = right;
        right = next;
    }
    left
}

fn hex_pair(high: u8, low: u8) -> Result<u8, Error> {
    Ok((hex_value(high)? << 4) | hex_value(low)?)
}

fn hex_value(byte: u8) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::InvalidS2kParamsHex(byte as char)),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
