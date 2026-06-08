//! Kerberos cryptographic primitives.
//!
//! The first implemented encryption families are RFC3962
//! `aes128-cts-hmac-sha1-96` and `aes256-cts-hmac-sha1-96`, matching the
//! gokrb5 v8 AES-SHA1 surface used by key derivation, checksums, and encrypted
//! message handling.

use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;

const AES_BLOCK_SIZE: usize = 16;
const HMAC_SHA1_96_SIZE: usize = 12;
const DEFAULT_S2KPARAMS: &str = "00001000";
const KERBEROS_CONSTANT: &[u8] = b"kerberos";

/// Kerberos AES CTS-HMAC-SHA1-96 encryption type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AesSha1Etype {
    /// `aes128-cts-hmac-sha1-96`, etype 17.
    Aes128,
    /// `aes256-cts-hmac-sha1-96`, etype 18.
    Aes256,
}

impl AesSha1Etype {
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
        DEFAULT_S2KPARAMS
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

    /// The n-fold input was empty.
    #[error("n-fold input must not be empty")]
    EmptyNfoldInput,

    /// The n-fold usage constant was empty.
    #[error("key usage constant must not be empty")]
    EmptyUsage,

    /// The n-fold output size was not a positive whole number of bytes.
    #[error("invalid n-fold output bit count: {0}")]
    InvalidNfoldOutputBits(usize),

    /// AES-CTS data encryption needs at least one plaintext byte.
    #[error("plaintext must not be empty")]
    EmptyPlaintext,
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

fn hmac_sha1_96(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC-SHA1 accepts keys of any size");
    mac.update(data);
    mac.finalize().into_bytes()[..HMAC_SHA1_96_SIZE].to_vec()
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
