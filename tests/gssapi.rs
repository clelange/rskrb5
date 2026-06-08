#![cfg(feature = "spnego")]

use pretty_assertions::assert_eq;
use rskrb5::keytab::EncryptionKey;
use rskrb5::spnego::{
    Error, GSS_TOKEN_FLAG_SEALED, GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR, GSSAPI_ACCEPTOR_SEAL_USAGE,
    GSSAPI_ACCEPTOR_SIGN_USAGE, GSSAPI_INITIATOR_SEAL_USAGE, GSSAPI_INITIATOR_SIGN_USAGE, MicToken,
    WrapToken,
};

const MIC_PAYLOAD: &str = "deadbeef";
const MIC_FROM_ACCEPTOR: &str = "040401ffffffffff00000000575e85d6c34d12ba3e5b1b1310cd9cb3";
const MIC_FROM_INITIATOR: &str = "040400ffffffffff00000000000000009649ca09d2f1bc51ff6e5ca3";

const WRAP_FROM_ACCEPTOR: &str = "050401ff000c000000000000575e85d601010000853b728d5268525a1386c19f";
const WRAP_FROM_INITIATOR: &str =
    "050400ff000c000000000000000000000101000079a033510b6f127212242b97";
const WRAP_PAYLOAD: &str = "01010000";
const WRAP_SEALED_CONFOUNDER: &str = "000102030405060708090a0b0c0d0e0f";
const WRAP_SEALED_FROM_INITIATOR: &str = "050402ff000000000000000000000000debcb2b270f4152cfe1cde9c62f90d12a59afda0127a094f4b18e8d8b8fc253c63239cc38ef96b6ce3e92c754f8a97b3";
const WRAP_SEALED_RRC_FROM_INITIATOR: &str = "050402ff00000009000000000000000741b1ec99c834f8c7d3debcb2b270f4152cfe1cde9c62f90d12bde6bc91659577018ad4118b1e18e27263239cc39150a9";

const SESSION_KEY: &str = "14f9bde6b50ec508201a97f74c4e5bd3";

#[test]
fn mic_token_decodes_and_roundtrips_gokrb5_vectors() {
    let acceptor_bytes = decode_hex(MIC_FROM_ACCEPTOR);
    let token = MicToken::decode(&acceptor_bytes, true).expect("acceptor MIC decodes");
    assert_eq!(
        token,
        MicToken {
            flags: GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR,
            snd_seq_num: u64::from_be_bytes(acceptor_bytes[8..16].try_into().unwrap()),
            payload: None,
            checksum: Some(acceptor_bytes[16..].to_vec()),
        }
    );
    assert_eq!(
        hex_encode(&token.encode().expect("acceptor MIC encodes")),
        MIC_FROM_ACCEPTOR
    );

    let initiator_bytes = decode_hex(MIC_FROM_INITIATOR);
    let token = MicToken::decode(&initiator_bytes, false).expect("initiator MIC decodes");
    assert_eq!(
        token,
        MicToken {
            flags: 0,
            snd_seq_num: 0,
            payload: None,
            checksum: Some(initiator_bytes[16..].to_vec()),
        }
    );
    assert_eq!(
        hex_encode(&token.encode().expect("initiator MIC encodes")),
        MIC_FROM_INITIATOR
    );
}

#[test]
fn mic_token_rejects_wrong_sender_and_missing_checksum() {
    assert!(matches!(
        MicToken::decode(&decode_hex(MIC_FROM_ACCEPTOR), false),
        Err(Error::UnexpectedGssTokenSender {
            expected_from_acceptor: false,
            actual_from_acceptor: true,
        })
    ));
    assert!(matches!(
        MicToken::decode(&decode_hex(MIC_FROM_INITIATOR), true),
        Err(Error::UnexpectedGssTokenSender {
            expected_from_acceptor: true,
            actual_from_acceptor: false,
        })
    ));
    assert!(matches!(
        MicToken::new(0, 0).encode(),
        Err(Error::MissingGssChecksum)
    ));
}

#[test]
fn mic_token_verifies_and_builds_initiator_token() {
    let key = session_key();
    let acceptor = MicToken::decode(&decode_hex(MIC_FROM_ACCEPTOR), true)
        .expect("acceptor MIC decodes")
        .with_payload(decode_hex(MIC_PAYLOAD));
    assert!(
        acceptor
            .verify(&key, GSSAPI_ACCEPTOR_SIGN_USAGE)
            .expect("acceptor MIC verifies")
    );
    assert!(matches!(
        acceptor.verify(&key, GSSAPI_INITIATOR_SIGN_USAGE),
        Err(Error::GssChecksumMismatch)
    ));

    let wrong_key = EncryptionKey {
        etype: 17,
        value: decode_hex("14f9bde6b50ec508201a97f74c4effff"),
    };
    assert!(matches!(
        acceptor.verify(&wrong_key, GSSAPI_ACCEPTOR_SIGN_USAGE),
        Err(Error::GssChecksumMismatch)
    ));

    let mut initiator =
        MicToken::new_initiator(decode_hex(MIC_PAYLOAD), &key).expect("initiator MIC builds");
    initiator.payload = None;
    assert_eq!(
        initiator,
        MicToken {
            flags: 0,
            snd_seq_num: 0,
            payload: None,
            checksum: Some(decode_hex(&MIC_FROM_INITIATOR[32..])),
        }
    );
    assert_eq!(
        hex_encode(&initiator.encode().expect("initiator MIC encodes")),
        MIC_FROM_INITIATOR
    );
}

#[test]
fn wrap_token_decodes_and_roundtrips_gokrb5_vectors() {
    let acceptor_bytes = decode_hex(WRAP_FROM_ACCEPTOR);
    let token = WrapToken::decode(&acceptor_bytes, true).expect("acceptor wrap decodes");
    assert_eq!(
        token,
        WrapToken {
            flags: GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR,
            ec: 12,
            rrc: 0,
            snd_seq_num: u64::from_be_bytes(acceptor_bytes[8..16].try_into().unwrap()),
            payload: Some(decode_hex(WRAP_PAYLOAD)),
            checksum: Some(acceptor_bytes[20..].to_vec()),
            encrypted_body: None,
        }
    );
    assert_eq!(
        hex_encode(&token.encode().expect("acceptor wrap encodes")),
        WRAP_FROM_ACCEPTOR
    );

    let initiator_bytes = decode_hex(WRAP_FROM_INITIATOR);
    let token = WrapToken::decode(&initiator_bytes, false).expect("initiator wrap decodes");
    assert_eq!(
        token,
        WrapToken {
            flags: 0,
            ec: 12,
            rrc: 0,
            snd_seq_num: 0,
            payload: Some(decode_hex(WRAP_PAYLOAD)),
            checksum: Some(initiator_bytes[20..].to_vec()),
            encrypted_body: None,
        }
    );
    assert_eq!(
        hex_encode(&token.encode().expect("initiator wrap encodes")),
        WRAP_FROM_INITIATOR
    );
}

#[test]
fn wrap_token_rejects_invalid_inputs() {
    assert!(matches!(
        WrapToken::decode(&decode_hex(WRAP_FROM_ACCEPTOR), false),
        Err(Error::UnexpectedGssTokenSender {
            expected_from_acceptor: false,
            actual_from_acceptor: true,
        })
    ));
    assert!(matches!(
        WrapToken::decode(&decode_hex(WRAP_FROM_INITIATOR), true),
        Err(Error::UnexpectedGssTokenSender {
            expected_from_acceptor: true,
            actual_from_acceptor: false,
        })
    ));
    assert!(matches!(
        WrapToken::new(0, 0).encode(),
        Err(Error::MissingGssPayload)
    ));
    assert!(matches!(
        WrapToken::new(0, 0)
            .with_payload(decode_hex(WRAP_PAYLOAD))
            .encode(),
        Err(Error::MissingGssChecksum)
    ));
}

#[test]
fn wrap_token_verifies_and_builds_initiator_token() {
    let key = session_key();
    let acceptor =
        WrapToken::decode(&decode_hex(WRAP_FROM_ACCEPTOR), true).expect("acceptor wrap decodes");
    assert!(
        acceptor
            .verify(&key, GSSAPI_ACCEPTOR_SEAL_USAGE)
            .expect("acceptor wrap verifies")
    );
    assert!(matches!(
        acceptor.verify(&key, GSSAPI_INITIATOR_SEAL_USAGE),
        Err(Error::GssChecksumMismatch)
    ));

    let wrong_key = EncryptionKey {
        etype: 17,
        value: decode_hex("14f9bde6b50ec508201a97f74c4effff"),
    };
    assert!(matches!(
        acceptor.verify(&wrong_key, GSSAPI_ACCEPTOR_SEAL_USAGE),
        Err(Error::GssChecksumMismatch)
    ));

    let initiator =
        WrapToken::new_initiator(decode_hex(WRAP_PAYLOAD), &key).expect("initiator wrap builds");
    assert_eq!(
        initiator,
        WrapToken {
            flags: 0,
            ec: 12,
            rrc: 0,
            snd_seq_num: 0,
            payload: Some(decode_hex(WRAP_PAYLOAD)),
            checksum: Some(decode_hex(&WRAP_FROM_INITIATOR[40..])),
            encrypted_body: None,
        }
    );
    assert_eq!(
        hex_encode(&initiator.encode().expect("initiator wrap encodes")),
        WRAP_FROM_INITIATOR
    );
}

#[test]
fn sealed_wrap_token_encrypts_decrypts_and_roundtrips() {
    let key = session_key();
    let token = WrapToken::new_initiator_sealed_with_confounder(
        decode_hex(WRAP_PAYLOAD),
        &key,
        &decode_hex(WRAP_SEALED_CONFOUNDER),
    )
    .expect("sealed initiator wrap builds");

    assert_eq!(token.flags, GSS_TOKEN_FLAG_SEALED);
    assert_eq!(token.ec, 0);
    assert_eq!(token.rrc, 0);
    assert_eq!(token.snd_seq_num, 0);
    assert_eq!(token.payload, Some(decode_hex(WRAP_PAYLOAD)));
    assert!(token.checksum.is_none());
    assert!(token.encrypted_body.is_some());

    let encoded = token.encode().expect("sealed wrap encodes");
    assert_eq!(hex_encode(&encoded), WRAP_SEALED_FROM_INITIATOR);
    let decoded = WrapToken::decode(&encoded, false).expect("sealed wrap decodes");
    assert!(decoded.is_sealed());
    assert!(decoded.payload.is_none());
    assert_eq!(
        decoded
            .decrypt_payload(&key, GSSAPI_INITIATOR_SEAL_USAGE)
            .expect("sealed wrap decrypts"),
        decode_hex(WRAP_PAYLOAD)
    );
    assert!(
        decoded
            .verify(&key, GSSAPI_INITIATOR_SEAL_USAGE)
            .expect("sealed wrap verifies")
    );

    let mut decoded = decoded;
    assert_eq!(
        decoded
            .decrypt_and_set_payload(&key, GSSAPI_INITIATOR_SEAL_USAGE)
            .expect("sealed wrap decrypts into token"),
        decode_hex(WRAP_PAYLOAD).as_slice()
    );
    assert_eq!(decoded.payload, Some(decode_hex(WRAP_PAYLOAD)));
}

#[test]
fn sealed_wrap_token_supports_rrc_rotation() {
    let key = session_key();
    let mut token = WrapToken::new(GSS_TOKEN_FLAG_SEALED, 7).with_payload(decode_hex(WRAP_PAYLOAD));
    token.rrc = 9;
    token
        .encrypt_payload_with_confounder(
            &key,
            GSSAPI_INITIATOR_SEAL_USAGE,
            &decode_hex(WRAP_SEALED_CONFOUNDER),
        )
        .expect("sealed wrap encrypts");

    let encoded = token.encode().expect("rotated sealed wrap encodes");
    assert_eq!(hex_encode(&encoded), WRAP_SEALED_RRC_FROM_INITIATOR);
    assert_eq!(u16::from_be_bytes(encoded[6..8].try_into().unwrap()), 9);

    let decoded = WrapToken::decode(&encoded, false).expect("rotated sealed wrap decodes");
    assert_eq!(decoded.rrc, 9);
    assert_eq!(
        decoded
            .decrypt_payload(&key, GSSAPI_INITIATOR_SEAL_USAGE)
            .expect("rotated sealed wrap decrypts"),
        decode_hex(WRAP_PAYLOAD)
    );
}

#[test]
fn sealed_wrap_token_rejects_tampering_and_wrong_usage() {
    let key = session_key();
    let token = WrapToken::new_initiator_sealed_with_confounder(
        decode_hex(WRAP_PAYLOAD),
        &key,
        &decode_hex(WRAP_SEALED_CONFOUNDER),
    )
    .expect("sealed initiator wrap builds");
    let mut decoded =
        WrapToken::decode(&token.encode().expect("sealed wrap encodes"), false).expect("decodes");

    assert!(matches!(
        decoded.decrypt_payload(&key, GSSAPI_ACCEPTOR_SEAL_USAGE),
        Err(Error::Crypto(_))
    ));

    decoded.snd_seq_num = 1;
    assert!(matches!(
        decoded.decrypt_payload(&key, GSSAPI_INITIATOR_SEAL_USAGE),
        Err(Error::InvalidGssEncryptedHeader)
    ));

    let mut encoded = token.encode().expect("sealed wrap encodes");
    let last = encoded.len() - 1;
    encoded[last] ^= 0x01;
    let decoded = WrapToken::decode(&encoded, false).expect("tampered sealed wrap still parses");
    assert!(matches!(
        decoded.decrypt_payload(&key, GSSAPI_INITIATOR_SEAL_USAGE),
        Err(Error::Crypto(_))
    ));
}

fn session_key() -> EncryptionKey {
    EncryptionKey {
        etype: 17,
        value: decode_hex(SESSION_KEY),
    }
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex input has even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_value(pair[0]) << 4) | hex_value(pair[1]))
        .collect()
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

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte: {byte}"),
    }
}
