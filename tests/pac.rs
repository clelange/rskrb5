#![cfg(feature = "evaluation")]

use std::time::{Duration, UNIX_EPOCH};

use pretty_assertions::assert_eq;
use rskrb5::crypto::{AesSha1Etype, KerberosEtype};
use rskrb5::keytab::{EncryptionKey, Keytab};
use rskrb5::pac::{
    self, CHECKSUM_HMAC_MD5_UNSIGNED, CHECKSUM_HMAC_SHA1_96_AES256, CLAIM_TYPE_ID_INT64,
    CLAIM_TYPE_ID_STRING, CLAIM_TYPE_ID_UINT64, CLAIMS_COMPRESSION_FORMAT_LZNT1,
    CLAIMS_COMPRESSION_FORMAT_NONE, CLAIMS_COMPRESSION_FORMAT_XPRESS,
    CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF, CLAIMS_SOURCE_TYPE_AD, ClaimValues, ClaimsInfo,
    ClaimsSetMetadata, ClientInfo, CredentialData, CredentialsInfo, DeviceInfo,
    INFO_TYPE_CREDENTIALS, INFO_TYPE_PAC_CLIENT_CLAIMS_INFO, INFO_TYPE_PAC_CLIENT_INFO,
    INFO_TYPE_PAC_DEVICE_CLAIMS_INFO, INFO_TYPE_PAC_DEVICE_INFO, INFO_TYPE_PAC_KDC_SIGNATURE_DATA,
    INFO_TYPE_PAC_SERVER_SIGNATURE_DATA, INFO_TYPE_S4U_DELEGATION_INFO, INFO_TYPE_UPN_DNS_INFO,
    KerbValidationInfo, NtlmSupplementalCredential, Pac, S4UDelegationInfo, SignatureData,
    UpnDnsInfo,
};

mod common;

const CLIENT_CLAIMS_INFO_STR: &str = "01100800cccccccc000100000000000000000200d80000000400020000000000d8000000000000000000000000000000d800000001100800ccccccccc80000000000000000000200010000000400020000000000000000000000000001000000010000000100000008000200010000000c000200030003000100000010000200290000000000000029000000610064003a002f002f006500780074002f00730041004d004100630063006f0075006e0074004e0061006d0065003a0038003800640035006400390030003800350065006100350063003000630030000000000001000000140002000a000000000000000a00000074006500730074007500730065007200310000000000000000000000";
const CLIENT_CLAIMS_INFO_INT: &str = "01100800cccccccce00000000000000000000200b80000000400020000000000b8000000000000000000000000000000b800000001100800cccccccca80000000000000000000200010000000400020000000000000000000000000001000000010000000100000008000200010000000c0002000100010001000000100002002a000000000000002a000000610064003a002f002f006500780074002f006d007300440053002d0053007500700070006f00720074006500640045003a0038003800640035006400650061003800660031006100660035006600310039000000010000001c0000000000000000000000";
const CLIENT_CLAIMS_INFO_MULTI: &str = "01100800cccccccc780100000000000000000200500100000400020000000000500100000000000000000000000000005001000001100800cccccccc400100000000000000000200010000000400020000000000000000000000000001000000010000000200000008000200020000000c000200010001000100000010000200140002000300030001000000180002002a000000000000002a000000610064003a002f002f006500780074002f006d007300440053002d0053007500700070006f00720074006500640045003a0038003800640035006400650061003800660031006100660035006600310039000000010000001c00000000000000290000000000000029000000610064003a002f002f006500780074002f00730041004d004100630063006f0075006e0074004e0061006d0065003a00380038006400350064003900300038003500650061003500630030006300300000000000010000001c0002000a000000000000000a000000740065007300740075007300650072003100000000000000";
const CLIENT_CLAIMS_INFO_MULTI_UINT: &str = "01100800ccccccccf00000000000000000000200c80000000400020000000000c8000000000000000000000000000000c800000001100800ccccccccb80000000000000000000200010000000400020000000000000000000000000001000000010000000100000008000200010000000c000200020002000400000010000200260000000000000026000000610064003a002f002f006500780074002f006f0062006a0065006300740043006c006100730073003a00380038006400350064006500370039003100650037006200320037006500360000000400000009000a000000000007000100000000000600010000000000000001000000000000000000";
const CLIENT_CLAIMS_INFO_MULTI_STR: &str = "01100800cccccccc480100000000000000000200200100000400020000000000200100000000000000000000000000002001000001100800cccccccc100100000000000000000200010000000400020000000000000000000000000001000000010000000100000008000200010000000c000200030003000400000010000200270000000000000027000000610064003a002f002f006500780074002f006f00740068006500720049007000500068006f006e0065003a003800380064003500640065003900660036006200340061006600390038003500000000000400000014000200180002001c000200200002000500000000000000050000007300740072003100000000000500000000000000050000007300740072003200000000000500000000000000050000007300740072003300000000000500000000000000050000007300740072003400000000000000000000000000";
const CLIENT_CLAIMS_INFO_XPRESS_HUFF: &str = "01100800ccccccccd00100000000000000000200a80100000400020004000000e0010000000000000000000000000000a8010000727807888708080007000800080008000800080880000080870870887807000080800000000080080000080000000000605767070007777707677700770000000000000000000000000000000000000000000000000000000000000000000000000000000000070007000000000000000000000000000000000000000000000076000700700000007600000000000000750700000000000064770700000000007607000000000000060700000000000077060700000000707770700070000770007700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a85652950bb9d8bae030b2212b90df95764d1b182da22f2c848b23b3cc4efc8e3499701e481cf938e490986a384c3d572250aaab2446572fc26be279c263e4a4c9c2c24f9649e2444d8ddb3277373c600363beb73200baaa783da183dd85830af863e1a00d5cf718aac4879519fbf0745bcc59214493a330f940bf99a446f1ade6df2610c5f154b432eaba964d7ad1f1182e522019fc21ce498a204d06b96a476f7386e6003000000000000";

const CLAIMS_ENTRY_ID_STR: &str = "ad://ext/sAMAccountName:88d5d9085ea5c0c0";
const CLAIMS_ENTRY_VALUE_STR: &str = "testuser1";
const CLAIMS_ENTRY_ID_INT64: &str = "ad://ext/msDS-SupportedE:88d5dea8f1af5f19";
const CLAIMS_ENTRY_VALUE_INT64: i64 = 28;
const CLAIMS_ENTRY_ID_UINT64: &str = "ad://ext/objectClass:88d5de791e7b27e6";

#[test]
fn parses_gokrb5_pac_container_and_buffers() {
    let bytes = decode_hex(common::PAC_AD_WIN2K);
    let pac = Pac::parse_and_process(&bytes).expect("PAC parses");

    assert_eq!(pac.c_buffers, 5);
    assert_eq!(pac.version, 0);
    assert_eq!(pac.buffers.len(), 5);
    assert!(pac.kerb_validation_info.is_some());
    assert!(pac.client_info.is_some());
    assert!(pac.upn_dns_info.is_some());
    assert!(pac.server_checksum.is_some());
    assert!(pac.kdc_checksum.is_some());

    let kvi = pac.kerb_validation_info.as_ref().expect("KVI parsed");
    assert_gokrb5_validation_info(kvi);
    assert_client_info(pac.client_info.as_ref().expect("client info parsed"));
    assert_upn_dns_info(pac.upn_dns_info.as_ref().expect("UPN/DNS info parsed"));
}

#[test]
fn parses_signature_data_and_zeroes_checksum_bytes() {
    let pac = Pac::parse_and_process(&decode_hex(common::PAC_AD_WIN2K)).expect("PAC parses");
    let server = pac
        .server_checksum
        .as_ref()
        .expect("server checksum parsed");
    let kdc = pac.kdc_checksum.as_ref().expect("KDC checksum parsed");

    assert_eq!(server.signature_type, CHECKSUM_HMAC_SHA1_96_AES256);
    assert_eq!(hex_encode(&server.signature), "1e251d98d552be7df384f550");
    assert_eq!(
        hex_encode(&server.zeroed_data),
        "10000000000000000000000000000000"
    );

    assert_eq!(kdc.signature_type, CHECKSUM_HMAC_MD5_UNSIGNED);
    assert_eq!(
        hex_encode(&kdc.signature),
        "340be28b48765d0519ee9346cf53d822"
    );
    assert_eq!(
        hex_encode(&kdc.zeroed_data),
        "76ffffff00000000000000000000000000000000"
    );

    let server_buffer = pac
        .buffer(INFO_TYPE_PAC_SERVER_SIGNATURE_DATA)
        .expect("server checksum buffer exists");
    let server_offset = usize::try_from(server_buffer.offset).expect("offset fits");
    assert_eq!(
        &pac.zero_signature_data[server_offset + 4..server_offset + 16],
        &[0; 12]
    );

    let kdc_buffer = pac
        .buffer(INFO_TYPE_PAC_KDC_SIGNATURE_DATA)
        .expect("KDC checksum buffer exists");
    let kdc_offset = usize::try_from(kdc_buffer.offset).expect("offset fits");
    assert_eq!(
        &pac.zero_signature_data[kdc_offset + 4..kdc_offset + 20],
        &[0; 16]
    );
}

#[test]
fn parses_component_buffers_directly() {
    let pac = Pac::parse(&decode_hex(common::PAC_AD_WIN2K)).expect("PAC header parses");

    let client_buffer = pac
        .buffer(INFO_TYPE_PAC_CLIENT_INFO)
        .expect("client buffer exists");
    let client =
        ClientInfo::parse(pac.buffer_bytes(client_buffer).expect("client bytes")).expect("client");
    assert_client_info(&client);

    let upn_buffer = pac
        .buffer(INFO_TYPE_UPN_DNS_INFO)
        .expect("UPN/DNS buffer exists");
    let upn =
        UpnDnsInfo::parse(pac.buffer_bytes(upn_buffer).expect("UPN/DNS bytes")).expect("UPN/DNS");
    assert_upn_dns_info(&upn);

    let signature_buffer = pac
        .buffer(INFO_TYPE_PAC_SERVER_SIGNATURE_DATA)
        .expect("server checksum buffer exists");
    let signature = SignatureData::parse(
        pac.buffer_bytes(signature_buffer)
            .expect("server checksum bytes"),
    )
    .expect("signature parses");
    assert_eq!(signature.signature_type, CHECKSUM_HMAC_SHA1_96_AES256);
}

#[test]
fn parses_gokrb5_client_claims_info_str() {
    let claims = ClaimsInfo::parse(&decode_hex(CLIENT_CLAIMS_INFO_STR)).expect("claims parse");
    let entry = assert_single_claim(&claims, CLAIM_TYPE_ID_STRING, CLAIMS_ENTRY_ID_STR);

    assert_eq!(
        entry.values,
        ClaimValues::String(vec![CLAIMS_ENTRY_VALUE_STR.to_string()])
    );
}

#[test]
fn parses_gokrb5_client_claims_info_int() {
    let claims = ClaimsInfo::parse(&decode_hex(CLIENT_CLAIMS_INFO_INT)).expect("claims parse");
    let entry = assert_single_claim(&claims, CLAIM_TYPE_ID_INT64, CLAIMS_ENTRY_ID_INT64);

    assert_eq!(
        entry.values,
        ClaimValues::Int64(vec![CLAIMS_ENTRY_VALUE_INT64])
    );
}

#[test]
fn parses_gokrb5_client_claims_info_multi_uint() {
    let claims =
        ClaimsInfo::parse(&decode_hex(CLIENT_CLAIMS_INFO_MULTI_UINT)).expect("claims parse");
    let entry = assert_single_claim(&claims, CLAIM_TYPE_ID_UINT64, CLAIMS_ENTRY_ID_UINT64);

    assert_eq!(
        entry.values,
        ClaimValues::UInt64(vec![655_369, 65_543, 65_542, 65_536])
    );
}

#[test]
fn parses_gokrb5_client_claims_info_multi_str() {
    let claims =
        ClaimsInfo::parse(&decode_hex(CLIENT_CLAIMS_INFO_MULTI_STR)).expect("claims parse");
    let entry = assert_single_claim(
        &claims,
        CLAIM_TYPE_ID_STRING,
        "ad://ext/otherIpPhone:88d5de9f6b4af985",
    );

    assert_eq!(
        entry.values,
        ClaimValues::String(vec![
            "str1".to_string(),
            "str2".to_string(),
            "str3".to_string(),
            "str4".to_string()
        ])
    );
}

#[test]
fn parses_gokrb5_client_claims_info_multi_entry() {
    let claims = ClaimsInfo::parse(&decode_hex(CLIENT_CLAIMS_INFO_MULTI)).expect("claims parse");
    let array = assert_single_claims_array(&claims, 2);

    assert_eq!(array.claim_entries[0].claim_type, CLAIM_TYPE_ID_INT64);
    assert_eq!(array.claim_entries[0].id, CLAIMS_ENTRY_ID_INT64);
    assert_eq!(
        array.claim_entries[0].values,
        ClaimValues::Int64(vec![CLAIMS_ENTRY_VALUE_INT64])
    );
    assert_eq!(array.claim_entries[1].claim_type, CLAIM_TYPE_ID_STRING);
    assert_eq!(array.claim_entries[1].id, CLAIMS_ENTRY_ID_STR);
    assert_eq!(
        array.claim_entries[1].values,
        ClaimValues::String(vec![CLAIMS_ENTRY_VALUE_STR.to_string()])
    );
}

#[test]
fn parses_gokrb5_xpress_huffman_compressed_claims_info() {
    let claims = ClaimsInfo::parse(&decode_hex(CLIENT_CLAIMS_INFO_XPRESS_HUFF))
        .expect("compressed claims parse");

    assert_eq!(
        claims.metadata.compression_format,
        CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF
    );
    assert_eq!(claims.claims_set.claims_array_count, 1);
    assert!(!claims.claims_set.claims_arrays[0].claim_entries.is_empty());
}

#[test]
fn parses_generated_compressed_claims_formats() {
    let raw = ClaimsSetMetadata::parse(&decode_hex(CLIENT_CLAIMS_INFO_STR))
        .expect("claims metadata parses")
        .claims_set_bytes;

    let mut xpress =
        compcol::vec::compress_to_vec::<compcol::xpress::Xpress>(&raw).expect("XPRESS compresses");
    let mut xpress_huff =
        compcol::vec::compress_to_vec::<compcol::xpress_huffman::XpressHuffman>(&raw)
            .expect("XPRESS Huffman compresses");
    let compressed_formats = [
        (
            CLAIMS_COMPRESSION_FORMAT_LZNT1,
            compcol::vec::compress_to_vec::<compcol::lznt1::Lznt1>(&raw).expect("LZNT1 compresses"),
        ),
        (CLAIMS_COMPRESSION_FORMAT_XPRESS, xpress.split_off(8)),
        (
            CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF,
            xpress_huff.split_off(4),
        ),
    ];

    for (compression_format, compressed) in compressed_formats {
        let metadata = ClaimsSetMetadata::parse(&claims_set_metadata_bytes(
            compression_format,
            &compressed,
            raw.len(),
        ))
        .expect("compressed claims metadata parses");
        assert_eq!(
            metadata
                .decoded_claims_set_bytes()
                .expect("claims bytes decode"),
            raw
        );

        let claims = metadata.claims_set().expect("claims set parses");
        let info = ClaimsInfo {
            metadata,
            claims_set: claims,
        };
        assert_eq!(info.claims_set.claims_array_count, 1);
        assert_eq!(info.claims_set.claims_arrays.len(), 1);
        let array = &info.claims_set.claims_arrays[0];
        assert_eq!(array.claims_source_type, CLAIMS_SOURCE_TYPE_AD);
        assert_eq!(array.claims_count, 1);
        assert_eq!(array.claim_entries.len(), 1);
        let entry = &array.claim_entries[0];
        assert_eq!(entry.claim_type, CLAIM_TYPE_ID_STRING);
        assert_eq!(entry.id, CLAIMS_ENTRY_ID_STR);
        assert_eq!(
            entry.values,
            ClaimValues::String(vec![CLAIMS_ENTRY_VALUE_STR.to_string()])
        );
    }
}

#[test]
fn processes_client_and_device_claims_pac_buffers() {
    let claim_bytes = decode_hex(CLIENT_CLAIMS_INFO_STR);
    let pac = Pac::parse_and_process(&single_buffer_pac(
        INFO_TYPE_PAC_CLIENT_CLAIMS_INFO,
        &claim_bytes,
    ))
    .expect("PAC parses");
    let entry = assert_single_claim(
        pac.client_claims_info
            .as_ref()
            .expect("client claims parsed"),
        CLAIM_TYPE_ID_STRING,
        CLAIMS_ENTRY_ID_STR,
    );
    assert_eq!(
        entry.values,
        ClaimValues::String(vec![CLAIMS_ENTRY_VALUE_STR.to_string()])
    );

    let pac = Pac::parse_and_process(&single_buffer_pac(
        INFO_TYPE_PAC_DEVICE_CLAIMS_INFO,
        &claim_bytes,
    ))
    .expect("PAC parses");
    let entry = assert_single_claim(
        pac.device_claims_info
            .as_ref()
            .expect("device claims parsed"),
        CLAIM_TYPE_ID_STRING,
        CLAIMS_ENTRY_ID_STR,
    );
    assert_eq!(
        entry.values,
        ClaimValues::String(vec![CLAIMS_ENTRY_VALUE_STR.to_string()])
    );
}

#[test]
fn parses_s4u_delegation_info() {
    let bytes = s4u_delegation_info_bytes();
    let info = S4UDelegationInfo::parse(&bytes).expect("S4U delegation info parses");

    assert_eq!(info.s4u2proxy_target.value, "HTTP/backend");
    assert_eq!(info.transited_list_size, 2);
    assert_eq!(
        info.s4u_transited_services
            .iter()
            .map(|service| service.value.as_str())
            .collect::<Vec<_>>(),
        vec!["HTTP/front", "HTTP/mid"]
    );
}

#[test]
fn parses_device_info() {
    let bytes = device_info_bytes();
    let info = DeviceInfo::parse(&bytes).expect("device info parses");

    assert_device_info(&info);
}

#[test]
fn processes_s4u_delegation_and_device_info_pac_buffers() {
    let pac = Pac::parse_and_process(&single_buffer_pac(
        INFO_TYPE_S4U_DELEGATION_INFO,
        &s4u_delegation_info_bytes(),
    ))
    .expect("PAC parses");
    assert_eq!(
        pac.s4u_delegation_info
            .as_ref()
            .expect("S4U info parsed")
            .s4u2proxy_target
            .value,
        "HTTP/backend"
    );

    let pac = Pac::parse_and_process(&single_buffer_pac(
        INFO_TYPE_PAC_DEVICE_INFO,
        &device_info_bytes(),
    ))
    .expect("PAC parses");
    assert_device_info(pac.device_info.as_ref().expect("device info parsed"));
}

#[test]
fn parses_credentials_info_header_and_processes_pac_buffer() {
    let encrypted = vec![0xde, 0xad, 0xbe, 0xef];
    let bytes = credentials_info_bytes(18, encrypted.clone());
    let info = CredentialsInfo::parse(&bytes).expect("credentials info parses");

    assert_eq!(info.version, 0);
    assert_eq!(info.encryption_type, 18);
    assert_eq!(info.encrypted_credential_data, encrypted);

    let pac =
        Pac::parse_and_process(&single_buffer_pac(INFO_TYPE_CREDENTIALS, &bytes)).expect("PAC");
    assert_eq!(
        pac.credentials_info
            .as_ref()
            .expect("credentials info parsed"),
        &info
    );
}

#[test]
fn decrypts_credentials_info_and_parses_ntlm_supplemental_credential() {
    let etype = KerberosEtype::Sha1(AesSha1Etype::Aes256);
    let key = EncryptionKey {
        etype: etype.etype_id(),
        value: (0u8..32).collect(),
    };
    let plaintext = credential_data_bytes();
    let encrypted = etype
        .encrypt_message_with_confounder(&key.value, &plaintext, 16, &[0xa5; 16])
        .expect("credential data encrypts");
    let info = CredentialsInfo::parse(&credentials_info_bytes(18, encrypted))
        .expect("credentials info parses");
    let credential_data = info
        .decrypt_credential_data(&key)
        .expect("credential data decrypts");

    assert_credential_data(&credential_data);
}

#[test]
fn parses_credential_data_directly() {
    let credential_data = CredentialData::parse(&credential_data_bytes()).expect("data parses");

    assert_credential_data(&credential_data);
}

#[test]
fn verifies_pac_server_checksum_with_service_key() {
    let pac = Pac::parse_and_process(&decode_hex(common::PAC_AD_WIN2K)).expect("PAC parses");
    let keytab = Keytab::parse(&decode_hex(common::SYSHTTP_KEYTAB)).expect("keytab parses");
    let (key, kvno) = keytab
        .find_key(&["sysHTTP"], "TEST.GOKRB5", 2, 18)
        .expect("service key exists");

    assert_eq!(kvno, 2);
    assert!(
        pac.verify_server_checksum(key)
            .expect("checksum verification runs")
    );
    pac.verify(key).expect("PAC verifies");
}

#[test]
fn rejects_tampered_pac_server_checksum() {
    let mut pac = Pac::parse_and_process(&decode_hex(common::PAC_AD_WIN2K)).expect("PAC parses");
    let keytab = Keytab::parse(&decode_hex(common::SYSHTTP_KEYTAB)).expect("keytab parses");
    let (key, _) = keytab
        .find_key(&["sysHTTP"], "TEST.GOKRB5", 2, 18)
        .expect("service key exists");
    pac.server_checksum
        .as_mut()
        .expect("server checksum parsed")
        .signature[0] ^= 0x01;

    assert!(
        !pac.verify_server_checksum(key)
            .expect("checksum verification runs")
    );
    assert!(matches!(
        pac.verify(key),
        Err(pac::Error::ServerChecksumVerificationFailed)
    ));
}

#[test]
fn parses_domain_trust_validation_info_resource_groups() {
    let kvi = KerbValidationInfo::parse(&decode_hex(common::PAC_KERB_VALIDATION_INFO_TRUST))
        .expect("trust KVI parses");

    assert_eq!(kvi.effective_name.value, "testuser1");
    assert_eq!(kvi.full_name.value, "Test1 User1");
    assert_eq!(kvi.logon_count, 46);
    assert_eq!(kvi.user_id, 1106);
    assert_eq!(kvi.primary_group_id, 513);
    assert_eq!(
        kvi.group_ids,
        vec![group(1110, 7), group(513, 7), group(1109, 7),]
    );
    assert_eq!(kvi.user_flags, 544);
    assert_eq!(kvi.logon_server.value, "UDC");
    assert_eq!(kvi.logon_domain_name.value, "USER");
    assert_eq!(
        kvi.logon_domain_id
            .as_ref()
            .expect("logon domain SID")
            .to_string(),
        "S-1-5-21-2284869408-3503417140-1141177250"
    );
    assert_eq!(kvi.sid_count, 1);
    assert_eq!(kvi.extra_sids.len(), 1);
    assert_eq!(kvi.extra_sids[0].sid.to_string(), "S-1-18-1");
    assert_eq!(kvi.extra_sids[0].attributes, 7);
    assert_eq!(
        kvi.resource_group_domain_sid
            .as_ref()
            .expect("resource group domain SID")
            .to_string(),
        "S-1-5-21-3062750306-1230139592-1973306805"
    );
    assert_eq!(
        kvi.resource_group_ids,
        vec![group(1107, 536870919), group(1108, 536870919)]
    );
    assert_eq!(
        kvi.group_membership_sids(),
        vec![
            "S-1-5-21-2284869408-3503417140-1141177250-1110",
            "S-1-5-21-2284869408-3503417140-1141177250-513",
            "S-1-5-21-2284869408-3503417140-1141177250-1109",
            "S-1-18-1",
            "S-1-5-21-3062750306-1230139592-1973306805-1107",
            "S-1-5-21-3062750306-1230139592-1973306805-1108",
        ]
    );
}

#[test]
fn extracts_pac_from_if_relevant_authorization_data() {
    let pac_bytes = decode_hex(common::PAC_AD_WIN2K);
    let nested =
        rasn_kerberos::AuthorizationData::from(vec![rasn_kerberos::AuthorizationDataValue {
            r#type: pac::AD_WIN2K_PAC,
            data: pac_bytes.into(),
        }]);
    let nested_der = rasn::der::encode(&nested).expect("nested authorization-data encodes");
    let authorization_data =
        rasn_kerberos::AuthorizationData::from(vec![rasn_kerberos::AuthorizationDataValue {
            r#type: pac::AD_IF_RELEVANT,
            data: nested_der.into(),
        }]);

    let pac = pac::find_pac_in_authorization_data(&authorization_data)
        .expect("authorization-data search succeeds")
        .expect("PAC exists");

    assert_eq!(pac.c_buffers, 5);
    assert_eq!(
        pac.kerb_validation_info
            .as_ref()
            .expect("KVI parsed")
            .effective_name
            .value,
        "testuser1"
    );
}

fn assert_gokrb5_validation_info(kvi: &KerbValidationInfo) {
    assert_eq!(
        kvi.logon_time.system_time(),
        unix_time(1_494_085_991, 825_766_900)
    );
    assert_eq!(
        kvi.password_last_set.system_time(),
        unix_time(1_494_055_388, 968_750_000)
    );
    assert_eq!(
        kvi.password_can_change.system_time(),
        unix_time(1_494_141_788, 968_750_000)
    );
    assert_eq!(kvi.effective_name.value, "testuser1");
    assert_eq!(kvi.full_name.value, "Test1 User1");
    assert_eq!(kvi.logon_script.value, "");
    assert_eq!(kvi.profile_path.value, "");
    assert_eq!(kvi.home_directory.value, "");
    assert_eq!(kvi.home_directory_drive.value, "");
    assert_eq!(kvi.logon_count, 216);
    assert_eq!(kvi.bad_password_count, 0);
    assert_eq!(kvi.user_id, 1105);
    assert_eq!(kvi.primary_group_id, 513);
    assert_eq!(kvi.group_count, 5);
    assert_eq!(
        kvi.group_ids,
        vec![
            group(513, 7),
            group(1108, 7),
            group(1109, 7),
            group(1115, 7),
            group(1116, 7),
        ]
    );
    assert_eq!(kvi.user_flags, 32);
    assert_eq!(kvi.user_session_key, [0; 16]);
    assert_eq!(kvi.logon_server.value, "ADDC");
    assert_eq!(kvi.logon_domain_name.value, "TEST");
    assert_eq!(
        kvi.logon_domain_id
            .as_ref()
            .expect("logon domain SID")
            .to_string(),
        "S-1-5-21-3167651404-3865080224-2280184895"
    );
    assert_eq!(kvi.user_account_control, 528);
    assert_eq!(kvi.sub_auth_status, 0);
    assert_eq!(kvi.sid_count, 2);
    assert_eq!(kvi.extra_sids.len(), 2);
    assert_eq!(
        kvi.extra_sids[0].sid.to_string(),
        "S-1-5-21-3167651404-3865080224-2280184895-1114"
    );
    assert_eq!(kvi.extra_sids[0].attributes, 536870919);
    assert_eq!(
        kvi.extra_sids[1].sid.to_string(),
        "S-1-5-21-3167651404-3865080224-2280184895-1111"
    );
    assert_eq!(kvi.extra_sids[1].attributes, 536870919);
    assert!(kvi.resource_group_domain_sid.is_none());
    assert!(kvi.resource_group_ids.is_empty());
    assert_eq!(
        kvi.group_membership_sids(),
        vec![
            "S-1-5-21-3167651404-3865080224-2280184895-513",
            "S-1-5-21-3167651404-3865080224-2280184895-1108",
            "S-1-5-21-3167651404-3865080224-2280184895-1109",
            "S-1-5-21-3167651404-3865080224-2280184895-1115",
            "S-1-5-21-3167651404-3865080224-2280184895-1116",
            "S-1-5-21-3167651404-3865080224-2280184895-1114",
            "S-1-5-21-3167651404-3865080224-2280184895-1111",
        ]
    );
}

fn assert_client_info(client: &ClientInfo) {
    assert_eq!(client.client_id.system_time(), unix_time(1_494_085_991, 0));
    assert_eq!(client.name_length, 18);
    assert_eq!(client.name, "testuser1");
}

fn assert_upn_dns_info(upn: &UpnDnsInfo) {
    assert_eq!(upn.upn_length, 42);
    assert_eq!(upn.upn_offset, 16);
    assert_eq!(upn.dns_domain_name_length, 22);
    assert_eq!(upn.dns_domain_name_offset, 64);
    assert_eq!(upn.flags, 0);
    assert_eq!(upn.upn, "testuser1@test.gokrb5");
    assert_eq!(upn.dns_domain, "TEST.GOKRB5");
}

fn assert_single_claim<'a>(
    claims: &'a ClaimsInfo,
    claim_type: u16,
    id: &str,
) -> &'a pac::ClaimEntry {
    let array = assert_single_claims_array(claims, 1);
    let entry = &array.claim_entries[0];
    assert_eq!(entry.claim_type, claim_type);
    assert_eq!(entry.id, id);
    entry
}

fn assert_single_claims_array(claims: &ClaimsInfo, claims_count: u32) -> &pac::ClaimsArray {
    assert_eq!(
        claims.metadata.compression_format,
        CLAIMS_COMPRESSION_FORMAT_NONE
    );
    assert_eq!(claims.claims_set.claims_array_count, 1);
    assert_eq!(claims.claims_set.claims_arrays.len(), 1);

    let array = &claims.claims_set.claims_arrays[0];
    assert_eq!(array.claims_source_type, CLAIMS_SOURCE_TYPE_AD);
    assert_eq!(array.claims_count, claims_count);
    assert_eq!(array.claim_entries.len(), claims_count as usize);
    array
}

fn group(relative_id: u32, attributes: u32) -> pac::GroupMembership {
    pac::GroupMembership {
        relative_id,
        attributes,
    }
}

fn assert_device_info(info: &DeviceInfo) {
    assert_eq!(info.user_id, 1201);
    assert_eq!(info.primary_group_id, 515);
    assert_eq!(
        info.account_domain_id
            .as_ref()
            .expect("account domain SID")
            .to_string(),
        "S-1-5-21-1-2-3"
    );
    assert_eq!(info.account_group_count, 2);
    assert_eq!(info.account_group_ids, vec![group(515, 7), group(1201, 7)]);
    assert_eq!(info.sid_count, 1);
    assert_eq!(info.extra_sids.len(), 1);
    assert_eq!(info.extra_sids[0].sid.to_string(), "S-1-18-1");
    assert_eq!(info.extra_sids[0].attributes, 7);
    assert_eq!(info.domain_group_count, 1);
    assert_eq!(info.domain_group.len(), 1);
    assert_eq!(info.domain_group[0].domain_id.to_string(), "S-1-5-21-9-8-7");
    assert_eq!(info.domain_group[0].group_count, 2);
    assert_eq!(
        info.domain_group[0].group_ids,
        vec![group(2201, 536870919), group(2202, 536870919)]
    );
    assert_eq!(
        info.group_membership_sids(),
        vec![
            "S-1-5-21-1-2-3-515",
            "S-1-5-21-1-2-3-1201",
            "S-1-18-1",
            "S-1-5-21-9-8-7-2201",
            "S-1-5-21-9-8-7-2202",
        ]
    );
}

fn assert_credential_data(data: &CredentialData) {
    assert_eq!(data.credential_count, 1);
    assert_eq!(data.credentials.len(), 1);

    let credential = &data.credentials[0];
    assert_eq!(credential.package_name.value, "NTLM");
    assert_eq!(credential.credential_size, 40);
    assert_eq!(credential.credentials.len(), 40);

    let ntlm = NtlmSupplementalCredential::parse(&credential.credentials)
        .expect("NTLM supplemental credential parses");
    assert_eq!(ntlm.version, 0);
    assert_eq!(ntlm.flags, 0x0300_0000);
    assert!(ntlm.has_lm_password());
    assert!(ntlm.has_nt_password());
    assert_eq!(ntlm.lm_password, Some([0x11; 16]));
    assert_eq!(ntlm.nt_password, Some([0x22; 16]));
}

fn credentials_info_bytes(encryption_type: u32, encrypted: Vec<u8>) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, encryption_type);
    bytes.extend_from_slice(&encrypted);
    bytes
}

fn claims_set_metadata_bytes(
    compression_format: u16,
    claims_set_bytes: &[u8],
    uncompressed_size: usize,
) -> Vec<u8> {
    let mut object = Vec::new();
    push_u32(
        &mut object,
        u32::try_from(claims_set_bytes.len()).expect("claims set size fits"),
    );
    push_u32(&mut object, 0x0002_0004);
    push_u16(&mut object, compression_format);
    align_vec(&mut object, 4);
    push_u32(
        &mut object,
        u32::try_from(uncompressed_size).expect("uncompressed size fits"),
    );
    push_u16(&mut object, 0);
    align_vec(&mut object, 4);
    push_u32(&mut object, 0);
    push_u32(&mut object, 0);
    push_deferred_u8_array(&mut object, claims_set_bytes);
    ndr_wrapped(object)
}

fn credential_data_bytes() -> Vec<u8> {
    let credential = ntlm_supplemental_credential_bytes();
    let mut object = Vec::new();
    push_u32(&mut object, 1);
    push_rpc_unicode_string_descriptor(&mut object, "NTLM", 0x0002_0004);
    push_u32(
        &mut object,
        u32::try_from(credential.len()).expect("credential size fits"),
    );
    push_u32(&mut object, 0x0002_0008);
    push_deferred_rpc_unicode_string(&mut object, "NTLM");
    push_deferred_u8_array(&mut object, &credential);
    ndr_wrapped(object)
}

fn ntlm_supplemental_credential_bytes() -> Vec<u8> {
    let mut bytes = Vec::new();
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0x0300_0000);
    bytes.extend_from_slice(&[0x11; 16]);
    bytes.extend_from_slice(&[0x22; 16]);
    bytes
}

fn s4u_delegation_info_bytes() -> Vec<u8> {
    let mut object = Vec::new();
    push_rpc_unicode_string_descriptor(&mut object, "HTTP/backend", 0x0002_0004);
    push_u32(&mut object, 2);
    push_u32(&mut object, 0x0002_0008);
    push_deferred_rpc_unicode_string(&mut object, "HTTP/backend");
    push_u32(&mut object, 2);
    push_rpc_unicode_string_descriptor(&mut object, "HTTP/front", 0x0002_000c);
    push_rpc_unicode_string_descriptor(&mut object, "HTTP/mid", 0x0002_0010);
    push_deferred_rpc_unicode_string(&mut object, "HTTP/front");
    push_deferred_rpc_unicode_string(&mut object, "HTTP/mid");
    ndr_wrapped(object)
}

fn device_info_bytes() -> Vec<u8> {
    let mut object = Vec::new();
    push_u32(&mut object, 1201);
    push_u32(&mut object, 515);
    push_u32(&mut object, 0x0002_0004);
    push_u32(&mut object, 2);
    push_u32(&mut object, 0x0002_0008);
    push_u32(&mut object, 1);
    push_u32(&mut object, 0x0002_000c);
    push_u32(&mut object, 1);
    push_u32(&mut object, 0x0002_0010);

    push_deferred_sid(&mut object, &[21, 1, 2, 3]);
    push_group_memberships(&mut object, &[group(515, 7), group(1201, 7)]);
    push_u32(&mut object, 1);
    push_u32(&mut object, 0x0002_0014);
    push_u32(&mut object, 7);
    push_deferred_sid_with_authority(&mut object, 18, &[1]);

    push_u32(&mut object, 1);
    push_u32(&mut object, 0x0002_0018);
    push_u32(&mut object, 2);
    push_u32(&mut object, 0x0002_001c);
    push_deferred_sid(&mut object, &[21, 9, 8, 7]);
    push_group_memberships(
        &mut object,
        &[group(2201, 536870919), group(2202, 536870919)],
    );

    ndr_wrapped(object)
}

fn ndr_wrapped(object: Vec<u8>) -> Vec<u8> {
    let object_len = u32::try_from(object.len() + 4).expect("NDR object length fits");
    let mut bytes = Vec::with_capacity(20 + object.len());
    bytes.extend_from_slice(&[0x01, 0x10, 0x08, 0x00]);
    bytes.extend_from_slice(&[0xcc; 4]);
    push_u32(&mut bytes, object_len);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0x0002_0000);
    bytes.extend_from_slice(&object);
    bytes
}

fn push_rpc_unicode_string_descriptor(bytes: &mut Vec<u8>, value: &str, referent_id: u32) {
    let len = u16::try_from(value.encode_utf16().count() * 2).expect("string length fits");
    push_u16(bytes, len);
    push_u16(bytes, len);
    push_u32(bytes, referent_id);
}

fn push_deferred_rpc_unicode_string(bytes: &mut Vec<u8>, value: &str) {
    let units = value.encode_utf16().collect::<Vec<_>>();
    push_u32(
        bytes,
        u32::try_from(units.len()).expect("UTF-16 length fits"),
    );
    push_u32(bytes, 0);
    push_u32(
        bytes,
        u32::try_from(units.len()).expect("UTF-16 length fits"),
    );
    for unit in units {
        push_u16(bytes, unit);
    }
    align_vec(bytes, 4);
}

fn push_group_memberships(bytes: &mut Vec<u8>, groups: &[pac::GroupMembership]) {
    push_u32(
        bytes,
        u32::try_from(groups.len()).expect("group count fits"),
    );
    for group in groups {
        push_u32(bytes, group.relative_id);
        push_u32(bytes, group.attributes);
    }
}

fn push_deferred_u8_array(bytes: &mut Vec<u8>, data: &[u8]) {
    push_u32(
        bytes,
        u32::try_from(data.len()).expect("byte array length fits"),
    );
    bytes.extend_from_slice(data);
    align_vec(bytes, 4);
}

fn push_deferred_sid(bytes: &mut Vec<u8>, sub_authorities: &[u32]) {
    push_deferred_sid_with_authority(bytes, 5, sub_authorities);
}

fn push_deferred_sid_with_authority(bytes: &mut Vec<u8>, authority: u64, sub_authorities: &[u32]) {
    push_u32(
        bytes,
        u32::try_from(sub_authorities.len()).expect("SID sub-authority count fits"),
    );
    bytes.push(1);
    bytes.push(u8::try_from(sub_authorities.len()).expect("SID sub-authority count fits"));
    let authority_bytes = authority.to_be_bytes();
    bytes.extend_from_slice(&authority_bytes[2..]);
    for sub_authority in sub_authorities {
        push_u32(bytes, *sub_authority);
    }
    align_vec(bytes, 4);
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn align_vec(bytes: &mut Vec<u8>, alignment: usize) {
    while !bytes.len().is_multiple_of(alignment) {
        bytes.push(0);
    }
}

fn single_buffer_pac(ul_type: u32, buffer: &[u8]) -> Vec<u8> {
    let offset = 24u64;
    let mut pac = Vec::with_capacity(usize::try_from(offset).expect("offset fits") + buffer.len());
    pac.extend_from_slice(&1u32.to_le_bytes());
    pac.extend_from_slice(&0u32.to_le_bytes());
    pac.extend_from_slice(&ul_type.to_le_bytes());
    pac.extend_from_slice(
        &u32::try_from(buffer.len())
            .expect("buffer length fits")
            .to_le_bytes(),
    );
    pac.extend_from_slice(&offset.to_le_bytes());
    pac.extend_from_slice(buffer);
    pac
}

fn unix_time(seconds: u64, nanos: u32) -> std::time::SystemTime {
    UNIX_EPOCH + Duration::new(seconds, nanos)
}

fn decode_hex(input: &str) -> Vec<u8> {
    hex::decode(input).expect("fixture hex decodes")
}

fn hex_encode(input: &[u8]) -> String {
    hex::encode(input)
}
