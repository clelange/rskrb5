#![cfg(feature = "evaluation")]

use std::time::{Duration, UNIX_EPOCH};

use pretty_assertions::assert_eq;
use rskrb5::keytab::Keytab;
use rskrb5::pac::{
    self, CHECKSUM_HMAC_MD5_UNSIGNED, CHECKSUM_HMAC_SHA1_96_AES256, ClientInfo,
    INFO_TYPE_PAC_CLIENT_INFO, INFO_TYPE_PAC_KDC_SIGNATURE_DATA,
    INFO_TYPE_PAC_SERVER_SIGNATURE_DATA, INFO_TYPE_UPN_DNS_INFO, KerbValidationInfo, Pac,
    SignatureData, UpnDnsInfo,
};

mod common;

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

fn group(relative_id: u32, attributes: u32) -> pac::GroupMembership {
    pac::GroupMembership {
        relative_id,
        attributes,
    }
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
