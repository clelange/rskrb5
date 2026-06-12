#![cfg(feature = "messages")]

use pretty_assertions::assert_eq;
use rasn::types::Integer;
use rskrb5::kdc_req::{
    KRB_AS_REQ_MSG_TYPE, KRB_TGS_REQ_MSG_TYPE, build_as_req, build_tgs_req, decode_as_req,
    decode_kdc_req_body, decode_tgs_req, encode_as_req, encode_build_as_req, encode_build_tgs_req,
    encode_kdc_req_body, encode_tgs_req,
};

const KDC_REQ_BODY: &str = "308201A6A007030500FEDCBA90A11A3018A003020101A111300F1B066866747361691B056578747261A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A411180F31393934303631303036303331375AA511180F31393934303631303036303331375AA611180F31393934303631303036303331375AA70302012AA8083006020100020101A920301E300DA003020102A106040412D00023300DA003020102A106040412D00023AA253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765";
const KDC_REQ_BODY_OPTIONALS_NULL_EXCEPT_SECOND_TICKET: &str = "3081FFA007030500FEDCBA98A2101B0E415448454E412E4D49542E454455A511180F31393934303631303036303331375AA70302012AA8083006020100020101AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765";
const KDC_REQ_BODY_OPTIONALS_NULL_EXCEPT_SERVER: &str = "3059A007030500FEDCBA90A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A511180F31393934303631303036303331375AA70302012AA8083006020100020101";
const AS_REQ: &str = "6A8201E4308201E0A103020105A20302010AA32630243010A10302010DA209040770612D646174613010A10302010DA209040770612D64617461A48201AA308201A6A007030500FEDCBA90A11A3018A003020101A111300F1B066866747361691B056578747261A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A411180F31393934303631303036303331375AA511180F31393934303631303036303331375AA611180F31393934303631303036303331375AA70302012AA8083006020100020101A920301E300DA003020102A106040412D00023300DA003020102A106040412D00023AA253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765";
const AS_REQ_OPTIONALS_NULL_EXCEPT_SECOND_TICKET: &str = "6A82011430820110A103020105A20302010AA48201023081FFA007030500FEDCBA98A2101B0E415448454E412E4D49542E454455A511180F31393934303631303036303331375AA70302012AA8083006020100020101AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765";
const AS_REQ_OPTIONALS_NULL_EXCEPT_SERVER: &str = "6A693067A103020105A20302010AA45B3059A007030500FEDCBA90A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A511180F31393934303631303036303331375AA70302012AA8083006020100020101";
const TGS_REQ: &str = "6C8201E4308201E0A103020105A20302010CA32630243010A10302010DA209040770612D646174613010A10302010DA209040770612D64617461A48201AA308201A6A007030500FEDCBA90A11A3018A003020101A111300F1B066866747361691B056578747261A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A411180F31393934303631303036303331375AA511180F31393934303631303036303331375AA611180F31393934303631303036303331375AA70302012AA8083006020100020101A920301E300DA003020102A106040412D00023300DA003020102A106040412D00023AA253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765";
const TGS_REQ_OPTIONALS_NULL_EXCEPT_SECOND_TICKET: &str = "6C82011430820110A103020105A20302010CA48201023081FFA007030500FEDCBA98A2101B0E415448454E412E4D49542E454455A511180F31393934303631303036303331375AA70302012AA8083006020100020101AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765";
const TGS_REQ_OPTIONALS_NULL_EXCEPT_SERVER: &str = "6C693067A103020105A20302010CA45B3059A007030500FEDCBA90A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A511180F31393934303631303036303331375AA70302012AA8083006020100020101";
const TEST_TIME_SECONDS: i64 = 771_228_197;

#[derive(Clone, Copy)]
enum BodyShape {
    Full,
    SecondTicketOnly,
    ServerOnly,
}

#[test]
fn decodes_gokrb5_kdc_req_body_fixtures() {
    for (fixture, shape) in [
        (KDC_REQ_BODY, BodyShape::Full),
        (
            KDC_REQ_BODY_OPTIONALS_NULL_EXCEPT_SECOND_TICKET,
            BodyShape::SecondTicketOnly,
        ),
        (
            KDC_REQ_BODY_OPTIONALS_NULL_EXCEPT_SERVER,
            BodyShape::ServerOnly,
        ),
    ] {
        let bytes = decode_hex(fixture);

        let body = decode_kdc_req_body(&bytes).expect("KDC-REQ-BODY decodes");

        assert_kdc_req_body(&body, shape);
        assert_eq!(
            encode_kdc_req_body(&body).expect("KDC-REQ-BODY encodes"),
            bytes,
        );
    }
}

#[test]
fn decodes_gokrb5_as_req_fixtures() {
    for (fixture, shape) in [
        (AS_REQ, BodyShape::Full),
        (
            AS_REQ_OPTIONALS_NULL_EXCEPT_SECOND_TICKET,
            BodyShape::SecondTicketOnly,
        ),
        (AS_REQ_OPTIONALS_NULL_EXCEPT_SERVER, BodyShape::ServerOnly),
    ] {
        let bytes = decode_hex(fixture);

        let as_req = decode_as_req(&bytes).expect("AS-REQ decodes");

        assert_kdc_req_fields(&as_req.0, KRB_AS_REQ_MSG_TYPE, shape);
        assert_eq!(encode_as_req(&as_req).expect("AS-REQ encodes"), bytes);
    }
}

#[test]
fn decodes_gokrb5_tgs_req_fixtures() {
    for (fixture, shape) in [
        (TGS_REQ, BodyShape::Full),
        (
            TGS_REQ_OPTIONALS_NULL_EXCEPT_SECOND_TICKET,
            BodyShape::SecondTicketOnly,
        ),
        (TGS_REQ_OPTIONALS_NULL_EXCEPT_SERVER, BodyShape::ServerOnly),
    ] {
        let bytes = decode_hex(fixture);

        let tgs_req = decode_tgs_req(&bytes).expect("TGS-REQ decodes");

        assert_kdc_req_fields(&tgs_req.0, KRB_TGS_REQ_MSG_TYPE, shape);
        assert_eq!(encode_tgs_req(&tgs_req).expect("TGS-REQ encodes"), bytes);
    }
}

#[test]
fn builds_as_req_from_body_and_padata() {
    let body = decode_kdc_req_body(&decode_hex(KDC_REQ_BODY)).expect("body decodes");
    let fixture = decode_as_req(&decode_hex(AS_REQ)).expect("AS-REQ decodes");
    let padata = fixture.0.padata.clone();

    let built = build_as_req(body.clone(), padata.clone());

    assert_eq!(built.0.pvno, Integer::from(5));
    assert_eq!(built.0.msg_type, Integer::from(KRB_AS_REQ_MSG_TYPE));
    assert_eq!(built.0.padata, padata);
    assert_eq!(built.0.req_body, body);
    assert_eq!(
        encode_as_req(&built).expect("AS-REQ encodes"),
        decode_hex(AS_REQ),
    );
    assert_eq!(
        encode_build_as_req(body, fixture.0.padata).expect("AS-REQ builds and encodes"),
        decode_hex(AS_REQ),
    );
}

#[test]
fn builds_tgs_req_from_body_and_padata() {
    let body = decode_kdc_req_body(&decode_hex(KDC_REQ_BODY)).expect("body decodes");
    let fixture = decode_tgs_req(&decode_hex(TGS_REQ)).expect("TGS-REQ decodes");
    let padata = fixture.0.padata.clone();

    let built = build_tgs_req(body.clone(), padata.clone());

    assert_eq!(built.0.pvno, Integer::from(5));
    assert_eq!(built.0.msg_type, Integer::from(KRB_TGS_REQ_MSG_TYPE));
    assert_eq!(built.0.padata, padata);
    assert_eq!(built.0.req_body, body);
    assert_eq!(
        encode_tgs_req(&built).expect("TGS-REQ encodes"),
        decode_hex(TGS_REQ),
    );
    assert_eq!(
        encode_build_tgs_req(body, fixture.0.padata).expect("TGS-REQ builds and encodes"),
        decode_hex(TGS_REQ),
    );
}

fn assert_kdc_req_fields(
    req: &rasn_kerberos::KdcReq,
    expected_msg_type: i32,
    expected_shape: BodyShape,
) {
    assert_eq!(req.pvno, Integer::from(5));
    assert_eq!(req.msg_type, Integer::from(expected_msg_type));
    match expected_shape {
        BodyShape::Full => assert_padata(req.padata.as_ref().expect("padata")),
        BodyShape::SecondTicketOnly | BodyShape::ServerOnly => assert!(req.padata.is_none()),
    }
    assert_kdc_req_body(&req.req_body, expected_shape);
}

fn assert_kdc_req_body(body: &rasn_kerberos::KdcReqBody, expected_shape: BodyShape) {
    let expected_options = match expected_shape {
        BodyShape::SecondTicketOnly => 0xfedc_ba98,
        BodyShape::Full | BodyShape::ServerOnly => 0xfedc_ba90,
    };
    assert_eq!(kdc_options_to_bits(&body.kdc_options), expected_options);
    assert_eq!(body.realm.as_bytes(), b"ATHENA.MIT.EDU");
    assert_eq!(body.till.0.timestamp(), TEST_TIME_SECONDS);
    assert_eq!(body.nonce, 42);
    assert_eq!(body.etype, vec![0, 1]);

    match expected_shape {
        BodyShape::Full => {
            assert_principal(body.cname.as_ref().expect("cname"));
            assert_principal(body.sname.as_ref().expect("sname"));
            assert_eq!(
                body.from.as_ref().expect("from").0.timestamp(),
                TEST_TIME_SECONDS,
            );
            assert_eq!(
                body.rtime.as_ref().expect("rtime").0.timestamp(),
                TEST_TIME_SECONDS,
            );
            assert_addresses(body.addresses.as_ref().expect("addresses"));
            assert_encrypted_data(body.enc_authorization_data.as_ref().expect("auth data"));
            assert_tickets(body.additional_tickets.as_ref().expect("tickets"), 2);
        }
        BodyShape::SecondTicketOnly => {
            assert!(body.cname.is_none());
            assert!(body.sname.is_none());
            assert!(body.from.is_none());
            assert!(body.rtime.is_none());
            assert!(body.addresses.is_none());
            assert!(body.enc_authorization_data.is_none());
            assert_tickets(body.additional_tickets.as_ref().expect("tickets"), 2);
        }
        BodyShape::ServerOnly => {
            assert!(body.cname.is_none());
            assert_principal(body.sname.as_ref().expect("sname"));
            assert!(body.from.is_none());
            assert!(body.rtime.is_none());
            assert!(body.addresses.is_none());
            assert!(body.enc_authorization_data.is_none());
            assert!(body.additional_tickets.is_none());
        }
    }
}

fn assert_padata(padata: &[rasn_kerberos::PaData]) {
    assert_eq!(padata.len(), 2);
    for entry in padata {
        assert_eq!(entry.r#type, 13);
        assert_eq!(entry.value.as_ref(), b"pa-data");
    }
}

fn assert_principal(name: &rasn_kerberos::PrincipalName) {
    assert_eq!(name.r#type, 1);
    assert_eq!(
        principal_components(name),
        vec![b"hftsai".as_slice(), b"extra".as_slice()],
    );
}

fn assert_addresses(addresses: &[rasn_kerberos::HostAddress]) {
    assert_eq!(addresses.len(), 2);
    for address in addresses {
        assert_eq!(address.addr_type, 2);
        assert_eq!(address.address.as_ref(), decode_hex("12d00023"));
    }
}

fn assert_encrypted_data(encrypted_data: &rasn_kerberos::EncryptedData) {
    assert_eq!(encrypted_data.etype, 0);
    assert_eq!(encrypted_data.kvno, Some(5));
    assert_eq!(encrypted_data.cipher.as_ref(), b"krbASN.1 test message");
}

fn assert_tickets(tickets: &[rasn_kerberos::Ticket], expected_count: usize) {
    assert_eq!(tickets.len(), expected_count);
    for ticket in tickets {
        assert_eq!(ticket.tkt_vno, Integer::from(5));
        assert_eq!(ticket.realm.as_bytes(), b"ATHENA.MIT.EDU");
        assert_principal(&ticket.sname);
        assert_encrypted_data(&ticket.enc_part);
    }
}

fn principal_components(name: &rasn_kerberos::PrincipalName) -> Vec<&[u8]> {
    name.string
        .iter()
        .map(|component| component.as_bytes())
        .collect()
}

fn kdc_options_to_bits(flags: &rasn_kerberos::KdcOptions) -> u32 {
    let raw = flags.0.as_raw_slice();
    u32::from_be_bytes([
        raw.first().copied().unwrap_or_default(),
        raw.get(1).copied().unwrap_or_default(),
        raw.get(2).copied().unwrap_or_default(),
        raw.get(3).copied().unwrap_or_default(),
    ])
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex input has even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let high = decode_hex_digit(chunk[0]);
            let low = decode_hex_digit(chunk[1]);
            (high << 4) | low
        })
        .collect()
}

fn decode_hex_digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte: {byte}"),
    }
}
