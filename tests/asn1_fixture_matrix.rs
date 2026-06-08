#![cfg(feature = "evaluation")]

use picky_asn1::wrapper::Asn1SequenceOf;
use rskrb5::evaluation::{ASN1_FIXTURES, DerType, Support};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Probe {
    Pass,
    Fail,
    Unsupported,
}

fn fixture_hex(id: &str) -> &'static str {
    match id {
        "authenticator" => {
            "6281A130819EA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A30F300DA003020101A106040431323334A405020301E240A511180F31393934303631303036303331375AA6133011A003020101A10A04083132333435363738A703020111A8243022300FA003020101A1080406666F6F626172300FA003020101A1080406666F6F626172"
        }
        "authenticator_optionals_empty" => {
            "624F304DA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A405020301E240A511180F31393934303631303036303331375A"
        }
        "authenticator_optionals_null" => {
            "624F304DA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A405020301E240A511180F31393934303631303036303331375A"
        }
        "ticket" => {
            "615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765"
        }
        "encryption_key" => "3011A003020101A10A04083132333435363738",
        "enc_ticket_part" => {
            "6382011430820110A007030500FEDCBA98A1133011A003020101A10A04083132333435363738A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A42E302CA003020101A12504234544552C4D49542E2C415448454E412E2C57415348494E47544F4E2E4544552C43532EA511180F31393934303631303036303331375AA611180F31393934303631303036303331375AA711180F31393934303631303036303331375AA811180F31393934303631303036303331375AA920301E300DA003020102A106040412D00023300DA003020102A106040412D00023AA243022300FA003020101A1080406666F6F626172300FA003020101A1080406666F6F626172"
        }
        "enc_ticket_part_optionals_null" => {
            "6381A53081A2A007030500FEDCBA98A1133011A003020101A10A04083132333435363738A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A42E302CA003020101A12504234544552C4D49542E2C415448454E412E2C57415348494E47544F4E2E4544552C43532EA511180F31393934303631303036303331375AA711180F31393934303631303036303331375A"
        }
        "kdc_req_body" => {
            "308201A6A007030500FEDCBA90A11A3018A003020101A111300F1B066866747361691B056578747261A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A411180F31393934303631303036303331375AA511180F31393934303631303036303331375AA611180F31393934303631303036303331375AA70302012AA8083006020100020101A920301E300DA003020102A106040412D00023300DA003020102A106040412D00023AA253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765"
        }
        "kdc_req_body_optionals_null_except_second_ticket" => {
            "3081FFA007030500FEDCBA98A2101B0E415448454E412E4D49542E454455A511180F31393934303631303036303331375AA70302012AA8083006020100020101AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765"
        }
        "kdc_req_body_optionals_null_except_server" => {
            "3059A007030500FEDCBA90A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A511180F31393934303631303036303331375AA70302012AA8083006020100020101"
        }
        "as_req" => {
            "6A8201E4308201E0A103020105A20302010AA32630243010A10302010DA209040770612D646174613010A10302010DA209040770612D64617461A48201AA308201A6A007030500FEDCBA90A11A3018A003020101A111300F1B066866747361691B056578747261A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A411180F31393934303631303036303331375AA511180F31393934303631303036303331375AA611180F31393934303631303036303331375AA70302012AA8083006020100020101A920301E300DA003020102A106040412D00023300DA003020102A106040412D00023AA253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765"
        }
        "as_req_optionals_null_except_second_ticket" => {
            "6A82011430820110A103020105A20302010AA48201023081FFA007030500FEDCBA98A2101B0E415448454E412E4D49542E454455A511180F31393934303631303036303331375AA70302012AA8083006020100020101AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765"
        }
        "as_req_optionals_null_except_server" => {
            "6A693067A103020105A20302010AA45B3059A007030500FEDCBA90A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A511180F31393934303631303036303331375AA70302012AA8083006020100020101"
        }
        "tgs_req" => {
            "6C8201E4308201E0A103020105A20302010CA32630243010A10302010DA209040770612D646174613010A10302010DA209040770612D64617461A48201AA308201A6A007030500FEDCBA90A11A3018A003020101A111300F1B066866747361691B056578747261A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A411180F31393934303631303036303331375AA511180F31393934303631303036303331375AA611180F31393934303631303036303331375AA70302012AA8083006020100020101A920301E300DA003020102A106040412D00023300DA003020102A106040412D00023AA253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765"
        }
        "tgs_req_optionals_null_except_second_ticket" => {
            "6C82011430820110A103020105A20302010CA48201023081FFA007030500FEDCBA98A2101B0E415448454E412E4D49542E454455A511180F31393934303631303036303331375AA70302012AA8083006020100020101AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765"
        }
        "tgs_req_optionals_null_except_server" => {
            "6C693067A103020105A20302010CA45B3059A007030500FEDCBA90A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A511180F31393934303631303036303331375AA70302012AA8083006020100020101"
        }
        "as_rep" => {
            "6B81EA3081E7A003020105A10302010BA22630243010A10302010DA209040770612D646174613010A10302010DA209040770612D64617461A3101B0E415448454E412E4D49542E454455A41A3018A003020101A111300F1B066866747361691B056578747261A55E615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765A6253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765"
        }
        "as_rep_optionals_null" => {
            "6B81C23081BFA003020105A10302010BA3101B0E415448454E412E4D49542E454455A41A3018A003020101A111300F1B066866747361691B056578747261A55E615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765A6253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765"
        }
        "tgs_rep" => {
            "6D81EA3081E7A003020105A10302010DA22630243010A10302010DA209040770612D646174613010A10302010DA209040770612D64617461A3101B0E415448454E412E4D49542E454455A41A3018A003020101A111300F1B066866747361691B056578747261A55E615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765A6253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765"
        }
        "tgs_rep_optionals_null" => {
            "6D81C23081BFA003020105A10302010DA3101B0E415448454E412E4D49542E454455A41A3018A003020101A111300F1B066866747361691B056578747261A55E615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765A6253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765"
        }
        "enc_tgs_rep_part" => {
            "7A82010E3082010AA0133011A003020101A10A04083132333435363738A13630343018A0030201FBA111180F31393934303631303036303331375A3018A0030201FBA111180F31393934303631303036303331375AA20302012AA311180F31393934303631303036303331375AA407030500FEDCBA98A511180F31393934303631303036303331375AA611180F31393934303631303036303331375AA711180F31393934303631303036303331375AA811180F31393934303631303036303331375AA9101B0E415448454E412E4D49542E454455AA1A3018A003020101A111300F1B066866747361691B056578747261AB20301E300DA003020102A106040412D00023300DA003020102A106040412D00023"
        }
        "enc_tgs_rep_part_optionals_null" => {
            "7A81B23081AFA0133011A003020101A10A04083132333435363738A13630343018A0030201FBA111180F31393934303631303036303331375A3018A0030201FBA111180F31393934303631303036303331375AA20302012AA407030500FE5CBA98A511180F31393934303631303036303331375AA711180F31393934303631303036303331375AA9101B0E415448454E412E4D49542E454455AA1A3018A003020101A111300F1B066866747361691B056578747261"
        }
        "ap_req" => {
            "6E819D30819AA003020105A10302010EA207030500FEDCBA98A35E615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765A4253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765"
        }
        "ap_rep" => {
            "6F333031A003020105A10302010FA2253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765"
        }
        "enc_ap_rep_part" => {
            "7B363034A011180F31393934303631303036303331375AA105020301E240A2133011A003020101A10A04083132333435363738A303020111"
        }
        "enc_ap_rep_part_optionals_null" => {
            "7B1C301AA011180F31393934303631303036303331375AA105020301E240"
        }
        "krb_safe" => {
            "746E306CA003020105A103020114A24F304DA00A04086B72623564617461A111180F31393934303631303036303331375AA205020301E240A303020111A40F300DA003020102A106040412D00023A50F300DA003020102A106040412D00023A30F300DA003020101A106040431323334"
        }
        "krb_safe_optionals_null" => {
            "743E303CA003020105A103020114A21F301DA00A04086B72623564617461A40F300DA003020102A106040412D00023A30F300DA003020101A106040431323334"
        }
        "krb_priv" => {
            "75333031A003020105A103020115A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765"
        }
        "enc_krb_priv_part" => {
            "7C4F304DA00A04086B72623564617461A111180F31393934303631303036303331375AA205020301E240A303020111A40F300DA003020102A106040412D00023A50F300DA003020102A106040412D00023"
        }
        "enc_krb_priv_part_optionals_null" => {
            "7C1F301DA00A04086B72623564617461A40F300DA003020102A106040412D00023"
        }
        "krb_cred" => {
            "7681F63081F3A003020105A103020116A281BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765"
        }
        "enc_krb_cred_part" => {
            "7D8202233082021FA08201DA308201D63081E8A0133011A003020101A10A04083132333435363738A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A307030500FEDCBA98A411180F31393934303631303036303331375AA511180F31393934303631303036303331375AA611180F31393934303631303036303331375AA711180F31393934303631303036303331375AA8101B0E415448454E412E4D49542E454455A91A3018A003020101A111300F1B066866747361691B056578747261AA20301E300DA003020102A106040412D00023300DA003020102A106040412D000233081E8A0133011A003020101A10A04083132333435363738A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A307030500FEDCBA98A411180F31393934303631303036303331375AA511180F31393934303631303036303331375AA611180F31393934303631303036303331375AA711180F31393934303631303036303331375AA8101B0E415448454E412E4D49542E454455A91A3018A003020101A111300F1B066866747361691B056578747261AA20301E300DA003020102A106040412D00023300DA003020102A106040412D00023A10302012AA211180F31393934303631303036303331375AA305020301E240A40F300DA003020102A106040412D00023A50F300DA003020102A106040412D00023"
        }
        "enc_krb_cred_part_optionals_null" => {
            "7D82010E3082010AA0820106308201023015A0133011A003020101A10A040831323334353637383081E8A0133011A003020101A10A04083132333435363738A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A307030500FEDCBA98A411180F31393934303631303036303331375AA511180F31393934303631303036303331375AA611180F31393934303631303036303331375AA711180F31393934303631303036303331375AA8101B0E415448454E412E4D49542E454455A91A3018A003020101A111300F1B066866747361691B056578747261AA20301E300DA003020102A106040412D00023300DA003020102A106040412D00023"
        }
        "krb_error" => {
            "7E81BA3081B7A003020105A10302011EA211180F31393934303631303036303331375AA305020301E240A411180F31393934303631303036303331375AA505020301E240A60302013CA7101B0E415448454E412E4D49542E454455A81A3018A003020101A111300F1B066866747361691B056578747261A9101B0E415448454E412E4D49542E454455AA1A3018A003020101A111300F1B066866747361691B056578747261AB0A1B086B72623564617461AC0A04086B72623564617461"
        }
        "krb_error_optionals_null" => {
            "7E60305EA003020105A10302011EA305020301E240A411180F31393934303631303036303331375AA505020301E240A60302013CA9101B0E415448454E412E4D49542E454455AA1A3018A003020101A111300F1B066866747361691B056578747261"
        }
        "authorization_data" => {
            "3022300FA003020101A1080406666F6F626172300FA003020101A1080406666F6F626172"
        }
        "ad_kdcissued" => {
            "3065A00F300DA003020101A106040431323334A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3243022300FA003020101A1080406666F6F626172300FA003020101A1080406666F6F626172"
        }
        "padata_sequence" => {
            "30243010A10302010DA209040770612D646174613010A10302010DA209040770612D64617461"
        }
        "padata_sequence_empty" => "3000",
        "typed_data" => {
            "30243010A00302010DA109040770612D646174613010A00302010DA109040770612D64617461"
        }
        "pa_enc_ts_enc" => "301AA011180F31393934303631303036303331375AA105020301E240",
        "pa_enc_ts_enc_no_usec" => "3013A011180F31393934303631303036303331375A",
        "etype_info" => {
            "30333014A003020100A10D040B4D6F72746F6E27732023303005A0030201013014A003020102A10D040B4D6F72746F6E2773202332"
        }
        "etype_info_only_1" => "30163014A003020100A10D040B4D6F72746F6E2773202330",
        "etype_info_no_info" => "3000",
        "etype_info2" => {
            "3051301EA003020100A10D1B0B4D6F72746F6E2773202330A208040673326B3A2030300FA003020101A208040673326B3A2031301EA003020102A10D1B0B4D6F72746F6E2773202332A208040673326B3A2032"
        }
        "etype_info2_only_1" => {
            "3020301EA003020100A10D1B0B4D6F72746F6E2773202330A208040673326B3A2030"
        }
        "encrypted_data" => {
            "3023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765"
        }
        "encrypted_data_msb_set_kvno" => {
            "3026A003020100A1060204FF000000A21704156B726241534E2E312074657374206D657373616765"
        }
        "encrypted_data_kvno_negative_one" => {
            "3023A003020100A1030201FFA21704156B726241534E2E312074657374206D657373616765"
        }
        "change_passwd_data" => {
            "3036a00d040b6e657770617373776f7264a1163014a003020101a10d300b1b09746573747573657231a20d1b0b544553542e474f4b524235"
        }
        _ => panic!("missing fixture hex for {id}"),
    }
}

fn expect_support(
    candidate: &str,
    operation: &str,
    fixture_id: &str,
    expected: Support,
    actual: Probe,
) {
    match expected {
        Support::Yes => assert_eq!(
            actual,
            Probe::Pass,
            "{candidate} should {operation} fixture {fixture_id}"
        ),
        Support::No => assert_ne!(
            actual,
            Probe::Pass,
            "{candidate} unexpectedly passed {operation} fixture {fixture_id}; update the report matrix"
        ),
        Support::Partial | Support::Excluded => {
            panic!(
                "ASN.1 fixture expectations must be yes/no for {candidate} {operation} {fixture_id}"
            )
        }
    }
}

#[test]
fn rasn_kerberos_decodes_expected_gokrb5_asn1_fixtures() {
    for fixture in ASN1_FIXTURES {
        let bytes = hex::decode(fixture_hex(fixture.id)).expect("fixture hex is valid");
        let actual = rasn_decode(fixture.der_type, &bytes);
        expect_support(
            "rasn-kerberos",
            "decode",
            fixture.id,
            fixture.rasn_kerberos,
            actual,
        );
    }
}

#[test]
fn rasn_kerberos_roundtrips_expected_gokrb5_asn1_fixtures() {
    for fixture in ASN1_FIXTURES {
        let bytes = hex::decode(fixture_hex(fixture.id)).expect("fixture hex is valid");
        let actual = rasn_roundtrip(fixture.der_type, &bytes);
        expect_support(
            "rasn-kerberos",
            "round-trip",
            fixture.id,
            fixture.rasn_kerberos_roundtrip,
            actual,
        );
    }
}

#[test]
fn picky_krb_decodes_expected_gokrb5_asn1_fixtures() {
    for fixture in ASN1_FIXTURES {
        let bytes = hex::decode(fixture_hex(fixture.id)).expect("fixture hex is valid");
        let actual = picky_decode(fixture.der_type, &bytes);
        expect_support("picky-krb", "decode", fixture.id, fixture.picky_krb, actual);
    }
}

#[test]
fn picky_krb_roundtrips_expected_gokrb5_asn1_fixtures() {
    for fixture in ASN1_FIXTURES {
        let bytes = hex::decode(fixture_hex(fixture.id)).expect("fixture hex is valid");
        let actual = picky_roundtrip(fixture.der_type, &bytes);
        expect_support(
            "picky-krb",
            "round-trip",
            fixture.id,
            fixture.picky_krb_roundtrip,
            actual,
        );
    }
}

fn rasn_decode(der_type: DerType, bytes: &[u8]) -> Probe {
    match der_type {
        DerType::Authenticator => rasn_decode_type::<rasn_kerberos::Authenticator>(bytes),
        DerType::Ticket => rasn_decode_type::<rasn_kerberos::Ticket>(bytes),
        DerType::EncryptionKey => rasn_decode_type::<rasn_kerberos::EncryptionKey>(bytes),
        DerType::EncTicketPart => rasn_decode_type::<rasn_kerberos::EncTicketPart>(bytes),
        DerType::KdcReqBody => rasn_decode_type::<rasn_kerberos::KdcReqBody>(bytes),
        DerType::AsReq => rasn_decode_type::<rasn_kerberos::AsReq>(bytes),
        DerType::TgsReq => rasn_decode_type::<rasn_kerberos::TgsReq>(bytes),
        DerType::AsRep => rasn_decode_type::<rasn_kerberos::AsRep>(bytes),
        DerType::TgsRep => rasn_decode_type::<rasn_kerberos::TgsRep>(bytes),
        DerType::EncTgsRepPart => rasn_decode_type::<rasn_kerberos::EncTgsRepPart>(bytes),
        DerType::ApReq => rasn_decode_type::<rasn_kerberos::ApReq>(bytes),
        DerType::ApRep => rasn_decode_type::<rasn_kerberos::ApRep>(bytes),
        DerType::EncApRepPart => rasn_decode_type::<rasn_kerberos::EncApRepPart>(bytes),
        DerType::KrbSafe => rasn_decode_type::<rasn_kerberos::KrbSafe>(bytes),
        DerType::KrbPriv => rasn_decode_type::<rasn_kerberos::KrbPriv>(bytes),
        DerType::EncKrbPrivPart => rasn_decode_type::<rasn_kerberos::EncKrbPrivPart>(bytes),
        DerType::KrbCred => rasn_decode_type::<rasn_kerberos::KrbCred>(bytes),
        DerType::EncKrbCredPart => rasn_decode_type::<rasn_kerberos::EncKrbCredPart>(bytes),
        DerType::KrbError => rasn_decode_type::<rasn_kerberos::KrbError>(bytes),
        DerType::AuthorizationData => rasn_decode_type::<rasn_kerberos::AuthorizationData>(bytes),
        DerType::AdKdcIssued => rasn_decode_type::<rasn_kerberos::AdKdcIssued>(bytes),
        DerType::PaDataSequence => rasn_decode_type::<rasn_kerberos::MethodData>(bytes),
        DerType::TypedData => rasn_decode_type::<rasn_kerberos::TypedData>(bytes),
        DerType::PaEncTsEnc => rasn_decode_type::<rasn_kerberos::PaEncTsEnc>(bytes),
        DerType::EtypeInfo => rasn_decode_type::<rasn_kerberos::EtypeInfo>(bytes),
        DerType::EtypeInfo2 => rasn_decode_type::<rasn_kerberos::EtypeInfo2>(bytes),
        DerType::EncryptedData => rasn_decode_type::<rasn_kerberos::EncryptedData>(bytes),
        DerType::ChangePasswdData => Probe::Unsupported,
    }
}

fn rasn_roundtrip(der_type: DerType, bytes: &[u8]) -> Probe {
    match der_type {
        DerType::Authenticator => rasn_roundtrip_type::<rasn_kerberos::Authenticator>(bytes),
        DerType::Ticket => rasn_roundtrip_type::<rasn_kerberos::Ticket>(bytes),
        DerType::EncryptionKey => rasn_roundtrip_type::<rasn_kerberos::EncryptionKey>(bytes),
        DerType::EncTicketPart => rasn_roundtrip_type::<rasn_kerberos::EncTicketPart>(bytes),
        DerType::KdcReqBody => rasn_roundtrip_type::<rasn_kerberos::KdcReqBody>(bytes),
        DerType::AsReq => rasn_roundtrip_type::<rasn_kerberos::AsReq>(bytes),
        DerType::TgsReq => rasn_roundtrip_type::<rasn_kerberos::TgsReq>(bytes),
        DerType::AsRep => rasn_roundtrip_type::<rasn_kerberos::AsRep>(bytes),
        DerType::TgsRep => rasn_roundtrip_type::<rasn_kerberos::TgsRep>(bytes),
        DerType::EncTgsRepPart => rasn_roundtrip_type::<rasn_kerberos::EncTgsRepPart>(bytes),
        DerType::ApReq => rasn_roundtrip_type::<rasn_kerberos::ApReq>(bytes),
        DerType::ApRep => rasn_roundtrip_type::<rasn_kerberos::ApRep>(bytes),
        DerType::EncApRepPart => rasn_roundtrip_type::<rasn_kerberos::EncApRepPart>(bytes),
        DerType::KrbSafe => rasn_roundtrip_type::<rasn_kerberos::KrbSafe>(bytes),
        DerType::KrbPriv => rasn_roundtrip_type::<rasn_kerberos::KrbPriv>(bytes),
        DerType::EncKrbPrivPart => rasn_roundtrip_type::<rasn_kerberos::EncKrbPrivPart>(bytes),
        DerType::KrbCred => rasn_roundtrip_type::<rasn_kerberos::KrbCred>(bytes),
        DerType::EncKrbCredPart => rasn_roundtrip_type::<rasn_kerberos::EncKrbCredPart>(bytes),
        DerType::KrbError => rasn_roundtrip_type::<rasn_kerberos::KrbError>(bytes),
        DerType::AuthorizationData => {
            rasn_roundtrip_type::<rasn_kerberos::AuthorizationData>(bytes)
        }
        DerType::AdKdcIssued => rasn_roundtrip_type::<rasn_kerberos::AdKdcIssued>(bytes),
        DerType::PaDataSequence => rasn_roundtrip_type::<rasn_kerberos::MethodData>(bytes),
        DerType::TypedData => rasn_roundtrip_type::<rasn_kerberos::TypedData>(bytes),
        DerType::PaEncTsEnc => rasn_roundtrip_type::<rasn_kerberos::PaEncTsEnc>(bytes),
        DerType::EtypeInfo => rasn_roundtrip_type::<rasn_kerberos::EtypeInfo>(bytes),
        DerType::EtypeInfo2 => rasn_roundtrip_type::<rasn_kerberos::EtypeInfo2>(bytes),
        DerType::EncryptedData => rasn_roundtrip_type::<rasn_kerberos::EncryptedData>(bytes),
        DerType::ChangePasswdData => Probe::Unsupported,
    }
}

fn rasn_decode_type<T>(bytes: &[u8]) -> Probe
where
    T: rasn::Decode,
{
    if rasn::der::decode::<T>(bytes).is_ok() {
        Probe::Pass
    } else {
        Probe::Fail
    }
}

fn rasn_roundtrip_type<T>(bytes: &[u8]) -> Probe
where
    T: rasn::Decode + rasn::Encode,
{
    let Ok(decoded) = rasn::der::decode::<T>(bytes) else {
        return Probe::Fail;
    };
    match rasn::der::encode(&decoded) {
        Ok(encoded) if encoded == bytes => Probe::Pass,
        Ok(_) | Err(_) => Probe::Fail,
    }
}

fn picky_decode(der_type: DerType, bytes: &[u8]) -> Probe {
    match der_type {
        DerType::Authenticator => picky_decode_type::<picky_krb::data_types::Authenticator>(bytes),
        DerType::Ticket => picky_decode_type::<picky_krb::data_types::Ticket>(bytes),
        DerType::EncryptionKey => picky_decode_type::<picky_krb::data_types::EncryptionKey>(bytes),
        DerType::EncTicketPart => picky_decode_type::<picky_krb::data_types::EncTicketPart>(bytes),
        DerType::KdcReqBody => picky_decode_type::<picky_krb::messages::KdcReqBody>(bytes),
        DerType::AsReq => picky_decode_type::<picky_krb::messages::AsReq>(bytes),
        DerType::TgsReq => picky_decode_type::<picky_krb::messages::TgsReq>(bytes),
        DerType::AsRep => picky_decode_type::<picky_krb::messages::AsRep>(bytes),
        DerType::TgsRep => picky_decode_type::<picky_krb::messages::TgsRep>(bytes),
        DerType::EncTgsRepPart => picky_decode_type::<picky_krb::messages::EncTgsRepPart>(bytes),
        DerType::ApReq => picky_decode_type::<picky_krb::messages::ApReq>(bytes),
        DerType::ApRep => picky_decode_type::<picky_krb::messages::ApRep>(bytes),
        DerType::EncApRepPart => picky_decode_type::<picky_krb::data_types::EncApRepPart>(bytes),
        DerType::KrbPriv => picky_decode_type::<picky_krb::messages::KrbPriv>(bytes),
        DerType::EncKrbPrivPart => {
            picky_decode_type::<picky_krb::data_types::EncKrbPrivPart>(bytes)
        }
        DerType::KrbError => picky_decode_type::<picky_krb::messages::KrbError>(bytes),
        DerType::AuthorizationData => {
            picky_decode_type::<picky_krb::data_types::AuthorizationData>(bytes)
        }
        DerType::PaDataSequence => {
            picky_decode_type::<Asn1SequenceOf<picky_krb::data_types::PaData>>(bytes)
        }
        DerType::PaEncTsEnc => picky_decode_type::<picky_krb::data_types::PaEncTsEnc>(bytes),
        DerType::EtypeInfo2 => picky_decode_type::<picky_krb::data_types::EtypeInfo2>(bytes),
        DerType::EncryptedData => picky_decode_type::<picky_krb::data_types::EncryptedData>(bytes),
        DerType::ChangePasswdData => {
            picky_decode_type::<picky_krb::data_types::ChangePasswdData>(bytes)
        }
        DerType::KrbSafe
        | DerType::KrbCred
        | DerType::EncKrbCredPart
        | DerType::TypedData
        | DerType::AdKdcIssued
        | DerType::EtypeInfo => Probe::Unsupported,
    }
}

fn picky_roundtrip(der_type: DerType, bytes: &[u8]) -> Probe {
    match der_type {
        DerType::Authenticator => {
            picky_roundtrip_type::<picky_krb::data_types::Authenticator>(bytes)
        }
        DerType::Ticket => picky_roundtrip_type::<picky_krb::data_types::Ticket>(bytes),
        DerType::EncryptionKey => {
            picky_roundtrip_type::<picky_krb::data_types::EncryptionKey>(bytes)
        }
        DerType::EncTicketPart => {
            picky_roundtrip_type::<picky_krb::data_types::EncTicketPart>(bytes)
        }
        DerType::KdcReqBody => picky_roundtrip_type::<picky_krb::messages::KdcReqBody>(bytes),
        DerType::AsReq => picky_roundtrip_type::<picky_krb::messages::AsReq>(bytes),
        DerType::TgsReq => picky_roundtrip_type::<picky_krb::messages::TgsReq>(bytes),
        DerType::AsRep => picky_roundtrip_type::<picky_krb::messages::AsRep>(bytes),
        DerType::TgsRep => picky_roundtrip_type::<picky_krb::messages::TgsRep>(bytes),
        DerType::EncTgsRepPart => picky_roundtrip_type::<picky_krb::messages::EncTgsRepPart>(bytes),
        DerType::ApReq => picky_roundtrip_type::<picky_krb::messages::ApReq>(bytes),
        DerType::ApRep => picky_roundtrip_type::<picky_krb::messages::ApRep>(bytes),
        DerType::EncApRepPart => picky_roundtrip_type::<picky_krb::data_types::EncApRepPart>(bytes),
        DerType::KrbPriv => picky_roundtrip_type::<picky_krb::messages::KrbPriv>(bytes),
        DerType::EncKrbPrivPart => {
            picky_roundtrip_type::<picky_krb::data_types::EncKrbPrivPart>(bytes)
        }
        DerType::KrbError => picky_roundtrip_type::<picky_krb::messages::KrbError>(bytes),
        DerType::AuthorizationData => {
            picky_roundtrip_type::<picky_krb::data_types::AuthorizationData>(bytes)
        }
        DerType::PaDataSequence => {
            picky_roundtrip_type::<Asn1SequenceOf<picky_krb::data_types::PaData>>(bytes)
        }
        DerType::PaEncTsEnc => picky_roundtrip_type::<picky_krb::data_types::PaEncTsEnc>(bytes),
        DerType::EtypeInfo2 => picky_roundtrip_type::<picky_krb::data_types::EtypeInfo2>(bytes),
        DerType::EncryptedData => {
            picky_roundtrip_type::<picky_krb::data_types::EncryptedData>(bytes)
        }
        DerType::ChangePasswdData => {
            picky_roundtrip_type::<picky_krb::data_types::ChangePasswdData>(bytes)
        }
        DerType::KrbSafe
        | DerType::KrbCred
        | DerType::EncKrbCredPart
        | DerType::TypedData
        | DerType::AdKdcIssued
        | DerType::EtypeInfo => Probe::Unsupported,
    }
}

fn picky_decode_type<T>(bytes: &[u8]) -> Probe
where
    T: for<'de> serde::Deserialize<'de>,
{
    if picky_asn1_der::from_bytes::<T>(bytes).is_ok() {
        Probe::Pass
    } else {
        Probe::Fail
    }
}

fn picky_roundtrip_type<T>(bytes: &[u8]) -> Probe
where
    T: for<'de> serde::Deserialize<'de> + serde::Serialize,
{
    let Ok(decoded) = picky_asn1_der::from_bytes::<T>(bytes) else {
        return Probe::Fail;
    };
    match picky_asn1_der::to_vec(&decoded) {
        Ok(encoded) if encoded == bytes => Probe::Pass,
        Ok(_) | Err(_) => Probe::Fail,
    }
}
