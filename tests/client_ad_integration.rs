#![cfg(feature = "tokio")]

use std::env;
use std::error::Error;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use rskrb5::client::{
    ApReqOptions, KdcProtocol, Principal, TgsRepSession, TokioClient, build_ap_req_with_confounder,
};
use rskrb5::config::Config;
use rskrb5::crypto::KerberosEtype;
use rskrb5::keytab::Keytab;
use rskrb5::service::ServiceValidator;

const USER_REALM: &str = "USER.GOKRB5";
const RESOURCE_REALM: &str = "RES.GOKRB5";
const TESTUSER1: &str = "testuser1";
const TESTUSER2: &str = "testuser2";
const TESTUSER3: &str = "testuser3";
const SYSHTTP: &str = "sysHTTP";
const USER_SERVICE_HOST: &str = "user2.user.gokrb5";
const RESOURCE_SERVICE_HOST: &str = "host.res.gokrb5";
const AES256_ETYPE: i32 = 18;
const RC4_HMAC_ETYPE: i32 = 23;

const KEYTAB_TESTUSER1_USER_GOKRB5: &str = "05020000003b0001000b555345522e474f4b5242350009746573747573657231000000015e80c2750100170010084768c373663b3bef1f6385883cf7ff000000010000003b0001000b555345522e474f4b5242350009746573747573657231000000015e80c2750100110010528b8ba0ae5131fbf71f6ddc5870cdce000000010000004b0001000b555345522e474f4b5242350009746573747573657231000000015e80c275010012002016475f89eba70e62af20a20e7bf3ca4ccad5ae22485c93ffb133650bc6f12585000000010000003b0001000b555345522e474f4b5242350009746573747573657231000000015e80c2750100130010a3ddea306fa06c068bc3e1fcf4b280ca000000010000004b0001000b555345522e474f4b5242350009746573747573657231000000015e80c27501001400205d2a66a8af5142db59bcaabac8310777bf60a85e8881469e2063bba4dff0c00a000000010000003b0001000b555345522e474f4b5242350009746573747573657231000000015e80c2750200170010084768c373663b3bef1f6385883cf7ff000000020000003b0001000b555345522e474f4b5242350009746573747573657231000000015e80c2750200110010528b8ba0ae5131fbf71f6ddc5870cdce000000020000004b0001000b555345522e474f4b5242350009746573747573657231000000015e80c275020012002016475f89eba70e62af20a20e7bf3ca4ccad5ae22485c93ffb133650bc6f12585000000020000003b0001000b555345522e474f4b5242350009746573747573657231000000015e80c2750200130010a3ddea306fa06c068bc3e1fcf4b280ca000000020000004b0001000b555345522e474f4b5242350009746573747573657231000000015e80c27502001400205d2a66a8af5142db59bcaabac8310777bf60a85e8881469e2063bba4dff0c00a00000002";
const KEYTAB_TESTUSER2_USER_GOKRB5: &str = "05020000003b0001000b555345522e474f4b5242350009746573747573657232000000015e80b9f30100170010084768c373663b3bef1f6385883cf7ff000000010000003b0001000b555345522e474f4b5242350009746573747573657232000000015e80b9f30100110010a771a31fae504621fffc644a521e0cee000000010000004b0001000b555345522e474f4b5242350009746573747573657232000000015e80b9f301001200203262b201af7ec73c77bbee75a4ff10950cf2bda56529ead30ced4f0f0b9a591d000000010000003b0001000b555345522e474f4b5242350009746573747573657232000000015e80b9f301001300104be17a4cf1761f0494475617f671fa6a000000010000004b0001000b555345522e474f4b5242350009746573747573657232000000015e80b9f301001400208b1c60589b6c0d78d5e8fe265e92c2babf920a6a2828c37fc343e43497ad9fab000000010000003b0001000b555345522e474f4b5242350009746573747573657232000000015e80c30a0200170010084768c373663b3bef1f6385883cf7ff000000020000003b0001000b555345522e474f4b5242350009746573747573657232000000015e80c30a0200110010a771a31fae504621fffc644a521e0cee000000020000004b0001000b555345522e474f4b5242350009746573747573657232000000015e80c30a02001200203262b201af7ec73c77bbee75a4ff10950cf2bda56529ead30ced4f0f0b9a591d000000020000003b0001000b555345522e474f4b5242350009746573747573657232000000015e80c30a02001300104be17a4cf1761f0494475617f671fa6a000000020000004b0001000b555345522e474f4b5242350009746573747573657232000000015e80c30a02001400208b1c60589b6c0d78d5e8fe265e92c2babf920a6a2828c37fc343e43497ad9fab00000002";
const KEYTAB_TESTUSER3_USER_GOKRB5: &str = "05020000003b0001000b555345522e474f4b5242350009746573747573657233000000015e80ba950100170010084768c373663b3bef1f6385883cf7ff000000010000003b0001000b555345522e474f4b5242350009746573747573657233000000015e80ba95010011001025b79e18723ecd0fdf76c3a5bb21d5dd000000010000004b0001000b555345522e474f4b5242350009746573747573657233000000015e80ba950100120020c98c6dcc3ee520d5712aba339b2aa1930414b24fb52b9f70bf46259a57c1740b000000010000003b0001000b555345522e474f4b5242350009746573747573657233000000015e80ba95010013001007f06e524ee5d738b5bb464c876a5087000000010000004b0001000b555345522e474f4b5242350009746573747573657233000000015e80ba95010014002024cb938c683c9fcbe548f2febc93f8090fbaf44541751fc2b781e453dba36a11000000010000003b0001000b555345522e474f4b5242350009746573747573657233000000015e80c37d0200170010084768c373663b3bef1f6385883cf7ff000000020000003b0001000b555345522e474f4b5242350009746573747573657233000000015e80c37d020011001025b79e18723ecd0fdf76c3a5bb21d5dd000000020000004b0001000b555345522e474f4b5242350009746573747573657233000000015e80c37d0200120020c98c6dcc3ee520d5712aba339b2aa1930414b24fb52b9f70bf46259a57c1740b000000020000003b0001000b555345522e474f4b5242350009746573747573657233000000015e80c37d020013001007f06e524ee5d738b5bb464c876a5087000000020000004b0001000b555345522e474f4b5242350009746573747573657233000000015e80c37d020014002024cb938c683c9fcbe548f2febc93f8090fbaf44541751fc2b781e453dba36a1100000002";
const KEYTAB_SYSHTTP_RES_GOKRB5: &str = "0502000000380001000a5245532e474f4b524235000773797348545450000000015e7a7e2f0200170010084768c373663b3bef1f6385883cf7ff00000002000000380001000a5245532e474f4b524235000773797348545450000000015e7a7e2f0200110010c622e44a32022f4cb81775263151140d00000002000000480001000a5245532e474f4b524235000773797348545450000000015e7a7e2f02001200209da0dc4802bf5d375dfe2a77ddfc5065b3bf789126c2dc89ff4c2aa90dfa43ce00000002000000380001000a5245532e474f4b524235000773797348545450000000015e7a7e2f0200130010541beb216c1cdf22ef7c2225066a385e00000002000000480001000a5245532e474f4b524235000773797348545450000000015e7a7e2f02001400205f0983acd70fcaee0acb7ac4a14f8ad89f3a35915914e696200370637d8fef2300000002";

static AD_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn active_directory_keytab_login() -> Result<(), Box<dyn Error>> {
    if !ad_enabled() {
        return Ok(());
    }
    let _guard = AD_LOCK.lock().expect("AD integration test lock");

    runtime().block_on(async {
        let mut client = ad_client(TESTUSER1, testuser1_keytab()?, false)?;
        let tgt = client.login().await?;

        assert_eq!(tgt.client, Principal::user(USER_REALM, TESTUSER1));
        assert_eq!(tgt.service, Principal::tgt_service(USER_REALM));
        assert_eq!(tgt.session_key.etype, AES256_ETYPE);

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn active_directory_keytab_login_without_preauth() -> Result<(), Box<dyn Error>> {
    if !ad_enabled() {
        return Ok(());
    }
    let _guard = AD_LOCK.lock().expect("AD integration test lock");

    runtime().block_on(async {
        let mut client = ad_client(TESTUSER3, keytab(KEYTAB_TESTUSER3_USER_GOKRB5)?, false)?;
        let tgt = client.login().await?;

        assert_eq!(tgt.client, Principal::user(USER_REALM, TESTUSER3));
        assert_eq!(tgt.service, Principal::tgt_service(USER_REALM));
        assert_eq!(tgt.session_key.etype, AES256_ETYPE);

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn active_directory_service_ticket_validates_user_domain_pac() -> Result<(), Box<dyn Error>> {
    if !ad_enabled() {
        return Ok(());
    }
    let _guard = AD_LOCK.lock().expect("AD integration test lock");

    runtime().block_on(async {
        let mut client = ad_client(TESTUSER1, testuser1_keytab()?, false)?;
        client.login().await?;

        let ticket = client
            .get_service_ticket(http_service(USER_REALM, USER_SERVICE_HOST))
            .await?;
        assert_eq!(ticket.service.name(), format!("HTTP/{USER_SERVICE_HOST}"));
        assert_eq!(ticket.session_key.etype, AES256_ETYPE);

        let service_keytab = keytab(KEYTAB_TESTUSER2_USER_GOKRB5)?;
        let validated = validate_service_ticket(&ticket, &service_keytab, [TESTUSER2])?;
        let pac = validated.pac.as_ref().expect("AD service ticket has a PAC");
        let credentials = pac.ad_credentials().expect("PAC has validation info");
        assert_eq!(credentials.logon_domain_name, "USER");

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn active_directory_trust_resource_domain_service_ticket_validates_pac()
-> Result<(), Box<dyn Error>> {
    if !ad_enabled() {
        return Ok(());
    }
    let _guard = AD_LOCK.lock().expect("AD integration test lock");

    runtime().block_on(async {
        let mut client = ad_client(TESTUSER1, testuser1_keytab()?, true)?;
        client.login().await?;

        let ticket = client
            .get_service_ticket(http_service(RESOURCE_REALM, RESOURCE_SERVICE_HOST))
            .await?;
        assert_eq!(
            ticket.service.name(),
            format!("HTTP/{RESOURCE_SERVICE_HOST}")
        );
        assert_eq!(ticket.session_key.etype, RC4_HMAC_ETYPE);

        let service_keytab = keytab(KEYTAB_SYSHTTP_RES_GOKRB5)?;
        let validated = validate_service_ticket(&ticket, &service_keytab, [SYSHTTP])?;
        let pac = validated.pac.as_ref().expect("AD service ticket has a PAC");
        let credentials = pac.ad_credentials().expect("PAC has validation info");
        assert_eq!(credentials.effective_name, TESTUSER1);

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn active_directory_trust_user_domain_service_ticket_validates_pac() -> Result<(), Box<dyn Error>> {
    if !ad_enabled() {
        return Ok(());
    }
    let _guard = AD_LOCK.lock().expect("AD integration test lock");

    runtime().block_on(async {
        let mut client = ad_client(TESTUSER1, testuser1_keytab()?, true)?;
        client.login().await?;

        let ticket = client
            .get_service_ticket(http_service(USER_REALM, USER_SERVICE_HOST))
            .await?;
        assert_eq!(ticket.service.name(), format!("HTTP/{USER_SERVICE_HOST}"));

        let service_keytab = keytab(KEYTAB_TESTUSER2_USER_GOKRB5)?;
        let validated = validate_service_ticket(&ticket, &service_keytab, [TESTUSER2])?;
        let pac = validated.pac.as_ref().expect("AD service ticket has a PAC");
        let credentials = pac.ad_credentials().expect("PAC has validation info");
        assert_eq!(credentials.effective_name, TESTUSER1);

        Ok::<_, Box<dyn Error>>(())
    })
}

fn ad_enabled() -> bool {
    if !ad_prefetch_gate() {
        eprintln!("skipping AD integration test; set TESTAD=1 to enable");
        return false;
    }

    let user_kdc = ad_user_kdc_addr();
    let resource_kdc = ad_resource_kdc_addr();

    if !tcp_reachable(&user_kdc, "USER realm KDC") {
        eprintln!("skipping AD integration test; cannot reach user KDC at {user_kdc}");
        return false;
    }

    if !tcp_reachable(&resource_kdc, "RESOURCE realm KDC") {
        eprintln!("skipping AD integration test; cannot reach resource KDC at {resource_kdc}");
        return false;
    }

    true
}

fn ad_prefetch_gate() -> bool {
    env::var("TESTAD").as_deref() == Ok("1")
}

fn ad_user_kdc_addr() -> String {
    env_value(
        &["TEST_AD_USER_KDC_ADDR", "TEST_AD_KDC_ADDR"],
        "192.168.88.100:88",
    )
}

fn ad_resource_kdc_addr() -> String {
    env_value(
        &["TEST_AD_RESOURCE_KDC_ADDR", "TEST_AD_RES_KDC_ADDR"],
        "192.168.88.101:88",
    )
}

fn ad_user_admin_addr() -> String {
    env_value(
        &["TEST_AD_USER_ADMIN_ADDR", "TEST_AD_ADMIN_ADDR"],
        "192.168.88.100:464",
    )
}

fn ad_resource_admin_addr() -> String {
    env_value(
        &["TEST_AD_RESOURCE_ADMIN_ADDR", "TEST_AD_RES_ADMIN_ADDR"],
        "192.168.88.101:464",
    )
}

fn tcp_reachable(endpoint: &str, label: &str) -> bool {
    let mut addrs = match endpoint.to_socket_addrs() {
        Ok(addrs) => addrs,
        Err(error) => {
            eprintln!("failed to resolve {label} {endpoint}: {error}");
            return false;
        }
    };
    let timeout = Duration::from_secs(1);

    addrs.any(|addr| TcpStream::connect_timeout(&addr, timeout).is_ok())
}

fn ad_client(user: &str, keytab: Keytab, rc4: bool) -> Result<TokioClient, Box<dyn Error>> {
    Ok(TokioClient::with_keytab(
        ad_config(rc4)?,
        KdcProtocol::Auto,
        Principal::user(USER_REALM, user),
        keytab,
    ))
}

fn ad_config(rc4: bool) -> Result<Config, Box<dyn Error>> {
    let user_kdc = ad_user_kdc_addr();
    let user_admin = ad_user_admin_addr();
    let resource_kdc = ad_resource_kdc_addr();
    let resource_admin = ad_resource_admin_addr();
    let rc4_options = if rc4 {
        r#"
  allow_weak_crypto = true
  canonicalize = true
  default_tkt_enctypes = rc4-hmac
  default_tgs_enctypes = rc4-hmac
  permitted_enctypes = rc4-hmac
"#
    } else {
        ""
    };

    Ok(Config::parse(&format!(
        r#"[libdefaults]
  default_realm = {USER_REALM}
  dns_lookup_realm = false
  dns_lookup_kdc = false
  ticket_lifetime = 24h
  forwardable = yes
  default_tkt_enctypes = aes256-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96
  noaddresses = false
{rc4_options}

[realms]
 {USER_REALM} = {{
  kdc = {user_kdc}
  admin_server = {user_admin}
  default_domain = user.gokrb5
 }}
 {RESOURCE_REALM} = {{
  kdc = {resource_kdc}
  admin_server = {resource_admin}
  default_domain = res.gokrb5
 }}

[domain_realm]
 .user.gokrb5 = {USER_REALM}
 user.gokrb5 = {USER_REALM}
 .res.gokrb5 = {RESOURCE_REALM}
 res.gokrb5 = {RESOURCE_REALM}
"#,
    ))?)
}

fn env_value(names: &[&str], default: &str) -> String {
    names
        .iter()
        .find_map(|name| env::var(name).ok().filter(|value| !value.is_empty()))
        .unwrap_or_else(|| default.to_owned())
}

fn http_service(realm: &str, host: &str) -> Principal {
    Principal::new(realm, 2, ["HTTP", host])
}

fn validate_service_ticket<const N: usize>(
    ticket: &TgsRepSession,
    keytab: &Keytab,
    keytab_principal: [&str; N],
) -> Result<rskrb5::service::ValidatedApReq, Box<dyn Error>> {
    let etype =
        KerberosEtype::from_etype_id(ticket.session_key.etype).expect("ticket etype is supported");
    let confounder = vec![0x42; etype.confounder_len()];
    let timestamp = SystemTime::now();
    let ap_req =
        build_ap_req_with_confounder(ticket, ApReqOptions::new(), timestamp, 0, &confounder)?;
    let mut validator = ServiceValidator::new(keytab)
        .with_now(timestamp)
        .with_keytab_principal(keytab_principal);
    Ok(validator.validate_ap_req(&ap_req.der)?)
}

fn testuser1_keytab() -> Result<Keytab, Box<dyn Error>> {
    keytab(KEYTAB_TESTUSER1_USER_GOKRB5)
}

fn keytab(hex: &str) -> Result<Keytab, Box<dyn Error>> {
    Ok(Keytab::parse(&decode_hex(hex))?)
}

fn decode_hex(input: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 2);
    for chunk in input.as_bytes().chunks_exact(2) {
        let hi = (chunk[0] as char).to_digit(16).expect("hex high nibble") as u8;
        let lo = (chunk[1] as char).to_digit(16).expect("hex low nibble") as u8;
        out.push((hi << 4) | lo);
    }
    out
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("tokio runtime builds")
}
