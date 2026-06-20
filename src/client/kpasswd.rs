//! Client-side kpasswd request helpers and high-level password changes.

use std::time::{Duration, SystemTime};

use crate::crypto::KerberosEtype;
use crate::keytab::EncryptionKey;

use super::{
    ApReqOptions, BuiltApReq, Error, TgsRepSession, ap_rep_error, build_ap_req_with_confounder,
    encryption_key_from_rasn, integer_to_u32, kerberos_time_from_system_time,
    system_time_from_kerberos_time,
};

#[cfg(feature = "tokio")]
use super::{
    KRB_NT_PRINCIPAL, Principal, TokioClient, TokioClientCredentials, current_preauth_time,
    random_nonce,
};
#[cfg(feature = "tokio")]
use zeroize::Zeroizing;

/// Options for constructing a kpasswd request from a service ticket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KpasswdRequestOptions {
    /// Authenticator and KRB-PRIV timestamp.
    pub timestamp: SystemTime,
    /// Authenticator and KRB-PRIV microseconds.
    pub cusec: u32,
    /// Authenticator and KRB-PRIV sequence number.
    pub sequence_number: u32,
    /// Sender address used in the KRB-PRIV encrypted part.
    pub sender_address: rasn_kerberos::HostAddress,
    /// Optional recipient address used in the KRB-PRIV encrypted part.
    pub recipient_address: Option<rasn_kerberos::HostAddress>,
}

impl KpasswdRequestOptions {
    /// Construct options with the required timestamp, sequence number, and sender address.
    pub fn new(
        timestamp: SystemTime,
        cusec: u32,
        sequence_number: u32,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Self {
        Self {
            timestamp,
            cusec,
            sequence_number,
            sender_address,
            recipient_address: None,
        }
    }

    /// Set the optional recipient address.
    pub fn with_recipient_address(mut self, recipient_address: rasn_kerberos::HostAddress) -> Self {
        self.recipient_address = Some(recipient_address);
        self
    }
}

/// Built kpasswd request plus the key needed to decrypt the reply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltKpasswdRequest {
    /// Parsed kpasswd request.
    pub request: crate::kadmin::Request,
    /// Encoded kpasswd request frame.
    pub der: Vec<u8>,
    /// Authenticator subkey used to encrypt request KRB-PRIV payloads and reply KRB-PRIV payloads
    /// when the AP-REP does not select a server subkey.
    pub reply_key: EncryptionKey,
    /// Built AP-REQ metadata.
    pub ap_req: BuiltApReq,
}

/// Verified kpasswd AP-REP reply metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedKpasswdApRep {
    /// Reply `ctime` without `cusec`.
    pub ctime: SystemTime,
    /// Reply microsecond field.
    pub cusec: u32,
    /// Reply timestamp including `cusec`.
    pub authenticator_time: SystemTime,
    /// Optional server-selected subkey.
    pub subkey: Option<EncryptionKey>,
    /// Optional server sequence number.
    pub sequence_number: Option<u32>,
}

/// Build a complete kpasswd request with explicit confounders.
pub fn build_kpasswd_request_with_confounders(
    service_ticket: &TgsRepSession,
    change_data: &crate::kadmin::ChangePasswdData,
    reply_key: EncryptionKey,
    options: KpasswdRequestOptions,
    ap_req_confounder: &[u8],
    krb_priv_confounder: &[u8],
) -> Result<BuiltKpasswdRequest, Error> {
    let ap_req = build_kpasswd_ap_req_with_confounder(
        service_ticket,
        &reply_key,
        &options,
        ap_req_confounder,
    )?;
    let krb_priv_options = kpasswd_krb_priv_options(&options)?;
    let built_request = crate::kadmin::build_change_password_request_with_confounder(
        ap_req.message.clone(),
        change_data,
        reply_key,
        krb_priv_options,
        krb_priv_confounder,
    )?;

    Ok(BuiltKpasswdRequest {
        request: built_request.request,
        der: built_request.der,
        reply_key: built_request.reply_key,
        ap_req,
    })
}

/// Build a complete kpasswd request with generated reply key and confounders.
pub fn build_kpasswd_request(
    service_ticket: &TgsRepSession,
    change_data: &crate::kadmin::ChangePasswdData,
    options: KpasswdRequestOptions,
) -> Result<BuiltKpasswdRequest, Error> {
    let etype = KerberosEtype::from_etype_id(service_ticket.session_key.etype)
        .ok_or(Error::UnsupportedEtype(service_ticket.session_key.etype))?;
    let mut reply_key = EncryptionKey {
        etype: service_ticket.session_key.etype,
        value: vec![0; etype.key_len()],
    };
    getrandom::fill(&mut reply_key.value)?;
    let mut ap_req_confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut ap_req_confounder)?;

    let ap_req = build_kpasswd_ap_req_with_confounder(
        service_ticket,
        &reply_key,
        &options,
        &ap_req_confounder,
    )?;
    let krb_priv_options = kpasswd_krb_priv_options(&options)?;
    let built_request = crate::kadmin::build_change_password_request(
        ap_req.message.clone(),
        change_data,
        reply_key,
        krb_priv_options,
    )?;

    Ok(BuiltKpasswdRequest {
        request: built_request.request,
        der: built_request.der,
        reply_key: built_request.reply_key,
        ap_req,
    })
}

fn build_kpasswd_ap_req_with_confounder(
    service_ticket: &TgsRepSession,
    reply_key: &EncryptionKey,
    options: &KpasswdRequestOptions,
    ap_req_confounder: &[u8],
) -> Result<BuiltApReq, Error> {
    build_ap_req_with_confounder(
        service_ticket,
        ApReqOptions::new()
            .with_subkey(Some(reply_key.clone()))
            .with_sequence_number(Some(options.sequence_number)),
        options.timestamp,
        options.cusec,
        ap_req_confounder,
    )
}

fn kpasswd_krb_priv_options(
    options: &KpasswdRequestOptions,
) -> Result<crate::kadmin::EncKrbPrivPartOptions, Error> {
    let mut krb_priv_options =
        crate::kadmin::EncKrbPrivPartOptions::new(options.sender_address.clone())
            .with_timestamp(
                kerberos_time_from_system_time(options.timestamp)?,
                options.cusec,
            )
            .with_sequence_number(options.sequence_number);
    if let Some(recipient_address) = &options.recipient_address {
        krb_priv_options = krb_priv_options.with_recipient_address(recipient_address.clone());
    }
    Ok(krb_priv_options)
}

/// Verify the AP-REP section of a successful kpasswd reply.
///
/// KRB-ERROR replies do not carry AP-REP and return `Ok(None)`. Successful
/// replies must echo the AP-REQ authenticator timestamp and are encrypted with
/// the kpasswd service-ticket session key.
pub fn verify_kpasswd_ap_rep(
    reply: &crate::kadmin::Reply,
    request: &BuiltKpasswdRequest,
) -> Result<Option<VerifiedKpasswdApRep>, Error> {
    if reply.is_krb_error() {
        return Ok(None);
    }

    let ap_rep = reply.ap_rep.as_ref().ok_or(Error::MissingKpasswdApRep)?;
    crate::ap_rep::validate_ap_rep(ap_rep).map_err(ap_rep_error)?;
    let enc_part = crate::ap_rep::decrypt_ap_rep_enc_part(ap_rep, &request.ap_req.session_key)
        .map_err(ap_rep_error)?;
    let ctime = system_time_from_kerberos_time(&enc_part.ctime)?;
    let cusec = integer_to_u32("ap-rep.cusec", &enc_part.cusec)?;
    let authenticator_time = ctime
        .checked_add(Duration::from_micros(cusec.into()))
        .ok_or(Error::TimeOverflow)?;

    if ctime != request.ap_req.authenticator_ctime || cusec != request.ap_req.authenticator_cusec {
        return Err(Error::KpasswdApRepTimestampMismatch {
            expected: request.ap_req.authenticator_time,
            actual: authenticator_time,
        });
    }

    Ok(Some(VerifiedKpasswdApRep {
        ctime,
        cusec,
        authenticator_time,
        subkey: enc_part.subkey.as_ref().map(encryption_key_from_rasn),
        sequence_number: enc_part.seq_number,
    }))
}

#[cfg(feature = "tokio")]
impl TokioClient {
    /// Change this client's password using generated timestamp and sequence metadata.
    pub async fn change_password(
        &mut self,
        new_password: impl AsRef<[u8]>,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Result<crate::kadmin::ChangePasswordResult, Error> {
        let (timestamp, cusec) = current_preauth_time()?;
        let sequence_number = random_nonce()?;
        self.change_password_for_with_options(
            self.client.clone(),
            new_password,
            KpasswdRequestOptions::new(timestamp, cusec, sequence_number, sender_address),
        )
        .await
    }

    /// Change the given target principal's password using generated timestamp and
    /// sequence metadata.
    pub async fn change_password_for(
        &mut self,
        target: Principal,
        new_password: impl AsRef<[u8]>,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Result<crate::kadmin::ChangePasswordResult, Error> {
        let (timestamp, cusec) = current_preauth_time()?;
        let sequence_number = random_nonce()?;
        self.change_password_for_with_options(
            target,
            new_password,
            KpasswdRequestOptions::new(timestamp, cusec, sequence_number, sender_address),
        )
        .await
    }

    /// Change this client's password using explicit kpasswd request metadata.
    pub async fn change_password_with_options(
        &mut self,
        new_password: impl AsRef<[u8]>,
        options: KpasswdRequestOptions,
    ) -> Result<crate::kadmin::ChangePasswordResult, Error> {
        self.change_password_for_with_options(self.client.clone(), new_password, options)
            .await
    }

    /// Change the given target principal's password using explicit request metadata.
    pub async fn change_password_for_with_options(
        &mut self,
        target: Principal,
        new_password: impl AsRef<[u8]>,
        options: KpasswdRequestOptions,
    ) -> Result<crate::kadmin::ChangePasswordResult, Error> {
        let new_password = new_password.as_ref().to_vec();
        let client = self.client.clone();
        let service = Principal::new(
            target.realm.clone(),
            KRB_NT_PRINCIPAL,
            ["kadmin".to_owned(), "changepw".to_owned()],
        );
        let update_password_credential = target == self.client
            && matches!(self.credentials, Some(TokioClientCredentials::Password(_)));
        let ticket = match self.credentials.clone() {
            Some(TokioClientCredentials::Password(password)) => {
                self.transport
                    .login_as_service_with_password_config(
                        &self.config,
                        self.protocol,
                        client,
                        service,
                        &password,
                        self.as_req_options()?,
                    )
                    .await?
            }
            Some(TokioClientCredentials::Keytab(keytab)) => {
                self.transport
                    .login_as_service_with_keytab_config(
                        &self.config,
                        self.protocol,
                        client,
                        service,
                        &keytab,
                        self.as_req_options()?,
                    )
                    .await?
            }
            None => self.get_service_ticket(service).await?,
        };
        let change_data = if target == self.client {
            crate::kadmin::ChangePasswdData::new(&new_password)
        } else {
            crate::kadmin::ChangePasswdData::for_target(
                &new_password,
                target.name_type,
                target.components.iter().map(String::as_str),
                &target.realm,
            )?
        };
        let request = build_kpasswd_request(&ticket, &change_data, options)?;
        let reply = self
            .transport
            .exchange_kpasswd_request_with_config(
                &self.config,
                self.protocol,
                &target.realm,
                &request.request,
            )
            .await?;
        let verified = verify_kpasswd_ap_rep(&reply, &request)?;
        let result_key = verified
            .as_ref()
            .and_then(|metadata| metadata.subkey.as_ref())
            .unwrap_or(&request.reply_key);
        let result = reply.decrypt_result(result_key)?;
        result.ensure_success()?;

        if update_password_credential {
            self.credentials = Some(TokioClientCredentials::Password(Zeroizing::new(
                new_password,
            )));
        }

        Ok(result)
    }
}
