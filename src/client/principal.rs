use super::{Error, KRB_NT_PRINCIPAL, KRB_NT_SRV_INST};

/// Kerberos principal identity used by client exchanges.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Principal {
    /// Principal realm.
    pub realm: String,
    /// Kerberos name type. Name type is advisory and is not used for matching.
    pub name_type: i32,
    /// Principal name components.
    pub components: Vec<String>,
}

impl Principal {
    /// Create a principal.
    pub fn new<I, S>(realm: impl Into<String>, name_type: i32, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            realm: realm.into(),
            name_type,
            components: components.into_iter().map(Into::into).collect(),
        }
    }

    /// Create a normal client principal.
    pub fn user(realm: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(realm, KRB_NT_PRINCIPAL, [name.into()])
    }

    /// Parse a single-component user principal in `user@REALM` form.
    ///
    /// Separator characters may be escaped with `\`, for example
    /// `user\@name@REALM` parses as user component `user@name`.
    pub fn parse_user(value: impl AsRef<str>) -> Result<Self, Error> {
        let value = value.as_ref();
        let (name, realm) = parse_name_and_realm(value)?;
        let components = parse_principal_components(value, name)?;
        if components.len() != 1 {
            return Err(invalid_principal_name(
                value,
                "user principal must contain exactly one name component",
            ));
        }
        Ok(Self::user(realm, components.into_iter().next().unwrap()))
    }

    /// Parse a host service principal in `service/host@REALM` form.
    ///
    /// This creates a name type 2 service principal with components
    /// `[service, host]`, matching the host-based service shape used by
    /// native GSSAPI.
    pub fn parse_service(value: impl AsRef<str>) -> Result<Self, Error> {
        let value = value.as_ref();
        let (name, realm) = parse_name_and_realm(value)?;
        let components = parse_principal_components(value, name)?;
        if components.len() != 2 {
            return Err(invalid_principal_name(
                value,
                "service principal must contain service and host components",
            ));
        }
        Ok(Self::new(realm, KRB_NT_SRV_INST, components))
    }

    /// Create a host-based service principal with an empty realm.
    ///
    /// High-level clients resolve the empty service realm from
    /// `[domain_realm]` and then from the client realm.
    pub fn host_based_service(
        service: impl AsRef<str>,
        host: impl AsRef<str>,
    ) -> Result<Self, Error> {
        host_based_service_principal(service.as_ref(), host.as_ref(), "")
    }

    /// Create a host-based service principal in a specific realm.
    pub fn host_based_service_in_realm(
        service: impl AsRef<str>,
        host: impl AsRef<str>,
        realm: impl AsRef<str>,
    ) -> Result<Self, Error> {
        let service = service.as_ref();
        let host = host.as_ref();
        let realm = realm.as_ref();
        if realm.is_empty() {
            return Err(invalid_principal_name(
                realm,
                "host-based service realm is empty",
            ));
        }
        host_based_service_principal(service, host, realm)
    }

    /// Create the TGT service principal for a realm.
    pub fn tgt_service(realm: impl Into<String>) -> Self {
        let realm = realm.into();
        Self::new(realm.clone(), KRB_NT_SRV_INST, ["krbtgt".to_owned(), realm])
    }

    /// Principal components joined by `/`.
    pub fn name(&self) -> String {
        self.components.join("/")
    }
}

fn host_based_service_principal(
    service: &str,
    host: &str,
    realm: &str,
) -> Result<Principal, Error> {
    if service.is_empty() {
        return Err(invalid_principal_name(
            service,
            "host-based service name is empty",
        ));
    }
    if host.is_empty() {
        return Err(invalid_principal_name(
            host,
            "host-based service host is empty",
        ));
    }
    Ok(Principal::new(
        realm,
        KRB_NT_SRV_INST,
        [service.to_owned(), host.to_owned()],
    ))
}

fn parse_name_and_realm(value: &str) -> Result<(&str, String), Error> {
    if value.is_empty() {
        return Err(invalid_principal_name(value, "principal name is empty"));
    }
    let separators = unescaped_separator_indices(value, '@');
    let [separator] = separators.as_slice() else {
        return Err(invalid_principal_name(
            value,
            if separators.is_empty() {
                "principal realm separator is missing"
            } else {
                "principal contains more than one unescaped realm separator"
            },
        ));
    };
    let (name, realm) = value.split_at(*separator);
    let realm = &realm['@'.len_utf8()..];
    if name.is_empty() {
        return Err(invalid_principal_name(
            value,
            "principal name component is empty",
        ));
    }
    let realm = unescape_principal_component(value, realm)?;
    if realm.is_empty() {
        return Err(invalid_principal_name(value, "principal realm is empty"));
    }
    Ok((name, realm))
}

fn parse_principal_components(value: &str, name: &str) -> Result<Vec<String>, Error> {
    let mut components = Vec::new();
    let mut start = 0usize;
    for separator in unescaped_separator_indices(name, '/') {
        components.push(unescape_principal_component(
            value,
            &name[start..separator],
        )?);
        start = separator + '/'.len_utf8();
    }
    components.push(unescape_principal_component(value, &name[start..])?);
    if components.iter().any(String::is_empty) {
        return Err(invalid_principal_name(
            value,
            "principal contains an empty name component",
        ));
    }
    Ok(components)
}

fn unescaped_separator_indices(value: &str, separator: char) -> Vec<usize> {
    let mut escaped = false;
    let mut positions = Vec::new();
    for (index, ch) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == separator {
            positions.push(index);
        }
    }
    positions
}

fn unescape_principal_component(value: &str, component: &str) -> Result<String, Error> {
    let mut escaped = false;
    let mut out = String::with_capacity(component.len());
    for ch in component.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            out.push(ch);
        }
    }
    if escaped {
        return Err(invalid_principal_name(
            value,
            "principal contains a trailing escape character",
        ));
    }
    Ok(out)
}

fn invalid_principal_name(value: &str, reason: &'static str) -> Error {
    Error::InvalidPrincipalName {
        value: value.to_owned(),
        reason,
    }
}
