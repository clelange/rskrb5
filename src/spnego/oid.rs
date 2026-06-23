use super::Error;

/// GSS-API object identifier.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ObjectIdentifier(Vec<u32>);

impl ObjectIdentifier {
    /// Kerberos 5 mechanism OID: `1.2.840.113554.1.2.2`.
    pub fn krb5() -> Self {
        Self(vec![1, 2, 840, 113_554, 1, 2, 2])
    }

    /// Microsoft legacy Kerberos mechanism OID: `1.2.840.48018.1.2.2`.
    pub fn ms_legacy_krb5() -> Self {
        Self(vec![1, 2, 840, 48_018, 1, 2, 2])
    }

    /// SPNEGO mechanism OID: `1.3.6.1.5.5.2`.
    pub fn spnego() -> Self {
        Self(vec![1, 3, 6, 1, 5, 5, 2])
    }

    /// Construct an object identifier from arcs.
    pub fn from_arcs(arcs: Vec<u32>) -> Result<Self, Error> {
        validate_arcs(&arcs)?;
        Ok(Self(arcs))
    }

    /// OID arcs.
    pub fn arcs(&self) -> &[u32] {
        &self.0
    }

    /// Whether this OID is one of the Kerberos mechanism OIDs accepted by
    /// gokrb5's SPNEGO verifier.
    pub fn is_kerberos_mechanism(&self) -> bool {
        self == &Self::krb5() || self == &Self::ms_legacy_krb5()
    }
}

pub(super) fn validate_arcs(arcs: &[u32]) -> Result<(), Error> {
    if arcs.len() < 2 {
        return Err(Error::InvalidOid);
    }
    if arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40) {
        return Err(Error::InvalidOid);
    }
    Ok(())
}
