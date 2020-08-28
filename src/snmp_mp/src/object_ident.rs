use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    str::FromStr,
};
use yasna::models::ObjectIdentifier;

/// Represents an object identifier.
///
/// For SNMP the expectation is that there are at most 128 sub-identifiers in a value, and each
/// sub-identifier has a maximum value of `4_294_967_295`. These limits are not enforced by
/// `ObjectIdent`.
///
/// # Examples
///
/// ```
/// use snmp_mp::ObjectIdent;
///
/// let sys_descr_oid = [1, 3, 6, 1, 2, 1, 1, 1];
/// let sys_descr = ObjectIdent::from_slice(&sys_descr_oid);
/// assert_eq!(sys_descr.components(), &sys_descr_oid);
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ObjectIdent(pub(crate) ObjectIdentifier);

impl ObjectIdent {
    /// Constructs a new `ObjectIdent` from a `Vec<u64>`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ObjectIdent;
    /// let sys_descr_oid = vec![1, 3, 6, 1, 2, 1, 1, 1];
    /// let sys_descr = ObjectIdent::new(sys_descr_oid.clone());
    /// assert_eq!(sys_descr.components(), &sys_descr_oid[..]);
    pub fn new(components: Vec<u64>) -> Self {
        Self(ObjectIdentifier::new(components))
    }

    /// Constructs a new `ObjectIdent` from  a slice.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ObjectIdent;
    /// let sys_descr_oid = [1, 3, 6, 1, 2, 1, 1, 1];
    /// let sys_descr = ObjectIdent::from_slice(&sys_descr_oid);
    /// assert_eq!(sys_descr.components(), &sys_descr_oid);
    /// ```
    pub fn from_slice(components: &[u64]) -> Self {
        Self(ObjectIdentifier::from_slice(components))
    }

    /// Returns the components of this `ObjectIdent`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ObjectIdent;
    /// let sys_descr_oid = [1, 3, 6, 1, 2, 1, 1, 1];
    /// let sys_descr = ObjectIdent::from_slice(&sys_descr_oid);
    /// assert_eq!(sys_descr.components(), &sys_descr_oid);
    /// ```
    pub fn components(&self) -> &[u64] {
        self.0.components()
    }
}

impl Display for ObjectIdent {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// An error indicating failure to parse an Object identifier.
pub struct ParseOidError;

impl Error for ParseOidError {}

impl Display for ParseOidError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        "failed to parse OID".fmt(formatter)
    }
}

impl FromStr for ObjectIdent {
    type Err = ParseOidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // The BER parsing library panics when trying to write an OID with only one component.
        let result = ObjectIdentifier::from_str(s);
        match result {
            Ok(oid) => {
                if oid.components().len() < 2 {
                    Err(ParseOidError)
                } else {
                    Ok(Self(oid))
                }
            }
            Err(_) => Err(ParseOidError),
        }
    }
}

impl From<Vec<u64>> for ObjectIdent {
    fn from(components: Vec<u64>) -> Self {
        Self::new(components)
    }
}
