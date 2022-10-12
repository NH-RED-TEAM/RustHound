//! Errors management
use ldap3::LdapError;
use std::error::Error as StdError;
use std::fmt;
//use std::num::ParseIntError;
use std::sync::Arc;

/// This is a shorthand for `rusthound`-based error results
pub type Result<T> = std::result::Result<T, Error>;
pub type Cause = Arc<dyn StdError + Send + Sync>;
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// RustHound error's type
pub struct Error {
    kind: Kind,
    cause: Option<Cause>,
    desc: Option<String>,
}

#[derive(Debug)]
pub enum Kind {
    /// Connection
    Connection(Connection),
    /// LdapError
    LdapError,
    /// Parse Error
    ParseError,
    /// Other
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Connection {
    Login,
    Host,
}

impl Error {
    /// Construct an error from scratch
    /// You can chain this method to `with`, as shown below.
    /// ```
    /// Error::new(Kind::Other).with()
    /// ```
    pub fn new(kind: Kind) -> Error {
        Error {
            kind,
            cause: None,
            desc: None,
        }
    }

    /// Specify a cause
    pub fn with<C: StdError + Send + Sync + 'static>(mut self, cause: C) -> Error {
        self.cause = Some(Arc::new(cause));
        self
    }

    pub fn desc<D: Into<String>>(mut self, desc: D) -> Error {
        self.desc = Some(desc.into());
        self
    }

    /// Get error kind
    pub fn kind(&self) -> &Kind {
        &self.kind
    }

    pub fn new_login() -> Error {
        Error::new(Kind::Connection(Connection::Login))
    }

    pub fn new_host() -> Error {
        Error::new(Kind::Connection(Connection::Host))
    }

    pub fn new_ldap_error(error: LdapError) -> Error {
        Error::new(Kind::LdapError).with(error)
    }

    /// Internally used for Display trait
    fn kind_description(&self) -> &str {
        match self.kind {
            Kind::Connection(Connection::Login) => "[!] LDAP Connection Failed, Invalid Credentials.\n",
            Kind::Connection(Connection::Host) => "[!] LDAP Connection Failed, No Route To Host.\n",
            Kind::LdapError => &"LDAP Error.\n",
            Kind::ParseError => &"Parsing Json Error.\n",
            Kind::Other => "[!] Other Error\n",
        }
    }

    /// Backtrace error source to find a cause matching given type
    pub fn find_source<E: StdError + 'static>(&self) -> Option<&E> {
        let mut source = self.source();
        while let Some(err) = source {
            if let Some(ref original) = err.downcast_ref() {
                return Some(original);
            }
            source = err.source();
        }
        // Not found
        None
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind_description())?;
        if let Some(ref desc) = self.desc {
            write!(f, ": {}", desc)?;
        }
        if let Some(ref cause) = self.cause {
            write!(f, ": {:?}", cause)?;
        }
        Ok(())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind_description())?;
        if let Some(ref desc) = self.desc {
            write!(f, ": {}", desc)?;
        }
        if let Some(ref cause) = self.cause {
            write!(f, ": {}", cause)?;
        }
        Ok(())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.cause
            .as_ref()
            .map(|cause| &**cause as &(dyn StdError + 'static))
    }
}

/// Converting from `LdapsearchError`
impl From<LdapError> for Error {
    fn from(err: LdapError) -> Error {
        Error::new(Kind::LdapError).with(err)
    }
}
