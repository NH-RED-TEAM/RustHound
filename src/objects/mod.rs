//! All structure needed by RustHound.
//!
//! Example in rust:
//!
//! ```rust
//! let user = User::new();
//! let group = Groupr::new();
//! let computer = Computerr::new();
//! let ou = Our::new();
//! let gpo = Gpor::new();
//! let domain = Domainr::new();
//! let container = Containerr::new();
//! ```
//! 
pub mod user;
pub mod group;
pub mod computer;
pub mod ou;
pub mod gpo;
pub mod domain;
pub mod container;
pub mod fsp;
pub mod trust;
pub mod common;
pub mod ntauthstore;
pub mod aiaca;
pub mod rootca;
pub mod enterpriseca;
pub mod certtemplate;