//! All structure needed by RustHound.
//!
//! Example in rust:
//!
//! ```rust
//! # use rusthound::objects::user::User;
//! # use rusthound::objects::group::Group;
//! # use rusthound::objects::computer::Computer;
//! # use rusthound::objects::ou::Ou;
//! # use rusthound::objects::gpo::Gpo;
//! # use rusthound::objects::domain::Domain;
//! # use rusthound::objects::container::Container;
//! let user = User::new();
//! let group = Group::new();
//! let computer = Computer::new();
//! let ou = Ou::new();
//! let gpo = Gpo::new();
//! let domain = Domain::new();
//! let container = Container::new();
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