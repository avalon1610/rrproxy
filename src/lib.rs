pub mod proxy;
pub mod common;
pub mod logging;
pub mod utils;
pub mod cert_gen;

// Re-export for backward compatibility
pub mod local_proxy {
    pub use crate::proxy::local::*;
}

pub mod remote_proxy {
    pub use crate::proxy::remote::*;
}
