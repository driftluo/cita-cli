#[cfg(all(feature = "rustls", feature = "openssl"))]
compile_error!("features `rustls` and `openssl` are mutually exclusive");

/// Basic client api, for Low-level interface
pub mod basic;
/// System contract client api, call system contract more easy
pub mod system_contract;

mod transaction_option;

pub use self::transaction_option::TransactionOptions;

use hyper::Uri;
use std::str;

/// Remove hexadecimal prefix "0x" or "0X".
/// Example:
/// ```rust
/// extern crate cita_tool;
///
/// use cita_tool::remove_0x;
///
/// let a = "0x0b";
/// let b = remove_0x(a);
/// let c = "0X0b";
/// let d = remove_0x(c);
/// assert_eq!("0b", b);
/// assert_eq!("0b", d);
/// println!("a = {}, b = {}, c = {}, d= {}", a, b, c, d);
/// ```
#[inline]
pub fn remove_0x(hex: &str) -> &str {
    if hex.len() >= 2 {
        let tmp = hex.as_bytes();
        if tmp[..2] == b"0x"[..] || tmp[..2] == b"0X"[..] {
            return str::from_utf8(&tmp[2..]).unwrap();
        }
    }
    hex
}

/// Verify the validity of the url address
#[inline]
pub fn parse_url(url: &str) -> Result<Uri, String> {
    url.parse().map_err(|_| "Invalid address".to_string())
}
