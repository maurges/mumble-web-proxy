#[cfg(feature = "openssl")]
extern crate openssl;
#[cfg(feature = "tokio")]
extern crate tokio;

pub use crate::error::{Error, ErrorKind};

pub mod io;
pub mod rfc3550;
pub mod rfc3711;
pub mod rfc4585;
pub mod rfc5761;
pub mod rfc5764;
pub mod traits;

mod error;

pub type Result<T> = ::std::result::Result<T, Error>;

pub mod types {
    pub type U2 = u8;
    pub type U4 = u8;
    pub type U5 = u8;
    pub type U6 = u8;
    pub type U7 = u8;
    pub type U13 = u16;
    pub type U24 = u32;
    pub type U48 = u64;
    pub type RtpTimestamp = u32;
    pub type NtpTimestamp = u64;
    pub type NtpMiddleTimetamp = u32;
    pub type Ssrc = u32;
    pub type Csrc = u32;
    pub type SsrcOrCsrc = u32;
}

pub mod constants {
    pub const RTP_VERSION: u8 = 2;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
