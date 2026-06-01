//! TCPv6 - RFC 9293

#[derive(Clone, Copy, Debug)]
pub struct PseudoHeader {
    pub source_address: u128,
    pub destination_address: u128,
    pub ul_length: u32,
    pub next_header: u8,
}

impl PseudoHeader {
    pub const PACKED_SIZE: usize = 40;
    pub fn from_bytes(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < Self::PACKED_SIZE {
            return Err("");
        }
        Ok(Self {
            source_address: u128::from_be_bytes(raw[..16].try_into().unwrap()),
            destination_address: u128::from_be_bytes(raw[16..32].try_into().unwrap()),
            ul_length: u32::from_be_bytes(raw[32..36].try_into().unwrap()),
            next_header: raw[39],
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut out = Vec::<u8>::with_capacity(Self::PACKED_SIZE);
        out.extend_from_slice(&self.source_address.to_be_bytes());
        out.extend_from_slice(&self.destination_address.to_be_bytes());
        out.extend_from_slice(
            &(((self.ul_length as u64) << 32) | (self.next_header as u64)).to_be_bytes(),
        );
        Ok(out)
    }
}

pub mod datagram {
    //! TCPv6 segment
    pub fn make(
        tuple: &mut (super::PseudoHeader, super::super::Header, &[u8]),
    ) -> Result<(), &'static str> {
        Ok(())
    }

    pub fn check(
        tuple: &mut (super::PseudoHeader, super::super::Header, &[u8]),
    ) -> Result<bool, &'static str> {
        Ok(true)
    }
}
