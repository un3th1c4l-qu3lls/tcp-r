//! TCPv's

//! RFC 1071 checksum.
pub fn checksum(words: &[u16]) -> u16 {
    let mut accumulator: u32 = 0;
    for word in words {
        accumulator += *word as u32; // word is a reference, ffs
    }
    while accumulator >> 16 != 0 {
        accumulator = (accumulator & 0xFFFF) + (accumulator >> 16);
    }
    !(accumulator as u16)
}

pub struct Checksum {
    pub accumulator: u32,
}

impl Checksum {
    pub fn new() -> Self {
        Self { accumulator: 0u32 }
    }

    pub fn update_from_words(&mut self, words: &[u16]) -> Result<(), &'static str> {
        for word in words {
            self.accumulator += *word as u32;
        }
        Ok(())
    }

    pub fn update_from_bytes(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        if bytes.len() % 2 != 0 {
            return Err("`bytes` needs to be word aligned.");
        }
        for i in 0..bytes.len() / 2 {
            let word = u16::from_be_bytes(bytes[2 * i..2 * (i + 1)].try_into().unwrap());
            self.accumulator += word as u32;
        }
        Ok(())
    }

    pub fn digest(&self) -> u16 {
        let mut accumulator: u32 = self.accumulator;
        while accumulator >> 16 != 0 {
            accumulator = (accumulator & 0xffffu32) + (accumulator >> 16);
        }
        !(accumulator as u16)
    }
}

pub mod v4;
pub mod v6;

pub const PROTOCOL: u8 = 0x06;

pub struct Header {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8, // 4-bits
    pub flags: u16,      // 9 bits (lower bits) are used.
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

impl Header {
    pub const PACKED_SIZE: usize = 20;

    // `Header.flags` allowed values.
    pub const FIN: u16 = 1; // Finish
    pub const SYN: u16 = 1 << 1; // Synchronize
    pub const RST: u16 = 1 << 2; // Reset
    pub const PSH: u16 = 1 << 3; // Push
    pub const ACK: u16 = 1 << 4; // Acknowledgment
    pub const URG: u16 = 1 << 5; // Urgent
    pub const ECE: u16 = 1 << 6; // ECN-Echo
    pub const CWR: u16 = 1 << 7; // Congestion Window Reduced
    pub const NS: u16 = 1 << 8; // Nonce Sum

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        //! Deserializes.
        if bytes.len() < Self::PACKED_SIZE {
            return Err("`tcp` header only partial, more data required.");
        }
        Ok(Self {
            source_port: u16::from_be_bytes(bytes[..2].try_into().unwrap()),
            destination_port: u16::from_be_bytes(bytes[2..4].try_into().unwrap()),
            sequence_number: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            acknowledgment_number: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
            data_offset: bytes[12] >> 4,
            flags: u16::from_be_bytes(bytes[12..14].try_into().unwrap()) & 0x1ff,
            window: u16::from_be_bytes(bytes[14..16].try_into().unwrap()),
            checksum: u16::from_be_bytes(bytes[16..18].try_into().unwrap()),
            urgent_pointer: u16::from_be_bytes(bytes[18..20].try_into().unwrap()),
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        //! Serializes.
        if self.data_offset > 0xf {
            return Err("`data_offset` expected 4 bit value.");
        } else if self.flags > 0x1ff {
            return Err("`flags` expected 9 bit value.");
        }
        let mut bytes = Vec::<u8>::with_capacity(Self::PACKED_SIZE);
        bytes.extend_from_slice(&self.source_port.to_be_bytes());
        bytes.extend_from_slice(&self.destination_port.to_be_bytes());
        bytes.extend_from_slice(&self.sequence_number.to_be_bytes());
        bytes.extend_from_slice(&self.acknowledgment_number.to_be_bytes());
        bytes.extend_from_slice(&((self.data_offset as u16) << 12 | self.flags).to_be_bytes());
        bytes.extend_from_slice(&self.window.to_be_bytes());
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.urgent_pointer.to_be_bytes());
        Ok(bytes)
    }
}

pub mod option {
    pub fn from_bytes(bytes: &[u8]) -> Result<(u8, &[u8]), &'static str> {
        if bytes.len() < 1 {
            return Err("`option` required at least 1 bytes.");
        }
        let kind = bytes[0];
        if matches!(kind, 0 | 1) {
            return Ok((kind, &[]));
        } else if bytes.len() < 2 {
            return Err("`option` required at least 2 bytes.");
        }
        let length = bytes[1];
        if bytes.len() < length as usize {
            return Err("`option` only partial, more data required.");
        }
        Ok((kind, &bytes[2..length as usize]))
    }

    pub fn to_bytes(tuple: (u8, &[u8])) -> Result<Vec<u8>, &'static str> {
        if tuple.1.len() > 0xfd {
            return Err("`option` data too big.");
        }
        let mut bytes = Vec::<u8>::with_capacity(2 + tuple.1.len());
        bytes.push(tuple.0);
        if !matches!(tuple.0, 0 | 1) {
            bytes.push(2 + tuple.1.len() as u8);
            bytes.extend_from_slice(tuple.1);
        }
        Ok(bytes)
    }

    pub fn make(option: (u8, &[u8])) -> Result<(), &'static str> {
        if option.1.len() > 0xfe {
            return Err("`option` too big.");
        } else if matches!(option.0, self::eol::KIND | self::nop::KIND) && option.1.len() != 0 {
            return Err("`eol` / `nop` expect no data.");
        }
        Ok(())
    }

    pub fn check(option: (u8, &[u8])) -> bool {
        !(option.1.len() > 0xfe || (matches!(option.0, self::eol::KIND | self::nop::KIND) && option.1.len() != 0))
    }

    pub mod eol {
        //! End of Option List
        pub const KIND: u8 = 0;
        pub fn from_option(tuple: (u8, &[u8])) -> Result<(), &'static str> {
            if tuple.0 != self::KIND {
                return Err("`eol` kind mismatch.");
            } else if tuple.1.len() != 0 {
                return Err("`eol` expected no data.");
            }
            Ok(())
        }

        pub fn to_option() -> Result<(u8, &'static [u8]), &'static str> {
            Ok((self::KIND, &[]))
        }
    }

    pub mod nop {
        //! No Operation
        pub const KIND: u8 = 1;
        pub fn from_option(tuple: (u8, &[u8])) -> Result<(), &'static str> {
            if tuple.0 != self::KIND {
                return Err("`nop` kind mismatch.");
            } else if tuple.1.len() != 0 {
                return Err("`nop` expected no data.");
            }
            Ok(())
        }

        pub fn to_option() -> Result<(u8, &'static [u8]), &'static str> {
            Ok((self::KIND, &[]))
        }
    }

    pub mod mss {
        //! Maximum Segment Size
        pub const KIND: u8 = 2;
        pub fn from_option(tuple: (u8, &[u8])) -> Result<u32, &'static str> {
            if tuple.0 != self::KIND {
                return Err("`mss` kind mismatch.");
            } else if tuple.1.len() != 4 {
                return Err("`mss` expected exactly 4 bytes.");
            }
            Ok(u32::from_be_bytes(tuple.1[..4].try_into().unwrap()))
        }

        pub fn to_option(mss: u32) -> Result<(u8, Vec<u8>), &'static str> {
            Ok((self::KIND, mss.to_be_bytes().to_vec()))
        }
    }
}

pub mod segment {
    pub fn from_bytes(
        bytes: &[u8],
    ) -> Result<(super::Header, Vec<(u8, &[u8])>, &[u8]), &'static str> {
        let header = super::Header::from_bytes(bytes)?;
        if bytes.len() < (header.data_offset * 4) as usize {
            return Err("`segment` only partial, more data required.");
        }
        let mut buffer = &bytes[super::Header::PACKED_SIZE..(header.data_offset * 4) as usize];
        let mut options = Vec::<(u8, &[u8])>::new();
        while !buffer.is_empty() {
            let option = super::option::from_bytes(buffer)?;
            let olen = 1 + if !matches!(option.0, 0 | 1) { 1 } else { 0 } + option.1.len();
            options.push(option);
            buffer = &buffer[olen..];
            if buffer.is_empty() {
                if option.0 != super::option::eol::KIND {
                    return Err("`option`s not terminated.");
                }
                break;
            }
        }
        let data_offset = header.data_offset as usize;
        Ok((header, options, &bytes[data_offset * 4..]))
    }

    pub fn to_bytes(
        tuple: (super::Header, Vec<(u8, &[u8])>, &[u8]),
    ) -> Result<Vec<u8>, &'static str> {
        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&tuple.0.to_bytes()?);
        for option in tuple.1 {
            bytes.extend_from_slice(&super::option::to_bytes(option)?);
        }
        bytes.extend_from_slice(tuple.2);
        Ok(bytes)
    }
}

/*
pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
*/
