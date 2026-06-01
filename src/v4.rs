//! TCPv4 - RFC 9293

#[derive(Clone, Copy, Debug)]
pub struct PseudoHeader {
    pub source_address: u32,
    pub destination_address: u32,
    pub protocol: u8,
    pub length: u16,
}

impl PseudoHeader {
    pub const PACKED_SIZE: usize = 12;
    pub fn from_bytes(raw: &[u8]) -> Result<PseudoHeader, &'static str> {
        //! Deserializes.
        if raw.len() < Self::PACKED_SIZE {
            return Err("UDP `PseudoHeader` expected at least 12 bytes (partial).");
        }
        Ok(Self {
            source_address: u32::from_be_bytes(raw[..4].try_into().unwrap()),
            destination_address: u32::from_be_bytes(raw[4..8].try_into().unwrap()),
            protocol: raw[9],
            length: u16::from_be_bytes(raw[10..12].try_into().unwrap()),
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        //! Serializes.
        let mut out = Vec::<u8>::with_capacity(Self::PACKED_SIZE);
        out.extend_from_slice(&self.source_address.to_be_bytes());
        out.extend_from_slice(&self.destination_address.to_be_bytes());
        out.extend_from_slice(&(self.protocol as u16).to_be_bytes());
        out.extend_from_slice(&(self.length).to_be_bytes());
        Ok(out)
    }
}

pub mod segment {
    //! TCPv4 segment
    pub fn make(
        tuple: &mut (super::PseudoHeader, super::super::Header, Vec<(u8, &[u8])>, &[u8]),
    ) -> Result<(), &'static str> {
        //! Construct a valid TCP segment from its components.
        // Sanity checks.
        if tuple.2.iter().any(|option| option.0 == super::super::option::eol::KIND) {
            return Err("`eol` should not be supplied by user.");
        } else if tuple.2.iter().any(|option| !super::super::option::check(*option)) {
            return Err("`option` encounter invalid.")
        } else if tuple.2.len() > 40 {
            return Err("`segment` too many options provided.")
        }
        let mut data_offset: usize = tuple.2.iter().map(|option| 1 + if !matches!(option.0, 0 | 1) {1} else {0} + option.1.len()).sum::<usize>();
        
        // Align 4 byte boundary.
        let pad: [(u8, &[u8]); 4] = [(1,&[]), (1, &[]), (1, &[]), (0, &[])];
        tuple.2.extend_from_slice(&pad[(data_offset % 4) as usize..]);
        data_offset += 4 - data_offset % 4;
        if data_offset > 40 {
            return Err("`option`s cannot fit inside a tcp segment header.");
        } else if tuple.3.len() > 0xffff - (20 + data_offset) {
            return Err("`segment`'s payload does not fit.")
        }

        // Set correct fields.
        tuple.0.length = (20 + data_offset + tuple.3.len()) as u16;
        tuple.1.data_offset = (data_offset >> 2) as u8 + 5;
        tuple.1.checksum = 0;
        
        // Checksum computation.
        let mut cs = super::super::Checksum::new();
        cs.update_from_bytes(&tuple.0.to_bytes()?)?;
        cs.update_from_bytes(&tuple.1.to_bytes()?)?;
        let mut buffer = Vec::<u8>::new();
        for option in &tuple.2 {
            buffer.extend_from_slice(&super::super::option::to_bytes(*option)?);
            cs.update_from_bytes(&buffer[..buffer.len() & !1])?;
            buffer[0] = buffer[buffer.len() - 1]; // always do this, so we save the last byte
            buffer.truncate(buffer.len() - (buffer.len() & !1));
        }
        cs.update_from_bytes(&tuple.3[..tuple.3.len() & !1])?;
        if tuple.3.len() & 0x1 == 1 {
            cs.update_from_bytes(&[tuple.3[tuple.3.len() - 1], 0])?;
        }
        tuple.1.checksum = cs.digest();

        Ok(())
    }

    pub fn check(
        tuple: &mut (super::PseudoHeader, super::super::Header, Vec<(u8, &[u8])>, &[u8]),
    ) -> bool {
        //! Verifies the integrity of a TCP segment.
        // Check protocol, 1st options check, lengths
        if tuple.0.protocol != super::super::PROTOCOL || tuple.2.len() > 40 || tuple.2.iter().any(|option| !super::super::option::check(*option)) || tuple.0.length < (tuple.1.data_offset as u16) * 4 || (tuple.0.length - (tuple.1.data_offset as u16) * 4) as usize != tuple.3.len() {
            return false;
        }
        
        // Check data_offset
        let data_offset: usize = 20 + tuple.2.iter().map(|option| 1 + if !matches!(option.0, 0 | 1) {1} else {0} + option.1.len()).sum::<usize>();
        if data_offset > 0x3c || data_offset != (tuple.1.data_offset as usize) << 2 {
            return false;
        }
        let checksum = tuple.1.checksum;

        // Checksum computation.
        let mut cs = super::super::Checksum::new();
        cs.update_from_bytes(&tuple.0.to_bytes().unwrap()).unwrap();
        cs.update_from_bytes(&tuple.1.to_bytes().unwrap()).unwrap();
        let mut buffer = Vec::<u8>::new();
        for option in &tuple.2 {
            buffer.extend_from_slice(&super::super::option::to_bytes(*option).unwrap());
            cs.update_from_bytes(&buffer[..buffer.len() & !1]).unwrap();
            buffer[0] = buffer[buffer.len() - 1]; // always do this, so we save the last byte
            buffer.truncate(buffer.len() - (buffer.len() & !1));
        }
        cs.update_from_bytes(&tuple.3[..tuple.3.len() & !1]).unwrap();
        if tuple.3.len() & 0x1 == 1 {
            cs.update_from_bytes(&[tuple.3[tuple.3.len() - 1], 0]).unwrap();
        }
        tuple.1.checksum = checksum;
        tuple.1.checksum == cs.digest()
    }
}


/*

the rule for options should be => when the user make() he cannot supply and eol (because we want it to be valid, so we need to ensure)
the packet ends on word (or dword for ip) boundaries


make() -> Result<(), &'static str> (make entry parameter mutable reference)
check() -> bool (error indicates false...)
*/