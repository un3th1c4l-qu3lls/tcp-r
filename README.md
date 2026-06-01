# TCP

A low‑level, `no_std` TCP library for Rust (RFC 9293).

## Features
- Parse/serialize TCP headers and options
- IPv4 and IPv6 pseudo‑headers with segment `make`/`check`
- Incremental checksum (RFC 1071)
- Supported options: EOL, NOP, MSS, Window Scale, SACK, Timestamps, User Timeout, TCP‑AO, Fast Open

## Example
```rust
use tcp::{Header, v4::PseudoHeader, v4::segment::make};

let mut header = Header { /* ... */ };
let mut options = vec![ /* ... */ ];
make(&mut (pseudo, header, options, payload))?;```
