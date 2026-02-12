//! Minimal BER/DER encoder + just-enough parser shared by LDAP and SNMP.
//!
//! We only need definite-length TLVs, INTEGER, OCTET STRING, NULL, OID,
//! SEQUENCE and a couple of context/application tags — not a general ASN.1
//! library.

/// Encode a definite-length field: tag + length + content.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let mut len_bytes = Vec::new();
        let mut n = len;
        while n > 0 {
            len_bytes.insert(0, (n & 0xff) as u8);
            n >>= 8;
        }
        out.push(0x80 | len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
    }
    out.extend_from_slice(content);
    out
}

/// INTEGER (0x02), minimal two's-complement-free encoding for small non-negatives.
pub fn integer(v: i64) -> Vec<u8> {
    if v == 0 {
        return tlv(0x02, &[0]);
    }
    let mut bytes = Vec::new();
    let mut n = v as u64;
    while n > 0 {
        bytes.insert(0, (n & 0xff) as u8);
        n >>= 8;
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0); // keep it positive
    }
    tlv(0x02, &bytes)
}

/// OCTET STRING (0x04).
pub fn octet_string(s: &[u8]) -> Vec<u8> {
    tlv(0x04, s)
}

/// NULL (0x05).
pub fn null() -> Vec<u8> {
    tlv(0x05, &[])
}

/// SEQUENCE (0x30).
pub fn sequence(content: &[u8]) -> Vec<u8> {
    tlv(0x30, content)
}

/// Encode an OID from its arc numbers (e.g. `[1,3,6,1,2,1,1,1,0]`).
pub fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut body = Vec::new();
    if arcs.len() >= 2 {
        body.push((arcs[0] * 40 + arcs[1]) as u8);
        for &arc in &arcs[2..] {
            let mut stack = Vec::new();
            let mut v = arc;
            stack.push((v & 0x7f) as u8);
            v >>= 7;
            while v > 0 {
                stack.push(((v & 0x7f) as u8) | 0x80);
                v >>= 7;
            }
            stack.reverse();
            body.extend_from_slice(&stack);
        }
    }
    tlv(0x06, &body)
}

/// A parsed TLV view.
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    /// Offset just past this TLV in the parent buffer.
    pub next: usize,
}

/// Parse one TLV at `pos`. Returns `None` on truncation.
pub fn parse(buf: &[u8], pos: usize) -> Option<Tlv<'_>> {
    let tag = *buf.get(pos)?;
    let len_byte = *buf.get(pos + 1)?;
    let (len, header) = if len_byte & 0x80 == 0 {
        (len_byte as usize, 2)
    } else {
        let n = (len_byte & 0x7f) as usize;
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *buf.get(pos + 2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let start = pos + header;
    let end = start + len;
    if end > buf.len() {
        return None;
    }
    Some(Tlv {
        tag,
        content: &buf[start..end],
        next: end,
    })
}
