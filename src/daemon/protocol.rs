use std::io::{self, Read, Write};

/// Maximum text payload: 16 MB.
const MAX_TEXT_LEN: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanType {
    /// Full scan including ML.
    Full = 0x00,
    /// Fast scan (regex + unicode only, no ML).
    Fast = 0x01,
    /// Ping to check if daemon is alive.
    Ping = 0x02,
}

impl ScanType {
    fn from_byte(b: u8) -> io::Result<Self> {
        match b {
            0x00 => Ok(Self::Full),
            0x01 => Ok(Self::Fast),
            0x02 => Ok(Self::Ping),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown scan type",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScanRequest {
    pub scan_type: ScanType,
    pub threshold: f32,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanResponse {
    Clean = 0x00,
    Injection = 0x01,
    Secret = 0x02,
    Pong = 0x03,
}

impl ScanResponse {
    fn from_byte(b: u8) -> io::Result<Self> {
        match b {
            0x00 => Ok(Self::Clean),
            0x01 => Ok(Self::Injection),
            0x02 => Ok(Self::Secret),
            0x03 => Ok(Self::Pong),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown response",
            )),
        }
    }
}

/// Write a scan request: `[1B type][4B threshold][4B text_len][text...]`
///
/// # Errors
///
/// Returns an error if writing to the stream fails or text exceeds size limit.
pub fn write_request<W: Write>(w: &mut W, req: &ScanRequest) -> io::Result<()> {
    w.write_all(&[req.scan_type as u8])?;
    w.write_all(&req.threshold.to_le_bytes())?;
    let text_bytes = req.text.as_bytes();
    let len = u32::try_from(text_bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "text too large"))?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(text_bytes)?;
    w.flush()
}

/// Read a scan request from the wire.
///
/// # Errors
///
/// Returns an error if reading fails, the scan type is unknown, or text exceeds 16MB.
pub fn read_request<R: Read>(r: &mut R) -> io::Result<ScanRequest> {
    let mut header = [0u8; 9]; // 1 + 4 + 4
    r.read_exact(&mut header)?;

    let scan_type = ScanType::from_byte(header[0])?;
    let threshold = f32::from_le_bytes([header[1], header[2], header[3], header[4]]);
    let text_len = u32::from_le_bytes([header[5], header[6], header[7], header[8]]);

    if text_len > MAX_TEXT_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "text exceeds 16MB limit",
        ));
    }

    let mut text_bytes = vec![0u8; text_len as usize];
    r.read_exact(&mut text_bytes)?;

    let text =
        String::from_utf8(text_bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(ScanRequest {
        scan_type,
        threshold,
        text,
    })
}

/// Write a scan response: single byte.
///
/// # Errors
///
/// Returns an error if writing to the stream fails.
pub fn write_response<W: Write>(w: &mut W, resp: ScanResponse) -> io::Result<()> {
    w.write_all(&[resp as u8])?;
    w.flush()
}

/// Read a scan response from the wire.
///
/// # Errors
///
/// Returns an error if reading fails or the response byte is unknown.
pub fn read_response<R: Read>(r: &mut R) -> io::Result<ScanResponse> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf)?;
    ScanResponse::from_byte(buf[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_full_request() {
        let req = ScanRequest {
            scan_type: ScanType::Full,
            threshold: 0.75,
            text: "hello world".to_string(),
        };
        let mut buf = Vec::new();
        write_request(&mut buf, &req).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = read_request(&mut cursor).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn roundtrip_fast_request() {
        let req = ScanRequest {
            scan_type: ScanType::Fast,
            threshold: 0.0,
            text: "test".to_string(),
        };
        let mut buf = Vec::new();
        write_request(&mut buf, &req).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = read_request(&mut cursor).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn roundtrip_ping() {
        let req = ScanRequest {
            scan_type: ScanType::Ping,
            threshold: 0.0,
            text: String::new(),
        };
        let mut buf = Vec::new();
        write_request(&mut buf, &req).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = read_request(&mut cursor).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn roundtrip_responses() {
        for resp in [
            ScanResponse::Clean,
            ScanResponse::Injection,
            ScanResponse::Secret,
            ScanResponse::Pong,
        ] {
            let mut buf = Vec::new();
            write_response(&mut buf, resp).unwrap();
            let mut cursor = Cursor::new(buf);
            let decoded = read_response(&mut cursor).unwrap();
            assert_eq!(decoded, resp);
        }
    }

    #[test]
    fn rejects_oversized_text() {
        // Forge a header with text_len > MAX_TEXT_LEN
        let mut buf = vec![0x00]; // Full
        buf.extend_from_slice(&0.5_f32.to_le_bytes());
        buf.extend_from_slice(&(MAX_TEXT_LEN + 1).to_le_bytes());
        let mut cursor = Cursor::new(buf);
        assert!(read_request(&mut cursor).is_err());
    }

    #[test]
    fn rejects_unknown_scan_type() {
        let mut buf = vec![0xFF]; // unknown
        buf.extend_from_slice(&0.5_f32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        let mut cursor = Cursor::new(buf);
        assert!(read_request(&mut cursor).is_err());
    }

    #[test]
    fn rejects_unknown_response() {
        let mut cursor = Cursor::new(vec![0xFF]);
        assert!(read_response(&mut cursor).is_err());
    }

    #[test]
    fn roundtrip_utf8_text() {
        let req = ScanRequest {
            scan_type: ScanType::Full,
            threshold: 0.5,
            text: "hello \u{1F600} \u{00E9}".to_string(),
        };
        let mut buf = Vec::new();
        write_request(&mut buf, &req).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = read_request(&mut cursor).unwrap();
        assert_eq!(decoded, req);
    }
}
