use std::io::{self, Read, Write};

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// Maximum text payload: 16 MB.
const MAX_TEXT_LEN: u32 = 16 * 1024 * 1024;

/// Header size: 1 byte type + 4 bytes threshold + 4 bytes text length.
const HEADER_LEN: usize = 9;

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

// ─── Tokio codec (for async daemon server) ───────────────────────────────────

/// Codec for the daemon wire protocol.
///
/// Decodes `ScanRequest` from: `[1B type][4B threshold][4B text_len][text...]`
/// Encodes `ScanResponse` as a single byte.
pub struct DaemonCodec;

impl Decoder for DaemonCodec {
    type Item = ScanRequest;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<ScanRequest>> {
        if src.len() < HEADER_LEN {
            return Ok(None);
        }

        let scan_type = ScanType::from_byte(src[0])?;
        let threshold = f32::from_le_bytes([src[1], src[2], src[3], src[4]]);
        let text_len = u32::from_le_bytes([src[5], src[6], src[7], src[8]]);

        if text_len > MAX_TEXT_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "text exceeds 16MB limit",
            ));
        }

        let total = HEADER_LEN + text_len as usize;
        if src.len() < total {
            src.reserve(total - src.len());
            return Ok(None);
        }

        // Consume header
        src.advance(HEADER_LEN);

        // Consume text
        let text_bytes = src.split_to(text_len as usize);
        let text = String::from_utf8(text_bytes.to_vec())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(Some(ScanRequest {
            scan_type,
            threshold,
            text,
        }))
    }
}

impl Encoder<ScanResponse> for DaemonCodec {
    type Error = io::Error;

    fn encode(&mut self, item: ScanResponse, dst: &mut BytesMut) -> io::Result<()> {
        dst.put_u8(item as u8);
        Ok(())
    }
}

// ─── Sync helpers (for client) ───────────────────────────────────────────────

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

/// Read a scan response from the wire: single byte.
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

    // ─── Codec tests ─────────────────────────────────────────────────────────

    fn encode_request(req: &ScanRequest) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(req.scan_type as u8);
        buf.put_f32_le(req.threshold);
        let text = req.text.as_bytes();
        buf.put_u32_le(text.len() as u32);
        buf.put_slice(text);
        buf
    }

    #[test]
    fn codec_decode_full_request() {
        let req = ScanRequest {
            scan_type: ScanType::Full,
            threshold: 0.75,
            text: "hello world".to_string(),
        };
        let mut buf = encode_request(&req);
        let decoded = DaemonCodec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, req);
        assert!(buf.is_empty());
    }

    #[test]
    fn codec_decode_partial_header() {
        let mut buf = BytesMut::from(&[0x00, 0x01][..]);
        assert!(DaemonCodec.decode(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 2); // not consumed
    }

    #[test]
    fn codec_decode_partial_body() {
        let req = ScanRequest {
            scan_type: ScanType::Full,
            threshold: 0.5,
            text: "hello".to_string(),
        };
        let full = encode_request(&req);
        // Only provide header + partial text
        let mut buf = BytesMut::from(&full[..HEADER_LEN + 2]);
        assert!(DaemonCodec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn codec_encode_response() {
        let mut buf = BytesMut::new();
        DaemonCodec
            .encode(ScanResponse::Injection, &mut buf)
            .unwrap();
        assert_eq!(buf.as_ref(), &[0x01]);
    }

    #[test]
    fn codec_roundtrip_all_responses() {
        for resp in [
            ScanResponse::Clean,
            ScanResponse::Injection,
            ScanResponse::Secret,
            ScanResponse::Pong,
        ] {
            let mut buf = BytesMut::new();
            DaemonCodec.encode(resp, &mut buf).unwrap();
            assert_eq!(buf.len(), 1);
            assert_eq!(ScanResponse::from_byte(buf[0]).unwrap(), resp);
        }
    }

    #[test]
    fn codec_rejects_oversized_text() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x00);
        buf.put_f32_le(0.5);
        buf.put_u32_le(MAX_TEXT_LEN + 1);
        assert!(DaemonCodec.decode(&mut buf).is_err());
    }

    #[test]
    fn codec_rejects_unknown_scan_type() {
        let mut buf = BytesMut::new();
        buf.put_u8(0xFF);
        buf.put_f32_le(0.5);
        buf.put_u32_le(0);
        assert!(DaemonCodec.decode(&mut buf).is_err());
    }

    // ─── Sync client helpers tests ───────────────────────────────────────────

    #[test]
    fn sync_roundtrip_request_response() {
        let req = ScanRequest {
            scan_type: ScanType::Full,
            threshold: 0.75,
            text: "hello".to_string(),
        };
        let mut buf = Vec::new();
        write_request(&mut buf, &req).unwrap();

        // Verify response round-trip
        let mut resp_buf = Vec::new();
        resp_buf.push(ScanResponse::Injection as u8);
        let resp = read_response(&mut &resp_buf[..]).unwrap();
        assert_eq!(resp, ScanResponse::Injection);
    }

    #[test]
    fn sync_rejects_unknown_response() {
        let buf = [0xFF];
        assert!(read_response(&mut &buf[..]).is_err());
    }

    #[test]
    fn codec_decode_utf8_text() {
        let req = ScanRequest {
            scan_type: ScanType::Full,
            threshold: 0.5,
            text: "hello \u{1F600} \u{00E9}".to_string(),
        };
        let mut buf = encode_request(&req);
        let decoded = DaemonCodec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn codec_decode_ping() {
        let req = ScanRequest {
            scan_type: ScanType::Ping,
            threshold: 0.0,
            text: String::new(),
        };
        let mut buf = encode_request(&req);
        let decoded = DaemonCodec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, req);
    }
}
