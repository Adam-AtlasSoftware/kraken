//! Length-prefixed framing: 4-byte big-endian length, then that many bytes of UTF-8 JSON.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum accepted frame payload (16 MiB).
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Framing failure.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Underlying I/O failure (including EOF in the middle of a frame).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The declared or supplied length exceeds [`MAX_FRAME_LEN`].
    #[error("frame of {0} bytes exceeds the {MAX_FRAME_LEN} byte limit")]
    TooLarge(usize),
}

/// Writes one frame (header and payload in a single write).
pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    payload: &[u8],
) -> Result<(), FrameError> {
    if payload.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(payload.len()));
    }
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Reads one frame. `Ok(None)` is a clean EOF at a frame boundary. An oversize length is rejected
/// before any payload is read or allocated.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
    let mut hdr = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        let n = r.read(&mut hdr[got..]).await?;
        if n == 0 {
            if got == 0 {
                return Ok(None);
            }
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        got += n;
    }
    let len = u32::from_be_bytes(hdr) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrip() {
        let (mut a, mut b) = duplex(1024);
        write_frame(&mut a, b"{\"x\":1}").await.unwrap();
        write_frame(&mut a, b"").await.unwrap();
        drop(a);
        assert_eq!(read_frame(&mut b).await.unwrap().unwrap(), b"{\"x\":1}");
        assert_eq!(read_frame(&mut b).await.unwrap().unwrap(), b"");
        assert!(read_frame(&mut b).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn partial_reads_reassemble() {
        let (mut a, mut b) = duplex(64);
        let payload = vec![b'x'; 5000];
        let mut wire = (payload.len() as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(&payload);
        let writer = tokio::spawn(async move {
            for chunk in wire.chunks(3) {
                a.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        assert_eq!(read_frame(&mut b).await.unwrap().unwrap(), payload);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn oversize_rejected_without_reading_body() {
        let (mut a, mut b) = duplex(64);
        a.write_all(&((MAX_FRAME_LEN as u32) + 1).to_be_bytes())
            .await
            .unwrap();
        assert!(matches!(
            read_frame(&mut b).await,
            Err(FrameError::TooLarge(_))
        ));
        let big = vec![0u8; MAX_FRAME_LEN + 1];
        assert!(matches!(
            write_frame(&mut a, &big).await,
            Err(FrameError::TooLarge(_))
        ));
    }

    #[tokio::test]
    async fn max_size_accepted() {
        let (mut a, mut b) = duplex(1 << 20);
        let payload = vec![b'y'; MAX_FRAME_LEN];
        let w = tokio::spawn(async move { write_frame(&mut a, &payload).await });
        assert_eq!(
            read_frame(&mut b).await.unwrap().unwrap().len(),
            MAX_FRAME_LEN
        );
        w.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn eof_mid_frame_is_error() {
        let (mut a, mut b) = duplex(64);
        a.write_all(&[0, 0]).await.unwrap();
        drop(a);
        assert!(matches!(read_frame(&mut b).await, Err(FrameError::Io(_))));
        let (mut a, mut b) = duplex(64);
        a.write_all(&[0, 0, 0, 9, b'a']).await.unwrap();
        drop(a);
        assert!(matches!(read_frame(&mut b).await, Err(FrameError::Io(_))));
    }
}
