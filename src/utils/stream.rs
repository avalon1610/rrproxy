use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// A simple wrapper to reconstruct a stream from buffered data
pub struct ReconstructedStream {
    buffer: Vec<u8>,
    position: usize,
    stream: TcpStream,
}

impl ReconstructedStream {
    pub fn new(buffer: Vec<u8>, stream: TcpStream) -> Self {
        Self {
            buffer,
            position: 0,
            stream,
        }
    }
}

impl AsyncRead for ReconstructedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // First, serve data from our buffer
        if self.position < self.buffer.len() {
            let remaining_buffer = &self.buffer[self.position..];
            let to_copy = std::cmp::min(remaining_buffer.len(), buf.remaining());
            buf.put_slice(&remaining_buffer[..to_copy]);
            self.position += to_copy;
            return Poll::Ready(Ok(()));
        }

        // Then delegate to the underlying stream
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReconstructedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
