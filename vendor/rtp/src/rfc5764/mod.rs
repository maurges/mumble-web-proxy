// FIXME: the current SRTP implementation does not support the maximum_lifetime parameter

#[cfg(feature = "rfc5764-openssl")]
mod openssl;

use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncWrite};
use futures::ready;
use futures::{Sink, Stream};
use std::collections::VecDeque;
use std::io;
use std::io::Read;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::Context;
use std::task::Poll;

use crate::rfc3711::{
    AuthenticationAlgorithm, Context as SrtpContext, EncryptionAlgorithm, Srtcp, Srtp,
};
use crate::types::Ssrc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrtpProtectionProfile {
    pub name: &'static str,
    pub cipher: EncryptionAlgorithm,
    pub cipher_key_length: u8,
    pub cipher_salt_length: u8,
    pub maximum_lifetime: u32,
    pub auth_function: AuthenticationAlgorithm,
    pub auth_key_length: u8,
    pub auth_salt_length: u8,
}

impl SrtpProtectionProfile {
    pub const AES128_CM_HMAC_SHA1_80: SrtpProtectionProfile = SrtpProtectionProfile {
        name: "SRTP_AES128_CM_SHA1_80",
        cipher: EncryptionAlgorithm::AesCm,
        cipher_key_length: 128,
        cipher_salt_length: 112,
        maximum_lifetime: 2 ^ 31,
        auth_function: AuthenticationAlgorithm::HmacSha1,
        auth_key_length: 160,
        auth_salt_length: 80,
    };
    // AES128_CM_HMAC_SHA1_32 is not supported due to recommendation in rfc3711#5.2
    // NULL_HMAC_SHA1_80 is not supported because the NULL cipher isn't implemented
    // NULL_HMAC_SHA1_32 is not supported due to recommendation in rfc3711#5.2 (and lack of NULL)

    pub const RECOMMENDED: &'static [&'static SrtpProtectionProfile] =
        &[&SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80];
    pub const SUPPORTED: &'static [&'static SrtpProtectionProfile] =
        &[&SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80];
}

#[async_trait]
pub trait DtlsBuilder<S> {
    type Instance: Dtls<S>;

    async fn handshake(self, stream: S) -> Result<Self::Instance, io::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + 'async_trait;
}

pub trait Dtls<S>: AsyncRead + AsyncWrite + Unpin {
    fn is_server_side(&self) -> bool;
    fn export_key(&mut self, exporter_label: &str, length: usize) -> Vec<u8>;
}

pub struct DtlsSrtpMuxer<S> {
    inner: S,
    dtls_buf: VecDeque<Vec<u8>>,
    srtp_buf: VecDeque<Vec<u8>>,
}

impl<S: AsyncRead + AsyncWrite> DtlsSrtpMuxer<S> {
    fn new(inner: S) -> Self {
        DtlsSrtpMuxer {
            inner,
            dtls_buf: VecDeque::new(),
            srtp_buf: VecDeque::new(),
        }
    }
}

impl<S> DtlsSrtpMuxer<S> {
    fn into_parts(self) -> (DtlsSrtpMuxerPart<S>, DtlsSrtpMuxerPart<S>) {
        let muxer = Arc::new(Mutex::new(self));
        let dtls = DtlsSrtpMuxerPart {
            muxer: muxer.clone(),
            srtp: false,
        };
        let srtp = DtlsSrtpMuxerPart { muxer, srtp: true };
        (dtls, srtp)
    }
}

impl<S: AsyncRead + Unpin> DtlsSrtpMuxer<S> {
    fn read(
        &mut self,
        cx: &mut Context,
        want_srtp: bool,
        dst_buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        {
            let want_buf = if want_srtp {
                &mut self.srtp_buf
            } else {
                &mut self.dtls_buf
            };
            if let Some(buf) = want_buf.pop_front() {
                return Poll::Ready((&buf[..]).read(dst_buf));
            }
        }

        let mut buf = [0u8; 2048];
        let len = ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buf))?;
        if len == 0 {
            return Poll::Ready(Ok(0));
        }
        let mut buf = &buf[..len];
        // Demux SRTP and DTLS as per https://tools.ietf.org/html/rfc5764#section-5.1.2
        let is_srtp = buf[0] >= 128 && buf[0] <= 191;
        if is_srtp == want_srtp {
            Poll::Ready(buf.read(dst_buf))
        } else {
            if is_srtp {
                &mut self.srtp_buf
            } else {
                &mut self.dtls_buf
            }
            .push_back(buf.to_vec());
            // We have to make sure we're not waiting for, e.g., a srtp packet when
            // we just got a dtls packet and the remote is waiting on a reply to it.
            // So, to prevent this kind of deadlock, we abort the current read-path
            // by pretending that we're doing non-blocking io (even if we aren't)
            // to get back to where we can enter the other (in the example: the dtls)
            // read-path and process the packet we just read.
            Poll::Pending // FIXME this doesn't see sound, shouldn't we store the waker!?
        }
    }
}

pub struct DtlsSrtpMuxerPart<S> {
    muxer: Arc<Mutex<DtlsSrtpMuxer<S>>>,
    srtp: bool,
}

impl<S> AsyncRead for DtlsSrtpMuxerPart<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.muxer.lock().unwrap().read(cx, self.srtp, buf)
    }
}

impl<S> AsyncWrite for DtlsSrtpMuxerPart<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.muxer.lock().unwrap().inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.muxer.lock().unwrap().inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.muxer.lock().unwrap().inner).poll_close(cx)
    }
}

pub struct DtlsSrtp<S: AsyncRead + AsyncWrite, D: DtlsBuilder<DtlsSrtpMuxerPart<S>>> {
    stream: DtlsSrtpMuxerPart<S>,
    #[allow(dead_code)] // we'll need this once we implement re-keying
    dtls: D::Instance,
    srtp_read_context: SrtpContext<Srtp>,
    srtcp_read_context: SrtpContext<Srtcp>,
    srtp_write_context: SrtpContext<Srtp>,
    srtcp_write_context: SrtpContext<Srtcp>,
    sink_buf: Option<Vec<u8>>,
}

impl<S, D> DtlsSrtp<S, D>
where
    S: AsyncRead + AsyncWrite + Unpin,
    D: DtlsBuilder<DtlsSrtpMuxerPart<S>>,
{
    pub async fn handshake(stream: S, dtls_builder: D) -> Result<DtlsSrtp<S, D>, io::Error> {
        let (stream_dtls, stream_srtp) = DtlsSrtpMuxer::new(stream).into_parts();
        let dtls = dtls_builder.handshake(stream_dtls).await?;
        Ok(DtlsSrtp::new(stream_srtp, dtls))
    }

    fn new(stream: DtlsSrtpMuxerPart<S>, mut dtls: D::Instance) -> Self {
        const EXPORTER_LABEL: &str = "EXTRACTOR-dtls_srtp";
        const KEY_LEN: usize = 16;
        const SALT_LEN: usize = 14;
        const EXPORT_LEN: usize = (KEY_LEN + SALT_LEN) * 2;

        let key_material = dtls.export_key(EXPORTER_LABEL, EXPORT_LEN);
        let client_material = (
            &(&key_material[0..])[..KEY_LEN],
            &(&key_material[KEY_LEN * 2..])[..SALT_LEN],
        );
        let server_material = (
            &(&key_material[KEY_LEN..])[..KEY_LEN],
            &(&key_material[KEY_LEN * 2 + SALT_LEN..])[..SALT_LEN],
        );
        let (read_material, write_material) = if dtls.is_server_side() {
            (client_material, server_material)
        } else {
            (server_material, client_material)
        };
        let (read_key, read_salt) = read_material;
        let (write_key, write_salt) = write_material;
        DtlsSrtp {
            stream,
            dtls,
            srtp_read_context: SrtpContext::new(&read_key, &read_salt),
            srtcp_read_context: SrtpContext::new(&read_key, &read_salt),
            srtp_write_context: SrtpContext::new(&write_key, &write_salt),
            srtcp_write_context: SrtpContext::new(&write_key, &write_salt),
            sink_buf: None,
        }
    }

    pub fn add_incoming_ssrc(&mut self, ssrc: Ssrc) {
        self.srtp_read_context.add_ssrc(ssrc);
        self.srtcp_read_context.add_ssrc(ssrc);
    }

    pub fn add_incoming_unknown_ssrcs(&mut self, count: usize) {
        self.srtp_read_context.add_unknown_ssrcs(count);
        self.srtcp_read_context.add_unknown_ssrcs(count);
    }

    pub fn add_outgoing_ssrc(&mut self, ssrc: Ssrc) {
        self.srtp_write_context.add_ssrc(ssrc);
        self.srtcp_write_context.add_ssrc(ssrc);
    }

    pub fn add_outgoing_unknown_ssrcs(&mut self, count: usize) {
        self.srtp_write_context.add_unknown_ssrcs(count);
        self.srtcp_write_context.add_unknown_ssrcs(count);
    }

    fn process_incoming_srtp_packet(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        // Demux SRTP and SRTCP packets as per https://tools.ietf.org/html/rfc5761#section-4
        let payload_type = buf[1] & 0x7f;
        if 64 <= payload_type && payload_type <= 95 {
            self.srtcp_read_context.process_incoming(buf).ok()
        } else {
            self.srtp_read_context.process_incoming(buf).ok()
        }
    }

    fn process_outgoing_srtp_packet(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        // Demux SRTP and SRTCP packets as per https://tools.ietf.org/html/rfc5761#section-4
        let payload_type = buf[1] & 0x7f;
        if 64 <= payload_type && payload_type <= 95 {
            self.srtcp_write_context.process_outgoing(buf).ok()
        } else {
            self.srtp_write_context.process_outgoing(buf).ok()
        }
    }
}

impl<S, D> AsyncRead for DtlsSrtp<S, D>
where
    S: AsyncRead + AsyncWrite + Unpin,
    D: DtlsBuilder<DtlsSrtpMuxerPart<S>>,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let item = ready!(self.poll_next(cx)?);
        if let Some(item) = item {
            Poll::Ready((&item[..]).read(buf))
        } else {
            Poll::Ready(Ok(0))
        }
    }
}

impl<S, D> Stream for DtlsSrtp<S, D>
where
    S: AsyncRead + AsyncWrite + Unpin,
    D: DtlsBuilder<DtlsSrtpMuxerPart<S>>,
{
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        loop {
            // Check if we have an SRTP packet in the queue
            if self.stream.muxer.lock().unwrap().srtp_buf.is_empty() {
                // if we don't, then poll the dtls layer which will read from the
                // underlying packet stream and produce either dtls data or fill
                // the SRTP packet queue or fail due to WouldBlock
                /* FIXME polling dtls eventually errs with a read timeout, for some reason
                 *       it does indeed send repeated "Change Cipher Spec" and "Encrypted Handshake
                 *       Message" as if its expecting a response to those but none is sent by FF?
                match self.dtls.read(buf) {
                    Ok(len) => return Ok(len),
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                        // Either we're using non-blocking io and there's no more data
                        // available, or we received an SRTP packet which needs handling
                    }
                    err => return err,
                };
                */
            }

            // Read and handle the next SRTP packet from the queue
            let mut raw_buf = [0u8; 2048];
            let len = ready!(Pin::new(&mut self.stream).poll_read(cx, &mut raw_buf))?;
            if len == 0 {
                return Poll::Ready(None);
            }
            let raw_buf = &raw_buf[..len];
            return match self.process_incoming_srtp_packet(raw_buf) {
                Some(result) => Poll::Ready(Some(Ok(result))),
                None => {
                    // FIXME: check rfc for whether this should be dropped silently
                    continue; // packet failed to auth or decrypt, drop it and try the next one
                }
            };
        }
    }
}

impl<S, D> AsyncWrite for DtlsSrtp<S, D>
where
    S: AsyncRead + AsyncWrite + Unpin,
    D: DtlsBuilder<DtlsSrtpMuxerPart<S>>,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(buf) = self.process_outgoing_srtp_packet(buf) {
            Pin::new(&mut self.stream).poll_write(cx, &buf)
        } else {
            Poll::Ready(Ok(buf.len()))
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_close(cx)
    }
}

impl<S, D> Sink<&[u8]> for DtlsSrtp<S, D>
where
    S: AsyncRead + AsyncWrite + Unpin,
    D: DtlsBuilder<DtlsSrtpMuxerPart<S>>,
{
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let _ = Sink::poll_flush(self.as_mut(), cx)?;
        if self.sink_buf.is_none() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: &[u8]) -> io::Result<()> {
        self.sink_buf = self.process_outgoing_srtp_packet(item.as_ref());
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        if let Some(buf) = self.sink_buf.take() {
            match Pin::new(&mut self.stream).poll_write(cx, &buf) {
                Poll::Pending => {
                    self.sink_buf = Some(buf);
                    return Poll::Pending;
                }
                _ => {}
            }
        }
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_close(cx)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::rfc3711::test::{
        TEST_MASTER_KEY, TEST_MASTER_SALT, TEST_SRTCP_PACKET, TEST_SRTCP_SSRC, TEST_SRTP_PACKET,
        TEST_SRTP_SSRC,
    };

    use futures::{AsyncReadExt, AsyncWriteExt, FutureExt};

    macro_rules! read_now {
        ( $expr:expr, $buf:expr ) => {
            $expr
                .read($buf)
                .now_or_never()
                .expect("would block")
                .expect("reading")
        };
    }

    macro_rules! write_now {
        ( $expr:expr, $buf:expr ) => {
            $expr
                .write($buf)
                .now_or_never()
                .expect("would block")
                .expect("writing")
        };
    }

    struct DummyDtlsBuilder;
    struct DummyDtls<S> {
        connected: bool,
        stream: S,
    }

    const DUMMY_DTLS_NOOP: &[u8] = &[20, 42];
    const DUMMY_DTLS_HELLO: &[u8] = &[62, 42];
    const DUMMY_DTLS_CONNECTED: &[u8] = &[63, 42];

    impl DummyDtlsBuilder {
        fn new() -> Self {
            DummyDtlsBuilder {}
        }
    }
    #[async_trait]
    impl<S: AsyncRead + AsyncWrite + Unpin + Send> DtlsBuilder<S> for DummyDtlsBuilder {
        type Instance = DummyDtls<S>;

        async fn handshake(self, mut stream: S) -> Result<Self::Instance, io::Error>
        where
            S: 'async_trait,
        {
            let _ = stream.write(DUMMY_DTLS_HELLO).await;
            let mut dtls = DummyDtls {
                stream,
                connected: false,
            };
            loop {
                let _ = futures::poll!(dtls.read(&mut []));
                if dtls.connected {
                    break;
                } else {
                    futures::pending!();
                }
            }
            Ok(dtls)
        }
    }
    impl<S: AsyncRead + AsyncWrite + Unpin> Dtls<S> for DummyDtls<S> {
        fn is_server_side(&self) -> bool {
            true
        }

        fn export_key(&mut self, exporter_label: &str, length: usize) -> Vec<u8> {
            assert_eq!(exporter_label, "EXTRACTOR-dtls_srtp");
            let mut buf = Vec::new();
            buf.extend(TEST_MASTER_KEY);
            buf.extend(TEST_MASTER_KEY);
            let idx = buf.len() - 1;
            buf[idx] = 0;
            buf.extend(TEST_MASTER_SALT);
            buf.extend(TEST_MASTER_SALT);
            let idx = buf.len() - 1;
            buf[idx] = 0;
            assert_eq!(length, buf.len());
            buf
        }
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for DummyDtls<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            _dst: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            loop {
                let mut buf = [0u8; 2048];
                let len = ready!(Pin::new(&mut self.stream).poll_read(cx, &mut buf))?;
                assert_eq!(len, 2);
                assert_eq!(buf[1], 42);
                match &buf[..len] {
                    DUMMY_DTLS_NOOP => {}
                    DUMMY_DTLS_HELLO => {
                        let _ = Pin::new(&mut self.stream).poll_write(cx, DUMMY_DTLS_CONNECTED)?;
                    }
                    DUMMY_DTLS_CONNECTED => {
                        self.connected = true;
                    }
                    _ => panic!(),
                };
            }
        }
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for DummyDtls<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.stream).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(cx)
        }

        fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(cx)
        }
    }

    type PacketBufArc = Arc<Mutex<VecDeque<Vec<u8>>>>;
    pub(crate) struct DummyTransport {
        read_buf: PacketBufArc,
        write_buf: PacketBufArc,
    }

    impl DummyTransport {
        pub fn new() -> (Self, Self) {
            let read_buf = Arc::new(Mutex::new(VecDeque::new()));
            let write_buf = Arc::new(Mutex::new(VecDeque::new()));
            (
                DummyTransport {
                    read_buf: read_buf.clone(),
                    write_buf: write_buf.clone(),
                },
                DummyTransport {
                    read_buf: write_buf.clone(),
                    write_buf: read_buf.clone(),
                },
            )
        }

        pub fn read_packet(&mut self) -> Option<Vec<u8>> {
            self.read_buf.lock().unwrap().pop_front()
        }
    }

    impl AsyncRead for DummyTransport {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            match self.read_buf.lock().unwrap().pop_front() {
                None => Poll::Pending,
                Some(elem) => Poll::Ready(std::io::Read::read(&mut &elem[..], buf)),
            }
        }
    }

    impl AsyncWrite for DummyTransport {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.write_buf.lock().unwrap().push_back(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn new_dtls_srtp() -> (DummyTransport, DtlsSrtp<DummyTransport, DummyDtlsBuilder>) {
        let (mut stream, dummy_stream) = DummyTransport::new();
        write_now!(stream, DUMMY_DTLS_CONNECTED);
        let mut dtls_srtp = DtlsSrtp::handshake(dummy_stream, DummyDtlsBuilder::new())
            .now_or_never()
            .expect("DTLS-SRTP handshake did not complete")
            .expect("DTL-SRTP handshake failed");
        assert_eq!(&stream.read_packet().unwrap()[..], DUMMY_DTLS_HELLO);
        dtls_srtp.add_incoming_ssrc(TEST_SRTP_SSRC);
        dtls_srtp.add_incoming_ssrc(TEST_SRTCP_SSRC);
        dtls_srtp.add_outgoing_ssrc(TEST_SRTP_SSRC);
        dtls_srtp.add_outgoing_ssrc(TEST_SRTCP_SSRC);
        (stream, dtls_srtp)
    }

    #[test]
    fn polls_dtls_layer_for_keys() {
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let (mut stream, dummy_stream) = DummyTransport::new();
        let mut handshake = DtlsSrtp::handshake(dummy_stream, DummyDtlsBuilder::new()).boxed();
        match handshake.as_mut().poll(&mut cx) {
            Poll::Pending => {}
            _ => panic!(),
        };

        // too early, should be discarded
        write_now!(stream, TEST_SRTP_PACKET);

        match handshake.as_mut().poll(&mut cx) {
            Poll::Pending => {}
            _ => panic!(),
        };
        assert_eq!(&stream.read_packet().unwrap()[..], DUMMY_DTLS_HELLO);

        write_now!(stream, DUMMY_DTLS_HELLO);
        match handshake.as_mut().poll(&mut cx) {
            Poll::Pending => {}
            _ => panic!(),
        };
        assert_eq!(&stream.read_packet().unwrap()[..], DUMMY_DTLS_CONNECTED);

        write_now!(stream, DUMMY_DTLS_CONNECTED);
        match handshake.as_mut().poll(&mut cx) {
            Poll::Ready(_) => {}
            _ => panic!(),
        };
    }

    #[test]
    fn decryption_of_incoming_srtp_and_srtcp_works() {
        let mut buf = [0u8; 2048];
        let (mut stream, mut dtls_srtp) = new_dtls_srtp();

        write_now!(stream, TEST_SRTP_PACKET);
        write_now!(stream, TEST_SRTCP_PACKET);
        assert_eq!(read_now!(dtls_srtp, &mut buf), 182); // srtp
        assert_eq!(read_now!(dtls_srtp, &mut buf), 68); // srtcp
    }

    #[test]
    fn does_not_allow_replay_of_packets() {
        let mut buf = [0u8; 2048];
        let (mut stream, mut dtls_srtp) = new_dtls_srtp();

        write_now!(stream, TEST_SRTP_PACKET);
        write_now!(stream, TEST_SRTP_PACKET);
        write_now!(stream, TEST_SRTP_PACKET);
        assert_eq!(read_now!(dtls_srtp, &mut buf), 182);
        assert!(dtls_srtp.read(&mut buf).now_or_never().is_none(),);

        write_now!(stream, TEST_SRTCP_PACKET);
        write_now!(stream, TEST_SRTCP_PACKET);
        write_now!(stream, TEST_SRTCP_PACKET);
        assert_eq!(read_now!(dtls_srtp, &mut buf), 68);
        assert!(dtls_srtp.read(&mut buf).now_or_never().is_none(),);
    }
}
