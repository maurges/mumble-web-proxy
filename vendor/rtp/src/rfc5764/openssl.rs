use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncWrite};
use std::io;
use tokio_openssl::SslStream;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, Tokio02AsyncReadCompatExt};

use openssl::ssl::{ConnectConfiguration, SslAcceptorBuilder};

use crate::rfc5764::{Dtls, DtlsBuilder, SrtpProtectionProfile};

type CompatSslStream<S> = Compat<SslStream<Compat<S>>>;

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Send + Unpin> DtlsBuilder<S> for ConnectConfiguration {
    type Instance = CompatSslStream<S>;

    async fn handshake(mut self, stream: S) -> Result<Self::Instance, io::Error>
    where
        S: 'async_trait,
    {
        let profiles_str: String = SrtpProtectionProfile::RECOMMENDED
            .iter()
            .map(|profile| profile.name.to_string())
            .collect::<Vec<_>>()
            .join(":");
        self.set_tlsext_use_srtp(&profiles_str).unwrap();
        match tokio_openssl::connect(self, "invalid", stream.compat()).await {
            Ok(stream) => Ok(stream.compat()),
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "handshake error")),
        }
    }
}

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Send + Unpin> DtlsBuilder<S> for SslAcceptorBuilder {
    type Instance = CompatSslStream<S>;

    async fn handshake(mut self, stream: S) -> Result<Self::Instance, io::Error>
    where
        S: 'async_trait,
    {
        let profiles_str: String = SrtpProtectionProfile::RECOMMENDED
            .iter()
            .map(|profile| profile.name.to_string())
            .collect::<Vec<_>>()
            .join(":");
        self.set_tlsext_use_srtp(&profiles_str).unwrap();
        match tokio_openssl::accept(&self.build(), stream.compat()).await {
            Ok(stream) => Ok(stream.compat()),
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "handshake error")),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Dtls<S> for Compat<SslStream<Compat<S>>> {
    fn is_server_side(&self) -> bool {
        self.get_ref().ssl().is_server()
    }

    fn export_key(&mut self, exporter_label: &str, length: usize) -> Vec<u8> {
        let mut vec = vec![0; length];
        self.get_mut()
            .ssl()
            .export_keying_material(&mut vec, exporter_label, None)
            .unwrap();
        vec
    }
}

#[cfg(test)]
mod test {
    use crate::rfc5764::test::DummyTransport;
    use crate::rfc5764::DtlsSrtp;

    use futures::FutureExt;
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode};
    use openssl::x509::X509;
    use std::task::{Context, Poll};

    #[test]
    fn connect_and_establish_matching_key_material() {
        let (client_sock, server_sock) = DummyTransport::new();

        let rsa = Rsa::generate(2048).unwrap();
        let key = PKey::from_rsa(rsa).unwrap();

        let mut cert_builder = X509::builder().unwrap();
        cert_builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert_builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert_builder.set_pubkey(&key).unwrap();
        cert_builder.sign(&key, MessageDigest::sha256()).unwrap();
        let cert = cert_builder.build();

        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::dtls()).unwrap();
        let mut connector = SslConnector::builder(SslMethod::dtls()).unwrap();
        acceptor.set_certificate(&cert).unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.set_verify(SslVerifyMode::NONE);
        connector.set_verify(SslVerifyMode::NONE);
        let handshake_server = DtlsSrtp::handshake(server_sock, acceptor);
        let handshake_client =
            DtlsSrtp::handshake(client_sock, connector.build().configure().unwrap());
        let mut future = futures::future::join(handshake_server, handshake_client).boxed();

        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        loop {
            if let Poll::Ready((server, client)) = future.as_mut().poll(&mut cx) {
                let server = server.unwrap();
                let client = client.unwrap();
                assert_eq!(
                    client.srtp_read_context.master_key,
                    server.srtp_write_context.master_key
                );
                assert_eq!(
                    client.srtp_read_context.master_salt,
                    server.srtp_write_context.master_salt
                );
                assert_eq!(
                    client.srtp_write_context.master_key,
                    server.srtp_read_context.master_key
                );
                assert_eq!(
                    client.srtp_write_context.master_salt,
                    server.srtp_read_context.master_salt
                );
                return;
            }
        }
    }
}
