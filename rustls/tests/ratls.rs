//! Tests for the Privasys RA-TLS fork features: the `0xFFBB` challenge
//! extension (ClientHello and CertificateRequest legs) and the session
//! channel binder derived from the handshake key schedule.

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use super::*;

mod common;

use std::sync::Mutex;

use common::{
    Arc, KeyType, client_config_builder_with_versions, do_handshake, get_client_root_store,
    make_client_config_with_versions, make_pair_for_arc_configs, make_server_config,
    make_server_config_with_mandatory_client_auth, server_config_builder,
};
use rustls::SignatureScheme;
use rustls::client::ResolvesClientCert;
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, RaTlsBindCertificate, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// Records the channel binder handed to the server's bind hook, without
/// re-minting the certificate.
#[derive(Debug)]
struct CaptureBinder(Arc<Mutex<Option<[u8; 32]>>>);

impl RaTlsBindCertificate for CaptureBinder {
    fn bind_certificate(&self, binder: &[u8; 32]) -> Option<Arc<CertifiedKey>> {
        *self.0.lock().unwrap() = Some(*binder);
        None // keep the resolved cert; we only observe the binder here
    }
}

/// The challenge a server cert resolver saw: `None` = not invoked yet,
/// `Some(None)` = invoked without a challenge.
type SeenChallenge = Arc<Mutex<Option<Option<Vec<u8>>>>>;

/// The (challenge, channel binder) pair a client cert resolver was offered.
type SeenClientParams = Arc<Mutex<Option<(Option<Vec<u8>>, Option<Vec<u8>>)>>>;

/// Server cert resolver that records the RA-TLS challenge surfaced from the
/// ClientHello.
#[derive(Debug)]
struct CaptureClientHelloChallenge {
    key: Arc<CertifiedKey>,
    seen: SeenChallenge,
}

impl ResolvesServerCert for CaptureClientHelloChallenge {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        *self.seen.lock().unwrap() = Some(
            client_hello
                .ratls_challenge()
                .map(<[u8]>::to_vec),
        );
        Some(self.key.clone())
    }
}

/// Client cert resolver that records the RA-TLS challenge and channel binder
/// it is offered.
#[derive(Debug)]
struct CaptureClientResolver {
    key: Arc<CertifiedKey>,
    seen: SeenClientParams,
}

impl ResolvesClientCert for CaptureClientResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
        ratls_challenge: Option<&[u8]>,
        ratls_channel_binder: Option<&[u8]>,
    ) -> Option<Arc<CertifiedKey>> {
        *self.seen.lock().unwrap() = Some((
            ratls_challenge.map(<[u8]>::to_vec),
            ratls_channel_binder.map(<[u8]>::to_vec),
        ));
        Some(self.key.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

fn client_certified_key(kt: KeyType, provider: &CryptoProvider) -> Arc<CertifiedKey> {
    let private_key = provider
        .key_provider
        .load_private_key(kt.get_client_key())
        .unwrap();
    Arc::new(CertifiedKey::new(kt.get_client_chain(), private_key))
}

/// RA-TLS channel binding: the 32-byte binder the server derives at the emit
/// seam must equal the binder the client derives and exposes via
/// `ratls_channel_binder()`. This is the runtime proof that both sides compute
/// the identical value from the shared key schedule, so folding it into a
/// quote's report_data binds the attestation to this exact TLS session.
#[test]
fn ratls_channel_binder_matches_across_the_handshake() {
    let provider = provider::default_provider();
    let kt = KeyType::Rsa2048;

    let server_binder = Arc::new(Mutex::new(None));
    let mut server_config = make_server_config(kt, &provider);
    server_config.ratls_bind_certificate = Some(Arc::new(CaptureBinder(server_binder.clone())));
    let server_config = Arc::new(server_config);

    let client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS13], &provider);
    let client_config = Arc::new(client_config);

    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let server_val = server_binder
        .lock()
        .unwrap()
        .expect("server hook must have received a channel binder");
    let client_val = client
        .ratls_channel_binder()
        .expect("client must have computed a channel binder");
    assert_eq!(
        server_val, client_val,
        "server and client channel binders must be identical"
    );
}

/// Binding is systematic: whenever the bind hook is configured the server
/// invokes it on every TLS 1.3 handshake, with no negotiation. The client
/// derives the matching binder unconditionally.
#[test]
fn ratls_channel_binding_is_systematic() {
    let provider = provider::default_provider();
    let kt = KeyType::Rsa2048;

    let server_binder = Arc::new(Mutex::new(None));
    let mut server_config = make_server_config(kt, &provider);
    server_config.ratls_bind_certificate = Some(Arc::new(CaptureBinder(server_binder.clone())));
    let server_config = Arc::new(server_config);

    let client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS13], &provider);
    let client_config = Arc::new(client_config);

    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    assert!(
        server_binder.lock().unwrap().is_some(),
        "server must bind on every handshake when the hook is configured"
    );
    assert!(
        client.ratls_channel_binder().is_some(),
        "client always derives its binder"
    );
}

/// The challenge nonce a client puts in `ClientConfig::ratls_challenge`
/// travels in ClientHello extension `0xFFBB` and surfaces byte-for-byte in
/// the server's cert resolver via `ClientHello::ratls_challenge()`; without
/// it the resolver sees `None`.
#[test]
fn client_hello_challenge_reaches_server_cert_resolver() {
    let provider = provider::default_provider();
    let kt = KeyType::Rsa2048;
    let nonce = b"client-challenge-nonce-32-bytes!".to_vec();

    let seen = Arc::new(Mutex::new(None));
    let server_config = Arc::new(
        server_config_builder(&provider)
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CaptureClientHelloChallenge {
                key: kt
                    .certified_key_with_cert_chain(&provider)
                    .unwrap(),
                seen: seen.clone(),
            })),
    );

    // Challenge configured: the exact nonce must surface in the resolver.
    let mut client_config =
        make_client_config_with_versions(kt, &[&rustls::version::TLS13], &provider);
    client_config.ratls_challenge = Some(nonce.clone());
    let (mut client, mut server) =
        make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
    do_handshake(&mut client, &mut server);
    assert_eq!(
        seen.lock().unwrap().take(),
        Some(Some(nonce)),
        "resolver must see the client's exact challenge nonce"
    );

    // No challenge configured: the extension is absent, resolver sees None.
    let client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS13], &provider);
    let (mut client, mut server) =
        make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
    do_handshake(&mut client, &mut server);
    assert_eq!(
        seen.lock().unwrap().take(),
        Some(None),
        "no challenge configured must surface as None"
    );
}

/// The mutual (client-cert) leg: a server's `ratls_challenge` travels in
/// CertificateRequest extension `0xFFBB` and reaches the client's cert
/// resolver together with the channel binder, and the binder equals the one
/// the server stores for post-handshake verification of the client cert.
#[test]
fn certificate_request_challenge_and_binder_reach_client_cert_resolver() {
    let provider = provider::default_provider();
    let kt = KeyType::Rsa2048;
    let nonce = b"server-challenge-nonce-32-bytes!".to_vec();

    let server_binder = Arc::new(Mutex::new(None));
    let mut server_config = make_server_config_with_mandatory_client_auth(kt, &provider);
    server_config.ratls_challenge = Some(nonce.clone());
    server_config.ratls_bind_certificate = Some(Arc::new(CaptureBinder(server_binder.clone())));
    let server_config = Arc::new(server_config);

    let seen = Arc::new(Mutex::new(None));
    let client_config = client_config_builder_with_versions(&[&rustls::version::TLS13], &provider)
        .with_root_certificates(get_client_root_store(kt))
        .with_client_cert_resolver(Arc::new(CaptureClientResolver {
            key: client_certified_key(kt, &provider),
            seen: seen.clone(),
        }));

    let (mut client, mut server) =
        make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
    do_handshake(&mut client, &mut server);

    let (challenge, binder) = seen
        .lock()
        .unwrap()
        .take()
        .expect("client cert resolver must have run");
    assert_eq!(
        challenge,
        Some(nonce),
        "client resolver must see the server's exact challenge nonce"
    );
    let binder = binder.expect("channel binder must be available to the client resolver");
    assert_eq!(
        binder.as_slice(),
        client
            .ratls_channel_binder()
            .unwrap()
            .as_slice(),
        "resolver must be offered the connection's channel binder"
    );
    // Mutual leg: the server stores the identical binder, so a verifier
    // (e.g. an Enclave Vault) can recompute the client cert's channel-bound
    // report_data post-handshake.
    assert_eq!(
        binder.as_slice(),
        server_binder
            .lock()
            .unwrap()
            .expect("server must store the binder")
            .as_slice(),
        "client-side and server-side binders must be identical"
    );
    assert_eq!(
        server.ratls_channel_binder(),
        client.ratls_channel_binder(),
        "both connections must expose the same binder"
    );
}

/// RA-TLS challenge and channel binder are TLS 1.3 only: on a TLS 1.2
/// handshake the client cert resolver must see `None` for both even when the
/// server has a challenge configured, and neither side derives a binder.
#[cfg(feature = "tls12")]
#[test]
fn client_cert_resolver_sees_no_challenge_or_binder_on_tls12() {
    let provider = provider::default_provider();
    let kt = KeyType::Rsa2048;

    let mut server_config = make_server_config_with_mandatory_client_auth(kt, &provider);
    server_config.ratls_challenge = Some(b"unused-on-tls12".to_vec());
    let server_config = Arc::new(server_config);

    let seen = Arc::new(Mutex::new(None));
    let client_config = client_config_builder_with_versions(&[&rustls::version::TLS12], &provider)
        .with_root_certificates(get_client_root_store(kt))
        .with_client_cert_resolver(Arc::new(CaptureClientResolver {
            key: client_certified_key(kt, &provider),
            seen: seen.clone(),
        }));

    let (mut client, mut server) =
        make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
    do_handshake(&mut client, &mut server);

    assert_eq!(
        seen.lock().unwrap().take(),
        Some((None, None)),
        "TLS 1.2 must not carry an RA-TLS challenge or channel binder"
    );
    assert!(
        client.ratls_channel_binder().is_none(),
        "no channel binder is derived on TLS 1.2"
    );
    assert!(
        server.ratls_channel_binder().is_none(),
        "no channel binder is derived on TLS 1.2"
    );
}

/// A bind hook that re-mints the certificate: the certificate it returns is
/// the one actually sent to the client.
#[derive(Debug)]
struct RebindTo(Arc<CertifiedKey>);

impl RaTlsBindCertificate for RebindTo {
    fn bind_certificate(&self, _binder: &[u8; 32]) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// When the bind hook returns a certificate, that certificate replaces the
/// originally-resolved one on the wire. The server resolves an RSA identity,
/// but the hook re-mints to ECDSA P-256; the client only trusts the ECDSA
/// root, so the handshake succeeds iff the hook's certificate is sent.
#[test]
fn bind_certificate_hook_replaces_the_server_certificate() {
    let provider = provider::default_provider();
    let resolved_kt = KeyType::Rsa2048;
    let rebound_kt = KeyType::EcdsaP256;

    let mut server_config = make_server_config(resolved_kt, &provider);
    server_config.ratls_bind_certificate = Some(Arc::new(RebindTo(
        rebound_kt
            .certified_key_with_cert_chain(&provider)
            .unwrap(),
    )));
    let server_config = Arc::new(server_config);

    let client_config =
        make_client_config_with_versions(rebound_kt, &[&rustls::version::TLS13], &provider);
    let (mut client, mut server) =
        make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
    do_handshake(&mut client, &mut server);

    assert_eq!(
        client.peer_certificates().unwrap(),
        rebound_kt.get_chain(),
        "client must receive the re-minted certificate chain"
    );
}
