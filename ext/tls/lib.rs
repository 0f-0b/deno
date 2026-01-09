// Copyright 2018-2026 the Deno authors. MIT license.
use std::io::BufRead;
use std::io::BufReader;
use std::io::Cursor;
use std::net::IpAddr;
use std::sync::Arc;

use deno_error::JsErrorBox;
pub use deno_native_certs;
pub use rustls;
use rustls::ClientConfig;
use rustls::DigitallySignedStruct;
use rustls::RootCertStore;
use rustls::SignatureScheme;
use rustls::client::EchMode;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerified;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::ServerName;
use rustls::pki_types::UnixTime;
pub use rustls_pemfile;
use rustls_pemfile::certs;
use rustls_pemfile::ec_private_keys;
use rustls_pemfile::pkcs8_private_keys;
use rustls_pemfile::rsa_private_keys;
pub use rustls_tokio_stream::*;
use serde::Deserialize;
pub use webpki;
pub use webpki_roots;

mod keylog;
mod tls_key;
pub use keylog::get_ssl_key_log;
pub use tls_key::*;

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum TlsError {
  #[class(generic)]
  #[error(transparent)]
  Rustls(#[from] rustls::Error),
  #[class(inherit)]
  #[error("Unable to add pem file to certificate store: {0}")]
  UnableAddPemFileToCert(std::io::Error),
  #[class("InvalidData")]
  #[error("Unable to decode certificate")]
  CertInvalid,
  #[class("InvalidData")]
  #[error("No certificates found in certificate data")]
  CertsNotFound,
  #[class("InvalidData")]
  #[error("No keys found in key data")]
  KeysNotFound,
  #[class("InvalidData")]
  #[error("Unable to decode key")]
  KeyDecode,
}

/// Lazily resolves the root cert store.
///
/// This was done because the root cert store is not needed in all cases
/// and takes a bit of time to initialize.
pub trait RootCertStoreProvider: Send + Sync {
  fn get_or_try_init(&self) -> Result<&RootCertStore, JsErrorBox>;
}

// This extension has no runtime apis, it only exports some shared native functions.
deno_core::extension!(
  deno_tls,
  state = |_state| {
    // Resolve `SSLKEYLOGFILE` before user JavaScript can mutate env vars.
    keylog::init_ssl_key_log();
  },
);

#[derive(Debug)]
pub struct NoCertificateVerification {
  pub ic_allowlist: Vec<String>,
  default_verifier: Arc<WebPkiServerVerifier>,
}

impl NoCertificateVerification {
  pub fn new(
    ic_allowlist: Vec<String>,
    default_verifier: Arc<WebPkiServerVerifier>,
  ) -> Self {
    Self {
      ic_allowlist,
      default_verifier,
    }
  }
}

impl ServerCertVerifier for NoCertificateVerification {
  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    self.default_verifier.supported_verify_schemes()
  }

  fn verify_server_cert(
    &self,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    ocsp_response: &[u8],
    now: UnixTime,
  ) -> Result<ServerCertVerified, rustls::Error> {
    if self.ic_allowlist.is_empty() {
      return Ok(ServerCertVerified::assertion());
    }
    let dns_name_or_ip_address = match server_name {
      ServerName::DnsName(dns_name) => dns_name.as_ref().to_owned(),
      ServerName::IpAddress(ip_address) => {
        Into::<IpAddr>::into(*ip_address).to_string()
      }
      _ => {
        // NOTE(bartlomieju): `ServerName` is a non-exhaustive enum
        // so we have this catch all errors here.
        return Err(rustls::Error::General(
          "Unknown `ServerName` variant".to_string(),
        ));
      }
    };
    if self.ic_allowlist.contains(&dns_name_or_ip_address) {
      Ok(ServerCertVerified::assertion())
    } else {
      self.default_verifier.verify_server_cert(
        end_entity,
        intermediates,
        server_name,
        ocsp_response,
        now,
      )
    }
  }

  fn verify_tls12_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, rustls::Error> {
    if self.ic_allowlist.is_empty() {
      return Ok(HandshakeSignatureValid::assertion());
    }
    filter_invalid_encoding_err(
      self
        .default_verifier
        .verify_tls12_signature(message, cert, dss),
    )
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, rustls::Error> {
    if self.ic_allowlist.is_empty() {
      return Ok(HandshakeSignatureValid::assertion());
    }
    filter_invalid_encoding_err(
      self
        .default_verifier
        .verify_tls13_signature(message, cert, dss),
    )
  }
}

#[derive(Debug)]
pub struct NoServerNameVerification {
  inner: Arc<WebPkiServerVerifier>,
}

impl NoServerNameVerification {
  pub fn new(inner: Arc<WebPkiServerVerifier>) -> Self {
    Self { inner }
  }
}

impl ServerCertVerifier for NoServerNameVerification {
  fn verify_server_cert(
    &self,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    ocsp_response: &[u8],
    now: UnixTime,
  ) -> Result<ServerCertVerified, rustls::Error> {
    match self.inner.verify_server_cert(
      end_entity,
      intermediates,
      server_name,
      ocsp_response,
      now,
    ) {
      Ok(scv) => Ok(scv),
      Err(rustls::Error::InvalidCertificate(cert_error)) => {
        if matches!(
          cert_error,
          rustls::CertificateError::NotValidForName
            | rustls::CertificateError::NotValidForNameContext { .. }
        ) {
          Ok(ServerCertVerified::assertion())
        } else {
          Err(rustls::Error::InvalidCertificate(cert_error))
        }
      }
      Err(e) => Err(e),
    }
  }

  fn verify_tls12_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, rustls::Error> {
    self.inner.verify_tls12_signature(message, cert, dss)
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, rustls::Error> {
    self.inner.verify_tls13_signature(message, cert, dss)
  }

  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    self.inner.supported_verify_schemes()
  }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", tag = "transport")]
pub enum Proxy {
  #[serde(rename_all = "camelCase")]
  Http {
    url: String,
    basic_auth: Option<BasicAuth>,
  },
  Tcp {
    hostname: String,
    port: u16,
  },
  Unix {
    path: String,
  },
  Vsock {
    cid: u32,
    port: u32,
  },
}

#[derive(Deserialize, Default, Debug, Clone)]
#[serde(default)]
pub struct BasicAuth {
  pub username: String,
  pub password: String,
}

pub fn create_default_root_cert_store() -> RootCertStore {
  let root_cert_store = rustls::RootCertStore {
    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
  };
  debug_assert!(!root_cert_store.is_empty());
  root_cert_store
}

#[derive(Default)]
pub struct CertVerifierOptions {
  pub root_cert_store: Option<RootCertStore>,
  pub ca_certs: Vec<Vec<u8>>,
  pub unsafely_ignore_certificate_errors: Option<Vec<String>>,
  pub unsafely_disable_hostname_verification: bool,
}

pub fn create_certificate_verifier(
  options: CertVerifierOptions,
) -> Result<Arc<dyn ServerCertVerifier>, TlsError> {
  let CertVerifierOptions {
    root_cert_store,
    ca_certs,
    unsafely_ignore_certificate_errors,
    unsafely_disable_hostname_verification,
  } = options;

  let mut root_cert_store =
    root_cert_store.unwrap_or_else(create_default_root_cert_store);

  // If custom certs are specified, add them to the store
  for cert in ca_certs {
    let reader = &mut BufReader::new(Cursor::new(cert));
    // This function does not return specific errors, if it fails give a generic message.
    for cert in rustls_pemfile::certs(reader) {
      let cert = cert.map_err(TlsError::UnableAddPemFileToCert)?;
      root_cert_store.add(cert)?;
    }
  }

  let verifier = WebPkiServerVerifier::builder(Arc::new(root_cert_store))
    .build()
    .expect("Failed to create WebPkiServerVerifier");

  Ok(
    if let Some(ic_allowlist) = unsafely_ignore_certificate_errors {
      Arc::new(NoCertificateVerification::new(ic_allowlist, verifier))
    } else if unsafely_disable_hostname_verification {
      Arc::new(NoServerNameVerification::new(verifier))
    } else {
      verifier
    },
  )
}

pub fn create_client_config(
  server_cert_verifier: Arc<dyn ServerCertVerifier>,
  client_cert_chain_and_key: TlsKeys,
  ech_mode: Option<EchMode>,
) -> ClientConfig {
  let builder = ClientConfig::builder_with_provider(
    rustls::crypto::CryptoProvider::get_default()
      .unwrap()
      .clone(),
  );

  let builder = match ech_mode {
    Some(mode) => builder.with_ech(mode),
    None => builder.with_safe_default_protocol_versions(),
  }
  .unwrap();

  let builder = builder
    .dangerous()
    .with_custom_certificate_verifier(server_cert_verifier);

  let mut client = match client_cert_chain_and_key {
    TlsKeys::Static(TlsKey(cert_chain, private_key)) => builder
      .with_client_auth_cert(cert_chain, private_key)
      .expect("invalid client key or certificate"),
    TlsKeys::Null => builder.with_no_client_auth(),
    TlsKeys::Resolver(_) => unimplemented!(),
  };

  client.key_log = get_ssl_key_log();
  client
}

pub fn load_certs(
  reader: &mut dyn BufRead,
) -> Result<Vec<CertificateDer<'static>>, TlsError> {
  let certs: Result<Vec<_>, _> = certs(reader).collect();

  let certs = certs.map_err(|_| TlsError::CertInvalid)?;

  if certs.is_empty() {
    return Err(TlsError::CertsNotFound);
  }

  Ok(certs)
}

/// Starts with -----BEGIN RSA PRIVATE KEY-----
fn load_rsa_keys(
  mut bytes: &[u8],
) -> Result<Vec<PrivateKeyDer<'static>>, TlsError> {
  let keys: Result<Vec<_>, _> = rsa_private_keys(&mut bytes).collect();
  let keys = keys.map_err(|_| TlsError::KeyDecode)?;
  Ok(keys.into_iter().map(PrivateKeyDer::Pkcs1).collect())
}

/// Starts with -----BEGIN EC PRIVATE KEY-----
fn load_ec_keys(
  mut bytes: &[u8],
) -> Result<Vec<PrivateKeyDer<'static>>, TlsError> {
  let keys: Result<Vec<_>, std::io::Error> =
    ec_private_keys(&mut bytes).collect();
  let keys2 = keys.map_err(|_| TlsError::KeyDecode)?;
  Ok(keys2.into_iter().map(PrivateKeyDer::Sec1).collect())
}

/// Starts with -----BEGIN PRIVATE KEY-----
fn load_pkcs8_keys(
  mut bytes: &[u8],
) -> Result<Vec<PrivateKeyDer<'static>>, TlsError> {
  let keys: Result<Vec<_>, std::io::Error> =
    pkcs8_private_keys(&mut bytes).collect();
  let keys2 = keys.map_err(|_| TlsError::KeyDecode)?;
  Ok(keys2.into_iter().map(PrivateKeyDer::Pkcs8).collect())
}

fn filter_invalid_encoding_err(
  to_be_filtered: Result<HandshakeSignatureValid, rustls::Error>,
) -> Result<HandshakeSignatureValid, rustls::Error> {
  match to_be_filtered {
    Err(rustls::Error::InvalidCertificate(
      rustls::CertificateError::BadEncoding,
    )) => Ok(HandshakeSignatureValid::assertion()),
    res => res,
  }
}

pub fn load_private_keys(
  bytes: &[u8],
) -> Result<Vec<PrivateKeyDer<'static>>, TlsError> {
  let mut keys = load_rsa_keys(bytes)?;

  if keys.is_empty() {
    keys = load_pkcs8_keys(bytes)?;
  }

  if keys.is_empty() {
    keys = load_ec_keys(bytes)?;
  }

  if keys.is_empty() {
    return Err(TlsError::KeysNotFound);
  }

  Ok(keys)
}
