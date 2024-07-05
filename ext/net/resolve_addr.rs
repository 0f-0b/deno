// Copyright 2018-2024 the Deno authors. All rights reserved. MIT license.

use crate::NetHost;
use deno_core::error::AnyError;
use either::Either;
use std::iter::once;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::net::ToSocketAddrs;
use tokio::net::lookup_host;

/// Resolve network address *asynchronously*.
pub async fn resolve_addr(
  host: &NetHost,
  port: u16,
) -> Result<impl Iterator<Item = SocketAddr> + '_, AnyError> {
  Ok(match *host {
    NetHost::Domain(ref name) => {
      Either::Left(lookup_host((name.as_ref(), port)).await?)
    }
    NetHost::Ipv4(ip) => {
      Either::Right(once(SocketAddr::V4(SocketAddrV4::new(ip, port))))
    }
    NetHost::Ipv6(ip) => {
      Either::Right(once(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))))
    }
  })
}

/// Resolve network address *synchronously*.
pub fn resolve_addr_sync(
  host: &NetHost,
  port: u16,
) -> Result<impl Iterator<Item = SocketAddr> + '_, AnyError> {
  Ok(match *host {
    NetHost::Domain(ref name) => {
      Either::Left((name.as_ref(), port).to_socket_addrs()?)
    }
    NetHost::Ipv4(ip) => {
      Either::Right(once(SocketAddr::V4(SocketAddrV4::new(ip, port))))
    }
    NetHost::Ipv6(ip) => {
      Either::Right(once(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))))
    }
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::Ipv4Addr;
  use std::net::Ipv6Addr;
  use std::net::SocketAddrV4;
  use std::net::SocketAddrV6;

  #[tokio::test]
  async fn resolve_addr1() {
    let expected = vec![SocketAddr::V4(SocketAddrV4::new(
      Ipv4Addr::new(127, 0, 0, 1),
      80,
    ))];
    let actual = resolve_addr(&"127.0.0.1".parse().unwrap(), 80)
      .await
      .unwrap()
      .collect::<Vec<_>>();
    assert_eq!(actual, expected);
  }

  #[tokio::test]
  async fn resolve_addr2() {
    let expected = vec![SocketAddr::V4(SocketAddrV4::new(
      Ipv4Addr::new(0, 0, 0, 0),
      80,
    ))];
    let actual = resolve_addr(&"".parse().unwrap(), 80)
      .await
      .unwrap()
      .collect::<Vec<_>>();
    assert_eq!(actual, expected);
  }

  #[tokio::test]
  async fn resolve_addr3() {
    let expected = vec![SocketAddr::V4(SocketAddrV4::new(
      Ipv4Addr::new(192, 0, 2, 1),
      25,
    ))];
    let actual = resolve_addr(&"192.0.2.1".parse().unwrap(), 25)
      .await
      .unwrap()
      .collect::<Vec<_>>();
    assert_eq!(actual, expected);
  }

  #[tokio::test]
  async fn resolve_addr_ipv6() {
    let expected = vec![SocketAddr::V6(SocketAddrV6::new(
      Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
      8080,
      0,
      0,
    ))];
    let actual = resolve_addr(&"[2001:db8::1]".parse().unwrap(), 8080)
      .await
      .unwrap()
      .collect::<Vec<_>>();
    assert_eq!(actual, expected);
  }

  #[tokio::test]
  async fn resolve_addr_err() {
    assert!(resolve_addr(&"test.invalid".parse().unwrap(), 1234)
      .await
      .is_err());
  }

  #[test]
  fn resolve_addr_sync1() {
    let expected = vec![SocketAddr::V4(SocketAddrV4::new(
      Ipv4Addr::new(127, 0, 0, 1),
      80,
    ))];
    let actual = resolve_addr_sync(&"127.0.0.1".parse().unwrap(), 80)
      .unwrap()
      .collect::<Vec<_>>();
    assert_eq!(actual, expected);
  }

  #[test]
  fn resolve_addr_sync2() {
    let expected = vec![SocketAddr::V4(SocketAddrV4::new(
      Ipv4Addr::new(0, 0, 0, 0),
      80,
    ))];
    let actual = resolve_addr_sync(&"".parse().unwrap(), 80)
      .unwrap()
      .collect::<Vec<_>>();
    assert_eq!(actual, expected);
  }

  #[test]
  fn resolve_addr_sync3() {
    let expected = vec![SocketAddr::V4(SocketAddrV4::new(
      Ipv4Addr::new(192, 0, 2, 1),
      25,
    ))];
    let actual = resolve_addr_sync(&"192.0.2.1".parse().unwrap(), 25)
      .unwrap()
      .collect::<Vec<_>>();
    assert_eq!(actual, expected);
  }

  #[test]
  fn resolve_addr_sync_ipv6() {
    let expected = vec![SocketAddr::V6(SocketAddrV6::new(
      Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
      8080,
      0,
      0,
    ))];
    let actual = resolve_addr_sync(&"[2001:db8::1]".parse().unwrap(), 8080)
      .unwrap()
      .collect::<Vec<_>>();
    assert_eq!(actual, expected);
  }

  #[test]
  fn resolve_addr_sync_err() {
    assert!(resolve_addr_sync(&"test.invalid".parse().unwrap(), 1234).is_err());
  }
}
