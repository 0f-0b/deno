// Copyright 2018-2025 the Deno authors. MIT license.

use std::cell::RefCell;
use std::rc::Rc;

use deno_core::futures::FutureExt;
use deno_core::url::Url;
use deno_core::CancelFuture;
use deno_core::OpState;
use deno_fs::FileSystemRc;
use deno_fs::OpenOptions;
use deno_io::fs::FileResource;
use deno_permissions::PermissionsContainer;
use http_body_util::combinators::BoxBody;

use crate::CancelHandle;
use crate::CancelableResponseFuture;
use crate::FetchHandler;
use crate::FetchPermissions;
use crate::ResourceToBodyAdapter;

fn async_permission_check<P: FetchPermissions + 'static>(
  state: Rc<RefCell<OpState>>,
  api_name: &'static str,
) -> impl deno_fs::AccessCheckFn + 'static {
  move |path, _options, resolve| {
    let mut state = state.borrow_mut();
    let permissions = state.borrow_mut::<P>();
    permissions.check_read(path, api_name, resolve)
  }
}

/// An implementation which tries to read file URLs from the file system via `deno_fs`.
#[derive(Clone)]
pub struct FsFetchHandler;

impl FetchHandler for FsFetchHandler {
  fn fetch_file(
    &self,
    state: Rc<RefCell<OpState>>,
    url: &Url,
  ) -> (CancelableResponseFuture, Option<Rc<CancelHandle>>) {
    let fs = state.borrow_mut().borrow::<FileSystemRc>().clone();
    let mut access_check =
      async_permission_check::<PermissionsContainer>(state, "fetch()");
    let cancel_handle = CancelHandle::new_rc();
    let Ok(path) = url.to_file_path() else {
      return (
        async move { Err(super::FetchError::NetworkError) }
          .or_cancel(&cancel_handle)
          .boxed_local(),
        Some(cancel_handle),
      );
    };
    let response_fut = async move {
      let file = fs
        .open_async(path, OpenOptions::read(), Some(&mut access_check))
        .await
        .map_err(|_| super::FetchError::NetworkError)?;
      let resource = Rc::new(FileResource::new(file, "fsFile".to_owned()));
      let body = BoxBody::new(ResourceToBodyAdapter::new(resource));
      let response = http::Response::new(body);
      Ok(response)
    }
    .or_cancel(&cancel_handle)
    .boxed_local();

    (response_fut, Some(cancel_handle))
  }
}
