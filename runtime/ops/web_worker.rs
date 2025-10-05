// Copyright 2018-2025 the Deno authors. MIT license.

mod sync_fetch;

use std::cell::RefCell;
use std::rc::Rc;

use deno_core::CancelFuture;
use deno_core::OpState;
use deno_core::convert::OptionNull;
use deno_core::op2;
use deno_web::MessageData;
pub use sync_fetch::SyncFetchError;

use self::sync_fetch::op_worker_sync_fetch;
use crate::web_worker::WebWorkerInternalHandle;
use crate::web_worker::WorkerThreadType;

deno_core::extension!(
  deno_web_worker,
  ops = [
    op_worker_post_message,
    op_worker_recv_message,
    // Notify host that guest worker closes.
    op_worker_close,
    op_worker_get_type,
    op_worker_sync_fetch,
  ],
);

#[op2]
fn op_worker_post_message(state: &mut OpState, #[from_v8] data: MessageData) {
  let handle = state.borrow::<WebWorkerInternalHandle>().clone();
  handle.port.send(data)
}

#[op2(async(lazy), fast)]
#[to_v8]
async fn op_worker_recv_message(
  state: Rc<RefCell<OpState>>,
) -> Result<OptionNull<MessageData>, deno_core::Canceled> {
  let handle = state.borrow().borrow::<WebWorkerInternalHandle>().clone();
  let data = handle.port.recv().or_cancel(handle.cancel).await?;
  Ok(data.into())
}

#[op2(fast)]
fn op_worker_close(state: &mut OpState) {
  // Notify parent that we're finished
  let mut handle = state.borrow_mut::<WebWorkerInternalHandle>().clone();

  handle.terminate();
}

#[op2]
#[serde]
fn op_worker_get_type(state: &mut OpState) -> WorkerThreadType {
  let handle = state.borrow::<WebWorkerInternalHandle>().clone();
  handle.worker_type
}
