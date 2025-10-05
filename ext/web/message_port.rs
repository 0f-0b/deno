// Copyright 2018-2025 the Deno authors. MIT license.

use std::cell::RefCell;
use std::convert::Infallible;
use std::future::poll_fn;
use std::rc::Rc;
use std::task::Context;
use std::task::Poll;

use deno_core::CancelFuture;
use deno_core::CancelHandle;
use deno_core::FromV8;
use deno_core::GarbageCollected;
use deno_core::ToV8;
use deno_core::convert::OptionNull;
use deno_core::op2;
use deno_core::v8;
use deno_error::JsError;
use thiserror::Error;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::unbounded_channel;

#[derive(Debug, Error, JsError)]
#[class(type)]
pub enum DetachedBufferFromV8Error {
  #[error("ArrayBuffer is not detachable")]
  NotDetachable,
  #[error(transparent)]
  Data(#[from] v8::DataError),
}

pub struct DetachedBuffer {
  backing_store: v8::SharedRef<v8::BackingStore>,
  byte_offset: usize,
  byte_length: usize,
}

impl<'a> FromV8<'a> for DetachedBuffer {
  type Error = DetachedBufferFromV8Error;

  fn from_v8(
    scope: &mut v8::PinScope<'a, '_>,
    value: v8::Local<'a, v8::Value>,
  ) -> Result<Self, Self::Error> {
    let data = value.cast::<v8::ArrayBufferView>();
    let byte_offset = data.byte_offset();
    let byte_length = data.byte_length();
    let buffer = data.buffer(scope).unwrap();
    let backing_store = buffer.get_backing_store();
    let Some(true) = buffer.detach(None) else {
      return Err(DetachedBufferFromV8Error::NotDetachable);
    };
    Ok(Self {
      backing_store,
      byte_offset,
      byte_length,
    })
  }
}

impl<'a> ToV8<'a> for DetachedBuffer {
  type Error = Infallible;

  fn to_v8(
    self,
    scope: &mut v8::PinScope<'a, '_>,
  ) -> Result<v8::Local<'a, v8::Value>, Self::Error> {
    let Self {
      backing_store,
      byte_offset,
      byte_length,
    } = self;
    let buffer = v8::ArrayBuffer::with_backing_store(scope, &backing_store);
    let value = v8::Uint8Array::new(scope, buffer, byte_offset, byte_length)
      .unwrap()
      .into();
    Ok(value)
  }
}

pub enum Transferable {
  MessagePort(MessagePort),
  ArrayBuffer(u32),
}

pub struct MessageData {
  data: DetachedBuffer,
  transferables: Vec<Transferable>,
}

pub const DATA_STR: deno_core::FastStaticString = deno_core::ascii_str!("data");
pub const KIND_STR: deno_core::FastStaticString = deno_core::ascii_str!("kind");
pub const MESSAGE_PORT_STR: deno_core::FastStaticString =
  deno_core::ascii_str!("messagePort");
pub const ARRAY_BUFFER_STR: deno_core::FastStaticString =
  deno_core::ascii_str!("arrayBuffer");
pub const TRANSFERABLES_STR: deno_core::FastStaticString =
  deno_core::ascii_str!("transferables");

impl<'a> FromV8<'a> for MessageData {
  type Error = Infallible;

  fn from_v8(
    scope: &mut v8::PinScope<'a, '_>,
    value: v8::Local<'a, v8::Value>,
  ) -> Result<Self, Self::Error> {
    let data_str = DATA_STR.v8_string(scope).unwrap();
    let kind_str = KIND_STR.v8_string(scope).unwrap();
    let message_port_str = MESSAGE_PORT_STR.v8_string(scope).unwrap();
    let array_buffer_str = ARRAY_BUFFER_STR.v8_string(scope).unwrap();
    let transferables_str = TRANSFERABLES_STR.v8_string(scope).unwrap();
    let value = value.cast::<v8::Object>();
    let data = {
      let data = value.get(scope, data_str.into()).unwrap();
      DetachedBuffer::from_v8(scope, data).unwrap()
    };
    let transferables = {
      let transferables = value
        .get(scope, transferables_str.into())
        .unwrap()
        .cast::<v8::Array>();
      let len = transferables.length();
      let mut vec = Vec::with_capacity(len as usize);
      for i in 0..len {
        let elem = transferables
          .get_index(scope, i)
          .unwrap()
          .cast::<v8::Object>();
        let kind = elem.get(scope, kind_str.into()).unwrap();
        let data = elem.get(scope, data_str.into()).unwrap();
        if kind == message_port_str {
          let handle = deno_core::cppgc::try_unwrap_cppgc_object::<
            MessagePortHandle,
          >(scope, data)
          .unwrap();
          handle.cancel.cancel();
          let port = handle.port.take().unwrap();
          vec.push(Transferable::MessagePort(port));
        } else if kind == array_buffer_str {
          let id = data.uint32_value(scope).unwrap();
          vec.push(Transferable::ArrayBuffer(id));
        } else {
          unreachable!();
        }
      }
      vec
    };
    Ok(Self {
      data,
      transferables,
    })
  }
}

impl<'a> ToV8<'a> for MessageData {
  type Error = Infallible;

  fn to_v8(
    self,
    scope: &mut v8::PinScope<'a, '_>,
  ) -> Result<v8::Local<'a, v8::Value>, Self::Error> {
    let data_str = DATA_STR.v8_string(scope).unwrap();
    let kind_str = KIND_STR.v8_string(scope).unwrap();
    let message_port_str = MESSAGE_PORT_STR.v8_string(scope).unwrap();
    let array_buffer_str = ARRAY_BUFFER_STR.v8_string(scope).unwrap();
    let transferables_str = TRANSFERABLES_STR.v8_string(scope).unwrap();
    let null = v8::null(scope);
    let data = self.data.to_v8(scope)?;
    let transferables = {
      let elems = self
        .transferables
        .into_iter()
        .map(|transferable| match transferable {
          Transferable::MessagePort(port) => {
            let port = deno_core::cppgc::make_cppgc_object(
              scope,
              MessagePortHandle::new(port),
            );
            v8::Object::with_prototype_and_properties(
              scope,
              null.into(),
              &[kind_str.into(), data_str.into()],
              &[message_port_str.into(), port.into()],
            )
            .into()
          }
          Transferable::ArrayBuffer(id) => {
            let id = v8::Integer::new_from_unsigned(scope, id);
            v8::Object::with_prototype_and_properties(
              scope,
              null.into(),
              &[kind_str.into(), data_str.into()],
              &[array_buffer_str.into(), id.into()],
            )
            .into()
          }
        })
        .collect::<Vec<_>>();
      v8::Array::new_with_elements(scope, &elems).into()
    };
    Ok(
      v8::Object::with_prototype_and_properties(
        scope,
        null.into(),
        &[data_str.into(), transferables_str.into()],
        &[data, transferables],
      )
      .into(),
    )
  }
}

pub struct MessagePort {
  rx: RefCell<UnboundedReceiver<MessageData>>,
  tx: RefCell<Option<UnboundedSender<MessageData>>>,
}

impl MessagePort {
  pub fn send(&self, data: MessageData) {
    // Swallow the failed to send error. It means the channel was disentangled,
    // but not cleaned up.
    if let Some(tx) = &*self.tx.borrow() {
      let _ = tx.send(data);
    }
  }

  pub fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Option<MessageData>> {
    let mut rx = self.rx.borrow_mut();
    rx.poll_recv(cx)
  }

  pub async fn recv(&self) -> Option<MessageData> {
    poll_fn(|cx| self.poll_recv(cx)).await
  }

  /// This forcefully disconnects the message port from its paired port. This
  /// will wake up the `.recv` on the paired port, which will return `Ok(None)`.
  pub fn disentangle(&self) {
    let mut tx = self.tx.borrow_mut();
    tx.take();
  }
}

pub fn create_entangled_message_port() -> (MessagePort, MessagePort) {
  let (port1_tx, port2_rx) = unbounded_channel();
  let (port2_tx, port1_rx) = unbounded_channel();

  let port1 = MessagePort {
    rx: RefCell::new(port1_rx),
    tx: RefCell::new(Some(port1_tx)),
  };

  let port2 = MessagePort {
    rx: RefCell::new(port2_rx),
    tx: RefCell::new(Some(port2_tx)),
  };

  (port1, port2)
}

pub struct MessagePortHandle {
  port: RefCell<Option<MessagePort>>,
  cancel: Rc<CancelHandle>,
}

impl MessagePortHandle {
  fn new(port: MessagePort) -> Self {
    Self {
      port: RefCell::new(Some(port)),
      cancel: Rc::new(CancelHandle::new()),
    }
  }
}

// SAFETY: this type has no members.
unsafe impl GarbageCollected for MessagePortHandle {
  fn trace(&self, _visitor: &mut v8::cppgc::Visitor) {}

  fn get_name(&self) -> &'static std::ffi::CStr {
    c"MessagePortHandle"
  }
}

#[op2]
pub fn op_message_port_create_entangled<'a>(
  scope: &mut v8::PinScope<'a, '_>,
) -> v8::Local<'a, v8::Array> {
  let (port1, port2) = create_entangled_message_port();
  let port1 =
    deno_core::cppgc::make_cppgc_object(scope, MessagePortHandle::new(port1));
  let port2 =
    deno_core::cppgc::make_cppgc_object(scope, MessagePortHandle::new(port2));
  v8::Array::new_with_elements(scope, &[port1.into(), port2.into()])
}

#[op2]
pub fn op_message_port_post_message(
  #[cppgc] handle: &MessagePortHandle,
  #[from_v8] data: MessageData,
) {
  let port = handle.port.borrow();
  let port = port.as_ref().unwrap();
  port.send(data)
}

#[op2(async)]
#[to_v8]
pub async fn op_message_port_recv_message(
  #[cppgc] handle: &MessagePortHandle,
) -> Result<OptionNull<MessageData>, deno_core::Canceled> {
  let data = poll_fn(|cx| {
    let port = handle.port.borrow();
    let port = port.as_ref().unwrap();
    port.poll_recv(cx)
  })
  .or_cancel(handle.cancel.clone())
  .await?;
  Ok(data.into())
}

#[op2]
#[to_v8]
pub fn op_message_port_recv_message_sync(
  #[cppgc] handle: &MessagePortHandle,
) -> OptionNull<MessageData> {
  let port = handle.port.borrow();
  let port = port.as_ref().unwrap();
  let mut rx = port.rx.borrow_mut();
  let data = match rx.try_recv() {
    Ok(data) => Some(data),
    Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => None,
  };
  data.into()
}

#[op2(fast)]
pub fn op_message_port_close(#[cppgc] handle: &MessagePortHandle) {
  handle.cancel.cancel();
}
