use crate::{build_config, raw::RawConfig};
use std::{
    cell::RefCell,
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Default)]
pub(crate) struct Context(Arc<parking_lot::Mutex<HashMap<PathBuf, Vec<u8>>>>);

tokio::task_local! {
    static CONTEXT: Context;
}

thread_local! {
    static BLOCKING_CONTEXT: RefCell<Option<Context>> = const { RefCell::new(None) };
}

pub(crate) fn is_active() -> bool {
    current().is_some()
}

pub(crate) fn current() -> Option<Context> {
    CONTEXT
        .try_with(Clone::clone)
        .ok()
        .or_else(|| BLOCKING_CONTEXT.with(|value| value.borrow().clone()))
}

pub(crate) fn resource(path: &Path) -> Option<Vec<u8>> {
    current().and_then(|context| context.0.lock().get(path).cloned())
}

pub(crate) fn has_resource(path: &Path) -> bool {
    current().is_some_and(|context| context.0.lock().contains_key(path))
}

pub(crate) fn insert_resource(path: PathBuf, bytes: Vec<u8>) {
    if let Some(context) = current() {
        context.0.lock().insert(path, bytes);
    }
}

struct BlockingScope(Option<Context>);

impl Drop for BlockingScope {
    fn drop(&mut self) {
        BLOCKING_CONTEXT.with(|value| value.replace(self.0.take()));
    }
}

pub(crate) fn with_blocking_scope<R>(context: Option<Context>, f: impl FnOnce() -> R) -> R {
    let _scope = BlockingScope(BLOCKING_CONTEXT.with(|value| value.replace(context)));
    f()
}

/// Validate runtime configuration without persistent stores, cache writes or binding.
/// Configured provider/geodata HTTP reads are allowed; DNS/bootstrap fetches are skipped.
pub async fn validate_config(raw: RawConfig, cache_dir: Option<&Path>) -> anyhow::Result<()> {
    CONTEXT
        .scope(Context::default(), async move {
            let config = build_config(raw, cache_dir).await?;
            drop(config);
            Ok(())
        })
        .await
}
