// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::resolver::ResolveError;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

thread_local! {
    #[allow(clippy::missing_const_for_thread_local)]
    static CURRENT: RefCell<Option<QueryCancellation>> = RefCell::new(None);
}

#[derive(Clone, Debug, Default)]
pub(crate) struct QueryCancellation(Arc<AtomicBool>);

impl QueryCancellation {
    pub(crate) fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    pub(crate) fn same_as(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

#[derive(Debug)]
struct CurrentGuard(Option<QueryCancellation>);

impl Drop for CurrentGuard {
    fn drop(&mut self) {
        CURRENT.with(|current| {
            current.replace(self.0.take());
        });
    }
}

pub(crate) fn current() -> Option<QueryCancellation> {
    CURRENT.with(|current| current.borrow().clone())
}

pub(crate) fn with<T>(cancellation: QueryCancellation, operation: impl FnOnce() -> T) -> T {
    let previous = CURRENT.with(|current| current.replace(Some(cancellation)));
    let _guard = CurrentGuard(previous);
    operation()
}

pub(crate) fn with_optional<T>(
    cancellation: Option<QueryCancellation>,
    operation: impl FnOnce() -> T,
) -> T {
    match cancellation {
        Some(cancellation) => with(cancellation, operation),
        None => operation(),
    }
}

pub(crate) fn check() -> Result<(), ResolveError> {
    let cancelled = CURRENT.with(|current| {
        current
            .borrow()
            .as_ref()
            .is_some_and(QueryCancellation::is_cancelled)
    });
    if cancelled {
        Err(ResolveError::QueryAborted)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_context_restores_the_outer_cancellation() {
        let outer = QueryCancellation::default();
        let inner = QueryCancellation::default();
        with(outer.clone(), || {
            assert!(!current().expect("outer context").is_cancelled());
            with(inner.clone(), || {
                inner.cancel();
                assert!(matches!(check(), Err(ResolveError::QueryAborted)));
            });
            assert!(!current().expect("restored outer context").is_cancelled());
        });
        assert!(current().is_none());
    }

    #[test]
    fn cancellation_check_does_not_clone_current_token() {
        let cancellation = QueryCancellation::default();
        with(cancellation.clone(), || {
            let before = Arc::strong_count(&cancellation.0);
            assert!(check().is_ok());
            assert_eq!(Arc::strong_count(&cancellation.0), before);
            cancellation.cancel();
            assert!(matches!(check(), Err(ResolveError::QueryAborted)));
            assert_eq!(Arc::strong_count(&cancellation.0), before);
        });
    }
}
