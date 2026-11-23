//! Lock helpers that ignore poisoning, for every `std::sync` lock in the daemon.
//!
//! A panic in a task while it holds one of the daemon's locks must not take every later
//! request down with it. Every critical section in the daemon leaves its data consistent
//! (it inserts, removes or replaces whole values), so a poisoned lock is used as it is.

use std::sync::{Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Locks `mutex`, also after a panic while it was held.
pub(crate) fn lock<T: ?Sized>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Locks `lock` for reading, also after a panic while it was held.
pub(crate) fn read<T: ?Sized>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(PoisonError::into_inner)
}

/// Locks `lock` for writing, also after a panic while it was held.
pub(crate) fn write<T: ?Sized>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poisoned_locks_are_used_as_they_are() {
        let mutex = Mutex::new(1);
        let rw = RwLock::new(2);
        std::thread::scope(|scope| {
            let _ = scope
                .spawn(|| {
                    let _mutex = mutex.lock().unwrap();
                    let _rw = rw.write().unwrap();
                    panic!("poison both");
                })
                .join();
        });
        assert!(mutex.is_poisoned() && rw.is_poisoned());
        *lock(&mutex) += 1;
        assert_eq!(*lock(&mutex), 2);
        *write(&rw) += 1;
        assert_eq!(*read(&rw), 3);
    }
}
