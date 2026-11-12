pub(crate) fn current() -> &'static str {
    #[cfg(test)]
    if let Some(version) = OVERRIDE.get() {
        return version;
    }
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
thread_local! {
    static OVERRIDE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

// Frozen byte tests run synchronously. A thread-local guard isolates concurrent
// tests and restores the previous version even when an assertion panics.
#[cfg(test)]
pub(crate) fn pin(version: &'static str) -> impl Drop {
    struct Reset(Option<&'static str>);
    impl Drop for Reset {
        fn drop(&mut self) {
            OVERRIDE.set(self.0);
        }
    }
    Reset(OVERRIDE.replace(Some(version)))
}
