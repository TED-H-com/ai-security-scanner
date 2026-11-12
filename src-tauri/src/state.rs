//! Desktop adapter owns the same shared state used by foreground scans.
pub type AppState = std::sync::Arc<crate::core_state::CoreState>;
