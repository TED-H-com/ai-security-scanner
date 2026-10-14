#![allow(dead_code)]

#[path = "../src/adapter.rs"]
mod adapter;
#[path = "../src/artifact_store.rs"]
mod artifact_store;
#[path = "../src/container_runtime.rs"]
mod container_runtime;
#[path = "../src/domain.rs"]
mod domain;
#[path = "../src/error.rs"]
mod error;
#[path = "../src/execution_coverage.rs"]
mod execution_coverage;
#[path = "../src/external_scope.rs"]
mod external_scope;
#[path = "../src/garak_input.rs"]
mod garak_input;
#[path = "../src/managed_network.rs"]
mod managed_network;
#[path = "../src/managed_runtime.rs"]
mod managed_runtime;
#[path = "../src/naabu_work_plan.rs"]
mod naabu_work_plan;
#[path = "../src/orchestrator.rs"]
mod orchestrator;
#[path = "../src/process_lease.rs"]
mod process_lease;
#[path = "../src/publication_origins.rs"]
mod publication_origins;
// Included so `container_runtime` can import the ZAP plan constants the same
// way it imports the Naabu ones. The enum is public in the library, where
// clippy skips `enum_variant_names` for exported items; this private copy is
// not exported, so the same enum would fail the harness.
#[allow(clippy::enum_variant_names)]
#[path = "../src/zap_work_plan.rs"]
mod zap_work_plan;
