//! The application core: the only module that coordinates the library crates
//! (`engine`, `fetcher`, `scanner`, `manifests`, `rules`, `model`) on behalf of
//! the CLI. Everything below `app` depends on this layer, and nothing in this
//! layer reaches back into presentation (`cli`, `output`, `diff`, `commands`).
//!
//! Keeping this isolated makes the orchestration boundary explicit: UI adapters
//! translate user input into [`Pipeline`] configuration, then render the results
//! returned by [`PipelineExecution`].

mod orchestration;
mod suppressions;

pub use orchestration::{AnalysisInput, AnalysisRunOptions, Pipeline, VersionReport};
pub use suppressions::{ConfiguredSuppression, apply_suppressions, configured_suppressions};
