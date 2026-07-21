//! Multi-project local index — metadata only (1.6 Phase F).

pub mod registry;

pub use registry::{
    default_index_path, discover_project_stores, ProjectIndexEntry, ProjectIndexQuery,
    ProjectRegistry,
};
