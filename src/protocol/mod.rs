//! Blackbox Evidence Protocol (1.9).
//!
//! Implementation-neutral protocol surface: canonical serialization, schema
//! identifiers, stability classification, and validation helpers.
//!
//! Published schemas live under `/spec`. Test vectors live under
//! `/test-vectors`. Protocol APIs intentionally avoid SQLite, clap, and
//! transport types so external encoders can reimplement them from the spec.

pub mod canonical;
pub mod proptest;
pub mod schema;
pub mod stability;
pub mod validate;

pub use canonical::{
    canonical_bytes, canonical_hash, canonical_string, CanonicalError, CANONICAL_HASH_ALG,
};
pub use schema::{
    find_schema, is_known_schema, ProtocolObjectKind, SchemaId, PROTOCOL_VERSION, SCHEMA_CATALOG,
};
pub use stability::{SurfaceClass, SurfaceEntry, SURFACE_INVENTORY};
pub use validate::{validate_json_object, validate_schema_id, ValidationError, ValidationReport};
