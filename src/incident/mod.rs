//! Multi-run incident reconstruction (1.7).
//!
//! Create/list/show incidents spanning runs and external evidence, build
//! reconstruction graphs (discovery, reuse, earliest signal), cursor-paginate
//! large lists, and export sanitized packs with integrity hashes.
//!
//! Not a SIEM case-management product — local evidence correlation only.
//! Dashboard: `/incidents` · CLI: `blackbox incident …`.

mod export;
mod graph;
mod model;
mod page;

pub use export::{
    build_incident_export, validate_incident_export, IncidentExport, INCIDENT_EXPORT_SCHEMA,
};
pub use graph::{
    build_incident_graph, GraphInputs, IncidentGraph, IncidentNode, IncidentSignal, TechniqueReuse,
};
pub use model::{
    attach_to_incident, Incident, IncidentAttachment, IncidentAttachmentKind, INCIDENT_SCHEMA,
};
pub use page::{
    compute_incident_aggregates, decode_incident_cursor, encode_incident_cursor, page_incidents,
    IncidentAggregates, IncidentPage, IncidentPageCursor,
};
