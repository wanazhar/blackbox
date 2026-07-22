//! Multi-run incident reconstruction (1.7 Phase F).

mod export;
mod graph;
mod model;

pub use export::{
    build_incident_export, validate_incident_export, IncidentExport, INCIDENT_EXPORT_SCHEMA,
};
pub use graph::{
    build_incident_graph, GraphInputs, IncidentGraph, IncidentNode, IncidentSignal,
    TechniqueReuse,
};
pub use model::{
    attach_to_incident, Incident, IncidentAttachment, IncidentAttachmentKind, INCIDENT_SCHEMA,
};
