//! Multi-run incident reconstruction (1.7 Phase F).

mod graph;
mod model;

pub use graph::{
    build_incident_graph, GraphInputs, IncidentGraph, IncidentNode, IncidentSignal,
    TechniqueReuse,
};
pub use model::{
    attach_to_incident, Incident, IncidentAttachment, IncidentAttachmentKind, INCIDENT_SCHEMA,
};
