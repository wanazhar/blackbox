//! End-of-run checkpoint construction (1.5 U1).

use crate::core::checkpoint::Checkpoint;
use crate::core::run::Run;
use crate::storage::TraceStore;
use crate::workspace_manifest::{capture_workspace_manifest, ManifestLimits};

/// Inputs for building the end-of-run checkpoint.
pub struct CheckpointInputs<'a> {
    pub run: &'a Run,
    pub end_event_id: &'a str,
    pub environment_blob_key: Option<String>,
    pub git_commit: Option<String>,
    pub git_diff_blob: Option<String>,
    pub harness_session_id: Option<String>,
    pub capture_workspace: bool,
}

/// Build (and optionally enrich with workspace manifest) the end checkpoint.
///
/// Does not insert the checkpoint — caller persists via [`TraceStore::insert_checkpoint`].
pub async fn build_end_checkpoint(
    store: &dyn TraceStore,
    input: CheckpointInputs<'_>,
) -> Checkpoint {
    let mut end_checkpoint =
        Checkpoint::new(&input.run.id, input.end_event_id, &input.run.cwd);
    end_checkpoint.environment_blob = input.environment_blob_key;
    end_checkpoint.git_commit = input.git_commit;
    end_checkpoint.git_diff_blob = input.git_diff_blob;
    end_checkpoint.harness_session_id = input.harness_session_id;

    if input.capture_workspace {
        match capture_workspace_manifest(
            std::path::Path::new(&input.run.cwd),
            Some(store),
            ManifestLimits::default(),
        )
        .await
        {
            Ok(manifest) => match manifest.to_json() {
                Ok(json) => match store.store_blob(json.as_bytes()).await {
                    Ok(bref) => {
                        end_checkpoint.filesystem_manifest_blob = Some(bref.key);
                        if !manifest.capture_complete {
                            tracing::info!(
                                limitations = ?manifest.limitations,
                                files = manifest.files_total,
                                "workspace manifest captured with limitations"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to store workspace manifest blob")
                    }
                },
                Err(e) => tracing::warn!(error = %e, "failed to serialize workspace manifest"),
            },
            Err(e) => tracing::warn!(error = %e, "workspace manifest capture failed"),
        }
    }

    end_checkpoint
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::run::Run;
    use crate::storage::sqlite::SqliteStore;
    use std::sync::Arc;

    #[tokio::test]
    async fn builds_checkpoint_without_workspace() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = Run::new(vec!["true".into()], "/tmp".into());
        store.insert_run(&run).await.unwrap();
        let cp = build_end_checkpoint(
            store.as_ref(),
            CheckpointInputs {
                run: &run,
                end_event_id: "evt-end",
                environment_blob_key: Some("env".into()),
                git_commit: None,
                git_diff_blob: None,
                harness_session_id: None,
                capture_workspace: false,
            },
        )
        .await;
        assert_eq!(cp.event_id, "evt-end");
        assert_eq!(cp.environment_blob.as_deref(), Some("env"));
        assert!(cp.filesystem_manifest_blob.is_none());
    }
}
