use sdk_rust::{
    ArtifactProfile, Client, ProtectionOperation, ResourceDescriptor, SdkProtectionPlanRequest,
    WorkloadDescriptor,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder("https://api.lattix.io")
        .with_bearer_token("replace-me")
        .build()?;

    let bootstrap = client.bootstrap()?;
    println!("bootstrap: {bootstrap:#?}");

    let plan = client.protection_plan(&SdkProtectionPlanRequest {
        operation: ProtectionOperation::Protect,
        workload: WorkloadDescriptor {
            application: "example-app".to_string(),
            environment: Some("dev".to_string()),
            component: Some("worker".to_string()),
        },
        resource: ResourceDescriptor {
            kind: "document".to_string(),
            id: Some("doc-123".to_string()),
            mime_type: Some("application/pdf".to_string()),
        },
        preferred_artifact_profile: Some(ArtifactProfile::Tdf),
        content_digest: Some("sha256:example".to_string()),
        content_size_bytes: Some(1024),
        purpose: Some("store".to_string()),
        labels: vec!["confidential".to_string()],
        attributes: std::collections::BTreeMap::new(),
    })?;

    println!("plan: {plan:#?}");
    Ok(())
}
