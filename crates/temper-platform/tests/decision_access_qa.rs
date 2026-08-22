//! San QA replays for ARN-389 / ADR-0172 decision access.
//!
//! Finding 1: operator `GET /decisions?status=pending` after a developer
//! denial must show that PD (`temper decide` polls this URL).
//! Finding 3: a second `AgentCredential` / new instance id for the denied
//! agent still gets 403 on approve.

use std::collections::BTreeMap;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use temper_platform::bootstrap::{bootstrap_agent_specs, bootstrap_operator_credential};
use temper_platform::router::build_platform_router;
use temper_platform::state::PlatformState;
use temper_runtime::tenant::TenantId;
use temper_server::StorageStack;
use temper_server::identity::hash_token;
use temper_server::request_context::AgentContext;
use temper_store_turso::TursoEventStore;
use tower::ServiceExt;

mod common;
use common::http::body_json;

const OPERATOR_KEY: &str = "tmpr_decision-access-qa-operator";
const DEVELOPER_KEY: &str = "tmpr_decision-access-qa-developer";
const DEVELOPER_KEY_2: &str = "tmpr_decision-access-qa-developer-2";

async fn virgin_state_with_store(tenant: &str) -> (PlatformState, tempfile::TempDir) {
    let temp = tempfile::tempdir().expect("temp policy db");
    let db_url = format!("file:{}", temp.path().join("policy.db").display());
    let store = TursoEventStore::new(&db_url, None)
        .await
        .expect("create turso store");
    let mut state = PlatformState::new(None);
    bootstrap_agent_specs(&state, tenant, false, &BTreeMap::new());
    state
        .server
        .set_storage_stack(StorageStack::from_turso(store));
    (state, temp)
}

async fn define_developer_type(state: &PlatformState, tenant: &str) {
    let tenant_id = TenantId::new(tenant);
    let ctx = AgentContext::system();
    let _ = state
        .server
        .dispatch_tenant_action(
            &tenant_id,
            "AgentType",
            "developer-type",
            "Define",
            json!({
                "name": "developer",
                "system_prompt": "test",
                "tool_set": "local",
                "model": "none",
                "max_turns": "0",
                "adapter_config": "{}",
                "default_budget_cents": "0"
            }),
            &ctx,
        )
        .await;
}

async fn issue_developer_credential(
    state: &PlatformState,
    tenant: &str,
    plaintext: &str,
    instance_id: &str,
) {
    let tenant_id = TenantId::new(tenant);
    let ctx = AgentContext::system();
    let key_hash = hash_token(plaintext);
    let _ = state
        .server
        .dispatch_tenant_action(
            &tenant_id,
            "AgentCredential",
            &key_hash,
            "Issue",
            json!({
                "agent_type_id": "developer-type",
                "agent_instance_id": instance_id,
                "key_hash": key_hash,
                "key_prefix": plaintext.chars().take(8).collect::<String>(),
                "description": "developer test credential",
                "created_by": "test",
                "expires_at": ""
            }),
            &ctx,
        )
        .await;
}

fn approve_body() -> String {
    json!({
        "scope": {
            "principal": "this_agent",
            "action": "this_action",
            "resource": "this_resource",
            "duration": "always"
        }
    })
    .to_string()
}

#[tokio::test]
async fn operator_list_sees_developer_pending_decision() {
    let tenant = "default";
    let (state, _temp) = virgin_state_with_store(tenant).await;
    bootstrap_operator_credential(&state, OPERATOR_KEY, tenant).await;
    define_developer_type(&state, tenant).await;
    issue_developer_credential(&state, tenant, DEVELOPER_KEY, "developer-inst-1").await;

    let app = build_platform_router(state);

    let denied = app
        .clone()
        .oneshot(
            Request::get(format!("/api/tenants/{tenant}/policies"))
                .header("Authorization", format!("Bearer {DEVELOPER_KEY}"))
                .header("X-Tenant-Id", tenant)
                .body(Body::empty())
                .expect("developer GET policies"),
        )
        .await
        .expect("developer GET policies should run");
    assert_eq!(
        denied.status(),
        StatusCode::FORBIDDEN,
        "developer GET /policies must create a pending decision"
    );
    let denied_body = body_json(denied).await;
    let message = denied_body["error"]["message"].as_str().unwrap_or_default();
    let decision_id = message
        .rsplit_once(" Decision ")
        .map(|(_, id)| id.trim().to_string())
        .expect("denial must name the pending decision");

    let listed = app
        .oneshot(
            Request::get(format!("/api/tenants/{tenant}/decisions?status=pending"))
                .header("Authorization", format!("Bearer {OPERATOR_KEY}"))
                .header("X-Tenant-Id", tenant)
                .body(Body::empty())
                .expect("operator list decisions"),
        )
        .await
        .expect("operator list should run");
    assert_eq!(
        listed.status(),
        StatusCode::OK,
        "operator GET /decisions must succeed"
    );
    let listed_body = body_json(listed).await;
    let empty = Vec::new();
    let ids: Vec<&str> = listed_body["decisions"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(|row| row["id"].as_str())
        .collect();
    assert!(
        ids.contains(&decision_id.as_str()),
        "operator list must include the developer PD {decision_id}: {listed_body}"
    );
    assert!(
        listed_body["pending_count"].as_u64().unwrap_or(0) >= 1,
        "temper decide polls pending_count: {listed_body}"
    );
}

#[tokio::test]
async fn second_credential_of_denied_agent_cannot_approve() {
    let tenant = "acme";
    let (state, _temp) = virgin_state_with_store(tenant).await;
    bootstrap_operator_credential(&state, OPERATOR_KEY, tenant).await;
    define_developer_type(&state, tenant).await;
    issue_developer_credential(&state, tenant, DEVELOPER_KEY, "developer-inst-1").await;
    issue_developer_credential(&state, tenant, DEVELOPER_KEY_2, "developer-inst-2").await;

    let developer_permit = format!(
        r#"permit(
  principal is Agent,
  action == Action::"manage_policies",
  resource == PolicySet::"{tenant}"
) when {{
  principal.agent_type == "developer" &&
  principal.agentTypeVerified == true
}};"#
    );

    let app = build_platform_router(state);

    let denied = app
        .clone()
        .oneshot(
            Request::get(format!("/api/tenants/{tenant}/policies"))
                .header("Authorization", format!("Bearer {DEVELOPER_KEY}"))
                .header("X-Tenant-Id", tenant)
                .body(Body::empty())
                .expect("developer GET policies"),
        )
        .await
        .expect("developer GET policies should run");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let denied_body = body_json(denied).await;
    let message = denied_body["error"]["message"].as_str().unwrap_or_default();
    let decision_id = message
        .rsplit_once(" Decision ")
        .map(|(_, id)| id.trim().to_string())
        .expect("denial must name the pending decision");

    let created = app
        .clone()
        .oneshot(
            Request::post(format!("/api/tenants/{tenant}/policies/create"))
                .header("Authorization", format!("Bearer {OPERATOR_KEY}"))
                .header("X-Tenant-Id", tenant)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "policy_id": "developer-manage-policies",
                        "cedar_text": developer_permit,
                    })
                    .to_string(),
                ))
                .expect("create developer policy"),
        )
        .await
        .expect("create developer policy should run");
    assert_eq!(created.status(), StatusCode::CREATED);

    let second_key_approve = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/tenants/{tenant}/decisions/{decision_id}/approve"
            ))
            .header("Authorization", format!("Bearer {DEVELOPER_KEY_2}"))
            .header("X-Tenant-Id", tenant)
            .header("content-type", "application/json")
            .body(Body::from(approve_body()))
            .expect("second-credential approve"),
        )
        .await
        .expect("second-credential approve should run");
    assert_eq!(
        second_key_approve.status(),
        StatusCode::FORBIDDEN,
        "new instance id for the denied agent must still get 403"
    );

    let first_key_approve = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/tenants/{tenant}/decisions/{decision_id}/approve"
            ))
            .header("Authorization", format!("Bearer {DEVELOPER_KEY}"))
            .header("X-Tenant-Id", tenant)
            .header("content-type", "application/json")
            .body(Body::from(approve_body()))
            .expect("first-credential approve"),
        )
        .await
        .expect("first-credential approve should run");
    assert_eq!(
        first_key_approve.status(),
        StatusCode::FORBIDDEN,
        "original denied instance must still get 403"
    );

    let operator_approve = app
        .oneshot(
            Request::post(format!(
                "/api/tenants/{tenant}/decisions/{decision_id}/approve"
            ))
            .header("Authorization", format!("Bearer {OPERATOR_KEY}"))
            .header("X-Tenant-Id", tenant)
            .header("content-type", "application/json")
            .body(Body::from(approve_body()))
            .expect("operator approve"),
        )
        .await
        .expect("operator approve should run");
    assert_eq!(
        operator_approve.status(),
        StatusCode::OK,
        "verified operator must still approve another agent's decision"
    );
}
