//! Decision read access helpers.

use std::collections::BTreeMap;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use temper_authz::{AuthenticatedRequestContext, Principal, PrincipalKind};

use super::require_policy_auth;
use crate::state::{PendingDecision, ServerState};

/// True when the caller is the principal who was denied.
///
/// Matches the denied instance id, and — when both sides have an agent type —
/// the stable agent identity. A new `AgentCredential` mints a new
/// `agent_instance_id` (`principal.id`); type is what survives that mint.
pub(crate) fn is_self_resolution(principal: &Principal, decision: &PendingDecision) -> bool {
    if !principal.id.is_empty() && principal.id == decision.agent_id {
        return true;
    }
    let caller_type = principal
        .agent_type
        .as_deref()
        .filter(|value| !value.is_empty());
    let denied_type = decision
        .agent_type
        .as_deref()
        .filter(|value| !value.is_empty());
    matches!((caller_type, denied_type), (Some(caller), Some(denied)) if caller == denied)
}

/// Forbid the denied principal from approving or denying their own decision.
///
/// Independent of Cedar (ADR-0172). A caller with `manage_policies` still
/// cannot resolve a decision whose denied agent is their own identity.
pub(crate) fn reject_self_resolution(
    principal: &Principal,
    decision: &PendingDecision,
) -> Option<Response> {
    if !is_self_resolution(principal, decision) {
        return None;
    }
    tracing::warn!(
        decision_id = %decision.id,
        agent_id = %decision.agent_id,
        agent_type = decision.agent_type.as_deref().unwrap_or(""),
        caller_id = %principal.id,
        caller_type = principal.agent_type.as_deref().unwrap_or(""),
        "denied principal cannot approve or deny their own decision"
    );
    Some(
        (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "error": {
                    "code": "AuthorizationDenied",
                    "message": "The denied principal cannot approve or deny this decision",
                }
            })),
        )
            .into_response(),
    )
}

#[derive(Debug)]
pub(crate) enum DecisionListAccess {
    Full,
    Owned { agent_id: String },
}

impl DecisionListAccess {
    pub(crate) fn filter(&self, data_strings: Vec<String>) -> Vec<String> {
        match self {
            Self::Full => data_strings,
            Self::Owned { agent_id } => data_strings
                .into_iter()
                .filter(|data| {
                    serde_json::from_str::<PendingDecision>(data)
                        .map(|decision| decision.agent_id == *agent_id)
                        .unwrap_or(false)
                })
                .collect(),
        }
    }
}

/// Classify list visibility from Cedar + principal kind.
///
/// `manage_policies` is Full (the operator queue). An Agent without that
/// permit is Owned. Anyone else is `None` and must be denied.
pub(crate) fn classify_decision_list_access(
    principal: &Principal,
    has_manage_policies: bool,
) -> Option<DecisionListAccess> {
    if has_manage_policies {
        return Some(DecisionListAccess::Full);
    }
    if matches!(principal.kind, PrincipalKind::Agent) {
        return Some(DecisionListAccess::Owned {
            agent_id: principal.id.clone(),
        });
    }
    None
}

fn has_manage_policies(state: &ServerState, authenticated: &AuthenticatedRequestContext) -> bool {
    let security_ctx = authenticated.security_context();
    let tenant = authenticated.tenant().as_str();
    let resource_attrs = BTreeMap::from([
        (
            "id".to_string(),
            serde_json::Value::String(tenant.to_string()),
        ),
        (
            "tenant".to_string(),
            serde_json::Value::String(tenant.to_string()),
        ),
    ]);
    state
        .authorize_with_context(
            security_ctx,
            "manage_policies",
            "PolicySet",
            &resource_attrs,
            tenant,
        )
        .is_ok()
}

pub(crate) async fn decision_list_access(
    state: &ServerState,
    authenticated: &AuthenticatedRequestContext,
) -> Result<DecisionListAccess, Response> {
    let security_ctx = authenticated.security_context();
    if let Some(access) = classify_decision_list_access(
        &security_ctx.principal,
        has_manage_policies(state, authenticated),
    ) {
        return Ok(access);
    }

    match require_policy_auth(state, authenticated).await {
        Some(response) => Err(response),
        None => Ok(DecisionListAccess::Full),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(id: &str, agent_type: Option<&str>) -> Principal {
        Principal {
            id: id.to_string(),
            kind: PrincipalKind::Agent,
            role: None,
            acting_for: None,
            agent_type: agent_type.map(str::to_string),
            attributes: Default::default(),
        }
    }

    fn pending(agent_id: &str, agent_type: Option<&str>) -> PendingDecision {
        let mut decision = PendingDecision::from_denial(
            "acme",
            agent_id,
            "Assign",
            "Issue",
            "issue-1",
            serde_json::json!({"id": "issue-1"}),
            "denied",
            None,
        );
        decision.agent_type = agent_type.map(str::to_string);
        decision
    }

    #[test]
    fn self_resolution_matches_denied_principal_only() {
        let decision = pending("developer", None);
        assert!(is_self_resolution(
            &agent("developer", Some("developer")),
            &decision
        ));
        assert!(!is_self_resolution(
            &agent("operator", Some("operator")),
            &decision
        ));
        assert!(!is_self_resolution(
            &agent("developer", Some("developer")),
            &pending("operator", None)
        ));
    }

    #[test]
    fn self_resolution_matches_stable_agent_type_across_instance_ids() {
        let decision = pending("developer-inst-1", Some("developer"));
        assert!(is_self_resolution(
            &agent("developer-inst-2", Some("developer")),
            &decision
        ));
        assert!(!is_self_resolution(
            &agent("operator", Some("operator")),
            &decision
        ));
    }

    #[test]
    fn reject_self_resolution_blocks_denied_principal() {
        let decision = pending("developer", None);
        assert!(
            reject_self_resolution(&agent("developer", Some("developer")), &decision).is_some()
        );
        assert!(reject_self_resolution(&agent("operator", Some("operator")), &decision).is_none());
    }

    #[test]
    fn list_access_manage_policies_is_full_even_for_agents() {
        let operator = agent("operator", Some("operator"));
        assert!(matches!(
            classify_decision_list_access(&operator, true),
            Some(DecisionListAccess::Full)
        ));
    }

    #[test]
    fn list_access_agent_without_manage_policies_is_owned() {
        let developer = agent("developer", Some("developer"));
        match classify_decision_list_access(&developer, false) {
            Some(DecisionListAccess::Owned { agent_id }) => assert_eq!(agent_id, "developer"),
            other => panic!("expected Owned, got {other:?}"),
        }
    }

    #[test]
    fn list_access_non_agent_without_manage_policies_is_denied() {
        let customer = Principal {
            id: "cust-1".to_string(),
            kind: PrincipalKind::Customer,
            role: None,
            acting_for: None,
            agent_type: None,
            attributes: Default::default(),
        };
        assert!(classify_decision_list_access(&customer, false).is_none());
    }
}
