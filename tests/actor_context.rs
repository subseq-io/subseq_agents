use subseq_agents::{ToolActor, api_keys::ApiKeyId, tool_actor_from_extensions};
use subseq_auth::prelude::UserId;
use uuid::Uuid;
#[test]
fn actor_resolution_uses_each_requests_direct_or_nested_extensions() {
    let actor = ToolActor {
        user_id: UserId(Uuid::new_v4()),
        mcp_mount_name: "queue".into(),
        api_key_id: ApiKeyId(Uuid::new_v4()),
        api_key_name: "key".into(),
    };
    let mut extensions = rmcp::model::Extensions::default();
    assert!(tool_actor_from_extensions(&extensions).is_none());
    let (mut parts, _) = http::Request::new(()).into_parts();
    parts.extensions.insert(actor.clone());
    extensions.insert(parts);
    assert_eq!(
        tool_actor_from_extensions(&extensions).unwrap().user_id.0,
        actor.user_id.0
    );
    let direct = ToolActor {
        user_id: UserId(Uuid::new_v4()),
        ..actor
    };
    extensions.insert(direct.clone());
    assert_eq!(
        tool_actor_from_extensions(&extensions).unwrap().user_id.0,
        direct.user_id.0
    );
}
