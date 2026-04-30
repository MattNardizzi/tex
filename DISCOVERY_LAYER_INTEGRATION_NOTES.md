# Tex Discovery Layer Integration Notes

## What was integrated

This backend now supports the hybrid Discovery architecture:

1. **External discovery remains intact**
   - Existing connector-based discovery still lives under `src/tex/discovery/`.
   - Existing `/v1/discovery/*` endpoints remain wired.

2. **Adjudication-derived discovery was added**
   - Every evaluation request can now carry an `agent_identity` block.
   - If an unknown agent submits an action through Tex, Tex auto-registers it as a controlled agent before PDP evaluation.
   - If no `agent_id` is supplied, Tex derives a stable UUID from the runtime identity fingerprint.

3. **Controlled agent registry upgrade**
   - Auto-registered agents are marked in metadata as:
     - `visibility_status: controlled`
     - `discovery_mode: adjudication_derived`
     - `agent_fingerprint_hash`
     - tool / MCP / data-scope metadata

4. **Evidence-backed agent ledger upgrade**
   - Agent action ledger entries now include:
     - `policy_version`
     - `evidence_hash`
     - `system_prompt_hash`
     - `tool_manifest_hash`
     - `memory_hash`
     - `mcp_server_ids`
     - `tools`
     - `data_scopes`

5. **Evidence summary endpoint**
   - Added:
     - `GET /v1/agents/{agent_id}/evidence_summary`
   - Returns:
     - PERMIT / ABSTAIN / FORBID counts and rates
     - policy versions
     - top ASI codes
     - top capability violations
     - evidence root hash
     - HMAC signature

6. **Cross-agent systemic risk endpoint**
   - Added:
     - `GET /v1/agents/systemic-risks`
   - Detects shared patterns across agents:
     - same ASI code
     - same capability violation
     - same MCP server
     - same tool manifest hash

## Main files changed

- `src/tex/domain/evaluation.py`
- `src/tex/api/schemas.py`
- `src/tex/domain/agent.py`
- `src/tex/commands/evaluate_action.py`
- `src/tex/stores/action_ledger.py`
- `src/tex/api/agent_routes.py`

## New request field

Evaluation requests now support:

```json
"agent_identity": {
  "agent_id": null,
  "external_agent_id": "slack-bot-123",
  "agent_name": "Customer Support Agent",
  "agent_type": "slack_bot",
  "tenant_id": "acme",
  "owner": "support",
  "environment": "production",
  "model_provider": "openai",
  "model_name": "gpt-4.1",
  "framework": "custom",
  "system_prompt_hash": "sha256-or-prompt-digest",
  "tool_manifest_hash": "sha256-or-tool-digest",
  "memory_hash": "sha256-or-memory-digest",
  "tools": ["send_slack_message", "crm_lookup"],
  "mcp_server_ids": ["crm-mcp"],
  "data_scopes": ["customer_support"],
  "metadata": {}
}
```

## Design principle

Tex Discovery is now dual-source:

- **Observed** = external connector saw the agent exists.
- **Controlled** = Tex adjudicated the agent's attempted action and can prove the decision.

This keeps the completeness path while making Tex's deeper edge the evidence-backed control path.
