# Release Notes

## 1.15.1 - 2026-06-11

- Scoped target-file S3 audits to listed buckets and limited automatic IAM enumeration to compute-context targets.

## 1.15.0 - 2026-05-24

- Switched installation to `uv run python -m scope.install`; Node remains dashboard/MCP-only.
- Added Antigravity CLI support and kept Gemini CLI as a legacy Google target.
- Expanded audit coverage to 19 AWS services, including ECS, CloudFront, and Route 53.
- Added deterministic attack candidate seeding, validator-owned promotion, grouped final paths, and public exposure findings.
- Added review-only AWS CLI replay artifacts for approved audit and exploit paths.
- Added controls dashboard ideas for monitor-worthy findings that should not become detections.
- Updated Splunk guidance for Splunk Cloud MCP, optional MCP setup, manual SPL mode, and custom SIEM MCPs.
- Reworked dashboard report selection so one audit workflow creates one selectable report with optional controls data attached.
- Removed stale `config/index.json`, SCP/RCP scaffolding, guardrail wording, and historical implementation-plan docs from active configuration.

Migration:

- Run `uv run python -m scope.install`.
- Use `uv run python -m scope.install --antigravity` for new Google CLI installs.
- Use `--no-splunk-mcp` when Splunk MCP is unavailable or another SIEM path will be configured.
- Regenerate dashboard HTML with `cd dashboard && npm run dashboard`.
