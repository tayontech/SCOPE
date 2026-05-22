# Graph V2 Python Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move deterministic graph extraction from `bin/extract-graph.js` into the Python runtime and emit graph v2 with traceable nodes, stable edge IDs, and evidence records.

**Architecture:** Add `scope/runtime/graph.py` as the graph builder. `scope.runtime.post_processing.build_graph()` calls the Python builder directly instead of shelling out to Node. Keep dashboard/report generation in Node, but remove the old JS graph extractor and JS graph tests after Python parity tests cover the current graph relationships.

**Tech Stack:** Python 3, pytest, Pydantic `ModuleEnvelope`, existing SCOPE runtime modules, existing Node tooling for dashboard and installer only.

**Current implementation note:** SCOPE now treats graph and schema contract coverage as Python-owned. Historical steps below that mention `tests/js/*`, `node tests/js/*`, or `npm test` map to pytest coverage under `tests/scope/runtime/` and `tests/scope/contracts/`. Keep Node for dashboard, report, and installer tooling only.

---

## File Structure

- Create: `scope/runtime/graph.py`
  - Owns module envelope loading, node extraction, edge extraction, evidence records, dedupe/sort, graph v2 metadata, and graph write helpers.
- Modify: `scope/runtime/post_processing.py`
  - Removes Node subprocess graph extraction.
  - Calls `scope.runtime.graph.build_graph_from_run()`.
- Create: `tests/scope/runtime/test_graph.py`
  - Tests graph v2 contract and relationship extraction.
- Modify: `tests/scope/runtime/test_post_processing.py`
  - Updates expectations for `schema_version`, metadata, stable edge IDs, and Python graph error handling.
- Modify: `config/schemas/audit.schema.json`
  - Allows graph v2 fields and new `edge_type` values: `resource_policy_allows`, `encrypted_by`.
- Delete: `bin/extract-graph.js`
  - Node no longer owns graph extraction.
- Delete: `tests/js/extract-graph.test.js`
  - Replaced by Python tests.
- Delete: `tests/js/fixtures/extract-graph/**`
  - Replaced by Python fixtures embedded in focused pytest tests.
- Modify: `README.md`, `ARCHITECTURE.md`, `agents/subagents/scope-attack-analyze.md`
  - Replace references to `extract-graph.js` with Python runtime graph extraction and graph v2.

## Task 1: Add Failing Graph V2 Contract Tests

**Files:**
- Create: `tests/scope/runtime/test_graph.py`

- [ ] **Step 1: Write failing tests for graph v2 base shape, node metadata, stable edge IDs, and evidence**

Add `tests/scope/runtime/test_graph.py`:

```python
from __future__ import annotations

import json
from pathlib import Path

from scope.runtime.graph import build_graph_from_run


def write_module(
    run_dir: Path,
    service: str,
    region: str,
    resources: list[dict],
    *,
    account_id: str = "123456789012",
    status: str = "complete",
) -> None:
    module_dir = run_dir / "modules" / service
    module_dir.mkdir(parents=True, exist_ok=True)
    (module_dir / f"{region}.json").write_text(
        json.dumps(
            {
                "module": service,
                "account_id": account_id,
                "region": region,
                "status": status,
                "resources": resources,
                "coverage": [],
                "errors": [],
            }
        ),
        encoding="utf-8",
    )


def test_graph_v2_extracts_iam_and_lambda_relationship_with_evidence(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "iam",
        "global",
        [
            {
                "resource_type": "iam_role",
                "resource_id": "LambdaExecRole",
                "arn": "arn:aws:iam::123456789012:role/LambdaExecRole",
                "is_service_linked": False,
                "trust_relationships": [
                    {
                        "principal": "lambda.amazonaws.com",
                        "trust_type": "service",
                        "is_wildcard": False,
                        "has_external_id": False,
                        "has_mfa_condition": False,
                    }
                ],
            }
        ],
    )
    write_module(
        tmp_path,
        "lambda",
        "us-east-1",
        [
            {
                "resource_type": "lambda_function",
                "resource_id": "api",
                "arn": "arn:aws:lambda:us-east-1:123456789012:function:api",
                "role": "arn:aws:iam::123456789012:role/LambdaExecRole",
            }
        ],
    )

    graph = build_graph_from_run(tmp_path)

    assert graph["schema_version"] == "2.0"
    assert graph["metadata"]["source"] == "scope-runtime"

    role = next(node for node in graph["nodes"] if node["id"] == "role:LambdaExecRole")
    assert role["resource_type"] == "iam_role"
    assert role["arn"] == "arn:aws:iam::123456789012:role/LambdaExecRole"
    assert role["service"] == "iam"
    assert role["region"] == "global"
    assert role["account_id"] == "123456789012"
    assert role["source_path"] == "modules/iam/global.json"

    edge = next(
        edge
        for edge in graph["edges"]
        if edge["source"] == "compute:lambda:api"
        and edge["target"] == "role:LambdaExecRole"
        and edge["edge_type"] == "executes_as"
    )
    assert edge["id"] == "edge:executes_as:compute:lambda:api->role:LambdaExecRole"
    assert edge["relationship"] == "lambda_function_executes_as_iam_role"
    assert edge["service"] == "lambda"
    assert edge["region"] == "us-east-1"
    assert edge["account_id"] == "123456789012"
    assert edge["evidence"] == [
        {
            "source_path": "modules/lambda/us-east-1.json",
            "resource_type": "lambda_function",
            "resource_id": "api",
            "arn": "arn:aws:lambda:us-east-1:123456789012:function:api",
            "field": "role",
        }
    ]
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run:

```bash
uv run pytest tests/scope/runtime/test_graph.py -q
```

Expected: fail with `ModuleNotFoundError: No module named 'scope.runtime.graph'`.

## Task 2: Implement Graph Builder Core

**Files:**
- Create: `scope/runtime/graph.py`
- Test: `tests/scope/runtime/test_graph.py`

- [ ] **Step 1: Add minimal graph module that passes Task 1**

Create `scope/runtime/graph.py`:

```python
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from pydantic import ValidationError

from scope.core.models import ModuleEnvelope

Graph = dict[str, Any]
Resource = dict[str, Any]


def build_graph_from_run(run_dir: Path) -> Graph:
    modules = _load_modules(run_dir)
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    omissions: list[dict[str, Any]] = []

    by_service = _group_by_service(modules)

    _extract_iam(by_service.get("iam", []), nodes, edges)
    _extract_lambda(by_service.get("lambda", []), nodes, edges)
    _ensure_edge_endpoint_nodes(nodes, edges)

    return {
        "schema_version": "2.0",
        "metadata": {
            "source": "scope-runtime",
            "relationship_extractors": ["iam", "lambda"],
            "omissions": omissions,
        },
        "nodes": _dedupe_sort(nodes, lambda node: node["id"]),
        "edges": _dedupe_edges(edges),
    }


def write_graph(run_dir: Path, graph: Graph) -> Path:
    path = run_dir / "graph.json"
    path.write_text(json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _load_modules(run_dir: Path) -> list[tuple[str, ModuleEnvelope]]:
    modules_dir = run_dir / "modules"
    if not modules_dir.exists():
        return []

    loaded: list[tuple[str, ModuleEnvelope]] = []
    for path in sorted(modules_dir.glob("*/*.json")):
        rel_path = path.relative_to(run_dir).as_posix()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            loaded.append((rel_path, ModuleEnvelope.model_validate(payload)))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValidationError):
            continue
    return loaded


def _group_by_service(modules: list[tuple[str, ModuleEnvelope]]) -> dict[str, list[tuple[str, ModuleEnvelope]]]:
    grouped: dict[str, list[tuple[str, ModuleEnvelope]]] = {}
    for rel_path, envelope in modules:
        grouped.setdefault(envelope.module, []).append((rel_path, envelope))
    return grouped


def _extract_iam(
    modules: list[tuple[str, ModuleEnvelope]],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> None:
    for source_path, envelope in modules:
        for resource in envelope.resources:
            resource_type = resource.get("resource_type")
            resource_id = resource.get("resource_id")
            if resource_type == "iam_role" and not resource.get("is_service_linked"):
                nodes.append(_node(f"role:{resource_id}", resource_id, "role", resource, envelope, source_path))
                for trust in resource.get("trust_relationships") or []:
                    principal = str(trust.get("principal") or "")
                    trust_type = trust.get("trust_type")
                    if trust_type == "service":
                        source = f"svc:{principal}"
                        edge_type = "service"
                    elif trust_type == "same-account" and ":user/" in principal:
                        source = f"user:{principal.split('/')[-1]}"
                        edge_type = "trust"
                    elif trust_type == "same-account" and ":role/" in principal:
                        source = f"role:{principal.split('/')[-1]}"
                        edge_type = "trust"
                    else:
                        source = f"external:{principal or 'unknown'}"
                        edge_type = "trust"
                    edges.append(
                        _edge(
                            source,
                            f"role:{resource_id}",
                            edge_type,
                            "can_assume",
                            "iam_role_trusts_principal",
                            envelope,
                            source_path,
                            resource,
                            "trust_relationships",
                            trust_type=trust_type,
                            severity=trust.get("risk"),
                        )
                    )
            elif resource_type == "iam_user":
                nodes.append(_node(f"user:{resource_id}", resource_id, "user", resource, envelope, source_path))
                for group in resource.get("groups") or []:
                    edges.append(
                        _edge(
                            f"user:{resource_id}",
                            f"group:{group}",
                            "membership",
                            "member_of",
                            "iam_user_member_of_group",
                            envelope,
                            source_path,
                            resource,
                            "groups",
                        )
                    )
            elif resource_type == "iam_group":
                nodes.append(_node(f"group:{resource_id}", resource_id, "group", resource, envelope, source_path))
            elif resource_type == "oidc_provider":
                url = resource.get("url") or resource_id
                nodes.append(_node(f"oidc:{url}", url, "oidc", resource, envelope, source_path))
                for role_arn in resource.get("assumed_role_arns") or []:
                    edges.append(
                        _edge(
                            f"oidc:{url}",
                            f"role:{str(role_arn).split('/')[-1]}",
                            "authenticates_to",
                            "authenticates_to",
                            "oidc_provider_authenticates_to_role",
                            envelope,
                            source_path,
                            resource,
                            "assumed_role_arns",
                        )
                    )


def _extract_lambda(
    modules: list[tuple[str, ModuleEnvelope]],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> None:
    for source_path, envelope in modules:
        for resource in envelope.resources:
            if resource.get("resource_type") != "lambda_function":
                continue
            resource_id = resource.get("resource_id")
            nodes.append(_node(f"compute:lambda:{resource_id}", resource_id, "compute", resource, envelope, source_path))
            role = resource.get("role")
            if role:
                edges.append(
                    _edge(
                        f"compute:lambda:{resource_id}",
                        f"role:{str(role).split('/')[-1]}",
                        "executes_as",
                        "executes_as",
                        "lambda_function_executes_as_iam_role",
                        envelope,
                        source_path,
                        resource,
                        "role",
                    )
                )


def _node(
    node_id: str,
    label: Any,
    node_type: str,
    resource: Resource,
    envelope: ModuleEnvelope,
    source_path: str,
) -> dict[str, Any]:
    return {
        "id": node_id,
        "label": str(label or node_id),
        "type": node_type,
        "resource_type": resource.get("resource_type"),
        "arn": resource.get("arn"),
        "service": envelope.module,
        "region": envelope.region,
        "account_id": envelope.account_id,
        "source_path": source_path,
        "_source": "api",
    }


def _edge(
    source: str,
    target: str,
    edge_type: str,
    label: str,
    relationship: str,
    envelope: ModuleEnvelope,
    source_path: str,
    resource: Resource,
    field: str,
    **extra: Any,
) -> dict[str, Any]:
    edge = {
        "id": f"edge:{edge_type}:{source}->{target}",
        "source": source,
        "target": target,
        "edge_type": edge_type,
        "label": label,
        "relationship": relationship,
        "service": envelope.module,
        "region": envelope.region,
        "account_id": envelope.account_id,
        "evidence": [
            {
                "source_path": source_path,
                "resource_type": resource.get("resource_type"),
                "resource_id": resource.get("resource_id"),
                "arn": resource.get("arn"),
                "field": field,
            }
        ],
        "_source": "api",
    }
    edge.update({key: value for key, value in extra.items() if value is not None})
    return edge


def _ensure_edge_endpoint_nodes(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> None:
    existing = {node["id"] for node in nodes}
    for edge in edges:
        for endpoint in (edge["source"], edge["target"]):
            if endpoint in existing:
                continue
            nodes.append(
                {
                    "id": endpoint,
                    "label": _label_from_endpoint(endpoint),
                    "type": _type_from_endpoint(endpoint),
                    "_source": "api",
                }
            )
            existing.add(endpoint)


def _label_from_endpoint(node_id: str) -> str:
    for prefix in (
        "compute:lambda:",
        "external:",
        "oidc:",
        "svc:",
        "user:",
        "role:",
        "group:",
    ):
        if node_id.startswith(prefix):
            return node_id[len(prefix):]
    return node_id


def _type_from_endpoint(node_id: str) -> str:
    if node_id.startswith("user:"):
        return "user"
    if node_id.startswith("role:"):
        return "role"
    if node_id.startswith("group:"):
        return "group"
    if node_id.startswith("compute:"):
        return "compute"
    if node_id.startswith("oidc:"):
        return "oidc"
    return "external"


def _dedupe_sort(items: list[dict[str, Any]], key_fn: Callable[[dict[str, Any]], str]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for item in items:
        seen.setdefault(key_fn(item), item)
    return [seen[key] for key in sorted(seen)]


def _dedupe_edges(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for edge in edges:
        existing = merged.get(edge["id"])
        if existing is None:
            merged[edge["id"]] = edge
            continue
        existing_evidence = existing.setdefault("evidence", [])
        for evidence in edge.get("evidence", []):
            if evidence not in existing_evidence:
                existing_evidence.append(evidence)
    return [merged[key] for key in sorted(merged)]
```

- [ ] **Step 2: Run focused graph tests**

Run:

```bash
uv run pytest tests/scope/runtime/test_graph.py -q
```

Expected: pass.

## Task 3: Add Full Relationship Coverage Tests

**Files:**
- Modify: `tests/scope/runtime/test_graph.py`

- [ ] **Step 1: Add failing tests for resource policy and KMS dependency edges**

Append:

```python
def test_graph_v2_extracts_resource_policy_and_kms_dependency_edges(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "s3",
        "global",
        [
            {
                "resource_type": "s3_bucket",
                "resource_id": "data-bucket",
                "arn": "arn:aws:s3:::data-bucket",
                "policy": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                                "Action": "s3:GetObject",
                                "Resource": "arn:aws:s3:::data-bucket/*",
                            }
                        ],
                    }
                ),
                "policy_status": "present",
                "encryption": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/key-1"}}]},
            }
        ],
    )
    write_module(
        tmp_path,
        "kms",
        "us-east-1",
        [
            {
                "resource_type": "kms_key",
                "resource_id": "key-1",
                "arn": "arn:aws:kms:us-east-1:123456789012:key/key-1",
                "policy_principals": ["arn:aws:iam::999999999999:root"],
            }
        ],
    )

    graph = build_graph_from_run(tmp_path)

    assert any(node["id"] == "data:s3:data-bucket" for node in graph["nodes"])
    assert any(node["id"] == "data:kms:key-1" for node in graph["nodes"])
    assert any(
        edge["source"] == "external:arn:aws:iam::999999999999:root"
        and edge["target"] == "data:s3:data-bucket"
        and edge["edge_type"] == "resource_policy_allows"
        and edge["relationship"] == "s3_bucket_policy_allows_principal"
        for edge in graph["edges"]
    )
    assert any(
        edge["source"] == "data:s3:data-bucket"
        and edge["target"] == "data:kms:key-1"
        and edge["edge_type"] == "encrypted_by"
        and edge["relationship"] == "s3_bucket_encrypted_by_kms_key"
        for edge in graph["edges"]
    )
```

- [ ] **Step 2: Run focused graph tests and verify failure**

Run:

```bash
uv run pytest tests/scope/runtime/test_graph.py -q
```

Expected: fail because `s3`, `kms`, `resource_policy_allows`, and `encrypted_by` extraction are not implemented.

## Task 4: Implement Remaining Relationship Extractors

**Files:**
- Modify: `scope/runtime/graph.py`
- Test: `tests/scope/runtime/test_graph.py`

- [ ] **Step 1: Add resource nodes for all supported services**

Add extractors and node ID helpers for:

```text
s3_bucket -> data:s3:<bucket>
kms_key -> data:kms:<key-id>
secrets_secret -> data:secrets:<secret-name>
rds_instance -> data:rds:<db-id>
rds_snapshot -> data:rds:<snapshot-id>
dynamodb_table -> data:dynamodb:<table-name>
ssm_parameter -> data:ssm:<parameter-name>
sns_topic -> messaging:sns:<topic-arn>
sqs_queue -> messaging:sqs:<queue-url>
apigateway_*_api -> gateway:apigw:<api-id>
ec2_instance -> compute:ec2:<instance-id>
codebuild_project -> compute:codebuild:<project-name>
bedrock_agent -> ai:bedrock:<agent-id>
bedrock_knowledge_base -> ai:bedrock:<kb-id>
cognito_identity_pool -> idp:cognito:<pool-id>
cognito_user_pool -> idp:cognito:<pool-id>
```

- [ ] **Step 2: Add relationship extractors**

Implement:

```text
CodeBuild service_role -> executes_as
Bedrock agent execution_role_arn -> executes_as
Bedrock knowledge base role_arn -> executes_as
API Gateway lambda_integrations[] -> invokes
Cognito authenticated_role_arn / unauthenticated_role_arn -> authenticates_to
resource policy principals -> resource_policy_allows
KMS key references -> encrypted_by
```

- [ ] **Step 3: Add EC2 omission behavior**

If `ec2_instance.iam_instance_profile` lacks a resolvable role ARN or role name, do not emit `executes_as`. Add:

```json
{
  "service": "ec2",
  "resource_id": "i-123",
  "relationship": "ec2_instance_executes_as_iam_role",
  "reason": "iam_instance_profile_role_unresolved"
}
```

to `metadata.omissions`.

- [ ] **Step 4: Run graph tests**

Run:

```bash
uv run pytest tests/scope/runtime/test_graph.py -q
```

Expected: pass.

## Task 5: Switch Post-Processing To Python Graph Builder

**Files:**
- Modify: `scope/runtime/post_processing.py`
- Modify: `tests/scope/runtime/test_post_processing.py`

- [ ] **Step 1: Write failing post-processing test for Python graph call**

Modify `test_build_graph_writes_graph_json_from_nested_modules` to assert:

```python
assert graph["schema_version"] == "2.0"
assert graph["metadata"]["source"] == "scope-runtime"
assert any(edge["id"].startswith("edge:") for edge in graph["edges"])
```

- [ ] **Step 2: Run focused test and verify failure**

Run:

```bash
uv run pytest tests/scope/runtime/test_post_processing.py::test_build_graph_writes_graph_json_from_nested_modules -q
```

Expected: fail while `post_processing.build_graph()` still uses `bin/extract-graph.js`.

- [ ] **Step 3: Replace Node subprocess implementation**

In `scope/runtime/post_processing.py`:

- remove `subprocess` import
- import Python graph builder:

```python
from scope.runtime.graph import build_graph_from_run, write_graph
```

- replace `build_graph()` body with:

```python
def build_graph(run_dir: Path, graph_script: Path | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if graph_script is not None:
        return _empty_graph(), [_graph_error("external graph scripts are no longer supported", graph_script=str(graph_script))]
    try:
        graph = build_graph_from_run(run_dir)
    except Exception as exc:
        graph = _empty_graph()
        write_graph(run_dir, graph)
        return graph, [_graph_error("python graph builder failed", error=str(exc))]
    write_graph(run_dir, graph)
    return graph, []
```

- [ ] **Step 4: Update failure test**

Modify `test_build_graph_records_failure_and_writes_empty_graph` so it still passes with `graph_script=tmp_path / "external-graph.js"` and expects:

```python
assert errors[0]["message"] == "external graph scripts are no longer supported"
```

- [ ] **Step 5: Run post-processing tests**

Run:

```bash
uv run pytest tests/scope/runtime/test_post_processing.py -q
```

Expected: pass.

## Task 6: Update Audit Schema For Graph V2

**Files:**
- Modify: `config/schemas/audit.schema.json`
- Test: `tests/js/schema-audit-results.test.js`

- [ ] **Step 1: Write failing schema fixture assertion**

Update or add a fixture in `tests/js/schema-audit-results.test.js` that includes:

```json
{
  "graph": {
    "schema_version": "2.0",
    "metadata": {"source": "scope-runtime"},
    "nodes": [
      {
        "id": "data:s3:data-bucket",
        "label": "data-bucket",
        "type": "data",
        "resource_type": "s3_bucket",
        "arn": "arn:aws:s3:::data-bucket",
        "service": "s3",
        "region": "global",
        "account_id": "123456789012",
        "_source": "api"
      }
    ],
    "edges": [
      {
        "id": "edge:resource_policy_allows:external:arn:aws:iam::999999999999:root->data:s3:data-bucket",
        "source": "external:arn:aws:iam::999999999999:root",
        "target": "data:s3:data-bucket",
        "edge_type": "resource_policy_allows",
        "label": "resource_policy_allows",
        "relationship": "s3_bucket_policy_allows_principal",
        "_source": "api",
        "evidence": []
      }
    ]
  }
}
```

- [ ] **Step 2: Run JS schema test and verify failure**

Run:

```bash
npm test -- --silent
```

Expected: fail because `resource_policy_allows` and graph v2 fields are not accepted.

- [ ] **Step 3: Update schema**

In `config/schemas/audit.schema.json`:

- allow `graph.schema_version`
- allow `graph.metadata`
- allow node fields: `resource_type`, `arn`, `service`, `region`, `account_id`, `source_path`, `_source`
- add edge fields: `id`, `relationship`, `service`, `region`, `account_id`, `evidence`, `_source`
- extend `edge_type.enum` with:

```json
"resource_policy_allows",
"encrypted_by"
```

- [ ] **Step 4: Run schema tests**

Run:

```bash
npm test -- --silent
```

Expected: pass.

## Task 7: Remove Node Graph Extractor And JS Graph Tests

**Files:**
- Delete: `bin/extract-graph.js`
- Delete: `tests/js/extract-graph.test.js`
- Delete: `tests/js/fixtures/extract-graph/**`
- Modify: `ARCHITECTURE.md`
- Modify: `README.md`
- Modify: `agents/subagents/scope-attack-analyze.md`

- [ ] **Step 1: Delete obsolete files**

Delete:

```text
bin/extract-graph.js
tests/js/extract-graph.test.js
tests/js/fixtures/extract-graph/
```

- [ ] **Step 2: Update docs and agent prompt references**

Replace references to `extract-graph.js` with Python runtime graph extraction.

Expected statements:

```text
scope.runtime.graph builds graph.json from module envelopes.
Graph v2 includes stable edge IDs and source evidence.
```

- [ ] **Step 3: Run stale reference scan**

Run:

```bash
rg -n "extract-graph|bin/extract-graph|extract graph" README.md ARCHITECTURE.md agents config scope tests bin
```

Expected: no references except historical notes in the graph design and implementation plan.

## Task 8: Full Verification

**Files:**
- No new files. This task verifies the complete phase.

- [ ] **Step 1: Run Python tests**

Run:

```bash
uv run pytest -q
```

Expected: all tests pass.

- [ ] **Step 2: Run JS tests**

Run:

```bash
npm test -- --silent
```

Expected: all JS tests pass without `extract-graph.test.js`.

- [ ] **Step 3: Run schema regeneration**

Run:

```bash
uv run python -m tools.regen_schemas
```

Expected: exits 0 and produces no unintended schema churn.

- [ ] **Step 4: Run remaining Node syntax checks**

Run:

```bash
node --check bin/generate-report.js && node --check bin/install.js
```

Expected: both syntax checks pass. `bin/extract-graph.js` no longer exists.

- [ ] **Step 5: Run shell hook syntax checks**

Run:

```bash
bash -n config/hooks/*.sh
```

Expected: all hooks pass syntax checks.

- [ ] **Step 6: Run CLI smoke checks**

Run:

```bash
uv run python -m scope --help
uv run python -m scope audit --help
```

Expected: both commands exit 0.

- [ ] **Step 7: Run diff checks**

Run:

```bash
git diff --check
git status --short
```

Expected: no whitespace errors. Status shows only intended graph v2 files plus any unrelated pre-existing local edits.

## Scope Boundaries

Do not modify:

- `scope-attack-analyze` behavior beyond prompt/docs references.
- `scope-controls` or controls worker prompts.
- dashboard UI components.
- installer skill semantics.
- top-level agent naming.
- IAM policy capability graph.

IAM capability edges move to a later phase after graph v2 lands.
