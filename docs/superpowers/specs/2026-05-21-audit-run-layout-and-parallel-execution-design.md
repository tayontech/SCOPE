# Audit Run Layout and Parallel Execution Design

## Purpose

SCOPE audit runs need a durable filesystem contract before the remaining enumeration work continues. The runner should make each real AWS run easy to identify, safe to execute in parallel, and easy for later consumers to aggregate into resources and relationships.

This design updates the Python audit runner around four decisions:

- run directories are named from account identity plus timestamp
- `config/accounts.json` classifies whether the caller account is owned/internal
- raw module output is isolated by service and region
- regional work runs with bounded parallelism, followed by aggregation

Enumeration scripts remain facts-only. Attack-path analysis, relationship inference, and dashboard shaping remain downstream steps.

## Account Registry

`config/accounts.json` is the local owned-account registry. It follows the existing example shape:

```json
{
  "accounts": [
    { "id": "123456789012", "name": "example-production" },
    { "id": "111222333444", "name": "example-staging" }
  ]
}
```

The runner loads this file if present. Missing file is not an error; it means ownership cannot be confirmed from local context.

Lookup behavior:

- match caller `account_id` against `accounts[].id`
- if matched, set `account_owned: true` and `account_name` to the registry name
- if not matched, set `account_owned: false` and `account_name: null`
- if `config/accounts.json` is absent, set `account_owned: false`, `account_name: null`, and `account_registry_source: null`

The registry is the source of truth for owned/internal account classification. AWS Organizations access may enrich context, but it must not replace the local registry because the caller may not have Organizations access from member accounts.

## Run Directory Naming

The audit command should support explicit `--run-dir` for automation, but when the caller supplies a parent output directory or uses the default runs directory, the runner creates a unique child run directory.

Run ID format:

```text
<safe-account-name-or-unknown>-<account-id>-<UTC timestamp>
```

Examples:

```text
prod-427909037973-2026-05-21T003147Z
unknown-427909037973-2026-05-21T003147Z
external-999988887777-2026-05-21T003147Z
```

Recommended default:

```text
runs/<run_id>/
```

`account_id` is always included. Account names are sanitized for filenames and are never the only identity marker.

If the resolved run directory already exists, the runner must fail with a clear error. It must not overwrite an existing run and must not silently create a suffix, because deterministic run paths are easier to reason about in automation.

## Filesystem Contract

Each run uses this layout:

```text
runs/<run_id>/
  manifest.json
  modules/
    iam/global.json
    sts/global.json
    s3/global.json
    ec2/us-east-1.json
    lambda/us-east-1.json
    kms/us-east-1.json
  logs/
    ec2-us-east-1.log
    lambda-us-east-1.log
  resources.jsonl
  summary.json
```

`modules/<service>/<region>.json` files are the raw truth. Each file is a valid `ModuleEnvelope` with top-level `resources`.

`resources.jsonl` is generated after enumeration. Each line is one resource with the envelope context injected:

```json
{
  "account_id": "427909037973",
  "account_name": "prod",
  "account_owned": true,
  "service": "lambda",
  "region": "us-east-1",
  "resource_type": "lambda_function",
  "resource_id": "example-function",
  "arn": "arn:aws:lambda:us-east-1:427909037973:function:example-function"
}
```

`summary.json` is generated after enumeration. It records service-region statuses, resource counts, error counts, skipped work, and aggregate totals.

`relationships.jsonl` is reserved for the later relationship builder. The audit runner omits it until the relationship phase exists. It must not infer relationships inside enumerators.

## Manifest

`manifest.json` records run identity and execution settings:

```json
{
  "run_id": "prod-427909037973-2026-05-21T003147Z",
  "started_at": "2026-05-21T00:31:47Z",
  "finished_at": "2026-05-21T00:34:10Z",
  "account_id": "427909037973",
  "account_name": "prod",
  "account_owned": true,
  "account_registry_source": "config/accounts.json",
  "services_requested": ["iam", "sts", "s3", "ec2"],
  "regions_requested": ["us-east-1", "us-west-2"],
  "concurrency": 8,
  "status": "complete"
}
```

Run status rules:

- `complete` when every requested service-region envelope validates
- `partial` when at least one requested service-region failed but at least one succeeded
- `error` when no requested service-region produced a valid envelope

Module envelope status remains service-specific. A run can be `complete` even when a module envelope is `partial`, because the module ran and produced valid coverage-aware inventory.

## Service Scope Classes

The runner should classify services before building work items.

Global modules:

- `iam`
- `sts`

Account-scoped modules:

- `s3`

Regional modules:

- `apigateway`
- `bedrock`
- `codebuild`
- `cognito`
- `dynamodb`
- `ec2`
- `kms`
- `lambda`
- `rds`
- `secrets`
- `sns`
- `sqs`
- `ssm`

Global and account-scoped modules run once with region `global`. Regional modules run once per enabled region or per `--regions` override.

S3 is intentionally account-scoped for runner scheduling. It lists buckets once and records each bucket's actual location in resource fields. Running S3 once per enabled region would duplicate bucket resources and waste API calls.

## Parallel Execution

The audit runner builds a queue of work items:

```text
(service, region, output_path, log_path)
```

It executes work items with bounded concurrency. Recommended default:

```text
--concurrency 8
```

The CLI should allow:

```text
--concurrency <N>
```

Rules:

- each worker writes to its own temporary module run directory
- each worker has its own log file
- the controller validates each resulting envelope before copying it into `modules/<service>/<region>.json`
- no worker writes to aggregate files
- aggregation starts only after all workers finish

This layout makes parallel writes safe and makes reruns/debugging straightforward.

## Region Discovery

If `--regions` is supplied, the runner uses that comma-separated list for regional modules.

If `--regions` is absent, the runner calls EC2 `DescribeRegions(AllRegions=False)` and uses enabled regions. If region discovery fails, the runner fails before dispatching regional modules. It must not silently use a hardcoded fallback list.

## Aggregation

After all module workers finish, the runner scans `modules/*/*.json`.

It writes `resources.jsonl` by flattening every envelope resource and injecting:

- run ID
- account ID
- account name
- account ownership
- service/module
- region
- source envelope path

It writes `summary.json` with:

- per-service-region status
- per-service totals
- total resources
- total errors
- failed work items
- output file paths

Aggregation must tolerate missing or invalid module files and record them in `summary.json`; it should not discard successful modules because another module failed.

## Relationship Builder Handoff

The relationship builder will run after enumeration and aggregation. It should use:

- `resources.jsonl`
- raw `modules/<service>/<region>.json` files when full service-specific context is needed
- `config/accounts.json` to classify internal vs external accounts

Relationship classification examples:

```json
{
  "account_id": "111222333444",
  "account_name": "staging",
  "ownership": "internal"
}
```

```json
{
  "account_id": "999988887777",
  "account_name": null,
  "ownership": "external"
}
```

Enumerators should not classify attack paths or security severity. They may preserve factual account IDs, principals, policy documents, resource ARNs, and trust conditions so the relationship builder has enough context.

## Testing

Implementation should include tests for:

- owned account lookup from `config/accounts.json`
- missing registry file behavior
- run ID sanitization and timestamp naming
- service scope classification
- work queue generation for global, account-scoped, and regional modules
- bounded worker dispatch with isolated output paths
- run status derivation from valid, missing, and invalid module outputs
- `resources.jsonl` aggregation from multiple service-region envelopes
- `summary.json` content

Real AWS smoke testing should run after unit tests:

```text
scope_runtime audit --all --run-dir <test-run-dir> --concurrency 8
```

The smoke test should verify:

- `manifest.json` exists and has account ownership metadata
- module outputs are under `modules/<service>/<region>.json`
- global/account-scoped services ran once
- regional services ran per selected enabled region
- `resources.jsonl` and `summary.json` exist
- no top-level `findings` appears in module envelopes
