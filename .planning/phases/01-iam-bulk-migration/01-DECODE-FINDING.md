# AssumeRolePolicyDocument Encoding Finding

**Phase:** 01-iam-bulk-migration
**Plan:** 01-01
**Date:** 2026-03-25
**Status:** RESOLVED — empirically tested

---

## Test Performed

```bash
DOC_TYPE=$(aws iam get-account-authorization-details --filter Role --output json 2>&1 | jq '.RoleDetailList[0].AssumeRolePolicyDocument | type' 2>/dev/null)
echo "[INFO] AssumeRolePolicyDocument type from GAAD: $DOC_TYPE"
```

## Result

```
[INFO] AssumeRolePolicyDocument type from GAAD: "object"
```

`jq` reports type `"object"` — the field is a parsed JSON object, not a URL-encoded string.

## AWS CLI Version

```
aws-cli/2.34.9 Python/3.13.12 Darwin/25.3.0 source/arm64
```

## Conclusion

**AWS CLI v2 auto-decodes `AssumeRolePolicyDocument`.** The field arrives as a native JSON object in the GAAD response after AWS CLI v2 processes it. No URL-decode step is required.

### Recommendation for Plan 02

The existing `TRUST_CLASSIFY_JQ` snippet that operates on `.AssumeRolePolicyDocument.Statement` **works directly without modification**. Do NOT add a `python3 -c "import urllib.parse; ..."` decode step — it is unnecessary and would break on already-decoded objects.

Specifically:
- `.AssumeRolePolicyDocument.Statement` — valid, returns the array directly
- `.AssumeRolePolicyDocument.Statement[].Principal` — valid, returns principal spec
- No `@uri` decode, no `python3 urllib.parse.unquote`, no `jq @uri` needed

### Defensive Note

This was tested against AWS CLI v2.34.9. AWS CLI v1 is known to NOT auto-decode (returns a URL-encoded string). If any SCOPE operator runs AWS CLI v1, the agent should handle the string case defensively:

```bash
# Defensive decode pattern for Plan 02 (handles both v1 and v2 output):
DOC_RAW=$(echo "$role_json" | jq -r '.AssumeRolePolicyDocument')
DOC_TYPE=$(echo "$DOC_RAW" | jq -r 'type' 2>/dev/null || echo "string")
if [ "$DOC_TYPE" = "string" ]; then
  DOC_DECODED=$(python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read()))" <<< "$DOC_RAW")
else
  DOC_DECODED=$(echo "$role_json" | jq -c '.AssumeRolePolicyDocument')
fi
```

This defensive pattern is OPTIONAL given AWS CLI v2 is the SCOPE standard. Include only if the IAM agent is expected to work in mixed CLI version environments.
