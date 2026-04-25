# dummy_tool

Meta-test fixture for docs-check.sh. Intentionally references `fake_param` which
does NOT exist in the source tool.go; the gate must emit a WARN line for this
drift. Also references `PLANTED_DRIFT_TOKEN` which is absent from source so the
error-token branch fires too.

## Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `path` | string | yes | Project root |
| `format` | string | no | Output format |
| `fake_param` | string | no | Intentional drift; this param does not exist in tool.go |

## Errors

`PLANTED_DRIFT_TOKEN` is intentionally referenced; not present in source.
