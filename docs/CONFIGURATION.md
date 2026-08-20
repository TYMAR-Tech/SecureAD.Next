# Configuration

> **This document covers 2 of the product's 43 settings.**
>
> It sits in the top level, where a document is expected to describe how the system works and to be
> true. This one is true about what it names and silent about most of the subject. **An absent
> setting here does not mean the setting does not exist** â€” it means nobody has written it down yet.
>
> The gap is measured in `work/DOCUMENTATION-AUDIT.md` in the predecessor repository, and the
> rebuild of this document is queued there. Until then, read the code for anything not listed.

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `SECUREAD_DB_PROFILE` | `0` | Set to `1`, `true`, or `yes` to run the post-capture database profiler and write profiling output |
| `SECUREAD_DIAG_CONNECTIONS` | `0` | Set to `1` to log every SQLite connection open/close with timing |
| `SECUREAD_RAW_LOGS` | `0` | Set to `1` to disable DN/SID/FQDN sanitization in log files |
| `SECUREAD_SKIP_BG_TREE` | `0` | Set to `1` to skip background offline tree loading after DB open |
| `SECUREAD_SKIP_BG_COVERAGE` | `0` | Set to `1` to skip background coverage/dashboard stats after DB open |

## SQLite Cache Profiles

The page cache size is auto-detected from system memory or stored user preferences:

| Profile | Cache Size | System Memory |
|---|---|---|
| `Standard` | 256 MB | < 12 GB |
| `Large` | 512 MB | 12â€“24 GB |
| `ExtraLarge` | 1024 MB | >= 24 GB |

Read-only connections apply PRAGMAs: `journal_mode=WAL`, `synchronous=NORMAL`, `cache_size` based on profile.

## Capture Settings

Capture settings control what is captured during an audit run:

- **CaptureProfile**: `Safe` (default), `Balanced`, `Accelerated`, `Custom`
- **SearchDepth**: `Subtree` (default), `OneLevel`, `Base`
- **PageSize**: LDAP page size for search results (default: 1000)

## Findings Policy

Custom policy via JSON file. Supports:

- **Allowed principals**: Suppress findings for expected admin accounts (match by SID, DN, or name pattern)
- **Severity overrides**: Reclassify rule severity (e.g., downgrade a rule from High to Medium)
- **Hop limits**: Maximum escalation path length per rule

Policy file DTOs are defined in the `SecureAD.Core.Findings` namespace (see `PolicyFileDtos.cs`, root type `PolicyFileDto`).

## Log Files

All logs are written to `%LocalAppData%/SecureAD/Logs/session/`:

| File | Content |
|---|---|
| `app.log` | Aggregate log (all levels) |
| `app-warnings.log` | Warnings and errors only |

### Log Sanitization

By default, logs sanitize sensitive AD data:
- Distinguished names are hashed
- FQDNs are hashed
- SIDs are hashed

Set `SECUREAD_RAW_LOGS=1` for full unsanitized output during debugging.

### Performance Tracing

- `[OPEN-SUMMARY]` log lines track database open timing
- `UiPerfTrace.Log()` tracks UI operation timing with configurable warning thresholds
- `ConnectionDiagnostics` logs connection lifecycle when enabled

## Settings UI

The Settings view in the app exposes:

- Theme selection (Dark/Light)
- Cache profile override
- Default export path
- Policy file path
- Log viewer access
