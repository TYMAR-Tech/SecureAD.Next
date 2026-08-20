# Control Edges and Escalation Paths

## Overview

SecureAD derives two layers of security analysis from captured ACE data:

1. **Control edges** — direct permission-based control relationships between principals and objects
2. **Escalation paths** — multi-hop attack paths discovered by traversing the control edge graph

## Control Edges

### What is a control edge?

A control edge represents a derived fact: "Principal X has capability Y over Object Z."

Each edge is derived from one or more ACEs in `fact_ace`, classified by the GUID catalog, and stored in `fact_control_edge`.

### Derivation rules (ControlEdgeService)

The `ControlEdgeService.DeriveControlTypes()` method classifies ACEs into semantic control types:

| ControlType | Source | Meaning |
|---|---|---|
| `GenericAll` | ACCESS_MASK bit 0x10000000 | Full control — early exit, no other types derived |
| `WriteDacl` | ACCESS_MASK bit 0x00040000 | Can modify permissions |
| `WriteOwner` | ACCESS_MASK bit 0x00080000 | Can take ownership |
| `Delete` | ACCESS_MASK bit 0x00010000 | Can delete the object |
| `ResetPassword` | Extended right GUID `00299570-...` | Can force password reset |
| `WriteSPN` | Validated write GUID `f3a64788-...` | Kerberoasting vector |
| `WriteKeyCredentialLink` | Property write GUID `5b47d60f-...` | Shadow Credentials attack |
| `WriteRBCD` | Property write GUID `3f78c3e5-...` | Resource-based constrained delegation |
| `AddMember` | Property write GUID `bf967a9c-...` | Can modify group membership |
| `DCSyncGetChanges` | Extended right GUID `1131f6aa-...` | Directory replication |
| `DCSyncGetChangesAll` | Extended right GUID `1131f6ad-...` | Replication including secrets |
| `WriteUserAccountControl` | Property write GUID `bf967a86-...` | Can toggle delegation/disable flags |
| `LinkGPO` | Property write GUID (gpLink) | Can link GPOs to containers |
| `CertificateEnroll` | Extended right GUID `0e10c968-...` | Certificate enrollment |
| `Owns` | Object owner SID | Implicit WriteDACL — can grant any permission |

### What is excluded

- **Principal Self (S-1-5-10)**: Placeholder SID resolved to the object's own SID — not an actionable attack source
- **Deny-cancelled edges**: If a deny ACE cancels a specific allow, the edge is marked `deny_cancelled = 1` and excluded from path traversal
- **SIDHistory expansion**: Old SIDs from `sIDHistory` are mapped to current principal SIDs via reverse lookup

### What is intentionally not expanded

- **Group membership is not materialized as ACE-derived control edges.** The `ControlEdgeService` does not create synthetic edges from group membership.
- **However, `MemberOf` traversal edges are injected into the escalation path graph.** During graph construction, `EscalationPathService` loads `fact_group_membership_closure` and adds synthetic `MemberOf` edges from each member SID to the group's object GUID.
- This means the path engine **does** discover group-mediated reachability: `User A --MemberOf--> Admin Group --GenericAll--> Domain Controller`.
- `MemberOf` edges have low danger weight (10) — they enable traversal but don't inflate danger scores. The dangerous step is the group's control edge, not the membership itself.

### Coverage requirements

Control edge derivation requires:
- `Objects` module — `dim_object` populated
- `SecurityDescriptors` module — `fact_ace` populated

## Escalation Paths

### What is an escalation path?

An escalation path is a multi-hop chain of control edges (and group membership edges) from a source principal to a high-value target. It answers: "Can Principal X reach Target Y through a sequence of control relationships and group memberships?"

### Graph construction (EscalationPathService)

1. **Control edges**: `source_sid → [edges to target objects]` from `fact_control_edge WHERE deny_cancelled = 0`
2. **MemberOf edges**: `member_sid → [group object GUIDs]` from `fact_group_membership_closure` joined to `dim_object`
3. **Reverse graph**: `target_sid → [edges from source principals]` (reverse lookup via `dim_object.sid`)
4. **High-value targets**: Objects classified as Tier 0 or with specific sensitive attributes
5. **Traversal**: BFS from each non-high-value principal to discover shortest paths to targets
6. **Edge filtering**: Only edges where `EscalationEdgeMetadata.IsTraversable(controlType)` returns true

### What traversal includes

- Direct ACE-based control edges (deny cancellation pre-applied)
- **Group membership edges** (`MemberOf`) from transitive group closure — enables paths through group chains
- Ownership edges (`Owns`)

### What traversal does NOT include

- Inherited ACEs expanded individually (inheritance is captured in `fact_ace` but not re-expanded)
- Cross-forest trust traversal (each forest is analyzed independently)

### Coverage requirements

Escalation path detection requires:
- `ControlEdges` module — `fact_control_edge` populated
- `Principals` module — `dim_principal` populated for SID-to-display resolution
- `GroupExpansion` module — `fact_group_membership_closure` populated for MemberOf traversal edges

## Findings

Findings are generated by `FindingsService` after control edges and escalation paths are built:

- Rule-based evaluation using `FindingRule` definitions
- Category-based evaluators (delegation, Kerberos, ownership, etc.)
- Severity classification: Critical, High, Medium, Low, Informational
- Policy customization via JSON policy files (`FindingsPolicy`)
- Suppression support via `dim_suppression`
- Run-scoped with deterministic ordering

## Confidence Language

| Term | Meaning |
|---|---|
| "has control over" | A control edge exists (derived fact from ACE data) |
| "can reach" | An escalation path exists (graph traversal result) |
| "effective access" | Computed considering group membership, deny cancellation, and inheritance |
| "coverage complete" | All required pipeline modules succeeded for all domains |
| "coverage incomplete" | One or more modules failed — results may be partial |
