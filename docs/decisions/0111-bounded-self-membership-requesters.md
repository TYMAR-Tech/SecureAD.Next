# 0111 - Bounded Self-Membership requester assessments

Date: 2026-09-06
Status: Accepted.

The owner approved the proposed bounded design with "continue then", after a plain-language explanation.

## Decision

Record whether a particular captured user is authorized to add or remove its own account through
Self-Membership. This is a separate stored assessment, not a promotion of the named-holder edge.
The initial supported routes are a direct user grant and one explicit membership in a same-domain
global security group. Nested, primary-group, SID-history, foreign-principal, cross-domain and
ambiguous resource-context routes remain unknown where they could affect the answer.

- Evaluate relevant allows and denies together, in captured order, against the concrete requester.
- Keep authorization, the own-account constraint, and operation readiness separate. A disabled
  account can retain permission evidence without being described as able to authenticate.
- SELF as an ACE trustee refers to the target object's identity, not automatically to the requester.
- Self-Membership (0x08) is not general member write (0x20). Failure of the Self-Membership path
  does not prove that all ways to modify membership would fail.
- Missing or unsupported inputs name their uncertainty. Missing member values do not prove
  non-membership; a finished object capture does not establish visibility of every attribute.
- Assess explicit requester/target requests, not every possible pair in the forest. Unrequested
  pairs are not evaluated, never silently negative.
- Persist the assessment, original permission entries, membership evidence, input limitations,
  evidence identity and generation before presentation. Both views read the same stored answer.
- Decision 0097 still governs counts: member assessments and duplicate routes do not add counted
  holder edges. One requester assessment may refer to multiple existing holder edges.
- Keep existing holder states, expectedness and ownership compounds unchanged. Requester counts
  are separate from edge counts and expectedness counts.

## Evidence and limits

Microsoft's [Self-Membership](https://learn.microsoft.com/windows/win32/adschema/r-self-membership)
and [Control Access Rights](https://learn.microsoft.com/windows/win32/ad/control-access-rights)
state the own-account restriction and distinct validated-write right. Its
[access-check description](https://learn.microsoft.com/windows/win32/secauthz/how-dacls-control-access-to-an-object)
explains trustee matching and ordered allows/denies. The bounded analysis models an ordinary
authenticated directory user, not the current machine's token, credentials or session.

The isolated 2026-09-06 measurement supports direct and single global-group-held own-account
behavior. It is not an input that grants permissions, a complete token test, or acceptance of all
stage-6 capabilities. Historical Unknown results stay as recorded. P-145 remains open.

No live directory access is part of this analysis. Existing sealed evidence and retained laboratory
artifacts are preserved; deleting laboratory objects requires the owner's separate approval.

## Implementation

Implemented in judgement schema 17. The governing judgement-store document records delivered
behavior and validation. This does not add a new live acceptance result or close P-145.
