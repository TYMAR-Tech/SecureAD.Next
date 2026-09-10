# Judgement half - what anchor each acceptance criterion needs

**This is discussion, not a decision.** It states no product position; it records, for each
acceptance criterion in [`JUDGEMENT-HALF.md`](JUDGEMENT-HALF.md), what kind of external evidence
would have to exist before that criterion could be called satisfied. Only records in
`docs/decisions/` state the product's position.

## What this is for

**It answers one question: what would prove this, and where would the proof come from?** A
criterion such as *membership cycles terminate deterministically* can be satisfied by a test that
agrees with the code and proves nothing; what makes it real is the kind of check named in the
`Oracle` column - a Microsoft protocol fixture, the platform's own access check, an observation
from a real forest, or a negative control that proves the tempting shortcut fails. That is
`F-S44-2` written down in advance, and it is the reason this file is worth keeping.

**It deliberately does not track whether anything is built.** It used to: every row carried a
`Test name` and a `Status`, and on 2026-09-04 those were removed. The reason is recorded as
`P-135`. No test of the promised name ever existed - zero, out of a hundred - and nothing checked
that, because `check-acceptance-manifest.ps1` compares this file against the source document and
never reads code. So ninety-eight rows read *not started* while the behaviour behind several of
them was built and tested under ordinary names, and `ROADMAP.md` took its stage statuses from that.

**A status maintained by hand rots without anyone editing it**, because it goes false when the
*code* moves rather than when the document does - which is exactly the failure a document-against-
document check cannot see. Whether a stage is built is now answered from the code by
`next/tools/check-stage-status.ps1`, and this file no longer offers a second answer.

**The criterion column is copied verbatim from the source table and must stay that way.** A
manifest with improved wording is a second version of the truth, which is the problem it exists
to prevent. `next/tools/check-acceptance-manifest.ps1` reconciles the two documents in both
directions and compares the text character for character.

## How to read the columns

| Column | Meaning |
|---|---|
| Id | As written in the source. Zero-padding is inconsistent there (`AC-01` against `AC-100`) and is reproduced rather than normalised. |
| Criterion | Verbatim from the source table. Not edited here, ever. |
| Oracle | The kind of external check the criterion needs before its implementation merges - not what exists today. `protocol fixture` derives from Microsoft protocol text, `native check` compares against the platform's own access check, `lab` is an observation from a real forest recorded as lab-verified, `negative control` proves the tempting shortcut fails. |

**Rows are in source order, not numeric order.** `AC-100` sits between `AC-98` and `AC-99` in the
source table and is left there, so the two documents can be compared line against line.

## Blocked criteria

Two criteria may not be implemented from inference. Both concern what SDProp traverses, which is a
separate question from what a group does for authorization, and neither has a Microsoft source.

- **`AC-64`** - primary-group membership in protected-principal derivation. The block is stated in
  the criterion's own text.
- **`AC-26`** - distribution-group nesting in protected-principal derivation. The criterion's text
  says the edge is followed only when the behaviour is enabled in the protected-principal
  catalogue; that it is not enabled, and why, is stated in *What SDProp actually traverses is
  evidence-gated* in the source. The latent-privilege finding half of `AC-26` is not blocked.

Each needs a Microsoft protocol citation, or a lab observation recorded and labelled as
lab-verified rather than specified.

## The manifest

| Id | Criterion | Oracle |
|---|---|---|
| AC-01 | Privileged is not automatically Tier0. A helpdesk group delegated password reset over ordinary users can be `IsPrivileged` while `TierClassification != Tier0`. | negative control |
| AC-02 | Protected is not automatically Tier0. A protected principal with no seed membership/direct-control basis is not promoted solely because SDProp covers it. | negative control |
| AC-03 | Dangerousness is target/capability-specific. `GenericAll`-derived control over an ordinary test account is dangerous without being Tier0. | negative control |
| AC-04 | A qualifying capability that directly controls a fixed Tier0 seed produces `Tier0Basis = DirectControl` and names the capability/target evidence. | negative control |
| AC-05 | A transitive control chain is discovered and reported without recursively assigning `Tier0` beyond the active policy's direct-control boundary. | negative control |
| AC-06 | A custom group/principal can become Tier0 without appearing in a hard-coded name list when evidence establishes `EffectiveMembership` or `DirectControl`. | negative control |
| AC-07 | `adminCount = 1` alone never produces current Tier0 or protected classification. | negative control |
| AC-08 | Current protected status is reported independently from Tier0 status. | negative control |
| AC-09 | Every non-seed classification carries typed evidence; `EffectiveMembership` carries a membership chain and `DirectControl` carries a capability/target. | negative control |
| AC-10 | Membership and control cycles terminate deterministically. Membership cycles can also produce a dedicated finding. | negative control |
| AC-11 | Renaming a well-known seed does not lose seed classification; matching uses stable SID/RID/object identity as appropriate. | negative control |
| AC-12 | Scope is retained so object/domain/forest authority is distinguishable. | negative control |
| AC-13 | Generic finding identity is `RuleId + typed SubjectRef + optional ObjectRef`; path is not part of identity. | negative control |
| AC-14 | A **reachability** finding resolves only when `Tier0Reachability = NotReachable` under complete required evidence; this lifecycle rule is not applied to unrelated finding types. | negative control |
| AC-15 | Every remediation recommendation states its residual effect; if nothing remains, that is stated explicitly. | negative control |
| AC-16 | Completeness/minimality is claimed only when proven for the analyzed captured graph. Unknown evidence prevents a "complete fix" claim. | negative control |
| AC-17 | Bounded route display never invents an exact total. Exact `Showing X of Y` wording is used only when `Y` was actually computed for a named path class. | negative control |
| AC-18 | Same bundle + same semantic versions + same `EvaluationAsOf` produces deterministic findings/routes/order. | negative control |
| AC-19 | Customer-visible routes/remediation evidence is stored or deterministically reconstructable from recorded versions/inputs. | negative control |
| AC-20 | Where no small remediation cut exists, the product says so rather than printing an unusable edge list as an answer. | negative control |
| AC-21 | A claimed mandatory remediation action really lies on every definite route for the finding; removing it and re-sweeping establishes the claimed residual. | negative control |
| AC-22 | When no single mandatory action exists, a multi-action change is required; a greedy approximation is not presented as a proven minimum. | negative control |
| AC-23 | A new route bypassing a previously mandatory action removes that action from the mandatory set and is detected as remediation drift. | negative control |
| AC-24 | A capability edge exists only where the requested operation is established by the applicable AD authorization semantics; allow-minus-deny shortcuts fail this test. | protocol fixture |
| AC-25 | Distribution-only nesting does not create current authorization/Tier0 reachability. | protocol fixture |
| AC-26 | Distribution-only nesting produces a latent-privilege finding and contributes to protected-principal derivation for an active root whose member propagation is established. It never creates current authorization/Tier0 reachability merely by that distribution-only hop. | Microsoft documentation anchor + protocol fixture |
| AC-27 | OWNER RIGHTS (`S-1-3-4`) is evaluated as part of owner implicit-right semantics and can alter the owner's implied access. | protocol fixture |
| AC-28 | `EdgeClass` is preserved as semantic category and is not treated as an ordered risk score. | negative control |
| AC-29 | Full-domain secret replication is represented by a compound semantic capability, not by treating each replication right independently. | protocol fixture |
| AC-30 | Adding an ordinary computer to RID 516 does not make it a domain controller/Tier0 asset. | protocol fixture |
| AC-31 | Reachability is tri-state: missing relevant evidence can produce `Unknown`; zero definite routes alone does not imply `NotReachable`. | negative control |
| AC-32 | `Unknown` reachability maps to `EvaluationOutcome = Indeterminate`, not to a resolved lifecycle. | negative control |
| AC-33 | No remediation claims complete coverage while relevant reachability is `Unknown`; unknown reasons are reported. | negative control |
| AC-34 | Multi-hop reachers remain `Unclassified` (unless another accepted tier catalogue classifies them) while retaining `Tier0Reachability` and distance. | negative control |
| AC-35 | No judgement rule reconstructs a raw-right equivalence set; rules ask for semantic capabilities/derived facts. | negative control |
| AC-36 | SELF (`S-1-5-10`) on a security principal resolves to that object's authorization SID and can participate in capability evaluation. | protocol fixture |
| AC-37 | Ownership alone does not create an unconditional `WriteDacl`/takeover edge. | protocol fixture |
| AC-38 | `PropagatesControl` is a capability property, not a hard-coded list of raw ACE names. | negative control |
| AC-39 | Route grade derives from feasibility/confidence/preconditions, not `EdgeClass` ordering. | negative control |
| AC-40 | Every conditional capability names at least one concrete precondition. | negative control |
| AC-41 | Membership is target-independent while authorization usability is context-dependent; cross-domain domain-local scope is asserted on a fixture with enough domains/contexts to make the distinction real. | protocol fixture |
| AC-42 | Builtin groups in different domain NCs remain distinct directory objects even when SID values match; authorization trustee matching remains SID/context-based and provenance is not merged. | protocol fixture |
| AC-43 | GPO applicability considers site/domain/OU scope, link state/order, enforced/block inheritance, policy-half status, security filtering and WMI; missing required evidence produces `Unknown`. | protocol fixture |
| AC-44 | `CanReplicateSecretDomainData` requires `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`; `Get-Changes` alone is not classified as full-domain secret replication. | protocol fixture |
| AC-45 | A membership cycle can be surfaced as a finding in addition to being safely traversed. | negative control |
| AC-46 | A Tier0 reachability finding targets the synthetic control-plane anchor and resolves only when no fixed seed is reachable. | negative control |
| AC-47 | Individual fixed seeds reached remain evidence under the anchor finding, each with route/distance evidence where requested. | negative control |
| AC-48 | Derived Tier0 classifications do not become new anchor endpoints; merely changing classification metadata does not change another principal's distance. | negative control |
| AC-49 | Effective security-group membership in a seed group produces `Tier0Basis = EffectiveMembership` and remediation points to the source membership relationship/path. | negative control |
| AC-50 | `PropagatesControl` and `Tier0ClassificationEffect` are independent catalogue properties. | negative control |
| AC-51 | A GPO with unresolved applicability inputs produces `Unknown` and names the missing evidence; WMI is one possible reason, not the only one. | negative control |
| AC-52 | Site-linked GPOs are considered; user and computer subjects are representable even if only the computer-side Tier0 capability is initially implemented. | protocol fixture |
| AC-53 | Application-partition handling does not equate Microsoft's "local group" warning with every AD domain-local group. Ambiguous servicing/resource context produces `Unknown`; a domain-local SID is not declared uninterpretable merely because the NC is an application partition. | protocol fixture |
| AC-54 | No principal is assigned Tier1/Tier2 until an accepted catalogue defines those values. | negative control |
| AC-55 | NULL/no DACL and present-but-empty DACL serialize as different states and produce different normal access-check results. | native check |
| AC-56 | Missing schema/property-set/object-class/inheritance/trustee/security-descriptor evidence yields `CapabilityEvaluation = Unknown`, never "capability absent". | negative control |
| AC-57 | `BlockOwnerImplicitRights` tests documented requester exceptions (Domain Admins / Enterprise Admins), applicable setting/server behavior and computer-derived target class. | protocol fixture |
| AC-58 | Non-computer ownership is not suppressed by the computer-specific `BlockOwnerImplicitRights` rule; OWNER RIGHTS remains independently applicable. | protocol fixture |
| AC-59 | Directory-object identity and authorization-trustee identity remain separate typed concepts throughout capture, derive, findings and remediation evidence. | negative control |
| AC-60 | A direct controller over a seed is graph evidence/classification but is not connected to the control-plane anchor as a destination. | negative control |
| AC-61 | `Tier0Basis` has one authoritative enumeration everywhere: `Seed`, `EffectiveMembership`, `DirectControl`. | negative control |
| AC-62 | Every finding records the rule, derivation-engine, capability-catalogue, privileged-catalogue, tier-policy and schema/GUID semantic versions that produced it. | negative control |
| AC-63 | `primaryGroupID` membership is included even when neither `memberOf` nor the group's `member` attribute contains the account. A user whose primary group is Domain Admins is found. | protocol fixture |
| AC-64 | Primary-group membership does **not** carry AdminSDHolder protection: a principal whose only route to a protected root is a `primaryGroupID` edge is `NotProtected`, not `Unknown`. **Unblocked 2026-09-11 by lab observation, per [`0118`](../../decisions/0118-primary-group-only-membership-is-not-protected.md).** The `primaryGroupID` citation establishes membership and its use in authorization, not the SDProp traversal, and no Microsoft source states what SDProp traverses — re-checked 2026-09-11 against Appendix C, *Reducing the Active Directory Attack Surface* and MS-ADA3. This criterion's alternative route was taken: `ba.ad.lab` on 2026-09-10 showed the Domain Controllers group itself stamped with no explicit `member` entries and `dSHeuristics` unset, while its domain controller carried neither `adminCount` nor a DACL refusing inheritance, against a stamped Domain Admins and an unstamped Domain Users in the same run. **Lab-verified, not specified**, and one domain: a contradicting forest reverts the answer to `Unknown`. Observation reproducible by `tools/Observe-Ac64PrimaryGroupTraversal.ps1`. | lab-verified |
| AC-65 | Many derived capability edges produced by one inherited ACE share one `RemediationActionId`; dominator/min-cut analysis recommends the source ACE once, not thousands of child edges. | negative control |
| AC-66 | One direct group membership that feeds many transitive paths remains one source remediation action. | negative control |
| AC-67 | Findings can have non-account subjects (OU, GPO, certificate template, domain root, topology object) without inventing a SID. | negative control |
| AC-68 | Aggregate/set, absence and temporal rules have typed rule shapes and stable finding keys. | negative control |
| AC-69 | `EvaluationOutcome` (`Established`, `NotEstablished`, `Indeterminate`, `DidNotRun`, `Error`), lifecycle (`Active`, `Resolved`, `Reopened`) and disposition (`None`, `Accepted`) are three separate state dimensions, and no implementation may collapse any two of them into one enum. | negative control |
| AC-70 | Temporal rules use recorded `EvaluationAsOf` (default capture completion time) so the same bundle does not change merely because it is opened later. | negative control |
| AC-71 | A failed new derivation generation cannot cause the judge stage to consume an older generation as though it were current; compatibility/status is checked explicitly. | negative control |
| AC-72 | Synthetic anchor edges are zero-cost, non-removable and not displayed as security hops. Seed distance is zero. | negative control |
| AC-73 | Unknown propagation is relevant, not global: missing evidence that cannot affect a principal's possible path does not automatically turn that principal `Unknown`. | negative control |
| AC-74 | Capability research blocks are build/rule-visible. A production rule cannot consume a `ResearchBlocked` capability as established. | negative control |
| AC-75 | `BlockOwnerImplicitRights` reads `dSHeuristics` character 29 and accepts values `0`–`3`, resolving any other value to `1` and an absent character to `0`. Treating `0` as "not configured" fails, and so does treating a malformed value as inert. Applicability follows the recorded server behavior, not a hard-coded release name. | protocol fixture |
| AC-76 | Ownership-derived capabilities are evaluated against the concrete security-descriptor modification the capability requires. A capability that names no modification evaluates to `Unknown`; one that does follows the documented rules and may be `Established` or `NotEstablished`. Returning `Unknown` for every ownership case on a given build fails. | protocol fixture |
| AC-77 | `CanReplicateFilteredAttributes` is derived as `Get-Changes AND (Get-Changes-All OR Get-Changes-In-Filtered-Set)`. A principal holding `Get-Changes` and `Get-Changes-In-Filtered-Set` alone yields this capability and does **not** yield `CanReplicateSecretDomainData`. | protocol fixture |
| AC-78 | Every replication control-access-right check used by these capabilities is evaluated against the naming-context root. Findings carrying `CanReplicateSecretDomainData` or `CanReplicateFilteredAttributes` target the applicable naming context or partition, never an object beneath it. | protocol fixture |
| AC-79 | Reachability to the anchor emits findings under SEC-071 only. A finding carrying SEC-070, SEC-072, SEC-076 or SEC-077 fails, and those identifiers are never reissued for anything else. | negative control |
| AC-80 | Path length and the reached destination are evidence fields on the SEC-071 finding, present and orderable. A design that recovers the distinction by varying severity per finding fails, because `0066` fixes severity on the rule card. | negative control |
| AC-81 | The key-credential capability names `msDS-KeyCredentialLink` and no other attribute. Mapping `altSecurityIdentities` to it fails: that attribute is certificate mapping, a separate capability with its own citation, and membership of the `BlockOwnerImplicitRights` protected-property list confers no capability meaning. | protocol fixture |
| AC-82 | `CanReplicateFilteredAttributes` carries its own security-significance citation, separate from the MS-DRSR procedure that establishes its boolean. A capability whose only source proves the authorization condition and not the impact fails. | protocol fixture |
| AC-83 | Missing evidence produces `UncertaintyRegion` records bounded explicitly or symbolically — explicit set, captured forest population, subtree, naming context or partition. An unreadable DACL yields a region covering the principals it could have named rather than omitting them, and an implementation that drops unidentifiable subjects and thereby reports `NotReachable` fails. No implementation materialises possible edges as a cross product. Evidence that cannot be bounded even symbolically is reported as an unbounded capture gap and blocks `NotReachable` within the scope it affects. | negative control |
| AC-84 | `RemediationActionId` derives from `RemediationActionKey` — captured configuration state — and never from `HumanDescription`. Rewording a description does not change the id; neither does adding an unrelated ACE to the same descriptor, nor a canonicalisation that changes ordinals. Descriptor hash, ordinal and expected bytes are apply-time concurrency evidence, not identity. Two ACEs differing only by inheritance source never share an id, and identical repeated ACEs are separated by an occurrence discriminator. | negative control |
| AC-85 | Route ordering is lexicographic in the ruled sequence: definite before possible; `Direct` before `Conditional` before `Potential`; fewer unmet preconditions; higher confidence; shorter; then stable signature. A two-hop route resting on an `Unknown` input never outranks a longer definite one, a route containing a `Potential` edge never outranks a conditional one, and no implementation trades certainty against length by summing weights. | negative control |
| AC-86 | Route ordering never alters severity, which `0066` fixes on the rule card, and never removes a route from the evidence. Two routes equal through all five criteria are ordered by signature alone, so repeated runs of one bundle agree. | negative control |
| AC-87 | Where one source action dominates every route from many principals, the report's primary recommendation is that action once, not one recommendation per affected principal. A design emitting a row per principal for a single dominating ACE fails. | negative control |
| AC-88 | A reachability finding resolves only when a later bundle evaluates it `NotEstablished` under complete evidence. An operator marking it fixed cannot resolve it, and a finding whose evaluation moves from `Reachable` to `Unknown` is reported as reduced coverage rather than as resolved. | negative control |
| AC-89 | A residual names what remains in a counterfactual re-sweep of the captured graph with the stated `RemediationActionId` removed. It is compared against the later bundle and is not treated as proof of future directory state; divergence is explained through changed source facts, coverage, semantic version or how the repair was applied. Wording that asserts the next capture must match fails. | negative control |
| AC-90 | A finding established in consecutive runs stays `Active` and never becomes `Reopened`. `Reopened` is reachable only from `Resolved`, which only a complete capture can produce. A finding whose evaluation becomes `Indeterminate` stays `Active`, so lost coverage cannot present as progress. | negative control |
| AC-91 | Where at least one definite route exists, the selected best route is definite. A possible route appears only as separately labelled supplemental evidence and never outranks a definite one, criterion 1 being absolute. | negative control |
| AC-92 | Findings stay keyed per principal. The report groups findings sharing a dominant `RemediationActionId` into one `RemediationIssue`, and that grouping never changes finding identity or lifecycle — resolving one member's finding leaves the others untouched. | negative control |
| AC-93 | Disposition does not replace lifecycle. An accepted finding can stay `Active`, become `Resolved` under complete evidence, and later become `Reopened`, retaining its acceptance and evaluation history throughout. An implementation where accepting overwrites lifecycle fails. | negative control |
| AC-94 | A replication finding closes only when a re-sweep shows no remaining authorization source establishes the capability at the naming-context root. Declaring it remediated after removing one ACE, without that re-sweep, fails. | negative control |
| AC-95 | The route comparison tuple is built by one rule: evidence class is `Definite` only when every edge is definite; feasibility is `Direct` only when every edge is `Direct` and `Potential` when any edge is `Potential`; confidence is the minimum edge confidence; unmet preconditions are the distinct normalized union across edges; length excludes synthetic anchor edges; signature is a deterministic serialization of normalized identities. Reordering a route's edges, or repeating one normalized precondition across several edges, does not change the tuple. | negative control |
| AC-96 | A `ResearchBlocked` capability yields no established edge at any confidence, never enters `G_definite`, and is never promoted by ordering. An implementation that admits blocked semantics as `Established` with `Confidence = Low` fails. | negative control |
| AC-97 | A principal with an observed candidate path to a protected group through a research-gated edge evaluates `Unknown` with the naming reason, not `NotProtected`. Principals with no intersecting gated path are unaffected, so one gated edge kind never makes the forest `Unknown`. | negative control |
| AC-98 | Each rule's findings commit atomically with its execution record. A run with any scheduled rule lacking a terminal execution record stays `Running`; a run whose coordinator could not establish scheduling, sealing or result integrity is `Failed`. Neither is presented as a judged bundle, and completed rules stay inspectable in both. | negative control |
| AC-100 | `Potential` survives route aggregation as a distinct feasibility rather than collapsing into `Conditional`, and a route containing a `Potential` edge is never described as presently exercisable. | negative control |
| AC-99 | `DominatesAllDefiniteRoutes` is computed over definite routes, with possible-route coverage carried separately. No wording asserting a complete fix is produced while `PossibleRouteCoverage` is `Incomplete` or `Unknown`. | negative control |

## Reconciliation

Run `next/tools/check-acceptance-manifest.ps1`. It extracts ids by regex from both documents,
differences each set against the other, and compares each criterion's text character for
character. It reports the counts and the method, and fails on any difference in either direction.
