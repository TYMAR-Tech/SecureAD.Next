<!-- PREDECESSOR-MATERIAL:BEGIN -->
> **Predecessor material. Not a specification for this product.**
>
> This file was written against the previous SecureAD, and every code path, table and query in it
> describes that product. `rules.yaml`, `FindingsService`, `RuleEvaluatorHelpers` and the `dim_*`
> tables **do not exist here** and are not going to. Where this file says what a rule *does*, it is
> reporting what the old tool did, not what this one must do.
>
> Read it as a source, not an answer. The Active Directory reasoning is worth having; the
> implementation is not. In this product executable rules are `IRule` implementations in `SecureAD.Judgement`,
> registered in `JudgingLauncher.Rules()`, resting on evidence stored by `JudgementWriter`, and
> reading only attributes declared in `CapturedAttributeCatalog`. What a rule is here is described
> in [`layers/judgement/what-a-finding-is.md`](../layers/judgement/what-a-finding-is.md).
>
> Nothing in here is held by any gate. It is quarantined rather than rewritten, per `P-101`.
<!-- PREDECESSOR-MATERIAL:END -->

# Rule Review — Next Up

> **This describes the predecessor, not this repository. It is history.**
> Everything below refers to the old application: its branches, its test projects
> (`SecureAD.Core.Tests`, `SecureAD.Infrastructure.Tests`), its `fact_finding` table and its
> `rules.yaml`. None of them exists here. The branch it names, `feature/sec080-sysvol-dacl-union`,
> is not a branch of this repository.
>
> **For where the rebuild is, read [`docs/ROADMAP.md`](../ROADMAP.md).** This file is kept only
> because the rule cards it describes were carried across and its per-rule detail is still the
> best account of what each rule was verified to do. It is consumed as the rules are implemented,
> on the same terms as the rest of `docs/rules/`.

> Single source of truth for "where were we?" between chats.
> Keep this file short. Update it at the end of every chat **before** committing.
> When in doubt, the repo (cards, tests, rules.yaml) is authoritative — not chat history.

## Status

- **Branch:** `feature/sec080-sysvol-dacl-union` (single-developer; the active branch for the LAPS/SYSVOL Phase B + lab-driven correctness work). Remotes: `origin` (razamus), `tymar`.
- **Build/tests:** green. This session: `SecureAD.Core.Tests` 1128, targeted `SecureAD.Infrastructure.Tests` suites (GPO rules, delegation, parity, provenance/coverage) all green, 0 failures. Rule count **62** (added SEC-093, SEC-063, SEC-064, SEC-065, SEC-066, SEC-067 this branch).
- **Per-rule audit:** COMPLETE — all SEC-001 … SEC-204 cards carry `Verified` or `Accepted-with-known-limitation`.
- **Cross-cutting `[IMP-*]` backlog:** **47 of 47 tags Resolved or Deferred.** `[IMP-GPO-SYSVOL]` **Phase A is RESOLVED and field-validated**.
- **`[IMP-GPO-SYSVOL]` Phase B:** **Evaluator-only Phase B is COMPLETE** — every security-relevant section Phase A captures now has a rule. Shipped this branch: **SEC-082** (GPO modify via SYSVOL folder write), **SEC-083** (GPP cpassword exposure, MS14-025), the **SEC-080 SYSVOL-DACL union**, the **SEC-093 LAPS decryptor-aware finding** (+ SEC-090 read-vs-decrypt enrichment), **SEC-064** (dangerous user right via GPO), **SEC-065** (privileged local group membership via Restricted Groups), **SEC-066** (weak directory/SMB signing posture, first-party-verified), and **SEC-067** (Tier-0 account exposed to delegation impersonation, risk-gated). **Remaining Phase B items require NEW CAPTURE WORK, not evaluator rules** (confirmed by probe `30-audit-applocker-presence.txt`): **audit policy** lives in `Machine\\Microsoft\\Windows NT\\Audit\\audit.csv` (NOT captured — no `[Event Audit]` section anywhere; the only 'audit' hit is `SeAuditPrivilege`, a user right) and **AppLocker** lives in `Machine\\Microsoft\\Windows\\AppLocker\\*.xml` (NOT captured). Each needs a new SYSVOL file parser in Phase A capture before a rule is possible. **Audit policy is the worthwhile one** (doc-grounded: Windows Security Baseline gives exact subcategory expected values, e.g. Audit Kerberos = `Equals(3)`; pairs with the prevention rules as the detection layer) but is a multi-step capture project. **AppLocker is deprioritized** — 'AppLocker present' ≠ secure (effectiveness needs deep XML rule-quality analysis; absence fires on every domain = config-checker risk). GPP scanning is opt-in (`CaptureSettings.CaptureGppPasswords`, **default off**). The Tier-0 Deny-logon-rights isolation variant remains deferred (absence-dominated, needs OU-classification).
- **Lab-driven correctness sweep (this session, all lab-validated end-to-end on the root + 2-child `audit.db`):** Triggered by a real false positive (Authenticated Users `ReadAllProperties` firing SEC-090). Fixed **SEC-090** (confidential-attribute gate: require CONTROL_ACCESS `0x100`, not ReadProperty `0x10` — killed the per-computer FP flood), fixed **SEC-123** sIDHistory false-negative (widen to non-object all-properties / GenericAll writes; +3 real findings incl. `Everyone`), added honest **SEC-081** `link_capability` labeling (specific gPLink vs via_broad_write; 1 specific / 1039 broad in lab), and shipped **SEC-063** "Unexpected Broad Control Over Container (Review Delegation)" — the new rule closing the named-non-admin OU-control coverage gap, with `disposition=review_required` + Tier-0-subtree severity tiering (Critical when a transitive-DA account lives anywhere in the OU subtree, depth-agnostic via `DnHelper.GetParentDn`). Rule count 56→57 (SEC-093) →58 (SEC-063). All suites green: Infrastructure 1781 (3 skipped) + Core 1074 + UI. A local-only read-only `LabDbProbe` harness (git-ignored) drove every fix; real-run `fact_finding` confirmed all five behave as designed.

### Most recently completed (newest first, with commit refs)

- **SEC-067 — Tier 0 Account Exposed to Delegation Impersonation — NEW RULE, lab-validated, first-party-doc-verified (`48a1e74f`):** Flags a Tier-0 user (transitive member of Domain/Enterprise/Schema Admins via `fact_group_membership_closure` RID 512/518/519) that is **delegatable** — has neither the `NOT_DELEGATED` userAccountControl flag (`0x100000`) nor Protected Users (RID 525) membership — **while a delegation impersonation vector exists** that the protection defeats: a non-DC host configured for protocol transition (S4U2Self), RBCD, or unconstrained delegation. `EvaluateTier0Delegatable` in `DelegationRuleEvaluator` (reused, not a new evaluator). **Risk-gated, not a config checker:** zero vectors -> zero findings; DC unconstrained excluded (inherent). **Medium** severity (fires on multiple admins by design since Protected Users is empty by default, so must not drown the High queue), `disposition=review_required`. **Operator explanation leads with the LOW-RISK fix** (set NOT_DELEGATED flag, account-scoped, no auth impact); Protected Users framed as stronger-but-test (blocks NTLM/AES-only/4h tickets, can lock out accounts). **Doc-verified (5 first-party sources):** Least-Privilege Admin Models states verbatim 'all accounts in AD can be delegated' by default (admin membership does NOT auto-protect — that misconception is AdminSDHolder/adminCount sticky behavior, a different mechanism = SEC-030); How to Configure Protected Accounts + PS-Remoting confirm the NOT_DELEGATED flag blocks unconstrained AND constrained delegation; Protected Users doc confirms members can't delegate but protection is live/reversible (not sticky). Full parity wiring (coverage `[Objects, GroupMembership]`, hint, evidence-matrix, parity snapshot + privilegedSidConsumers, rule-count 61→62), rich UI guidance, SEC-067.md card. 7 evaluator tests. **Lab-validated:** user staged 2 non-DC vectors (ProtocolTransition on BAMS1, RBCD on BAWK1) -> SEC-067 fires exactly 6 Medium (the 6 delegatable Tier-0 users); 3 DC unconstrained hosts excluded; risk gate confirmed (0 when no vector). **Bonus:** staging RBCD proved the `msDS-AllowedToActOnBehalfOfOtherIdentity` -> `dim_delegation` derivation end-to-end, confirming SEC-013/122 are NOT silently blind (earlier 0-RBCD was just no config, no bug). **Lab cleanup TODO for user:** revert the staged BAMS1 protocol-transition + BAWK1 RBCD (real exposure added only for testing).

- **SEC-066 — Weak Directory/SMB Signing Posture — NEW RULE, lab-validated, first-party-doc-verified (`e3dcbf8b`):** Flags a Group Policy security template (`GptTmpl.inf [Registry Values]`, in `dim_gpo_setting`) that explicitly sets an AD/SMB signing or channel-binding control to a known-weak value — the on-ramp for NTLM/Kerberos relay + MITM (MITRE T1557), which undermines the directory-write (SEC-013/025/123/204) and cert (SEC-040) findings that assume an attacker must already hold a permission. New `SigningHardeningCatalog` (in `SecureAD.Core.Findings`) tracks 5 settings with a **per-setting** secure value + comparison (`EqualsSecure` vs `AtLeastSecure`), so the **same captured value 1** is correctly read as SECURE for SMB signing (1=required) but WEAK for LDAP server signing (1=None, secure=2) — a flat "1=secure" check would be wrong. `EvaluateSigningHardening` in `GpoRuleEvaluator`; fires only on an explicitly-captured weak value (absence is not flagged). **Every value encoding is grounded in a first-party Microsoft source (KB4520412 gives the verbatim GPO→registry map: LDAP signing None=1/Require=2, channel binding Never=0/WhenSupported=1/Always=2; SMB 0/1 + Netlogon RequireSignOrSeal from the SMB-signing overview + Windows security baseline).** Each finding is **self-explanatory by design** (the user asked for clear explanations): Detail + ContextJson carry `policy_name`, `weak_meaning`, `attack_impact`, `recommended_fix`, and the `reference` URL. Full parity wiring (coverage `[Objects, Sysvol]`, hint, evidence-matrix, parity snapshot, rule-count 60→61, rich UI guidance, SEC-066.md card). 17 tests (8 catalog + 9 evaluator). **Lab-validated the full matrix:** true positive (`LDAPServerIntegrity=1` None fires 3 High, one per DC); **true negative on remediation** (user changed one domain to Require signing=2 → that exact domain dropped, 3→2, others unchanged); the 1-means-opposite distinction (SMB/Netlogon =1 correctly silent); per-target precision. **Known limitations documented** (SEC-066.md §11): GPO precedence/RSoP (assesses per-GPO not effective), WS2025 `LDAPServerEnforceIntegrity` override (lab `{6AC1786C}` is pre-2025), absence not flagged. **Verification discipline note:** the LDAP `1=None` encoding was initially inference; deferred and verified against KB4520412 before shipping, per the "ship a blindspot rather than get it wrong" rule.

- **SEC-065 — Privileged Local Group Membership via Restricted Groups — NEW RULE, lab-validated (`bc5ccd1c`):** Flags a Group Policy Restricted Groups assignment (`[Group Membership]` in GptTmpl.inf, in `dim_gpo_setting`) that configures membership of a privileged builtin local group on every targeted computer — a fleet-wide grant invisible to directory group-membership rules (which only see domain groups). New `LocalPrivilegedGroupCatalog` (in `SecureAD.Core.Principals`) tiers severity by the controlled group: Administrators 544=**Critical** (local admin → on a DC, domain compromise), Backup/Server/Account/Print Operators 551/549/548/550=**High**, Power Users 547=**Medium**; access-only groups (RDP 555 / DCOM 562 / Remote Mgmt 580) deferred to v2. A **broad** member (Everyone/Auth Users/Domain Users) escalates any tier to Critical. Handles both `__Members` and `__Memberof` capture forms (reduced to `(controlledGroup, member)` pairs). `disposition=review_required` two-axis model (same as SEC-063/064). `EvaluateRestrictedGroupMembership` in `GpoRuleEvaluator`; shares the `ParseSecurityTemplateSidList` `*`-strip parser with SEC-064. Full parity wiring (rules.yaml, coverage `[Objects, Sysvol, GroupMembership]`, hint, evidence-matrix, parity snapshot + privilegedSidConsumers list, rule-count 59→60, UI guidance, SEC-065.md card). 16 tests (7 catalog + 9 evaluator). **Also (same commit): aligned SEC-064 + SEC-065 member exclusion to the closure-aware `ShouldExcludePrivilegedTrustee` (matching SEC-063) instead of `IsAdminSid` alone** — a named account that is only *transitively* privileged via group membership (e.g. a user in Domain Admins) is now correctly excluded rather than false-firing; both rules declare GroupMembership coverage and are pinned in `privilegedSidConsumers`. **Lab-validated both directions:** the privileged member `ba.admin` (transitive DA/EA/SA) is correctly suppressed (true negative); after the user swapped in a genuinely non-privileged account (`kdavis`, plain `OU=Users`), SEC-065 fired exactly 1 Medium review (true positive — confirmed via persisted `fact_finding`, where the *absence* of `subject_privileged_via` proves non-privileged). No regressions: other rules unchanged (SEC-063 2C+1036M, SEC-081 1040, SEC-090 2, SEC-123 3, SEC-064 0).

- **SEC-064 — Dangerous User Right Granted via Group Policy — NEW RULE, lab-validated (`a6ac44a4`):** Flags a GPO User Rights Assignment (`GptTmpl.inf [Privilege Rights]`, in `dim_gpo_setting`) that grants a sensitive privilege (SeDebug/SeBackup/SeRestore/SeTakeOwnership/SeTcb/SeLoadDriver/SeEnableDelegation/SeImpersonate/…) to a principal beyond its documented default holders — a Tier-0-equivalent capability applied by policy to every targeted computer, invisible to directory membership rules. New `UserRightCatalog` (in `SecureAD.Core.Findings`) grounds the sensitive privileges + their Microsoft Security Baseline default-holder SIDs; **`SeChangeNotifyPrivilege` deliberately excluded** (enabled for all users by default — a FP landmine). `disposition=review_required`; **Critical** if the holder is broad, else **High**. `EvaluateDangerousUserRight` in `GpoRuleEvaluator`. Full parity wiring + rule-count 58→59 + SEC-064.md card. 18 tests (10 catalog + 8 evaluator). **Lab-validated:** 0 findings (true negative — the lab's `[Privilege Rights]` is the default DC policy, every sensitive privilege held only by documented/admin/system holders; `SeChangeNotify=Everyone` correctly excluded). Also shipped (`e35fb32e`): `fix(logging)` — FileLoggerProvider tolerates transient log-file locks at startup (FileShare.ReadWrite + retry), killing a startup unhandled-exception popup.

- **SEC-063 — Unexpected Broad Control Over Container (Review Delegation) — NEW RULE, lab-validated:** Closes the coverage gap the SEC-081 investigation exposed — 824 named non-admin principals with broad control (`GenericAll`/`GenericWrite`/`WriteAllProperties`/`WriteDacl`/`WriteOwner`/`Owns`) over OUs that **no other rule surfaced** (SEC-060 is broad-principal-only; SEC-081 only labels them as gPLink). `EvaluateBroadContainerControl` in `GroupMembershipRuleEvaluator`. **Two-axis design (user-approved):** severity = impact, disposition = certainty. `disposition=review_required` (AD legitimately delegates broad OU control to OU owners / data admins — Microsoft Delegation-of-Control model), Detail leads "Review delegation:". Severity tiers: **Critical** when the OU subtree contains a Tier-0 object — including an account that is DA/EA/SA **by transitive membership** at any nesting depth (the "DA 15 OUs deep" case), detected via `fact_group_membership_closure` + a robust `DnHelper.GetParentDn` ancestor-OU walk (no fragile DN suffix-match); **Medium** otherwise. Excludes admins/privileged-by-membership (expected owners) **and** broad principals (SEC-060's domain — clean partition). Perf verified cheap: `fact_ace` is NOT inheritance-materialized, so findings scale with explicit-delegation count, not tree size; single indexed query + in-memory ancestor set. Full parity wiring (rules.yaml, coverage `[Objects, SecurityDescriptors, ControlEdges, GroupMembership]`, hint, evidence-matrix, parity snapshot + GroupMembership-coverage list, rule-count 57→58, UI guidance, SEC-063.md card). 9 tests incl. the deeply-nested-DA Critical headline. **Lab real-run:** 2 Critical (OU subtree holds `ba.admin`, DA-by-membership) + 1036 Medium review = 1038. **Open thread:** SEC-081 and SEC-063 both fire on broad OU writes (intentional, different questions — documented in SEC-063 card §11; revisit if noisy).

- **SEC-123 sIDHistory false-negative fixed (`[IMP-CTRL-SCOPE]` widening, decision reversed on lab evidence) — lab-validated:** SEC-123 keyed only on a sIDHistory-scoped object ACE (`object_type_guid = sIDHistory AND mask & 0x20`), missing every non-object all-properties / `GenericAll` write — which genuinely confers sIDHistory write because `sIDHistory` is `System-Only=False` (Server 2003+) and non-confidential (verified Microsoft adschema `a-sidhistory` + property-ACE inheritance semantics; the SEC-090 confidential exception does NOT apply here). The earlier card argued "documented partition, don't widen" — **lab disproved it** (3 real misses incl. `Everyone`). Widened to `(object_type_guid = sIDHistory OR object_type_guid IS NULL) AND mask & 0x20`; added `write_scope` (`specific` | `all_properties`). 6 new tests. **Lab real-run: 3 Critical (was 0).**

- **SEC-081 honest labeling (`link_capability`) — lab-validated:** SEC-081's `[IMP-CTRL-SCOPE]` widening fires on any broad OU write that subsumes gPLink (verified correct: "write all properties" includes `gPLink` per Microsoft adschema). Of 1040 lab findings, only 1 was a targeted `LinkGPO` edge; 1039 were broad `WriteAllProperties`. New dedicated `EvaluateGpoLink` adds `link_capability` (`specific` vs `via_broad_write`) so the 1 real delegation is distinguishable; count unchanged (no coverage loss). 3 new/updated tests. Lab: 1 specific / 1039 via_broad_write.

- **SEC-090 confidential-attribute fix (CONTROL_ACCESS, not READ_PROPERTY) — the trigger, lab-validated:** Real lab evidence (Authenticated Users mask `0x00020094` = ReadAllProperties on a computer) was firing SEC-090 as a false positive on ~every computer. Microsoft KB922836 + LAPS AD docs confirm: LAPS attributes are confidential, so reading them requires **CONTROL_ACCESS (`0x100`)** in addition to READ_PROPERTY; the real `Set-LapsADReadPasswordPermission` delegation grants CONTROL_ACCESS. The `0x10` gate was both a false positive (default AuthUsers read) AND a latent false negative (CONTROL_ACCESS-only delegations). Re-gated both branches on `0x100`; renamed `broad_read`→`all_extended_rights`. ~6 tests updated/added incl. the Evidence-59017 regression. **Lab real-run: 2 High (was a per-computer flood under the old gate).**

3 SEC-090: not-decryptor, implicit-DA, legacy-omits). Infrastructure 1746 passed (3 skipped) + Core 1074 green. **Lab-validated:** 3 decryptor configs across 3 domains all resolved to non-broad SIDs (incl. a sAMAccountName with a space and a cross-domain NetBIOS form) → SEC-093 correctly produces 0 findings (true negative, not a silent resolver failure).

- **`[IMP-GPO-SYSVOL]` Phase B — SEC-080 SYSVOL-DACL union (branch `feature/sec080-sysvol-dacl-union`):** A GPO can be modified via two independent ACLs — the directory-object ACL (SEC-080's `fact_control_edge` vector) **or** filesystem write on its SYSVOL policy folder (SEC-082's `fact_sysvol_ace` vector). Chose **Option A (enrich, don't merge)** to deliver the "complete who-can-modify-this-GPO" picture without disturbing the SEC-082 rule shipped earlier this session: `EvaluateGpoModify` now loads the non-admin SYSVOL writers per GPO (`LoadSysvolWritersByGpo`, table-guarded via `TableExists("fact_sysvol_ace")`, same `SysvolWriteMask` + admin exclusion as SEC-082) and adds `also_writable_via_sysvol` + sorted `sysvol_writer_sids` to the SEC-080 `ContextJson` **only** when a second non-admin path exists (base shape unchanged otherwise). SEC-082 untouched — still fires independently. Enrichment-only, so no rules.yaml / parity / rule-count change. Closes SEC-080 review-card §13 item #9 (the long-standing "SEC-080 silently misses the SYSVOL half" gap). 4 new tests (flag+writers present, base-shape-unchanged, admin-writer-excluded, different-principal-writer). Infrastructure 1737 passed (3 skipped) + Core 1074 green. GPP off-by-default confirmed by the user as intended (verified off in lab); `_NEXT.md` reconciled.
Default ON by design (the environments that still have cpassword are the ones that think they are clean). **Resolved:** flipped to **off-by-default** (commit `4e48b507`, surfaced on the audit screen with an explanation) and confirmed by the user as the intended behavior (verified off in lab). 6 tests; Core 1072 + Infrastructure 1733 green.
- **`[IMP-GPO-SYSVOL]` Phase B — SEC-083 GPP cpassword exposure shipped & lab-validated (`9f60c47b` parser + `4125b8b` capture + `246d60bf` finding):** Detects Group Policy Preferences cpassword exposures (CVE-2014-1812) — a credential in SYSVOL XML, AES-encrypted with a public key, recoverable by any authenticated SYSVOL reader. **Presence-only end to end:** no password value, no AES key, no decryption anywhere (also keeps the binary clear of GPP-recovery hacktool signatures); the finding names the file + account, verified natively via `findstr`. **Key design pivot:** the CSE-GUID smart-filter could not be used (GPP CSE GUIDs are not published in first-party docs and could not be verified — so they were NOT hard-coded). Instead capture **enumerates SYSVOL `*.xml` directly** (`ISysvolFileReader.EnumerateRelativeFilesAsync`), which is provably complete and scope-agnostic (finds Machine + User GPP without `gPCUserExtensionNames`). Module restructured so GPP + DACL scans run for EVERY GPO while Registry/GptTmpl stay CSE-filtered. Parser is XXE-hardened. SEC-083 (Critical / CredentialTheft / T1552.006) in `GpoRuleEvaluator` over `dim_gpo_setting` GPP rows. Full wiring (rules.yaml, hint with findstr, evidence-matrix, coverage, parity, rule-count 55→56). **Lab-validated:** GPMC on Server 2022 blocks creating cpassword (MS14-025 working as designed), so validated by dropping a legacy `Groups.xml` manually — the enumeration approach found it even though the GPO had no GPP CSE registered.

- **`[IMP-GPO-SYSVOL]` Phase B — SEC-082 shipped & lab-validated (`6fe177b` fix + `046b4877` feature):** First Phase B finding consuming `fact_sysvol_ace`. **SEC-082** (Critical / ConfigurationHygiene / T1484.001) flags a non-admin principal with filesystem write (FILE_WRITE_DATA / WRITE_DAC / WRITE_OWNER / GENERIC_WRITE / GENERIC_ALL) on a GPO's SYSVOL policy folder — the on-disk modify vector SEC-080's directory-object ACL cannot see. **Prerequisite bug caught by code-verification before writing the query** (`6fe177b`): `SysvolAceWriter` had run filesystem ACEs through `AceNormalizer`/`GenericRightsExpander`, which applies AD-DS generic-rights semantics — a filesystem `GENERIC_WRITE 0x40000000` was rewritten to AD `DS_WRITE_PROPERTY` bits, so SEC-082's write check would have silently missed a principal who can rewrite Registry.pol (security false negative). Fixed to store the raw `ParsedAce.AccessMask` verbatim with a local SHA-256 dedup hash; 2 regression tests pin raw masks. SEC-082 evaluator in `GpoRuleEvaluator` (groups `fact_sysvol_ace` by (trustee, gpo), filesystem write-mask filter, admin exclusion, `dim_object` join; ContextJson `vector=sysvol_folder_dacl`). Wiring: rules.yaml, remediation hint, evidence-matrix entry, `RuleCoverageRequirements [Objects, Sysvol]`, parity snapshot + known-module set + rule-count (54→55). 8 evaluator tests. **Live validation:** empty on clean default SYSVOL ACLs (no false positives); fires Critical when a non-admin is granted Modify on a GPO's SYSVOL folder. Core 1052 + Infrastructure 1720 green.

- **`[IMP-GPO-SYSVOL]` Phase A — SHIPPED & field-validated (branch `feature/sysvol-capture`, 11 commits `58f1947b` → `cdc2642`):** Full SYSVOL group-policy capture, integrated into the live per-shard pipeline with integrated Windows auth (no DA — SYSVOL is `Authenticated Users` readable). **Pure Core parsers:** `RegistryPolicyParser` (`[MS-GPREG]` Registry.pol, `58f1947b`), `SecurityTemplateParser` (GptTmpl.inf, lossless + typed PrivilegeRights/GroupMembership accessors, `eea79b09`), `GpoClientSideExtensions` CSE smart-filter (permissive fallback, `8ef6ae89`). **Capture attribute:** `gPCMachineExtensionNames` added to `GpoAttributes` (CatalogVersion 9→10, `8f5ace8e`). **Schema:** `dim_gpo_setting` + `fact_sysvol_ace` in SecurityTableDdl (`6029a9e`). **Infra:** `ISysvolFileReader` seam + `SmbSysvolFileReader` (UNC + `WNetAddConnection2`, `d8ce130`), `SysvolSettingWriter` (`19d47e1`), `SysvolAceWriter` (via `AceNormalizer` — same canonical `ace_hash` as `fact_ace`, in `e63fdb9`), `SysvolCaptureModule` (`16719a5b` settings + `e63fdb9` DACL), `GpoCaptureTargetBuilder` LDAP work list (`0b50b51`), runner wiring (failure-isolated; never fails the LDAP shard, `a3106ad`). **Live validation (root + 2-child lab):** all 3 domains `Sysvol` coverage `Complete`; `dim_gpo_setting` populated (LAPS / EFS-DRA / `SeDebugPrivilege` data observed); `fact_sysvol_ace` populated. **Two interop-boundary bugs caught:** nested SQLite transaction (overlapping writers → sequenced into two scopes); `GetAccessControl(AccessControlSections.All)` requested the SACL (needs `SeSecurityPrivilege`, unavailable over SMB) → silent null → empty `fact_sysvol_ace` → fixed to `Owner|Group|Access` (`cdc2642`) with a real-filesystem regression test the in-memory seam had been hiding. **Lesson:** any real-I/O class behind a test seam needs a test against the real implementation.

- **Carved-out follow-ups closed (SEC-090 broad-read fix + SEC-121 acceptance):** (1) **SEC-090** — the broad-`ReadAllProperties` LAPS gap (`[IMP-CTRL-SCOPE]` residual). A non-object ACE (`object_type_guid IS NULL`, `access_mask & 0x10`) on a computer reads the LAPS attribute too but was dropped by the attribute-GUID predicate. Widened SEC-090's SQL with an `object_type_guid IS NULL` branch; the finding reports `laps_password_attribute = "any"` + `broad_read = true` (the READ analog of the property-write widening; does not reuse `PropertyWriteEquivalents`). Admin-source exclusion + ReadProperty-bit gate preserved. 3 new tests; Infrastructure 1656 passed (3 skipped). (2) **SEC-121** — the DC-OU-by-English-DN note (`[IMP-DC-DETECT]` residual): **accepted-with-known-limitation**. Unlike SEC-122 (DC computer account, already robust via `IsDomainControllerSql`), SEC-121 targets the OU *container* (no UAC/primaryGroupID), and the resilient signals (`systemFlags` / `wellKnownObjects`) are not captured today — the robust fix needs capture-side work. Residual risk is low (AD does not localize the default DC OU; DN is head-anchored; only a renamed default DC OU misses). Docs-only.
- **`[IMP-CYC-CONTEXT]` + `[IMP-CYC-MULTI-WITNESS]` (SEC-052 — structured cycle context + meshedness, done together):** SEC-052 carried each circular group-nesting cycle only as an arrow-joined name string (not machine-actionable, lossy when two groups share a CN) and emitted one representative cycle per SCC with no signal about how tangled the component was. Added to ContextJson: `cycle_sids` + `cycle_edges` (directed group→member, closing edge included) for `[IMP-CYC-CONTEXT]`; and `scc_size`, `back_edge_count` (`intra-SCC edges − scc_size`, exact O(edges) meshedness signal), bounded `alternate_cycles` (cap 5, harvested from the per-anchor-neighbor BFS that already runs) + `alternate_cycles_capped` for `[IMP-CYC-MULTI-WITNESS]`. Chose option (b) — one finding per SCC — over per-simple-cycle findings (exponential enumeration / finding explosion risk); FindingKey shape unchanged. `ExtractRepresentativeCycle` now returns a `CycleExtraction` record. Pinned by 3 new tests. Infrastructure 1653 passed (3 skipped) green.
- **`[IMP-COV-REASON]` (SEC-002 — resolved by decision, will not implement):** The ask was to surface, in `coverage_reason`, when a principal that would otherwise fire SEC-002 is suppressed solely by a `deny_cancelled = 1` edge. **Decision (analogous to `[IMP-LAPS-ENCRYPTION]`):** a deny that cancels a DCSync grant is *working* security control, not a defect; emitting a per-principal finding for every deny-suppressed (principal, target) would convert correct defensive config into noise (deny-cancelled edges are common via inheritance + explicit denies). The suppressed edges are retained + directly queryable in `fact_control_edge` (`deny_cancelled = 1`), and `StampCoverageOnFindings` structurally only annotates findings that *did* fire (capture-completeness), not absences. Cheapest useful form if ever needed = a run-level aggregate count in the coverage summary, not per-principal findings. Docs-only resolution; no code change.
- **`[IMP-RBCD-TRUSTEE]` (SEC-013 / SEC-122 — enumerate RBCD trustees):** `msDS-AllowedToActOnBehalfOfOtherIdentity` is captured as a base64 security descriptor in `dim_delegation.details` but was never parsed, so the findings said "RBCD is configured" without naming who can impersonate. Added `RuleEvaluatorHelpers.ExtractRbcdTrusteeSids` (decode base64 → `SecurityDescriptorParser.Parse` → distinct DACL trustee SIDs, sorted) and surfaced `delegated_trustee_sids` in both SEC-013 and SEC-122 ContextJson. Evaluator-side only (no schema/capture change); malformed SDs degrade to an empty array. Pinned by 3 new tests (trustee enumeration on both rules + malformed-SD guard). Infrastructure 1650 passed (3 skipped). Option (b) per-trustee control edges deferred — not needed for the actionable-subject gap.
- **`[IMP-FALLBACK-TIER]` (escalation fallback tier classifier; product decision: full alignment):** When `dim_asset_tier` is absent, the escalation rules fell back to a bespoke `ClassifyFallbackTier` that mapped only RID 512→Tier0, 519→Tier0Shadow, 516→Tier1 — diverging from both the sibling `IsTierZeroFallbackSid` and the authoritative `StaticAssetTierClassifier`. Verified in code that the static classifier maps RIDs 500/502/512/516/518/519 all to Tier0, operator RIDs to Tier1, and that Tier0Shadow is purely behavioural (not RID-based). Per the user's decision (full alignment), replaced `ClassifyFallbackTier` with a delegation to `StaticAssetTierClassifier` and removed the `GetFallbackSeverity`/`IsTierZeroFallbackSid` boost helpers (fallback severity now equals catalog severity). SEC-070/071 now fire on the full Tier-0 set (4 `_KnownLimitation` pins flipped positive); SEC-073/074 use the real Tier-1 operator RIDs at catalog Medium; SEC-072/075/076/077 do not fire in fallback (Tier0Shadow/Custom need the table — covered by `EscalationPathTierFindingsTests`). Large test churn (~30 tests re-targeted/flipped). Infrastructure 1647 + tier-table 57 + Core 997 green.
- **`[IMP-KEY-COLLAPSE]` (FindingKey sub-object discriminator):** `fact_finding` PK is `(run_id, finding_key)` with `INSERT OR IGNORE`, so two findings sharing a key silently collapse to one. Code-verified triage found **two genuine sub-object collapses that undercounted**: SEC-012 (one row per `(account, sensitive SPN)` but key omitted the SPN — N SPNs → 1 finding) and SEC-100 (one row per `(service_account, privileged_group)` but key omitted the group — SA in DA+EA → 1 finding). Added an optional `findingKeyDiscriminator` param to `CreateDelegationFinding`; SEC-012 passes the SPN target, SEC-100 the group SID. Flipped both collapse pins to `...FiresPerSpn` / `...FiresPerGroup`. The other listed rules were left unchanged: SEC-014/060/080 collapse by design (one "can-modify-X" finding per X, pinned by `...EmitsSingleFinding`), and SEC-020/026/062/092 emit one finding per object. Full Infrastructure suite 1651 passed (3 skipped) green.
- **`[IMP-TGT-CLASS]` (target object_class enforcement):** Code-verified triage of the ~18 listed rules showed most already had class filters (SEC-020/021/022/023='user', SEC-050/051/052='group', SEC-100/101=ServiceAccountClassifier, and SEC-006/014/024/025/081 filtered last session via the CTRL-SCOPE coupling). Added the genuinely-missing `object_class IN (...)` filter to five rules: **SEC-040** (`pKIEnrollmentService`/`pKICertificateTemplate`), **SEC-123** (`user`/`computer`/`inetOrgPerson`/gMSA), **SEC-124** (`domainDNS`/`configuration`/`dMD`), **SEC-026** (account classes), and **SEC-120** (`'container'` + DN-head anchoring `LIKE 'CN=AdminSDHolder,CN=System,%'` to stop child-DN leakage). SEC-060 accepted by design (spans many classes; Tier-0 detection is SID/DN-based). Each fix pinned by a wrong-class guard test (6 new). Full Infrastructure suite 1651 passed (3 skipped) green. SEC-121/122 DN-by-English-name notes remain open under `[IMP-DC-DETECT]` (re-tagged last session).
- **`[IMP-CTRL-SCOPE]` finished (remaining cards resolved):** After the widening group (SEC-006/014/024/025/081), closed out the rest by code-verified classification: (1) **documented partition** for SEC-201 / SEC-204 / SEC-123 / SEC-124 — their equivalents intentionally fire under a sibling rule (verified the actual `control_type IN (...)` sets in `AdvancedRuleEvaluator`); added the SEC-204 `WhenNonPrivilegedHasGenericWriteOnPrivilegedTarget_ThenSEC204DoesNotFire` regression pin (GenericWrite lacks WRITE_DAC/WRITE_OWNER, so it is deliberately not in the spill set). (2) **resolved SEC-060** — its "shared TakeoverControlTypes constant" ask is satisfied by `BroadPropertyWriteRights`. (3) **re-tagged mis-classified notes** — SEC-120 → `[IMP-TGT-CLASS]` (DN anchoring), SEC-121/122 → `[IMP-DC-DETECT]` (DC-OU-by-English-DN), SEC-131 → `[IMP-DELEGATION-SOURCE]`; these were never control-type-equivalence issues. (4) **carved out** SEC-090's broad-`ReadAllProperties` LAPS gap as a distinct READ-equivalence follow-up (the property-write helper does not apply to reads). Full Infrastructure suite 1645 passed (3 skipped) green.
- **`[IMP-CTRL-SCOPE]` widening group (SEC-006 / SEC-024 / SEC-025 / SEC-081 + SEC-014 retrofit):** Capture tags each ACE with exactly one `control_type` and never decomposes `GenericAll` (`ControlEdgeService.DeriveControlTypes` early-returns), so rules keyed on a specific property-write edge missed principals who hold the capability via a broad grant. **Key discovery:** widening is coupled with `[IMP-TGT-CLASS]` — the broad rights are class-agnostic, so widening without a target `object_class` filter would (e.g.) fire "can write SPNs" on a group. Added shared `RuleEvaluatorHelpers.BroadPropertyWriteRights` + `PropertyWriteEquivalents(specific)`, a class-filtered multi-type overload of `EvaluateControlEdgeOnAdminTarget`, and `GROUP BY MIN(control_type)` dedup on `EvaluateControlEdgeRule`. Widened SEC-006 (`AddMember`→group), SEC-024 (`WriteSPN`→user/computer/gMSA, bespoke method), SEC-025 (`WriteKeyCredentialLink`→user/computer/gMSA), SEC-081 (`LinkGPO`→OU/domain/site); retrofitted SEC-014's missing class filter. DACL-pivot rights excluded (SEC-004/005's domain). Each pin flipped DoesNotFire→Fires + paired class-guard negative. Committed SEC-006 first as a reviewed proof-of-shape (`dea7344`), then the rest. Core 997 + Infrastructure 1644 passed (3 skipped) green. **Remaining `[IMP-CTRL-SCOPE]` follow-ups (separate, smaller):** document the sibling-rule partition for SEC-090/123/124; re-tag SEC-120/121/122 (DN-identification, not control-scope) to `[IMP-TGT-CLASS]`; SEC-003 (`ResetPassword`) is an extended-right class (GenericAll-only).
- **`[IMP-DUP-RULE]` (SEC-010/011 — unconstrained-delegation duplicate; product decision: partition):** SEC-010 and SEC-011 ran byte-for-byte identical SQL (`delegation_type = 'Unconstrained' AND NOT IsDomainController`), so every non-DC unconstrained-delegation principal fired both — `High` (SEC-010) + `Critical` (SEC-011) — duplicating findings. Per the user's product decision (option b), partitioned the two evaluators on `object_class`: SEC-010 adds `AND o.object_class != 'computer'` (users / gMSAs, `High`); SEC-011 adds `AND o.object_class = 'computer'` (computer principals, `Critical`). Each non-DC principal now fires exactly one rule, aligning with the catalog wording set under `[IMP-CAT-WORDING]`. Flipped the duplicate pin to two mutual-exclusion tests (`WhenComputerHasUnconstrained_ThenOnlySEC011Fires`, `WhenNonComputerHasUnconstrained_ThenOnlySEC010Fires`); converted user/gMSA SEC-011 tests to partition negatives and computer SEC-010 tests to non-computer cases; removed two redundant DC-detection mirrors. Parity unaffected. Core 997 + Infrastructure 1636 passed (3 skipped) green. SEC-013/020/021/022/023/076/077 are privileged-vs-general variants (distinct SQL), not duplicates — out of scope.
- **`[IMP-HV-CAT]` (SEC-024 — high-value SID catalog consistency):** `WellKnownSidCatalog.IsHighValue` disagreed with the codebase's other Tier-0 authorities — RID 512 (Domain Admins) was high-value but RID 500 (built-in `Administrator`) was not, so a `WriteSPN` edge onto RID 500 surfaced as `High` instead of `Critical`. Audited the flags in one sweep against `IsTierZeroFallbackSid` (`{500,502,512,516,518,519}`) and `HighValueTargets.AdminUserRids` (`{500,502}`); flipped RID 500 (Administrator) and `S-1-5-32-550` (`BUILTIN\Print Operators`, inconsistent with its three AdminSDHolder sibling operator groups) to high-value; bumped `CatalogVersion` 2→3. Blast radius confined to SEC-024 severity + the tier-0 action-priority boost; escalation paths use `HighValueTargets` (unaffected). Pinned by expanded `WellKnownSidCatalogTests` + `WhenWriteSpnTargetIsBuiltinAdministrator_ThenSEC024IsCritical`. Core 997 + Infrastructure 1638 passed (3 skipped) green.
- **`[IMP-SPN-PARSE]` (SEC-012 — SPN host:port parsing):** SEC-012's constrained-delegation host match had fragile substring math — when the sensitive SPN host carried a port but no dot (`cifs/DC05:445`), both branches of the old `INSTR`/`SUBSTR` OR returned the `:445` suffix, so the host never equalled the DC's short CN (false negative). Added the shared `RuleEvaluatorHelpers.ShortSpnHostSql(column)` SQL fragment (substring-after-`/` → strip `:port` → strip DNS suffix) and rewrote the host match as a single `UPPER(ShortSpnHostSql(d.target)) = UPPER(<DC short CN>)` equality. Flipped `WhenConstrainedDelegationCifsWithPortAndNoDot_ThenSEC012DoesNotFireKnownLimitation` to `..._ThenSEC012Fires` and added `WhenConstrainedDelegationCifsWithPortAndDot_ThenSEC012Fires`. Focused filter 34 passing; full `SecureAD.Infrastructure.Tests` green (1637 passed, 3 skipped).
- **DC-detection investigation (3 commits — `ff8f58d`, `068faaa`, `22b5d65`):** Triggered by a real symptom — *child-domain DCs were firing SEC-091 ("LAPS Missing") because each child DC also has a member-server computer account in the parent domain*.
  - `22b5d65` — **the fix for that symptom.** Added `RuleEvaluatorHelpers.IsDomainControllerOrChildShadowSql(connection, alias)`: ORs the per-row DC check with a cross-domain correlation — a computer row is also treated as a DC if another `dim_object` row with the **same `sam_account_name`**, a **different `domain_fqdn`**, is itself a DC. Wired into SEC-091 (main + legacy paths) and SEC-092. Added `idx_dim_object_sam` index. Requires the same-named peer to actually be a DC, so it does NOT over-exclude two different member servers sharing a short name. Pinned by `WhenChildDcHasMemberAccountInParentDomain_ThenSEC091DoesNotFire`, `WhenTwoMemberServersShareSamAccountNameAcrossDomains_ThenBothStillFireSEC091`, `WhenChildDcStaleLapsHasParentMemberAccount_ThenSEC092DoesNotFireOnParentAccount`.
  - `068faaa` — broadened the per-row DC check to multi-signal: `IsDomainControllerSql` now ORs `userAccountControl & 0x2000` **OR** `primary_group_id IN (516,521)` **OR** anchored DN `LIKE '%,OU=Domain Controllers,DC=%'`, wrapped in `COALESCE(...,0)=1` to avoid NULL three-valued-logic poisoning. Added schema-adaptive overload `IsDomainControllerSql(connection, alias)` that drops clauses for absent columns (used by the legacy-schema path). All 7 production callers migrated.
  - `ff8f58d` — Resolved `[IMP-LAPS-ENCRYPTION]` **by product decision** (SEC-090 stays `High` regardless of LAPS encryption mode; added `laps_password_attribute` ContextJson key). Expanded `[IMP-GPO-SYSVOL]` into a full scoped SYSVOL roadmap (Phase A infra + 10+ Phase B findings, runs as `Authenticated Users`, no DA).
  - **NOTE for next chat:** the symptom fix is committed but **not yet verified against a live lab**. First action when a lab is available: re-run an audit and confirm child-domain DCs no longer appear under SEC-091/092.
- **Classifier / catalog trilogy + correctness sweep (commits `a483ffb` → `c6dc6ef`):** `[IMP-PRIV-GROUPSET]` (`PrivilegedGroupCatalog`), `[IMP-OS-CLASSIFIER]` (`OperatingSystemClassifier`), `[IMP-SA-DETECT]` (`ServiceAccountClassifier`), `[IMP-WK-GUID]` (`WellKnownGuids.GetGuid` lookup + evaluator migration), `[IMP-MEMB-UNION]` (`v_group_membership_effective` view), `[IMP-REASON-DRIFT]` (`TierReasonCatalog`), `[IMP-DELEGATION-SOURCE]` (SEC-077 → `dim_delegation`), `[IMP-ACE-VS-EDGE]` (SEC-090/123/124 LEFT JOIN `fact_control_edge` for deny-cancelled + edge provenance), `[IMP-MITRE-FIT]` (dropped misleading T1078.002 from SEC-091/092), `[IMP-DCSYNC-FILTERED-SET]` (tier classifier now matches SEC-002's `GetChanges + GetChangesAll|GetChangesInFilteredSet`), `[IMP-LEGACY-FALLBACK]`, `[IMP-DETAIL-UNICODE]`, `[IMP-FILETIME-SQL]`, `[IMP-DATETIME-COMPARE]` (audited, already correct), `[IMP-EMPTY-SUBJECT]`.
- **Earlier cross-cutting wins:** `[IMP-ALLOWLIST]` (typed `SuppressionEntry` + `SuppressionMatcher` + post-evaluator pass), `[IMP-ACTION-REPORT]` (action synthesis pipeline), `[IMP-DN-ENRICH]`, `[IMP-PRIV-PROV]`, `[IMP-PRIV-MEMB-SRC]` Option C, `[IMP-MEMB-SOURCE]`, `[IMP-NAME-DERIVE]`, `[IMP-OBJ-JOIN]`, `[IMP-BROAD-DRIFT]`, `[IMP-COV-MEMB]`, `[IMP-NULL-SID]`, `[IMP-CTX-RULEID]`, `[IMP-DISABLED-FILTER]`, `[IMP-KRBTGT-FILTER]`, `[IMP-DC-DETECT]`, `[IMP-DEAD-CHECK]`, `[IMP-PARITY-TEST]`, `[IMP-CAT-WORDING]`.

### Next candidate work — backlog complete

**All 47 cross-cutting `[IMP-*]` tags are Resolved or Deferred.** There is no open
cross-cutting work. Authoritative check (run to confirm — every tag should show a
Resolved/Deferred/by-decision marker):
```powershell
Select-String -Path docs\rules\IMPROVEMENTS.md -Pattern "\[IMP-[A-Z-]+\]"
```

**The two small carved-out follow-ups are now closed:**
- SEC-090 broad-`ReadAllProperties` LAPS read gap — **RESOLVED** by widening SEC-090's SQL
  with an `object_type_guid IS NULL` ReadProperty branch (`laps_password_attribute = "any"`
  + `broad_read`). The READ analog of the property-write widening.
- SEC-121 DC-OU-by-English-DN detection — **Accepted-with-known-limitation** (blocked on
  uncaptured `systemFlags` / `wellKnownObjects`; low residual risk — AD does not localize
  the default DC OU and the DN is head-anchored). SEC-122 was already robust via
  `IsDomainControllerSql`.

**Deferred (Phase B — needs Phase A, now available):** `[IMP-GPO-SYSVOL]` **Phase B findings** —
the 10 SYSVOL-data findings that consume `dim_gpo_setting` + `fact_sysvol_ace` (starting with the
SEC-080 SYSVOL-DACL union and LAPS decryptor-identity tiering, which closes the deferred half of
`[IMP-LAPS-ENCRYPTION]`). Phase A capture infrastructure is complete and field-validated.

**Lab-verified:** the DC-detection symptom fix (commit `22b5d65`, on `master`) is now
**confirmed against the live root + 2-child lab** — child-domain DCs no longer appear as
computer-object findings under SEC-091/092 in the root domain. No open lab-verification items.

**Review TODO — audit-toolbar report contents:** the AppShell header-bar report buttons
(`Forest`, `Hygiene`, `Delegation`, `Export`) and their handlers were relocated/restyled in
an earlier session (now in `AppShell.xaml` / `AppShell.xaml.cs`; neutral styling against the
blue header is intentional and kept). Their *location and color are confirmed good*, but the
**actual content of each generated report** (`ForestReportGenerator`,
`AccountHygieneReport`, `DelegationReportGenerator`) has not been reviewed recently — sit
down and confirm each report still surfaces the right sections/findings before relying on them.

**Follow-up — interactive suppression is not durable in the grid across runs:** the two
findings views disagree on where `is_suppressed` comes from. `v_grid_findings` (the UI grid)
reads the **static** `fact_finding.suppressed` column, whereas `v_export_findings_evidence`
(exports) reads a **live** `LEFT JOIN dim_suppression ... WHERE active = 1`. `SuppressionService`
(the grid "accept risk" button) now stamps `fact_finding.suppressed` at suppress-time so the grid
reflects it *within the current run* (this fixed `FindingsGridViewModelTests`), but generation-time
reconciliation only applies the `SuppressionEntry` allowlist via `SuppressionMatcher` — it never
re-applies `dim_suppression`. **Consequence:** a finding suppressed interactively stays suppressed
in *exports* across runs but reappears in the *grid* after the next analysis run (because
`fact_finding` is regenerated). Decide the fix: either (a) reconcile `dim_suppression` →
`fact_finding.suppressed` at run start, or (b) point `v_grid_findings.is_suppressed` at the live
`dim_suppression` join like the export view (note: the grid `MapRow` reads columns positionally,
so a view-column change there is fragile — see the reverted attempt this session).

**Suggested order for a fresh chat:** the cross-cutting `[IMP-*]` backlog is **complete** (47/47 Resolved or Deferred), and the two small carved-out follow-ups are closed (SEC-090 broad-read was re-opened and *corrected* this session — confidential-attribute CONTROL_ACCESS gate; SEC-121/122 DC-OU remains accepted-with-known-limitation, blocked on uncaptured `systemFlags`). **Remaining work, in suggested priority:**
Revisit encryption-types if a future capture contains it. **Tier-0 isolation:** **SEC-067 (Tier-0 Account Exposed to Delegation Impersonation) is SHIPPED & lab-validated (`48a1e74f`)** — risk-gated delegatable-admin detection. The *Deny-logon-rights* variant (adding DA/EA/SA to the 5 `SeDeny*` rights on member/workstation OUs) remains **DEFERRED** — absence-dominated (lab has zero `SeDeny*` rows; the secure state is the *presence* of denies, and we deliberately don't flag absence from GptTmpl), and it needs OU-classification we don't have. **Evaluator-only Phase B is now COMPLETE** (every captured GptTmpl/Registry.pol/GPP section has a rule). The remaining roadmap items — **audit policy** and **AppLocker** — are confirmed NOT captured (probe `30-audit-applocker-presence.txt`) and require NEW Phase A SYSVOL parsers (`audit.csv` / `AppLocker\\*.xml`) before any rule. **Audit policy is the worthwhile capture project** (doc-grounded baseline subcategories, detection-layer complement to the prevention rules); **AppLocker is deprioritized** (presence ≠ secure; config-checker risk). Treat these as a separate, larger capture effort — not the next quick win.
2. **Cheap correctness sweeps (this session's residue):** `[IMP-DEL-OBJ]` — add `is_deleted = 0` to SEC-124 / SEC-201 / SEC-204 (SEC-123 got it; same mechanical pattern). `[IMP-WK-GUID]` candidate — three different sIDHistory GUIDs scattered across the codebase (SEC-123 evaluator now correct; centralize/guard the literals).
3. **SEC-081 ↔ SEC-063 overlap review** — both fire on broad OU writes (intentional today; revisit if noisy in a real environment).
4. **UI/reporting (different gear):** audit-toolbar report contents review; interactive-suppression durability across runs (see the two TODOs below).

### NEXT UP (prior) — SEC-067 Tier-0 Account Exposed to Delegation Impersonation — ✅ SHIPPED & LAB-VALIDATED (`48a1e74f`)

> **One-liner:** Flag a Tier-0 **user** account (transitive member of Domain/Enterprise/Schema Admins,
> RID 512/519/518, via `fact_group_membership_closure`) that is **delegatable** — i.e. has **neither**
> the `NOT_DELEGATED` UAC flag (`0x100000`, `UserAccountControlFlags.NotDelegated`) **nor** membership
> in **Protected Users** (RID 525). Such an account's Kerberos credentials can be forwarded by a service
> it authenticates to (delegation abuse → impersonation), defeating tiering.
>
> **Doc grounding (first-party, verified this session):** *Implementing Least-Privilege Administrative
> Models* states verbatim **"By default, all accounts in Active Directory can be delegated"** and lists
> "Enable the 'Account is sensitive and cannot be delegated' flag" as a manual hardening step — so admin
> membership does NOT auto-protect delegation (that misconception was the AdminSDHolder/adminCount sticky
> behavior, which is a different mechanism — protects ACLs, handled by SEC-030). *Protected Users security
> group* doc confirms members "cannot delegate with unconstrained or constrained delegation" but the
> protection is **live/reversible** (ends when you leave the group; NOT sticky — RID 525, default members
> None). So the exclusion must be **flag OR current Protected Users membership** (neither = fire).
>
> **Lab true positives (probe `ProbeTier0DelegatableAccounts`, output `26-tier0-delegatable.txt`):** 6
> Tier-0 user accounts, **all 6 delegatable** (ba.admin uac=66048, jimmy.strand.da uac=66048, jimmystrand
> x3 uac=512, ph.admin uac=66048) — none have the flag, need to confirm none are in Protected Users (525)
> during build (could lower the count). No existing rule consumes `NotDelegated` (only surfaced in UI —
> KerberosDelegationViewModel / ObjectDetailPanel), so no duplication.
>
> **Proposed shape:** severity **High**, `disposition=review_required` (two-axis model like SEC-063/064/065/066);
> **user accounts only** (computers/gMSAs have different delegation semantics — out of v1 scope). Pairs with
> the delegation family SEC-010..014. **Known limitation to document:** Protected Users protection requires
> DFL 2012 R2+ and 2012 R2+ DCs (we don't capture DFL reliably) — note, don't try to detect.
>
> **First build step (the SEC-066 discipline):** confirm Protected Users (RID 525) membership for the 6
> accounts before claiming the true-positive count, then a `Tier0DelegationCatalog`-or-inline evaluator in
> a suitable evaluator (AccountHygiene or Delegation family), full parity wiring (rule count 61→62), tests,
> SEC-067.md card, lab validation.

### NEXT UP (prior) — LAPS decryptor-aware finding — ✅ SHIPPED & LAB-VALIDATED

> Shipped on `feature/sec080-sysvol-dacl-union` as **SEC-093** + SEC-090 enrichment (see "Most
> recently completed" above). Lab-validated this session: 3 decryptor configs across 3 domains
> all resolved to non-broad SIDs (incl. a name with a space + a cross-domain NetBIOS form), so
> SEC-093 correctly produces 0 findings (true negative, not a silent resolver failure). Closes the
> deferred half of `[IMP-LAPS-ENCRYPTION]`.

**Shape (user-approved, delivered):** ONE new rule (broad-decryptor risk, SEC-093) **+** enrichment of existing **SEC-090**. Not a single mega-rule.

**Verified format (Microsoft Learn — do NOT re-guess, these are confirmed):**
- Windows LAPS Group Policy writes the authorized decryptor into **Registry.pol** at key root
  `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS`, value name **`ADPasswordEncryptionPrincipal`**.
  (The CSP/Intune root `Software\Microsoft\Policies\LAPS` is MDM, not SYSVOL — out of scope for a SYSVOL scan.)
- Value is stored **as-is** in one of three forms: a **SID string** (`S-1-5-21-…-35197`), **`DOMAIN\name`** (`contoso\LAPSAdmins`), or a **UPN** (`lapsadmins@contoso.com`).
- **Already captured:** `SysvolSettingWriter.WriteRegistryPolicy` writes ALL Registry.pol entries generically into `dim_gpo_setting` (`section = KeyPath`, `setting_key = ValueName`, value via `SerializeRegistryValue`). So the decryptor row is already in the DB if configured — **no capture-side work**. Filter `dim_gpo_setting` where section = the LAPS key root AND setting_key = 'ADPasswordEncryptionPrincipal'.

**Key facts from the docs that shape behavior:**
1. **Single principal only.** LAPS (CNG DPAPI) encrypts against exactly ONE security principal; the official multi-principal pattern is a **wrapper group** — which IS the user's prod env (a universal group with many nested groups, incl. Domain Admins). So: never a list to reconcile, just one identity per scope.
2. **Absence = Domain Admins.** If `ADPasswordEncryptionPrincipal` is NOT configured, the decryptor defaults to **Domain Admins** — and there is **no Registry.pol row**. Treat a missing row as "decryptor = Domain Admins (implicit default)", NOT as "no decryptor". (DSRM-on-DC case also forces DA default.)
3. **Read ≠ decrypt** is Microsoft's own two-circle model (middle = query/read permission = SEC-090's set; inner = decrypt permission = this decryptor identity). Query permission does not imply decrypt.

**Scope guardrails (user-decided — hold these):**
- The ONLY risk check on the decryptor group is **broad principals** (Everyone / Authenticated Users / etc. via `BroadPrincipalCatalog`). Otherwise **trust the org's chosen decryptor group** — do NOT flag non-admins in it (orgs legitimately delegate LAPS decrypt to non-admins).
- **Surface, don't drop:** if the configured name/SID does not resolve in captured `dim_object`/`dim_principal`, emit an `unresolved` coverage signal — never silently ignore it (show truth).

**Outputs:**
| Output | Trigger | Kind |
| --- | --- | --- |
| **Broad decryptor** (NEW RULE, candidate SEC-093) | decryptor principal, or its effective members, includes a broad principal (`BroadPrincipalCatalog`) | Risk finding |
| **Reader-not-decryptor** (SEC-090 enrichment) | a SEC-090 reader who is NOT the decryptor and NOT in its effective membership | Informational context on SEC-090 |
| **Implicit DA default** (SEC-090 enrichment) | no `ADPasswordEncryptionPrincipal` row present | Context: decryptor = Domain Admins |
| **Unresolvable principal** | configured name/SID not resolvable in captured data | Coverage `unresolved` signal (never dropped) |

**Perf (verified — cheap):** transitive expansion is precomputed at build time into `fact_group_membership_closure` (indexed BOTH directions: `idx_fact_gm_closure_group` + `idx_fact_gm_closure_member`); `v_group_membership_effective` UNIONs direct+closure. The evaluator does indexed set lookups only — it does NOT walk the nested groups at eval time. Cost ≈ one indexed query per distinct decryptor identity, proportional to effective member count, independent of nesting depth.

**Name→SID resolution (the one genuinely new bit of work):** the decryptor value may be a name (`DOMAIN\name` or UPN) but `BroadPrincipalCatalog` / closure key on **SID**. Resolve name→SID against captured `dim_object` / `dim_principal` (sam/UPN/DN). Unresolvable ⇒ the `unresolved` coverage signal above.

**Rule-parity checklist — ✅ ALL WIRED (rule count 56 → 57):** rules.yaml (SEC-093); `LapsRuleEvaluator` + RuleIds (`EvaluateLapsDecryptor`); `RemediationHintCatalog`; `FindingEvidenceMatrix` (Context / `dim_gpo_setting`); `FindingsService.RuleCoverageRequirements` (`[Objects, Sysvol, GroupMembership]`); `RuleCatalogParityTests` snapshot; `RuleDefinitionLoaderTests` rule-count (57); `FindingInvestigationProvider.SpecificGuidanceByRule` (UI parity test green). **Remaining:** lab-validate with the user's wrapper-group env.


### Deferred (need new capture-side work — not "open")

- `[IMP-GPO-SYSVOL]` — full SYSVOL capture roadmap (Phase A infra ~3–4 days: `SysvolCaptureModule`, `Registry.pol` + `GptTmpl.inf` parsers, `fact_sysvol_ace`, GPO→OU resolver; Phase B = 10+ new findings: SYSVOL DACL union, LAPS decryptor identity, GPP `cpassword`, Restricted Groups, Kerberos/SMB/LDAP hardening, user-right assignments, Tier-0 isolation, audit policy, AppLocker). Runs as `Authenticated Users` — no DA. See the expanded card in `IMPROVEMENTS.md`.
- `[IMP-LAPS-ENCRYPTION]` — resolved by decision (SEC-090 stays High); decryptor-aware severity tiering is a Phase B item under `[IMP-GPO-SYSVOL]`.


## How to resume in a new chat

Paste this prompt into the new chat (nothing else is needed):

```
Continue work on branch feature/sec080-sysvol-dacl-union (single developer,
no shipped backward-compat constraint). Read docs/rules/_NEXT.md and
docs/rules/IMPROVEMENTS.md first. Per-rule audit is COMPLETE; the
cross-cutting [IMP-*] backlog is COMPLETE (47/47 Resolved or Deferred). Rule
count is 58.

CONTEXT FROM PRIOR CHAT: a lab-driven correctness sweep shipped 5 items, all
lab-validated end-to-end on a real audit.db — SEC-090 (confidential-attribute
CONTROL_ACCESS gate, killed a per-computer FP flood), SEC-123 (sIDHistory
false-negative widening, +3 real findings), SEC-081 (link_capability honest
labeling), and the NEW rule SEC-063 (Unexpected Broad Control Over Container,
Review Delegation, Tier-0-subtree severity tiering). A local-only read-only
LabDbProbe harness (git-ignored at tests/SecureAD.Infrastructure.Tests/Lab/)
drove every fix and is kept on disk for iterative validation.

Trust no documentation — verify everything in code (evaluators,
RuleEvaluatorHelpers, FindingsService, rules.yaml, test fixtures). Fix
correctness defects immediately. After each work item: focused test,
dotnet test green, lab-validate via LabDbProbe when relevant, update
IMPROVEMENTS.md + _NEXT.md. Stop after each item with a summary.

Remaining work, suggested priority: (1) Phase B SYSVOL findings — data is
captured; next candidate is Restricted Groups (Tier-0 membership via GptTmpl);
(2) cheap sweeps — [IMP-DEL-OBJ] is_deleted=0 on SEC-124/201/204, [IMP-WK-GUID]
sIDHistory GUID centralization; (3) SEC-081<->SEC-063 overlap review;
(4) UI/reporting (report contents, suppression durability). Ask which to start.
```


## House rules (must hold every chat)

1. **Code-first.** Verify against evaluators (`ControlEdgeRuleEvaluator`,
   `LapsRuleEvaluator`, `ServiceAccountRuleEvaluator`), `RuleEvaluatorHelpers`,
   `FindingsService`, `rules.yaml`, and the test fixtures. Trust no doc.
2. **One rule at a time**, ending in a summary stop.
3. **Fix correctness defects immediately.** No backward-compat constraint —
   nothing has shipped on this branch.
4. **Cross-cutting ideas → `[IMP-*]` tags in §13**, never inline detours.
5. **Every verified card needs**: catalog claim, SQL, exclusions, output
   assertions, test inventory, parity reference, signed-off `Verified` status.
6. **Every code change needs**: focused test, `dotnet test` green, commit.

## Open `[IMP-*]` backlog — pointer

> **Authoritative source: `docs/rules/IMPROVEMENTS.md`.** Do not maintain a
> second copy of the full taxonomy here — it drifts. The 11 genuinely-open tags
> are listed in the "Next candidate work" table near the top of this file.

To regenerate the open-vs-done split at any time:

```powershell
# Every IMP tag and whether it is marked Resolved/Deferred anywhere in IMPROVEMENTS.md
Select-String -Path docs\rules\IMPROVEMENTS.md -Pattern "\[IMP-[A-Z-]+\]"
```

**Resolved this branch (representative, not exhaustive — see `IMPROVEMENTS.md`):**
`IMP-ALLOWLIST`, `IMP-ACTION-REPORT`, `IMP-PRIV-GROUPSET`, `IMP-OS-CLASSIFIER`,
`IMP-SA-DETECT`, `IMP-WK-GUID`, `IMP-MEMB-UNION`, `IMP-REASON-DRIFT`,
`IMP-DELEGATION-SOURCE`, `IMP-ACE-VS-EDGE`, `IMP-MITRE-FIT`,
`IMP-DCSYNC-FILTERED-SET`, `IMP-LEGACY-FALLBACK`, `IMP-DETAIL-UNICODE`,
`IMP-FILETIME-SQL`, `IMP-DATETIME-COMPARE`, `IMP-EMPTY-SUBJECT`, `IMP-DC-DETECT`
(+ the cross-domain `sAMAccountName` shadow correlation), `IMP-DN-ENRICH`,
`IMP-PRIV-PROV`, `IMP-MEMB-SOURCE`, `IMP-NAME-DERIVE`, `IMP-OBJ-JOIN`,
`IMP-BROAD-DRIFT`, `IMP-COV-MEMB`, `IMP-NULL-SID`, `IMP-CTX-RULEID`,
`IMP-DISABLED-FILTER`, `IMP-KRBTGT-FILTER`, `IMP-DEAD-CHECK`, `IMP-PARITY-TEST`,
`IMP-CAT-WORDING`, `IMP-PRIV-MEMB-SRC` (Option C), `IMP-SPN-PARSE`,
`IMP-HV-CAT`, `IMP-DUP-RULE`, `IMP-CTRL-SCOPE`, `IMP-TGT-CLASS`,
`IMP-KEY-COLLAPSE`, `IMP-FALLBACK-TIER`, `IMP-RBCD-TRUSTEE`,
`IMP-COV-REASON` (by decision), `IMP-CYC-CONTEXT`, `IMP-CYC-MULTI-WITNESS`.

**Deferred (need new capture-side work):** `IMP-GPO-SYSVOL`, `IMP-LAPS-ENCRYPTION`
(both detailed in `IMPROVEMENTS.md`; LAPS-ENCRYPTION resolved-by-decision with
decryptor tiering folded into the GPO-SYSVOL roadmap).

**Open: none.** All 47 cross-cutting `[IMP-*]` tags are Resolved or Deferred.
(Two small carved-out follow-ups remain under existing tags: SEC-090 broad-`ReadAllProperties`
LAPS read gap under `[IMP-CTRL-SCOPE]`; SEC-121/122 DC-OU-by-English-DN under `[IMP-DC-DETECT]`.)


## End-of-chat checklist

Before closing a chat:

- [ ] `dotnet test tests/SecureAD.Infrastructure.Tests` is green.
- [ ] `git status` is clean except for intentional changes.
- [ ] New / updated `SEC-XXX.md` card committed with a conventional message
      (e.g. `docs(rules): verify SEC-004`).
- [ ] Any evaluator / SQL / rules.yaml change committed separately
      (e.g. `feat(findings): tighten SEC-004 DACL filter`).
- [ ] `_NEXT.md` updated with the new "Last verified" and "Next rule to audit".
- [ ] `git push origin feature/finding-investigation`.
