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

# First-Party Verification Ledger

> Single source of truth for the **claim-level** verification of SecureAD's rules against
> first-party Microsoft sources. The goal is not to re-review 62 rules in prose, but to verify each
> unique **fact** a rule depends on **once**, record the exact source, and map it to the rules that
> consume it. A wrong shared fact is the highest-blast-radius bug in a security tool, so those are
> verified first.
>
> This ledger doubles as the **pre-ship maintenance backbone**: when a new Windows Server version or
> Microsoft guidance changes a value, the affected claim row tells you exactly which rules to re-check.

## How to read this

- **Claim** — the atomic verifiable fact (a GUID, an access-mask bit, a SID/RID, a baseline value, an
  attribute semantic, a UAC flag).
- **Value** — what the code uses.
- **First-party source** — the authoritative Microsoft URL (adschema, MS-ADTS, winnt.h, Security
  Baseline, KB). "Trust no doc" — search results are not enough; the cited page must state the value.
- **Status** — `Verified` (first-party page confirms), `Code-review` (validated by reading code only,
  not yet first-party), `Pending`.
- **Rules** — every SEC-* that depends on the claim. Edit this when a rule is added/changed.

## Verification status legend (for rule cards)

To make the audit trackable, rule cards should distinguish:
- **`Verified (first-party)`** — every claim the rule depends on is `Verified` in this ledger.
- **`Verified (code-review)`** — logic reviewed, but one or more claims are still `Code-review`/`Pending`.

---

## Methodology — the claims-inventory approach

Rules fail because a **specific fact** they depend on is wrong, and those facts are **heavily shared**
(RID 512 appears in dozens of rules; the access masks in many). So:

1. **Extract** every literal (GUIDs, masks, SID/RIDs, baselines, UAC flags) from the catalogs +
   evaluators. *(Done this session — see categories below.)*
2. **Dedup** to unique claims; map each to consuming rules.
3. **Verify each unique claim once** against a first-party source; record the URL.
4. **Stamp** rule cards with `Verified (first-party)` once all their claims are green.
5. **Pin** each verified constant with a test (many already exist: `WellKnownGuidsTests`,
   `WellKnownSidCatalogTests`, `UserRightCatalogTests`, `SigningHardeningCatalogTests`, etc.).

**Key finding from the extraction:** the constant surface is **heavily centralized** (`WellKnownGuids`,
`PrivilegedGroupCatalog`, `WellKnownSidCatalog`, `UserAccountControlFlags`, the new catalogs) and much
of it **already carries prior-verification comments** (`[IMP-WK-GUID-RIGHTS]` / `[IMP-WK-GUID-FULL]`
document adschema verification of every Rights-GUID and schemaIDGUID). So the real remaining surface is
the **per-rule baselines and attribute semantics**, not the GUIDs.

---

## Claims inventory — category sizes (extracted this session)

| Category | Approx. count | Where centralized | Risk if wrong | Prior verification? |
| --- | --- | --- | --- | --- |
| Schema GUIDs (extended rights, attrs, classes) | ~50 | `WellKnownGuids` | **Silent false negative** (crown-jewel attack missed) | ✅ Yes — `[IMP-WK-GUID-*]` comments cite adschema per entry |
| Access-mask bits | ~12 | evaluators + `ControlType`/`GenericRightsExpander` | Both (miss or over-fire) | Partial (SEC-090 CONTROL_ACCESS verified this branch) |
| Privileged SID / RID set | ~25 | `PrivilegedGroupCatalog`, `WellKnownSidCatalog`, `RuleEvaluatorHelpers.AdminRids` | Misclassifies privilege | Partial (`[IMP-PRIV-GROUPSET]`, `[IMP-HV-CAT]`) |
| UAC flags | ~10 | `UserAccountControlFlags` | Wrong detection | Code-review |
| Baseline / "secure" values | per-rule | `UserRightCatalog`, `SigningHardeningCatalog`, `LocalPrivilegedGroupCatalog` | **FP flood** (invented threshold) | ✅ SEC-064/065/066 this branch (first-party) |
| Attribute semantics (confidential, System-Only, "all props includes X") | per-rule | evaluator comments + cards | Both | ✅ SEC-090/123 this branch (adschema) |

---

## Verified claims

### Schema GUIDs — extended rights (DCSync pilot)

| Claim | Value | First-party source | Status | Rules |
| --- | --- | --- | --- | --- |
| DS-Replication-Get-Changes Rights-GUID | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | [adschema r-ds-replication-get-changes](https://learn.microsoft.com/windows/win32/adschema/r-ds-replication-get-changes) | **Verified** | SEC-002 |
| DS-Replication-Get-Changes-All Rights-GUID | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | [adschema r-ds-replication-get-changes-all](https://learn.microsoft.com/windows/win32/adschema/r-ds-replication-get-changes-all) | **Verified** | SEC-002 |
| DS-Replication-Get-Changes-In-Filtered-Set Rights-GUID | `89e95b76-444d-4c62-991a-0facbeda640c` | [adschema r-ds-replication-get-changes-in-filtered-set](https://learn.microsoft.com/windows/win32/adschema/r-ds-replication-get-changes-in-filtered-set) | **Verified** | SEC-002 |
| DCSync detection semantics | Get-Changes **AND** (Get-Changes-All **OR** In-Filtered-Set) | adschema (Get-Changes-All = "replication of secret domain data") + Mimikatz DCSync model | **Verified** (logic: `ControlEdgeRuleEvaluator.EvaluateDCSync` self-join) | SEC-002 |

### Access masks

| Claim | Value | First-party source | Status | Rules |
| --- | --- | --- | --- | --- |
| CONTROL_ACCESS (extended right / confidential-attr read) | `0x100` | [KB922836](https://support.microsoft.com/help/922836) + winnt.h `ADS_RIGHT_DS_CONTROL_ACCESS` | **Verified** (this branch, SEC-090 fix) | SEC-090 |
| ReadProperty | `0x10` | winnt.h `ADS_RIGHT_DS_READ_PROP` | Code-review | SEC-090, family |
| WriteProperty | `0x20` | winnt.h `ADS_RIGHT_DS_WRITE_PROP` | Code-review | SEC-123, family |
| GENERIC_ALL / GENERIC_WRITE / WRITE_DAC / WRITE_OWNER | `0x10000000` / `0x40000000` / `0x40000` / `0x80000` | winnt.h generic + standard rights | Code-review | SEC-001..006, 060, 063, 080 |

### Baseline / secure values (verified this branch)

| Claim | Value | First-party source | Status | Rules |
| --- | --- | --- | --- | --- |
| LDAP server signing secure value | `LDAPServerIntegrity = 2` (None=1) | [KB4520412](https://support.microsoft.com/topic/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a) mapping table | **Verified** | SEC-066 |
| LDAP channel binding secure value | `LdapEnforceChannelBinding = 2` (Never=0/WhenSupported=1) | KB4520412 mapping table | **Verified** | SEC-066 |
| SMB server/client signing secure value | `RequireSecuritySignature = 1` (0=disable) | [SMB signing overview](https://learn.microsoft.com/troubleshoot/windows-server/networking/overview-server-message-block-signing) | **Verified** | SEC-066 |
| Netlogon secure-channel secure value | `RequireSignOrSeal = 1` | [Windows security baseline](https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows) (CCE-36142-8) | **Verified** | SEC-066 |
| Sensitive user-right default holders | per `UserRightCatalog` | [Windows Security Baseline — User Rights Assignment](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/user-rights-assignment) | **Verified** | SEC-064 |
| Privileged local-group tiers | per `LocalPrivilegedGroupCatalog` | [AD security groups](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups) + [KB279301 Restricted Groups](https://learn.microsoft.com/troubleshoot/windows-server/group-policy/description-of-group-policy-restricted-groups) | **Verified** | SEC-065 |

### Attribute semantics (verified this branch)

| Claim | Value | First-party source | Status | Rules |
| --- | --- | --- | --- | --- |
| LAPS attributes are confidential (need CONTROL_ACCESS, not just READ_PROP) | confidential | KB922836 + LAPS AD docs | **Verified** | SEC-090, SEC-093 |
| sIDHistory is System-Only=False, non-confidential (all-props write confers it) | non-confidential | [adschema a-sidhistory](https://learn.microsoft.com/windows/win32/adschema/a-sidhistory) | **Verified** | SEC-123 |
| NOT_DELEGATED flag blocks unconstrained + constrained delegation | `0x100000` | [How to Configure Protected Accounts](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts) | **Verified** | SEC-067 |
| Protected Users (RID 525) blocks delegation; live/reversible (not sticky) | RID 525 | [Protected Users security group](https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/protected-users-security-group) | **Verified** | SEC-067 |
| All accounts delegatable by default (admin membership ≠ protection) | n/a | [Implementing Least-Privilege Administrative Models](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models) | **Verified** | SEC-067 |

### Schema GUIDs — property-write attributes (F-1/F-2/F-3 resolution)

| Claim | Value | First-party source | Status | Rules |
| --- | --- | --- | --- | --- |
| `member` attribute schemaIDGUID (capture-side `control_type` = `AddMember`) | `bf9679c0-0de6-11d0-a285-00aa003049e2` | [adschema a-member](https://learn.microsoft.com/windows/win32/adschema/a-member) (System-Id-Guid) | **Verified** | SEC-006 |
| `msDS-AllowedToDelegateTo` attribute schemaIDGUID (capture-side `control_type` = `WriteAllowedToDelegateTo`) | `800d94d7-b7a1-42a1-b14d-7cae1423d07f` | [adschema a-msds-allowedtodelegateto](https://learn.microsoft.com/windows/win32/adschema/a-msds-allowedtodelegateto) (System-Id-Guid) | **Verified** | escalation-path engine (DelegationAbuse) |
| `userAccountControl` attribute schemaIDGUID (capture-side `control_type` = `WriteUserAccountControl`) | `bf967a68-0de6-11d0-a285-00aa003049e2` | [adschema a-useraccountcontrol](https://learn.microsoft.com/windows/win32/adschema/a-useraccountcontrol) (System-Id-Guid) | **Verified** | escalation-path engine (DelegationAbuse) |

### Wave 2 — Kerberos / AS-REP family (SEC-020–026)

| Claim | Value | First-party source | Status | Rules |
| --- | --- | --- | --- | --- |
| AS-REP roastable flag (`DONT_REQUIRE_PREAUTH`) | `userAccountControl & 0x400000` | [adschema a-useraccountcontrol](https://learn.microsoft.com/windows/win32/adschema/a-useraccountcontrol) (ADS_UF_DONT_REQUIRE_PREAUTH) | **Verified** | SEC-022, SEC-023 |
| Unconstrained-delegation flag (`TRUSTED_FOR_DELEGATION`) | `userAccountControl & 0x80000` | adschema a-useraccountcontrol (ADS_UF_TRUSTED_FOR_DELEGATION) | **Verified** | SEC-010/011, F-3 |
| Full `userAccountControl` (ADS_UF_*) bit table | per `UserAccountControlFlags` | adschema a-useraccountcontrol Remarks (ADS_USER_FLAG_ENUM) | **Verified** (pin: `UserAccountControlFlagsTests`) | SEC-022/023 + delegation family |
| Kerberoast detection key | `servicePrincipalName` present on a `user` object (not krbtgt/disabled/deleted) | [adschema a-serviceprincipalname](https://learn.microsoft.com/windows/win32/adschema/a-serviceprincipalname) + service-SPN-prefix allowlist | **Verified** (logic: `EvaluateKerberoastable` + `ServiceSpnPrefixes`) | SEC-020, SEC-021 |
| Kerberos enc-type bitmask (display only) | `0x1` DES-CBC-CRC / `0x2` DES-CBC-MD5 / `0x4` RC4-HMAC / `0x8` AES128-CTS / `0x10` AES256-CTS | [MS-KILE Supported Encryption Types Bit Flags](https://learn.microsoft.com/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919) + [adschema a-msds-supportedencryptiontypes](https://learn.microsoft.com/windows/win32/adschema/a-msds-supportedencryptiontypes) | **Verified** (`FormatEncryptionTypes`) | UI only — **no SEC-020–026 detection consumes it** |

### Wave 2 — service accounts / gMSA (SEC-100–102)

| Claim | Value | First-party source | Status | Rules |
| --- | --- | --- | --- | --- |
| `msDS-GroupMSAMembership` is an NT security descriptor; DACL AccessAllowed ACEs = password-retrieval principals | `String(NT-Sec-Desc)`; = `PrincipalsAllowedToRetrieveManagedPassword` | [adschema a-msds-groupmsamembership](https://learn.microsoft.com/windows/win32/adschema/a-msds-groupmsamembership) + [Manage gMSAs](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/manage-group-managed-service-accounts) | **Verified** (extraction: `ExtractGmsaPasswordRetrievalSids` walks DACL, allow-only; pin: `DirectObjectWriterTests.WhenGmsaMembershipDaclPresent...`) | SEC-102 |
| gMSA object class | `msDS-GroupManagedServiceAccount` | [adschema c-msds-groupmanagedserviceaccount](https://learn.microsoft.com/windows/win32/adschema/c-msds-groupmanagedserviceaccount) | **Verified** | SEC-101 (exclude), SEC-102 (target) |
| SEC-100/101 service-account detection | `ServiceAccountClassifier` (comma-anchored OU + class) + `PrivilegedGroupCatalog` | derived from verified RID/group set | **Verified** (code-review) | SEC-100, SEC-101 |

### Wave 2 — AD CS (SEC-040)

| Claim | Value | First-party source | Status | Rules |
| --- | --- | --- | --- | --- |
| Certificate-Enrollment extended-right Rights-GUID | `0e10c968-78fb-11d2-90d4-00c04f79dc55` | [adschema r-certificate-enrollment](https://learn.microsoft.com/windows/win32/adschema/r-certificate-enrollment) | **Verified** (pin: `GuidCatalogTests`, `ControlEdgeServiceTests`) | SEC-040 |
| `pKICertificateTemplate` class schemaIDGUID + LDAP name (SEC-040 target filter) | `e5209ca2-3bba-11d2-90cc-00c04fd91ab1` / `pKICertificateTemplate` | [adschema c-pkicertificatetemplate](https://learn.microsoft.com/windows/win32/adschema/c-pkicertificatetemplate) | **Verified** | SEC-040 |
| SEC-040 target class filter is correct (string match on captured `objectClass`, not GUID) | `object_class IN ('pKIEnrollmentService','pKICertificateTemplate')` | `ExtractMostSpecificClass` = raw LDAP `objectClass` last value | **Verified** (no catalog GUID needed for `pKIEnrollmentService`) | SEC-040 |

### Wave 2 — Shadow credentials (SEC-025)

| Claim | Value | First-party source | Status | Rules |
| --- | --- | --- | --- | --- |
| `msDS-KeyCredentialLink` schemaIDGUID (write = shadow-credential injection) | `5b47d60f-6090-40b2-9f37-2a4de88f3063` | [AD DS domain-wide schema updates](https://learn.microsoft.com/windows-server/identity/ad-ds/deploy/domain-wide-updates) (domainprep ACE `OA;CI;RPWP;5b47d60f-…;;Key Admins`) | **Verified** (pins: `BuiltInBundlesTests`, `ControlEdgeServiceTests`, `GuidCatalogTests`, drift guard) | SEC-025 | 
| Prior mislabel corrected | `ffa6f046` = MS-TS-GatewayAccess, NOT key-credential-link | adschema (b/c ledger consistency) | **Verified** (already fixed) | SEC-025 |

---

## Wave plan — prioritized by blast radius × danger

### Wave 1 — shared constants + crown-jewel detections (highest priority)
- [x] **DCSync GUIDs + semantics (SEC-002)** — pilot, **Verified** (adschema + EvaluateDCSync self-join logic).
- [x] **Access-mask family** — **Verified first-party** (ADS_RIGHTS_ENUM / Directory Services Access Rights / ActiveDirectoryRights / Control Access Rights). Every bit confirmed: DELETE 0x10000, READ_CONTROL 0x20000, WRITE_DAC 0x40000, WRITE_OWNER 0x80000, SYNCHRONIZE 0x100000, ACCESS_SYSTEM_SECURITY 0x1000000, GENERIC_READ/WRITE/EXECUTE/ALL 0x80000000/0x40000000/0x20000000/0x10000000; DS bits CREATE_CHILD 1/DELETE_CHILD 2/LIST 4/SELF 8/READ_PROP 0x10/WRITE_PROP 0x20/LIST_OBJECT 0x80/CONTROL_ACCESS 0x100; DS_GENERIC_ALL 0xF01FF=983551. Covers SEC-001..006/060/063/080/090/123/124/201/204.
- [x] **Privileged RID / Tier-0 set** — **Verified first-party** ([Security identifiers — Well-known SIDs](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers#well-known-sids)). All RIDs match: 500/501/502/512/513/514/515/516/517/518/519/520/521/522/525/526/527 + BUILTIN S-1-5-32-544/545 + S-1-5-9/10/11/18/19/20. Covers SEC-006/050/051/063/064/065/067/120/121 + all closure rules. (pin: `WellKnownSidCatalogTests`.)
- [x] **GUID → control_type derivation** — **Verified first-party**. `ControlEdgeService.DeriveControlTypes` mapping logic is sound (gates extended rights on ExtendedRight 0x100 + object ACE; property writes on WriteProperty 0x20 + attribute GUID; non-object fallback to WriteAllProperties/ReadAllProperties — the SEC-090/123 semantic). Findings **F-1 / F-2 / F-3 confirmed wrong and fixed this session** — all three constants were wrong GUIDs (member→group-class bf967a9c, userAccountControl→computer-class bf967a86, AllowedToDelegateTo→User-Logon-propset/d3cf), now sourced from the adschema-verified `WellKnownAdGuids` catalog. See RESOLVED section below.

### Wave 2 — per-rule baselines & semantics (FP risk)
- [x] Kerberoast / ASREP (SEC-020–026): SPN logic, `DONT_REQUIRE_PREAUTH 0x400000`, encryption types.
  **Verified first-party** — all `UserAccountControlFlags` match adschema ADS_UF_* (pinned by
  `UserAccountControlFlagsTests`); enc-type bits match MS-KILE but are **display-only** (no SEC-020–026
  detection consumes `msDS-SupportedEncryptionTypes`); Kerberoast keys on `servicePrincipalName` +
  service-SPN allowlist. UAC is a single source of truth (capture `DirectObjectWriter` + UI).
- [x] AD CS (SEC-040): Certificate-Enrollment GUID (already in catalog) + template enrollment semantics.
  **Verified first-party** — Certificate-Enrollment Rights-GUID `0e10c968-…` (adschema r-certificate-enrollment) +
  pKICertificateTemplate class GUID `e5209ca2-…` (adschema c-pkicertificatetemplate). Target filter matches
  raw captured `objectClass`, so `pKIEnrollmentService` needs no catalog entry. Already pinned; no code change.
- [ ] Service accounts / gMSA (SEC-100–102): `msDS-GroupMSAMembership` reader semantics.
  **Verified first-party** — `msDS-GroupMSAMembership` is `String(NT-Sec-Desc)`; DACL allow-ACEs =
  `PrincipalsAllowedToRetrieveManagedPassword`. `ExtractGmsaPasswordRetrievalSids` parses the SD,
  allow-only (deny excluded) — pinned by `DirectObjectWriterTests.WhenGmsaMembershipDaclPresent...`.

- [ ] Shadow credentials (SEC-025): `msDS-KeyCredentialLink` (catalog note: prior mislabel fixed).
  **Verified first-party** — GUID `5b47d60f-…` confirmed via AD DS domainprep ACE; write = shadow-cred
  injection. Prior `ffa6f046` mislabel fixed. Pinned 4x (incl. cross-catalog drift guard). No code change.

### Wave 3 — structural & cosmetic
- [x] Escalation-path tiering (SEC-070+): tier classification thresholds.
  **Reviewed** — `DerivedAssetTierClassifier` promotes on already-verified Wave 1 facts (Tier-0 RIDs
  512/518/519/516/502/500 + DCSync/unconstrained-delegation/RBCD/GPO-linked-to-DCOU causes). Reason
  strings centralized in `TierReasonCatalog` (`[IMP-REASON-DRIFT]`, shared with SEC-076/077). No new
  unverified constants.
- [x] MITRE technique mappings (credibility, not safety).
  **Verified first-party** (Defender for Identity alert catalog + adschema): T1558.001 Golden Ticket,
  T1558.003 Kerberoasting, T1558.004 AS-REP, T1003.006 DCSync, T1207 Rogue DC/DCShadow (SEC-124).
  Delegation→T1558.001 has Microsoft precedent (DfI "Golden Ticket using RBCD"). SEC-090/093 LAPS→
  T1003.003 (NTDS) is imprecise but no LAPS-specific technique exists. All defensible; no `rules.yaml`
  churn — credibility-tier judgment calls, not errors.
- [x] Wording / category consistency.
  **Reviewed** — 9-category taxonomy is coherent (PrivilegeEscalation, CredentialTheft,
  ConfigurationHygiene, Delegation, AccountSecurity, GroupMembership, CertificateServices,
  DangerousPermissions, Persistence). The lone `Persistence` rule (AdminSDHolder ACL backdoor) is a
  correct singleton (SDProp propagation persistence). Reason/label strings already centralized
  (`TierReasonCatalog`, `ControlTypeLabels`). No churn warranted.

---

## Pilot conclusion (this session)

The DCSync pilot **validated the methodology and the crown-jewel rule**: all 3 replication GUIDs match
adschema exactly, and `EvaluateDCSync` combines them correctly (Get-Changes AND a secret-replication
right), gating deny-cancelled edges and excluding admin sources. The broader extraction showed the
constant surface is **smaller and better-verified than feared** — heavily centralized, much of it
already adschema-checked. The remaining work is mostly **Wave 1 access-masks/RIDs** (mechanical, winnt.h
/ well-known-SID verification) and **Wave 2 per-rule semantics** (the FP-risk baselines). This is a
days-of-focused-work audit, not a months-long rewrite — and every step produces a durable ledger row
that also serves maintenance.

---

## ✅ RESOLVED FINDINGS — F-1 / F-2 / F-3 (this session)

Three GUID constants in `ControlEdgeService.DeriveControlTypes` (the capture-side GUID→`control_type`
mapper) were **confirmed wrong against first-party adschema** and **fixed**. Each was a real
**silent false negative** in the capture pipeline — the highest-stakes bug class. All three were the
same root cause — an *attribute* constant accidentally set to a same-namespace *object-class* GUID (or,
for F-2, a property set) — and all are now sourced from the adschema-verified `WellKnownAdGuids` catalog
(the same `[IMP-WK-GUID]` consolidation already applied to `GpLinkAttribute`), eliminating the
duplicate literals. **F-3 was found by widening the F-1/F-2 sweep to the constant physically between
them** (`UACAttributeGuid`, line 35).

### F-1 — `MemberAttributeGuid` was the GROUP CLASS guid, not the `member` attribute — **FIXED**
- **Was:** `MemberAttributeGuid = "bf967a9c-0de6-11d0-a285-00aa003049e2"` (the `group` object class).
- **Verified:** [adschema a-member](https://learn.microsoft.com/windows/win32/adschema/a-member)
  System-Id-Guid = `bf9679c0-0de6-11d0-a285-00aa003049e2`. Confirmed wrong.
- **Blast radius (true FN):** **SEC-006** consumes `PropertyWriteEquivalents(AddMember)` gated to
  `object_class = 'group'`. A least-privilege, member-scoped *property-write object ACE* (the common
  "Modify the membership of a group" delegation) carries `object_type_guid = bf9679c0`, lands in the
  object-ACE branch, matched **no** constant, and received **no** `control_type` at all — the
  `WriteAllProperties` fallback only fires on the *non-object* branch. So a targeted member-write grant
  was invisible to SEC-006 *and* to the escalation-path engine's `GroupEscalation` hop. Attackers who
  *also* held a broad `GenericAll`/`GenericWrite`/`WriteAllProperties` grant were still caught via the
  equivalence set — the gap was the targeted-grant case.
- **Fix:** `MemberAttributeGuid = WellKnownAdGuids.MemberAttribute` (already the correct `bf9679c0`).

### F-2 — `AllowedToDelegateToGuid` was the User-Logon property set with the `d3cf` drift-trap — **FIXED**
- **Was:** `AllowedToDelegateToGuid = "5f202010-79a5-11d0-9020-00c04fc2d3cf"` (User-Logon property set,
  and with the **`d3cf`** suffix the catalog flags as a prior-drift trap; authoritative namespace is
  `d4cf`).
- **Verified:** [adschema a-msds-allowedtodelegateto](https://learn.microsoft.com/windows/win32/adschema/a-msds-allowedtodelegateto)
  System-Id-Guid = `800d94d7-b7a1-42a1-b14d-7cae1423d07f`. Confirmed wrong.
- **Blast radius (escalation-path FN):** no SEC-0xx rule queries `WriteAllowedToDelegateTo` directly;
  the consumer is the **escalation-path engine** (`EscalationEdgeMetadata` maps it to `DelegationAbuse`,
  `IsTraversable = true`). A targeted constrained-delegation-write ACE was mapped to no `control_type`,
  dropping a traversable `DelegationAbuse` hop from path analysis. (Constrained-delegation *config*
  detection — SEC-012, reading `dim_delegation` — is unaffected; this is the *who-can-write-it* edge.)
- **Fix:** added adschema-verified `WellKnownAdGuids.AllowedToDelegateToAttribute` and pointed the
  constant at it.

### F-3 — `UACAttributeGuid` was the COMPUTER CLASS guid, not the `userAccountControl` attribute — **FIXED**
- **Was:** `UACAttributeGuid = "bf967a86-0de6-11d0-a285-00aa003049e2"` (the `computer` object class).
- **Verified:** [adschema a-useraccountcontrol](https://learn.microsoft.com/windows/win32/adschema/a-useraccountcontrol)
  System-Id-Guid = `bf967a68-0de6-11d0-a285-00aa003049e2`. Confirmed wrong (transposed `68`↔`86`).
- **Blast radius (escalation-path FN):** like F-2, no SEC-0xx rule queries `WriteUserAccountControl`
  directly; the consumer is the **escalation-path engine** (`EscalationEdgeMetadata` → `DelegationAbuse`,
  `EscalationEdgeWeights` → weight 80, traversable). A targeted `userAccountControl`-write object ACE —
  the classic *set `TRUSTED_FOR_DELEGATION` (0x80000) → unconstrained delegation* primitive — was mapped
  to no `control_type`, dropping a high-weight `DelegationAbuse` hop. Attackers also holding a broad
  write were still caught; the targeted-grant case was the gap.
- **Fix:** added adschema-verified `WellKnownAdGuids.UserAccountControlAttribute` and pointed the
  constant at it. This was the **last** suspect inline literal in `DeriveControlTypes` — the remaining
  constants (ResetPassword, DCSync ×3, KeyCredentialLink, RBCD, SPN, Cert enroll/auto-enroll, gPLink)
  all cross-check clean against `WellKnownGuids`.

### Regression tests added
- `ControlEdgeServiceTests.BuildAllEdgesAsync_ObjectSpecificMappings_CreateExpectedEdge` — the three
  stale `[InlineData]` rows that **pinned the buggy GUIDs** (member, AllowedToDelegateTo, UAC) were
  corrected to the adschema values (they were the reason the suite stayed green over the bug).
- `ControlEdgeServiceTests.BuildAllEdgesAsync_LegacyMismappedGuids_DoNotProduceControlType` — **new**
  negative guard: the old GUIDs (`bf967a9c`, `bf967a86`, `5f202010-…-d3cf`) must **not** yield
  `AddMember` / `WriteUserAccountControl` / `WriteAllowedToDelegateTo`.
- `BuiltInBundlesTests` — authoritative-GUID pins for `AllowedToDelegateToAttribute` and
  `UserAccountControlAttribute`.
- `WellKnownGuidsTests` — **cross-catalog drift guard** (`WellKnownAdGuids_AttributeConstant_MatchesVerifiedCatalogByName`,
  `WellKnownAdGuids_ExtendedRightConstant_MatchesVerifiedCatalogByName`, and
  `VerifiedCatalog_AttributeName_DoesNotResolveToHistoricalMisswap`): every `WellKnownAdGuids`
  attribute / extended-right constant must agree with the verified catalog on **both GUID and
  `GuidType`**, looked up by LDAP name (never by GUID — AD GUIDs collide across types). This is the
  systemic guard that would have caught F-1/F-2/F-3 at build time.
- Result: ControlEdgeServiceTests 43/43, BuiltInBundlesTests 29/29, WellKnownGuidsTests 57/57;
  full Core 1139/1139, Infrastructure 1839 passed / 0 failed (3 pre-existing skips).

### ⚠ Operational note — re-capture required
This is a **capture-side** mapping. The fix only affects **newly captured** DBs. Existing
`fact_control_edge` rows built before this fix still carry the missing/incorrect `control_type` for
member-write, constrained-delegation-write, and userAccountControl-write ACEs — **re-run capture** (or
rebuild edges from `fact_ace`) to pick up the corrected derivation.

### Repo-wide GUID-drift sweep (this session)
After fixing F-1/F-2/F-3, every inline schema-GUID literal in `src/` outside the catalogs was regexed
and cross-checked against the verified catalog. **`ControlEdgeService` was the only drifted site.** Two
other hand-typed GUID sets are **correct** and independently corroborate the fixes:
- `LiveDiagnosticsService.AclTools.cs` (effective-access checks) — all 8 GUIDs correct, incl.
  `member = bf9679c0` (it had `member` right while `ControlEdgeService` had it wrong). No UAC /
  AllowedToDelegateTo literals present, so no F-2/F-3 analogue.
- `GuidCatalog.cs` (a third catalog, effective-access pipeline) — clean: `userAccountControl = bf967a68`,
  `msDS-AllowedToDelegateTo = 800d94d7`, `member` via the shared Self-Membership validated write.

Remaining GUID literals are benign non-schema GUIDs (COM CLSIDs in `DsObjectPickerDialog`, GPO
client-side-extension GUIDs in `GpoClientSideExtensions`).

**Follow-up — done:** `LiveDiagnosticsService.AclTools.cs` *duplicated* the GUID literals (the same
drift surface that allowed F-1/F-2/F-3). Its eight GUID consts now source from `WellKnownAdGuids`
(three DS-Replication/DCSync extended-right constants were added to the catalog for this), and the
drift guard was extended with an extended-right parity theory. Value-preserving; Core + live-access
suites green. `GuidCatalog.cs` remains an independent (correct) catalog for the effective-access
pipeline — now **guarded** by `GuidCatalog_SharedGuids_AgreeWithVerifiedCatalogCategory` (every GUID
shared with the adschema-verified `WellKnownGuids` must agree on category, GUID-keyed; the
ValidatedWrite/Attribute GUID collisions are skipped). Full consolidation is a larger, optional future
cleanup, not a correctness issue.

**State at handoff:** Wave 1 is fully **Verified first-party** — access-masks, privileged-RIDs, DCSync
GUIDs, and the GUID→`control_type` derivation (F-1/F-2/F-3 closed, systemic drift guard in place, repo
swept clean). Next up: Wave 2 per-rule baselines & semantics (FP risk).

