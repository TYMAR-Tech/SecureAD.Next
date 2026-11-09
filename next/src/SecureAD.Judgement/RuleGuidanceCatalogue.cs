using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

/// <summary>
/// What an operator is told about each rule this product runs.
/// </summary>
/// <remarks>
/// <para>
/// <b>Written out, one entry per rule, beside <see cref="RuleCatalogue"/> but not inside it.</b>
/// <c>docs/decisions/0010</c> keeps the fields that decide behaviour apart from the copy an operator
/// reads, so a severity change and a rewording are different diffs in different files.
/// <c>RuleGuidanceTests</c> binds the two lists in both directions: a rule with no guidance and a
/// guidance entry naming no rule both fail the build.
/// </para>
/// <para>
/// <b>Filled when the rule is built, while its sources are in hand.</b> The research behind a rule -
/// which Microsoft page says what, and what the remedy costs - is done once, at the moment the rule
/// is written. Written down then it is nearly free; reconstructed later, for sixty-two rules, by
/// somebody without the sources open, it is a project. The predecessor's guidance was rebuilt this
/// way and it is the part the owner missed most.
/// </para>
/// </remarks>
public static class RuleGuidanceCatalogue
{
    private const string UnconstrainedDelegationRisk =
        "For authentication that permits delegation, a service trusted for unconstrained "
        + "delegation can reuse delegated Kerberos credentials to access other services. "
        + "The captured setting does not establish that a service is in use, credentials "
        + "were received, impersonation occurred or a route to Tier 0 was completed.";

    private const string UnconstrainedDelegationAction =
        "Identify the services and authentication flows that depend on this account, and "
        + "confirm the account's actual role. If unconstrained delegation is unnecessary, "
        + "remove that trust under change control and verify dependent authentication. "
        + "Where delegation is required, assess a compatible, narrowly scoped design rather "
        + "than assuming any one alternative is automatically safe.";

    /// <summary>Guidance for every rule in <see cref="RuleCatalogue.All"/>.</summary>
    public static IReadOnlyList<RuleGuidance> All { get; } =
    [
        new RuleGuidance("SEC-002", "Credentials", MitreTechnique: null,
            WhyItMatters: UnexpectedDomainSecretReplication.Explanation,
            WhatToDo: UnexpectedDomainSecretReplication.Guidance,
            About: UnexpectedDomainSecretReplication.Explanation + "\n\n" + UnexpectedDomainSecretReplication.ScopeNote,
            MicrosoftReference: "https://learn.microsoft.com/openspecs/windows_protocols/ms-drsr/15bbda52-7742-4ce3-9327-018647b0fc26"),
        new RuleGuidance("SEC-012", "Delegation configuration", MitreTechnique: null,
            WhyItMatters: "Where Kerberos permits delegation, a service using this account may act on a user's behalf to the configured services. "
                + "Unintended delegation to a Tier 0-relevant destination warrants review. "
                + "The captured configuration does not establish current service use, working delegation, successful impersonation, credential extraction or a completed Tier 0 path.",
            WhatToDo: "Confirm the service owner, intended destination and business need for each listed value. Review dependencies before making changes. "
                + "If a destination is unnecessary, remove only the unnecessary values from msDS-AllowedToDelegateTo on the delegating account under change control, "
                + "then test dependent authentication. Do not remove the resource's legitimate servicePrincipalName registration, clear every destination "
                + "or switch to unconstrained delegation as a shortcut.",
            About: ConstrainedDelegationToRelevantService.Summary + "\n\n" + ConstrainedDelegationToRelevantService.ScopeNote,
            MicrosoftReference: "https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview"),
        new RuleGuidance("SEC-013", "Delegation configuration", MitreTechnique: null,
            WhyItMatters: "The captured RBCD configuration contains delegation grants for the recorded holders on this Tier 0-relevant resource. "
                + "Unintended grants warrant review. A group-held grant does not establish authorization for each member. "
                + "This finding does not establish current service use, working delegation, successful impersonation, credential extraction or a completed Tier 0 path.",
            WhatToDo: "Confirm each configured holder and its business need. Review service dependencies and shared or group-held grants before making changes. "
                + "If a grant is unnecessary, narrow or remove only that grant from msDS-AllowedToActOnBehalfOfOtherIdentity on the resource account under change control, "
                + "then test dependent authentication. Do not clear the entire configuration indiscriminately or change general object permissions as a substitute.",
            About: ResourceBasedDelegationOnRelevantResource.Summary + "\n\n" + ResourceBasedDelegationOnRelevantResource.ScopeNote,
            MicrosoftReference: "https://learn.microsoft.com/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94"),
        new RuleGuidance("SEC-050", "Group membership", MitreTechnique: null,
            WhyItMatters: LargePrivilegedGroupReview.Explanation,
            WhatToDo: "Review whether the recorded members still need this privilege.",
            About: LargePrivilegedGroupReview.Explanation + "\n\n"
                + "The default Direct-count review thresholds are 10 for Domain Admins, 5 for Enterprise Admins, 5 for Schema Admins and 15 for domain BUILTIN Administrators; only counts strictly above them trigger a finding. "
                + "These are product review defaults, not Microsoft limits. Nested groups count once in Direct; Known total and primary-group relationships remain separate.",
            MicrosoftReference: "https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups"),
        new RuleGuidance("SEC-051", "Group membership", MitreTechnique: null,
            WhyItMatters: GroupNestedInDomainAdmins.Explanation,
            WhatToDo: "Review its membership and who can change it.",
            About: GroupNestedInDomainAdmins.Explanation + "\n\n"
                + "Each finding retains the captured direct member link and both group identities; membership shape is not an effective-access or attack-path calculation.",
            MicrosoftReference: "https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups"),
        new RuleGuidance("SEC-061", "Group membership", MitreTechnique: null,
            WhyItMatters: BroadPreWindows2000Membership.Explanation,
            WhatToDo: "Review whether this compatibility access is still required.",
            About: BroadPreWindows2000Membership.Explanation + "\n\n"
                + "Reports one finding per resource-domain legacy group with supported broad membership, keeping symbolic broad identities and alternative recorded security links rather than expanding them into accounts.",
            MicrosoftReference: "https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups"),
        new RuleGuidance("SEC-014", "Property permissions", MitreTechnique: null,
            WhyItMatters: "The saved assessment identifies unexpected permission to write this account's RBCD configuration. "
                + "If misused, this permission could allow the delegation configuration to be altered. "
                + "It does not show that delegation is configured or in use, that a directory change will succeed, or that impersonation, authentication, "
                + "account takeover or a completed Tier 0 path has occurred. A group-held permission does not establish authorization for each member.",
            WhatToDo: "Confirm the holder's legitimate service or delegation-administration responsibilities. Review dependent services and other rights in the same assignment before making changes. "
                + "If this write permission is unintended, remove or narrow only that permission on the target account. "
                + "For an inherited assignment, verify its original source and wider impact before changing it. Review shared or group-held grants and do not assume removing one member eliminates the permission. "
                + "Do not clear legitimate RBCD configuration as a substitute for correcting the write permission.",
            About: "Reports established WRITE_PROPERTY permission on msDS-AllowedToActOnBehalfOfOtherIdentity using captured account identity, schema and scoped expectedness.\n\n"
                + "Permission is not proof of a successful RBCD configuration or service impersonation. WRITE_DAC and ownership pivots are separate assessments. "
                + AttributeWriteRules.ScopeNote,
            MicrosoftReference: "https://learn.microsoft.com/openspecs/windows_protocols/ms-ada2/cea4ac11-a4b2-4f2d-84cc-aebb4a4ad405"),
        new RuleGuidance("SEC-024", "Property permissions", MitreTechnique: null,
            WhyItMatters: "The saved assessment identifies unexpected permission to write this account's servicePrincipalName attribute. "
                + "If misused, this permission could allow unintended service registrations or changes to existing registrations. "
                + "It does not show that a service principal name has been added or changed, that a service is in use, that a directory change will succeed, "
                + "or that authentication, impersonation, credential theft, account takeover or a completed Tier 0 path has occurred. "
                + "A group-held permission does not establish authorization for each member.",
            WhatToDo: "Confirm the holder's legitimate service-registration responsibilities. Review dependent services and other rights in the same assignment before making changes. "
                + "If this write permission is unintended, remove or narrow only that permission on the target account. "
                + "For an inherited assignment, verify its original source and wider impact before changing it. Review shared or group-held grants and do not assume removing one member eliminates the permission. "
                + "Do not remove legitimate service principal names or reset passwords as a substitute for correcting the write permission.",
            About: "Reports established WRITE_PROPERTY permission on servicePrincipalName, including a captured containing property set.\n\n"
                + "Restricted validated-SPN writes are not unrestricted attribute-write permission. Existing SPNs, service usage, password strength and successful Kerberos ticket requests are not prerequisites established here. "
                + AttributeWriteRules.ScopeNote,
            MicrosoftReference: "https://learn.microsoft.com/windows/win32/api/ntdsapi/nf-ntdsapi-dswriteaccountspnw"),
        new RuleGuidance("SEC-025", "Property permissions", MitreTechnique: null,
            WhyItMatters: "The saved assessment identifies unexpected permission to write this account's msDS-KeyCredentialLink attribute. "
                + "If misused, this permission could allow key-credential registrations to be added or changed. "
                + "It does not show that a usable key is registered, that a directory change will succeed, that key-based authentication is available or will succeed, "
                + "or that credential extraction, account takeover or a completed Tier 0 path has occurred. "
                + "A group-held permission does not establish authorization for each member.",
            WhatToDo: "Confirm the holder's legitimate account, device-authentication and key-enrolment responsibilities. Review dependent services and other rights in the same assignment before making changes. "
                + "If this write permission is unintended, remove or narrow only that permission on the target account. "
                + "For an inherited assignment, verify its original source and wider impact before changing it. Review shared or group-held grants and do not assume removing one member eliminates the permission. "
                + "Do not delete existing key credentials or reset passwords as a substitute for correcting the write permission.",
            About: "Reports the existing CanWriteKeyCredentialLink permission assessment for msDS-KeyCredentialLink.\n\n"
                + "The SELF-only validated computer operation is separate. Adding a usable key, certificate infrastructure, authentication and credential extraction are not established. "
                + AttributeWriteRules.ScopeNote,
            MicrosoftReference: "https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/f70afbcc-780e-4d91-850c-cfadce5bb15c"),
        new RuleGuidance("SEC-100", "Service accounts", MitreTechnique: null,
            WhyItMatters: SavedServiceAccountContext.AdministrativeWhy,
            WhatToDo: SavedServiceAccountContext.AdministrativeAction,
            About: "Reports sMSA/gMSA accounts and ordinary SPN-bearing users with captured security membership in Domain Admins, "
                + "forest-root Enterprise Admins or Schema Admins, or resource-domain BUILTIN Administrators.\n\n"
                + "Disabled accounts remain visible as dormant exposure. Established membership remains a finding when other routes could not be assessed. "
                + ServiceAccountWithAdministrativeMembership.ScopeNote,
            MicrosoftReference: "https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups"),
        new RuleGuidance("SEC-101", "Service accounts", MitreTechnique: null,
            WhyItMatters: SavedServiceAccountContext.PasswordWhy,
            WhatToDo: SavedServiceAccountContext.PasswordAction,
            About: "Reports ordinary SPN-bearing users with the captured Password never expires setting; managed service accounts and computers are excluded.\n\n"
                + "Disabled accounts remain visible as dormant exposure. " + ServiceAccountWithNonExpiringPassword.ScopeNote,
            MicrosoftReference: "https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties"),
        new RuleGuidance("SEC-062", "Group membership", MitreTechnique: null,
            WhyItMatters: BroadAdministrativeGroupMembership.Explanation,
            WhatToDo: BroadAdministrativeGroupMembership.Guidance,
            About: BroadAdministrativeGroupMembership.MembershipSummary + "\n\n" + BroadAdministrativeGroupMembership.ScopeNote,
            MicrosoftReference: "https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups"),
        new RuleGuidance("SEC-026", "Kerberos", MitreTechnique: null,
            WhyItMatters: "Duplicate service principal names can prevent Kerberos from identifying the intended service account. "
                + "This finding records captured registrations, not a confirmed outage, current service use, successful authentication, "
                + "credential exposure, compromise or a completed Tier 0 path.",
            WhatToDo: DuplicateServicePrincipalNames.Guidance,
            About: "Reports the same complete service principal name on distinct captured objects in this forest, using Windows case-insensitive comparison.\n\n"
                + "Ports, instance names and service-name suffixes remain part of the match; HOST registrations are not blanket-exempt. "
                + "SPN aliases, other forests, live service identity and successful authentication are not assessed. "
                + "Known duplicates remain findings when incomplete evidence prevents a complete inventory.",
            MicrosoftReference: "https://learn.microsoft.com/windows-server/administration/windows-commands/setspn"),
        new RuleGuidance(
            "SEC-052", "Group membership", MitreTechnique: null,
            WhyItMatters: CircularGroupMembership.Explanation,
            WhatToDo: CircularGroupMembership.Guidance,
            About: "These groups form a circular membership relationship.\n\n"
                + "Review the recorded links and the membership or permissions that depend on them; this finding does not establish a route to Tier 0.",
            MicrosoftReference: "https://learn.microsoft.com/windows/win32/ad/determining-a-userampaposs-or-groupampaposs-membership-in-a-group"),
        new RuleGuidance(
            "SEC-071",
            "Tier 0",
            MitreTechnique: null,
            WhyItMatters:
                "The saved evidence establishes a supported route to Tier 0 outside this account's expected administrative authority on the reached target.",
            WhatToDo:
                "Open View saved routes for the account, target, relevant permission and actual granting entry. "
                + "Remove only the permission identified there, keeping the entry's other permissions unchanged unless separately reviewed. "
                + "Group-held and inherited grants must be reviewed at their actual source, including effects on other members and descendants. "
                + "This addresses the relationship shown, not every possible route. A new capture is needed to verify the change.",
            About:
                "Reports saved supported routes to Tier 0 outside an account's expected administrative authority on the reached target.\n\n"
                + "Saved permission, membership and ownership evidence is not proof of account takeover or a successful live operation.",
            MicrosoftReference:
                "https://learn.microsoft.com/security/privileged-access-workstations/privileged-access-access-model"),
        new RuleGuidance(
            "SEC-010",
            "Delegation",
            MitreTechnique: null,
            WhyItMatters: UnconstrainedDelegationRisk,
            WhatToDo: UnconstrainedDelegationAction,
            About:
                "Reports a saved unconstrained-delegation setting under this rule's existing "
                + "non-computer classification and controller-exclusion logic. It does not assess "
                + "current service use or exercise delegation. Missing findings do not establish "
                + "that excluded or unassessed accounts lack the setting; classification and "
                + "coverage limitations remain separate from this presentation.",
            MicrosoftReference:
                "https://learn.microsoft.com/defender-for-identity/security-assessment-unsecure-account-attributes"),

        new RuleGuidance(
            "SEC-011",
            "Delegation",
            MitreTechnique: null,
            WhyItMatters: UnconstrainedDelegationRisk,
            WhatToDo: UnconstrainedDelegationAction + " Do not change a domain controller's normal "
                + "delegation configuration based only on this finding.",
            About:
                "Reports a saved unconstrained-delegation setting under this rule's existing "
                + "computer-class classification and controller-exclusion logic, including managed "
                + "service-account subclasses selected by that ancestry. The saved indicators do "
                + "not independently verify the account's current directory role or show that "
                + "delegation was used. Missing findings do not establish complete coverage or "
                + "correct the separately known classification and exclusion limitations.",
            MicrosoftReference:
                "https://learn.microsoft.com/defender-for-identity/security-assessment-unsecure-account-attributes"),

        new RuleGuidance(
            "SEC-022",
            "Kerberos",
            "T1558.004",
            WhyItMatters:
                "This setting can allow an attacker to obtain password-derived material for offline "
                + "password guessing without first proving knowledge of the account password. "
                + "The saved setting does not establish that a request succeeded, the password is "
                + "weak or cracked, or an attack occurred.",
            WhatToDo:
                "Confirm what uses this account and whether any integration requires this exception. "
                + "If it is unnecessary, clear \"Do not require Kerberos preauthentication\" using "
                + "the appropriate account-management tool under change control, then verify "
                + "dependent authentication still works.",
            About:
                "Reports accounts whose captured account options waive Kerberos pre-authentication, "
                + "including disabled accounts. It reports a saved setting, not current live state, "
                + "successful ticket issuance or password compromise.",
            MicrosoftReference:
                "https://learn.microsoft.com/defender-for-identity/security-assessment-unsecure-account-attributes"),

        new RuleGuidance(
            "SEC-030",
            "Privileged access",
            MitreTechnique: null,
            WhyItMatters:
                "Blocked permission inheritance prevents permission changes delegated through the parent container from reaching this object through inheritance. "
                + "This can prevent delegated administration from working as intended. Microsoft documents that this condition can remain after protected membership ends, "
                + "but this finding does not establish that history for this object or determine what its explicit permissions grant.",
            WhatToDo:
                "Confirm the object's current protection requirements and intended delegated administration. "
                + "Review its current explicit permissions and the permissions it would inherit from its parent before making changes. "
                + "If the object is no longer protected and blocked inheritance is unintended, clear the unnecessary adminCount marker and re-enable inheritance under change control, "
                + "then test delegated management and dependent access. Preserve legitimate explicit permissions. "
                + "Do not change AdminSDHolder or the SDProp schedule as a shortcut. Clearing adminCount alone does not re-enable inheritance, "
                + "and enabling inheritance does not remove existing explicit grants.",
            About:
                "Reports the saved combination of adminCount=1, disabled permission inheritance and a completed captured-evidence assessment that the object is not AdminSDHolder-protected. "
                + "adminCount alone is not the protection test. The rule does not reconstruct past membership or an old AdminSDHolder permissions template, "
                + "assess every explicit permission, or test current SDProp operation. A missing or uncertain protection answer must not be presented as this finding.",
            MicrosoftReference:
                "https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface#privileged-accounts-and-groups-in-active-directory"),

        new RuleGuidance(
            "SEC-027",
            "Privileged access",
            "T1134.005",
            WhyItMatters:
                "SID history can retain access through earlier identifiers without adding the object to the corresponding group. "
                + "A privileged historical identifier can therefore preserve access that a group-membership review would miss. "
                + "Actual access depends on resource permissions and, where applicable, trust and SID-filtering rules. "
                + "This finding does not prove a specific current group membership, effective access, successful use, compromise or a completed Tier 0 path.",
            WhatToDo:
                "Verify why each flagged value is present, the migration history and current resource dependencies. "
                + "When authorised, check relevant trust and SID-filtering behaviour. If a value is no longer needed, remove only that specific sIDHistory value "
                + "using administration appropriate to the user, computer or group shown, under change control, then test dependent access. "
                + "Do not clear the entire attribute or assume that unranked or unreadable values are harmless. "
                + "Removing a historical identifier may break access still granted only to that identifier.",
            About:
                "Reports a captured user, computer or group carrying a SID-history value recognised by SecureAD's existing privileged-identifier catalogue. "
                + "Recognition uses well-known SID patterns, not a live lookup of the issuing domain or group. "
                + "Custom identifiers are not assessed for privilege by this rule. Other captured values remain available, and unreadable values are reported. "
                + "This rule does not establish current group membership, effective access, trust acceptance, SID filtering or a completed Tier 0 path.",
            MicrosoftReference:
                "https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#unsecure-sid-history-attributes"),

        new RuleGuidance(
            "SEC-028",
            "Credentials",
            MitreTechnique: null,
            WhyItMatters:
                "This setting permits a password requirement exception. It does not show that "
                + "the account has an empty or weak password, or that passwordless sign-in succeeded.",
            WhatToDo:
                "Confirm what uses the account and how its password is managed. If the exception "
                + "is unnecessary, ensure appropriate password protection and remove it under "
                + "change control, coordinating dependent services. Do not reset the password blindly.",
            About:
                "Reports the captured Password not required option on user or computer accounts, "
                + "excluding interdomain trust accounts. It reports an exception, not whether a "
                + "password exists, its strength or current live state.",
            MicrosoftReference:
                "https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#unsecure-account-attributes"),

        new RuleGuidance(
            "SEC-029",
            "Credentials",
            MitreTechnique: null,
            WhyItMatters:
                "This is a captured account option, not proof that a reversible copy of the password "
                + "currently exists. Clearing the option alone does not establish that a previously "
                + "stored copy has been removed.",
            WhatToDo:
                "Check application and protocol dependencies and the applicable password policy. "
                + "If the requirement is unnecessary, remove it under change control, then "
                + "coordinate a password change and verify dependent authentication.",
            About:
                "Reports the captured reversible-password-storage option on user or computer "
                + "accounts, including disabled accounts. It does not inspect password material or "
                + "establish that a reversible copy is currently stored or has been removed.",
            MicrosoftReference:
                "https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#unsecure-account-attributes"),

        new RuleGuidance(
            "SEC-033",
            "Credentials",
            MitreTechnique: null,
            WhyItMatters:
                "DES is an old, weak encryption method. This captured option can restrict the "
                + "account's Kerberos encryption choices; it does not show which encryption an "
                + "actual ticket used.",
            WhatToDo:
                "Identify legacy clients and applications and check their encryption and key "
                + "requirements. Address those dependencies, clear an unnecessary DES-only "
                + "restriction under change control, and verify actual authentication. Clearing "
                + "it does not by itself guarantee stronger encryption.",
            About:
                "Reports the captured DES-only account option, including disabled accounts. It "
                + "does not assess domain encryption policy or establish the encryption used for "
                + "actual tickets.",
            MicrosoftReference:
                "https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#unsecure-account-attributes"),

        new RuleGuidance(
            "SEC-021",
            "Credentials",
            "T1558.003",
            WhyItMatters:
                ServiceRegistrationPresentation.Why,
            WhatToDo:
                ServiceRegistrationPresentation.Action,
            About:
                ServiceRegistrationPresentation.About,
            MicrosoftReference:
                "https://learn.microsoft.com/defender-for-identity/alerts-mdi-classic#credential-access-alerts"),

        new RuleGuidance(
            "SEC-090",
            "Credentials",

            // NOT T1003.003, WHICH THE PREDECESSOR'S CARD CARRIED. That technique is credential
            // dumping from the domain database - the NTDS file. Reading a LAPS password is an
            // authorised LDAP read of an attribute, using a permission somebody granted, and the
            // tag looks copied rather than reasoned. No technique is claimed rather than a wrong
            // one asserted.
            MitreTechnique: null,
            WhyItMatters: LapsPasswordReadMessages.Get("WhyItMatters"),
            WhatToDo: LapsPasswordReadMessages.Get("WhatToDo"),
            About: LapsPasswordReadMessages.Get("About"),
            MicrosoftReference:
                "https://learn.microsoft.com/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential"),

        new RuleGuidance(
            "SEC-060",
            "Permissions",

            // T1222 is permission modification, which is what holding WriteDacl or WriteOwner lets
            // somebody do. Claimed rather than omitted because the mapping is direct: the technique
            // describes modifying object permissions to enable follow-on access, and that is
            // exactly the capability being reported.
            MitreTechnique: "T1222",
            WhyItMatters:
                "A principal that is broad in every organisation - Everyone, Authenticated Users, "
                + "Domain Users, Domain Computers, Guests or Anonymous - can rewrite this object's "
                + "permission list. That means any person who can log on can grant themselves, or "
                + "anybody else, full control of this object, and nothing about it will look "
                + "unusual afterwards. A permission list shows what was granted; it does not show "
                + "what the grant is worth. The principal is usually not the one named in the "
                + "permission - it falls out of the group nesting underneath, which is why nobody "
                + "notices.",
            WhatToDo:
                "Follow every membership path on the finding and cut the links that bring broad "
                + "principal into the group the permission names, or narrow the permission so it "
                + "names only the administrators who need it. Do not simply delete the entry: this "
                + "product cannot know which principals your organisation intended to hold this "
                + "access, and the group named may be entirely legitimate apart from what is "
                + "nested inside it. Where the entry was inherited, the container it came from is "
                + "named on the finding, and changing it there will affect everything beneath it.",
            About:
                "Reports an object over which a principal broad in every organisation effectively "
                + "holds Full Control, Write DACL, or the ability to take ownership - found by "
                + "expanding whichever principal the permission actually names all the way down.\n\n"
                + "GenericWrite is deliberately excluded: Microsoft's generic mapping shows it "
                + "does not include the right to change permissions, so it cannot yield control of "
                + "the list.\n\nTaking ownership is reported only where an owner would actually keep "
                + "the implicit right to rewrite permissions; where the object carries an OWNER "
                + "RIGHTS entry, or the forest has blocked implicit owner rights for computer "
                + "objects, that route reaches nothing and is not reported.\n\nEntries that sit on an "
                + "object only to be inherited by the objects beneath it grant nothing where they "
                + "sit and are not counted. Deny entries are applied in the order the directory "
                + "stores them, which is how Windows itself evaluates them.\n\nWhere the object's "
                + "permissions could not be read, or the membership walk did not finish, the rule "
                + "says so rather than reporting the object as safe.",
            MicrosoftReference:
                "https://learn.microsoft.com/defender-for-identity/security-posture-assessments/certificates"),

        new RuleGuidance(
            "SEC-031",
            "Permissions",

            // No technique claimed. This reports a capability that exists by ordinary
            // administrative accident, not an attacker action - the commonest cause is that
            // somebody created the object. Tagging it as a technique would frame a benign
            // condition as an attack, which is the wording error section 1 of the rule document
            // exists to prevent.
            MitreTechnique: null,
            WhyItMatters:
                SavedOwnershipAssessment.Risk,
            WhatToDo:
                SavedOwnershipAssessment.Action,
            About:
                SavedOwnershipAssessment.ScopeNote,
            MicrosoftReference:
                "https://learn.microsoft.com/windows/win32/secauthz/owner-of-a-new-object"),

        new RuleGuidance(
            "SEC-032",
            "Permissions",
            MitreTechnique: null,
            WhyItMatters:
                SavedOwnershipAssessment.Risk + "\n\n" + SavedOwnershipAssessment.ProtectedRisk,
            WhatToDo:
                SavedOwnershipAssessment.Action,
            About:
                SavedOwnershipAssessment.ScopeNote + "\n\n" + SavedOwnershipAssessment.ProtectedRisk,
            MicrosoftReference:
                "https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"),

        new RuleGuidance(
            "SEC-093",
            "Credentials",

            // No technique claimed, for the reason SEC-090's entry gives. The predecessor's card
            // carried T1003.003 - credential dumping from the domain database - which is not what
            // this is: decrypting a stored LAPS password uses a key the policy granted, and the
            // tag looks copied rather than reasoned.
            MitreTechnique: null,
            WhyItMatters:
                "Windows LAPS encrypts each local administrator password against exactly one "
                + "security principal, and this policy names one that is broad in every "
                + "organisation - or a group that contains one. Every member can therefore "
                + "decrypt the local administrator password of every machine this policy covers. "
                + "This is a separate gate from directory permissions: Microsoft states that "
                + "being allowed to query a password does not imply being allowed to decrypt it, "
                + "so an estate can have tightly held read access and still be exposed here. The "
                + "broad principal is usually not the one the policy names - it falls out of the "
                + "group nesting underneath, which is why nobody notices.",
            WhatToDo:
                "Follow the membership path on the finding and cut the link that brings the broad "
                + "principal into the decryptor group, or point ADPasswordEncryptionPrincipal at "
                + "a tightly scoped administrative group. Then rotate the stored passwords: "
                + "Microsoft states the authorized decryptor cannot be changed after a password "
                + "is encrypted, so every password already in the directory stays decryptable by "
                + "the old principal until it is replaced. Correcting the policy alone does not "
                + "close the exposure. Where the finding says the value could not be resolved, "
                + "check it against the directory first - an invalid principal stops policy "
                + "processing and the password is not backed up at all, which is a different and "
                + "equally urgent problem.",
            About:
                "Reports a Group Policy Object whose authorized Windows LAPS password decryptor "
                + "is, or contains through nesting, a principal broad in every organisation.\n\nThe "
                + "subject is the policy rather than a machine, and that is deliberate: Microsoft "
                + "states the authorized decryptor cannot be changed after a password is "
                + "encrypted, so a stored password was encrypted against whatever the policy "
                + "named at the time, and the directory does not record what that was. Naming "
                + "affected machines would assert something about the past that no evidence "
                + "establishes.\n\nA policy that sets no decryptor is not reported, because "
                + "Microsoft's default is the Domain Admins group of the machine's own domain. A "
                + "scoped group containing no broad principal is not reported either - delegating "
                + "to a wrapper group is Microsoft's own documented pattern, since only one "
                + "principal can be named.\n\nWhere the configured value could not be resolved to a "
                + "principal the finding says so rather than staying silent, and where the "
                + "membership walk could not finish it says that too.",
            MicrosoftReference:
                "https://learn.microsoft.com/windows-server/identity/laps/laps-concepts-overview"),

        new RuleGuidance(
            "SEC-091",
            "Credentials",
            MitreTechnique: null,
            WhyItMatters:
                "Nothing visible in this directory is rotating this machine's local administrator "
                + "password. Where that password came from an image, a build script or a "
                + "technician, every machine built the same way shares it, so one compromised "
                + "machine yields a credential that works on all of them. That access is local, so "
                + "no domain authentication is involved and nothing is logged centrally - which is "
                + "the step that lets an intrusion spread sideways across an estate without "
                + "touching a domain controller.",
            WhatToDo:
                "Deploy Windows LAPS to this machine, and confirm it by looking for "
                + "msLAPS-PasswordExpirationTime appearing on this computer object - the check "
                + "Microsoft names for a successful deployment. Before you deploy, check that LAPS "
                + "is not already installed and failing: if the policy names an encryption "
                + "principal that cannot be resolved, Windows LAPS stores nothing at all and the "
                + "machine is indistinguishable from an unmanaged one in the directory. Measured in "
                + "a lab on 2026-09-03 - the machine logs event 10035 naming the unmappable "
                + "principal, or 10034 where the name is ambiguous because it carries no domain, "
                + "and 10017 to say Active Directory was not updated, and there is no "
                + "fallback to Domain Admins. Applications or scripts that sign "
                + "in with a shared local administrator password will stop working once it starts "
                + "rotating, so find those before you deploy. This rule reads Active Directory "
                + "only: a machine whose password is backed up to Microsoft Entra ID carries no "
                + "directory attribute and cannot be told apart from an unmanaged one here.",
            About:
                "Reports a computer carrying neither LAPS expiration timestamp, so nothing "
                + "visible in this directory is rotating its local administrator password.\n\n"
                + "It reads Active Directory only. A machine whose password is backed up to "
                + "Microsoft Entra ID instead carries no directory attribute at all and looks "
                + "exactly like an unmanaged one - the likeliest false finding in a real estate, "
                + "and one the product cannot detect while an administrator can.\n\nDomain "
                + "controllers are out of scope, having no ordinary local administrator account to "
                + "manage, and so are disabled accounts, which have no running machine behind "
                + "them.\n\nA forest whose schema was never extended for either LAPS product is not "
                + "reported at all, machine by machine: no computer in it could carry the "
                + "attribute, so its absence says nothing about any one of them. Both those "
                + "populations are listed in the LAPS inventory, which shows every computer "
                + "including the ones no rule judges.",
            MicrosoftReference:
                "https://learn.microsoft.com/windows-server/identity/laps/laps-overview"),

        new RuleGuidance(
            "SEC-094",
            "Credentials",
            MitreTechnique: null,
            WhyItMatters:
                "This machine could be managed by the current version of LAPS and the directory "
                + "shows no sign that it is. What it does show is a timestamp from the old "
                + "product, and that attribute is never cleared - migrating away from legacy LAPS "
                + "removes the policy and the software and leaves the value behind. So an "
                + "administrator reading it as proof the machine is managed may be reading a "
                + "fossil, and false assurance stops an investigation that should have happened.",
            WhatToDo:
                "Check the machine itself before changing anything, because the directory cannot "
                + "tell the three causes apart: a Windows LAPS policy that is not reaching it, a "
                + "deliberate legacy emulation-mode configuration, or a machine that has not taken "
                + "the April 2023 update. Event 10023 in the Windows LAPS log records emulation "
                + "mode. Where emulation mode is deliberate, note that it stores passwords in "
                + "clear text and cannot encrypt them or back them up to Microsoft Entra ID, so "
                + "moving to native Windows LAPS gains those - and will change which attribute the "
                + "password is read from, which any tooling reading ms-Mcs-AdmPwd depends on.",
            About:
                "Reports a computer capable of running Windows LAPS that carries the legacy "
                + "timestamp and not the modern one - the absence of the confirmation Microsoft "
                + "names for a successful deployment.\n\nIt states what was observed and never "
                + "which cause produced it, because the three causes are identical in the "
                + "directory and what separates them is on the machine: a policy that is not "
                + "reaching it, a deliberate legacy emulation-mode configuration, or a machine "
                + "that never took the April 2023 update.\n\nMachines too old for Windows LAPS are "
                + "excluded on capability, since Microsoft never shipped it for them. Whether the "
                + "legacy timestamp is recent or years stale is judged by SEC-092 rather than "
                + "here.",
            MicrosoftReference:
                "https://learn.microsoft.com/windows-server/identity/laps/laps-scenarios-migration"),

        new RuleGuidance(
            "SEC-092",
            "Credentials",
            MitreTechnique: null,
            WhyItMatters:
                "This machine's local administrator password should have been replaced by now and "
                + "was not. Windows LAPS reads the expiration time from the directory on every "
                + "policy cycle and rotates the password the moment it has passed, so a time still "
                + "in the past means no cycle has completed since then. The password is still "
                + "unique to this machine, which is worth something, but it has become a fixed "
                + "secret: whatever exposure it has had since it was last set, it keeps. That is "
                + "the half of LAPS that limits how long a recovered password stays useful, and it "
                + "has stopped working here while the directory still looks as though it is "
                + "managed.",
            WhatToDo:
                "Check that the LAPS policy still applies to this computer, that the machine can "
                + "reach a domain controller, and that the LAPS agent is running - then read the "
                + "LAPS event log on the machine itself, which is the only place the causes are "
                + "distinguishable. One cause is worth checking first because it is silent in the "
                + "directory and quick to fix: if the policy names an encryption principal that "
                + "cannot be resolved - a renamed group, or a typo - Windows LAPS refuses to store "
                + "anything and logs event 10035, or 10034 where the name carries no domain and is "
                + "ambiguous, with 10017 to say Active Directory was not "
                + "updated. Measured in a lab on 2026-09-03; there is no fallback to Domain "
                + "Admins. If the machine has simply been switched off or is out of "
                + "service, no action is needed and the finding will clear on its own once it "
                + "comes back and completes one policy cycle. To force a rotation once the machine "
                + "is healthy, Microsoft's Set-LapsADPasswordExpirationTime sets the expiration to "
                + "now and the next cycle does the rest.",
            About:
                "Reports a computer whose stored LAPS expiration time passed more than a day ago, "
                + "so the password it governs has not rotated.\n\nThe one-day grace is deliberate: "
                + "Microsoft's own way of forcing an early rotation sets the expiration to the "
                + "current time and lets the next policy cycle act, and a policy cycle can take "
                + "two hours, so a healthy machine is briefly past due by design.\n\nIt never asserts "
                + "a cause, because a policy that stopped reaching the machine, a failed agent, a "
                + "machine that cannot reach a controller and a machine switched off for a month "
                + "are identical in the directory - the finding gives the date and how far overdue "
                + "it is so that a transient fault can be told from a machine nobody has managed "
                + "in years.\n\nA machine carrying both timestamps is reported only if neither has "
                + "rotated, since a fresh value proves something is still doing the job.\n\nDomain "
                + "controllers and disabled accounts are out of scope for the reasons SEC-091 "
                + "gives, and a machine carrying no timestamp at all is SEC-091's rather than this "
                + "rule's. A timestamp dated far in the future is not judged here.",
            MicrosoftReference:
                "https://learn.microsoft.com/windows-server/identity/laps/laps-concepts-overview"),
    ];

    /// <summary>The guidance for one rule, or null where none is written.</summary>
    /// <param name="ruleId">The rule identifier.</param>
    public static RuleGuidance? For(string ruleId) =>
        All.FirstOrDefault(g => string.Equals(g.RuleId, ruleId, StringComparison.Ordinal));
}
