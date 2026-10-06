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
    /// <summary>Guidance for every rule in <see cref="RuleCatalogue.All"/>.</summary>
    public static IReadOnlyList<RuleGuidance> All { get; } =
    [
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
            WhyItMatters:
                "Any service running as this account can impersonate whoever authenticates to it, "
                + "to any other service. An attacker who compromises the account inherits that: "
                + "every user who has authenticated to it becomes an identity he can borrow, "
                + "including administrators.",
            WhatToDo:
                "Move the service to resource-based constrained delegation, which lets each "
                + "resource decide who may impersonate to it. Removing the setting outright will "
                + "break whatever relied on it, so identify what authenticates to this account "
                + "first - Microsoft marks unconstrained delegation \"Supported (not recommended)\" "
                + "rather than unsupported, and it is often load-bearing.",
            About:
                "Reports a user or service account whose account options trust it for "
                + "unconstrained delegation.\n\nIt reads that one setting and nothing else: it does "
                + "not report constrained delegation or resource-based constrained delegation, "
                + "which are the safer forms and are not judged here at all, and it cannot say "
                + "whether anyone has ever actually authenticated to this account.\n\nAn account "
                + "nothing uses carries the same setting as one every administrator signs in "
                + "through, and the directory does not record the difference.",
            MicrosoftReference:
                "https://learn.microsoft.com/defender-for-identity/security-assessment-unsecure-account-attributes"),

        new RuleGuidance(
            "SEC-011",
            "Delegation",
            MitreTechnique: null,
            WhyItMatters:
                "This host collects the Kerberos tickets of everyone who authenticates to it, and "
                + "it is not a domain controller, so it is unlikely to be defended like one. "
                + "Anyone who compromises it can reuse those tickets as the people they belong to.",
            WhatToDo:
                "Move the host to resource-based constrained delegation. As with any delegation "
                + "change, find out what depends on it before removing it.",
            About:
                "Reports a computer trusted for unconstrained delegation that is not a domain "
                + "controller.\n\nDomain controllers are excluded deliberately, because the setting "
                + "is normal on them; a controller identified by any of three independent signals "
                + "is left alone, and a machine that looks like one by some signals and not others "
                + "is reported with that disagreement recorded rather than resolved.\n\nAs with "
                + "SEC-010 it reads one setting: the safer forms of delegation are not judged, and "
                + "whether the machine has actually collected anyone's tickets cannot be seen from "
                + "the directory.",
            MicrosoftReference:
                "https://learn.microsoft.com/defender-for-identity/security-assessment-unsecure-account-attributes"),

        new RuleGuidance(
            "SEC-022",
            "Kerberos",
            "T1558.004",
            WhyItMatters:
                "A domain controller will answer an authentication request for this account without "
                + "the asker proving they know the password, and the reply contains material "
                + "derived from that password which can be cracked offline. No credentials are "
                + "needed to begin, which is what separates this from most credential attacks - an "
                + "attacker who has reached the network but holds no account can start here.",
            WhatToDo:
                "Clear \"Do not require Kerberos preauthentication\" on the account. The flag is "
                + "usually set for a non-Windows Kerberos client that could not send "
                + "pre-authentication data, so establish what uses the account before clearing it.",
            About:
                "Reports an account whose account options waive Kerberos pre-authentication.\n\nIt "
                + "judges the setting, not the risk: a long random password makes the offline "
                + "attack impractical without changing anything this rule can see, so a reported "
                + "account is not necessarily crackable and an unreported one is not necessarily "
                + "safe from anything else.\n\nIt also cannot tell whether the weakness is being used "
                + "- that is a question for sign-in telemetry, which this product does not read.",
            MicrosoftReference:
                "https://learn.microsoft.com/defender-for-identity/security-assessment-unsecure-account-attributes"),

        new RuleGuidance(
            "SEC-030",
            "Privileged access",
            MitreTechnique: null,
            WhyItMatters:
                "This object was privileged once and is not now, and it is carrying the leftovers. "
                + "Microsoft states that its access control list is no longer maintained, and that "
                + "it still does not inherit permissions from where it lives - so it sits in a "
                + "state nobody chose, with a frozen set of permissions that no longer reflects "
                + "either its old role or its new one.",
            WhatToDo:
                "Confirm the object is genuinely no longer privileged, then clear its adminCount "
                + "value and re-enable inheritance on it so it picks up the permissions of the "
                + "container it now lives in. Check what its current access control list grants "
                + "before doing so: it is a snapshot of AdminSDHolder from the day it was last "
                + "stamped, and something may be relying on it.",
            About:
                "Reports an object carrying the AdminSDHolder marker whose permissions still "
                + "refuse to inherit, where the captured evidence does not establish that "
                + "AdminSDHolder protects it now.\n\nIt does not prove the object was ever "
                + "privileged - the marker is set when protection begins and is never cleared when "
                + "it ends, so it records a history nobody can read back - and it does not examine "
                + "what the frozen access control list actually grants. Whether those permissions "
                + "are dangerous is a separate question this product does not yet answer.",
            MicrosoftReference:
                "https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface#privileged-accounts-and-groups-in-active-directory"),

        new RuleGuidance(
            "SEC-027",
            "Privileged access",
            "T1134.005",
            WhyItMatters:
                "Every value in an account's SID history is placed in its access token when it "
                + "signs in, and grants access exactly as membership of that group would. This "
                + "account carries an identifier Microsoft documents as privileged, so it has that "
                + "privilege - but it appears in no group membership listing, because nothing was "
                + "ever added to a group. An administrator reviewing who is in Domain Admins will "
                + "not see this account, and the account has the access anyway.",
            WhatToDo:
                "Establish why the account carries the value, then remove it with "
                + "Set-ADUser -Remove @{SIDHistory='S-1-5-21-…'}. Removing it may take away access "
                + "the account still depends on: permissions left behind by the migration may name "
                + "only the old identifier, and nothing will have re-stamped them. This rule ranks "
                + "only the identifiers Microsoft documents, so an account carrying a custom group "
                + "from a domain that no longer exists is not reported here - the values it holds "
                + "are shown on the object itself.",
            About:
                "Reports an account whose SID history contains an identifier Microsoft documents "
                + "as privileged - Domain Admins, Enterprise Admins, the built-in operator groups "
                + "and their like.\n\nIt ranks a value by the number at the end of it, which it can "
                + "only do for the identifiers Microsoft publishes. A custom group that was "
                + "powerful in the old domain has an ordinary, sequentially allocated number, and "
                + "nothing in that number says what it once granted; if the old domain is gone, "
                + "nothing can. Such an account is not reported, and every value it carries is "
                + "shown on the object itself so a reader is not left with a filtered view.",
            MicrosoftReference:
                "https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#unsecure-sid-history-attributes"),

        new RuleGuidance(
            "SEC-028",
            "Credentials",
            MitreTechnique: null,
            WhyItMatters:
                "This account is exempt from the domain's minimum password length, so it may have "
                + "no password at all. Anyone who can reach authentication could sign in as it "
                + "without knowing anything - no cracking, no interception, no foothold first. The "
                + "password policy screen still shows the policy, and does not show that this "
                + "account is not subject to part of it.",
            WhatToDo:
                "Clear \"Password not required\" on the account, then set a password on it. "
                + "Clearing the flag alone does not give the account a password - if it currently "
                + "has none, it still has none until one is set. Establish what uses the account "
                + "first: something that was created without a password may not survive being "
                + "given one.",
            About:
                "Reports an account whose account options exempt it from the domain's minimum "
                + "password length.\n\nIt does not report accounts with no password, and the "
                + "difference matters: the flag says the rule does not apply to this account, not "
                + "that the account took advantage of it. The directory does not disclose whether "
                + "a password is set or what it is, and this product never asks - so a reported "
                + "account may have a perfectly good password, and what is wrong is that nothing "
                + "obliges it to.",
            MicrosoftReference:
                "https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#unsecure-account-attributes"),

        new RuleGuidance(
            "SEC-029",
            "Credentials",
            MitreTechnique: null,
            WhyItMatters:
                "The directory holds this account's password in a form that can be decrypted back "
                + "to the password itself, rather than a hash that an attacker would have to work "
                + "on. Whoever reaches the stored value gets a working credential immediately, and "
                + "people reuse passwords, so the reach of it is rarely limited to this account.",
            WhatToDo:
                "Clear \"Store password using reversible encryption\" on the account and then "
                + "change its password. The order matters and the second step is not optional: "
                + "clearing the setting stops a new reversible copy being stored, but the existing "
                + "one stays until the password changes. Find out why it was set - it is usually "
                + "an application that required it, and that application may stop working.",
            About:
                "Reports an account set to store its password using reversible encryption.\n\nIt "
                + "reads the setting, which governs what happens at the next password change; it "
                + "cannot see whether a reversible copy is stored right now. So an account cleared "
                + "of the setting but never given a new password still holds one and is not "
                + "reported, which is why the guidance insists on the password change as well as "
                + "the clearing.",
            MicrosoftReference:
                "https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#unsecure-account-attributes"),

        new RuleGuidance(
            "SEC-033",
            "Credentials",
            MitreTechnique: null,
            WhyItMatters:
                "This account is restricted to DES, a cipher broken long ago, so Kerberos tickets "
                + "encrypted for it are far cheaper to attack than tickets for any other account. "
                + "It also drags the account back from whatever stronger encryption the rest of "
                + "the domain has moved to.",
            WhatToDo:
                "Clear \"Use Kerberos DES encryption types for this account\". The setting is "
                + "almost always present because something authenticating as this account could "
                + "not do better - a legacy appliance or an old integration - so establish what "
                + "that is before clearing it, or that thing stops authenticating.",
            About:
                "Reports an account restricted to DES encryption by its account options.\n\nIt reads "
                + "the account's own setting and not the domain's: what encryption types the domain "
                + "permits, and which are used for the tickets actually issued, are configured "
                + "elsewhere and are not judged here. An account without this flag may still be "
                + "negotiating weak encryption for other reasons, and this rule says nothing about "
                + "that.",
            MicrosoftReference:
                "https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#unsecure-account-attributes"),

        new RuleGuidance(
            "SEC-021",
            "Credentials",
            "T1558.003",
            WhyItMatters:
                "Any authenticated member of the domain can ask a domain controller for a ticket to "
                + "this account's service, and that ticket is encrypted with this account's "
                + "password. Compromising it exposes the authority it actually holds. AdminSDHolder "
                + "protection alone does not prove domain administration: distribution-group paths "
                + "can propagate protection without authorization. The request is ordinary protocol traffic, the account is never "
                + "contacted, and the cracking leaves no failed logons, so nothing about it looks "
                + "like an attack while it is happening.",
            WhatToDo:
                "If the account does not actually run a service, remove the service name - a stale "
                + "name left from a test is the commonest case and the only one where the exposure "
                + "goes away rather than getting more expensive. If it does run a service, replace "
                + "it with a group managed service account, whose password Windows generates and "
                + "rotates itself; where that is not possible, give it a long random password. "
                + "Consider whether the account needs its privilege at all. Removing the service "
                + "name closes this route to the account and says nothing about any other. Review "
                + "each initial membership in the supporting evidence, including longer routes. "
                + "Changing a shared group can affect other accounts. Removing the listed memberships "
                + "does not establish that every other form of privilege is gone.",
            About:
                "Reports a service name registered on an account that AdminSDHolder protects.\n\n"
                + "Ordinary service accounts with service names are not reported, and that "
                + "is the rule rather than an omission: a service name on an ordinary account is "
                + "what a service account is, and reporting every one would report the normal "
                + "operation of every application in the estate. Microsoft scopes its own "
                + "recommendation the same way. The key distribution centre's own account is "
                + "excluded too - it carries a service name by default and cannot be changed. This "
                + "rule does not measure password strength, which is what actually decides whether "
                + "the offline attack succeeds.",
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
                "Follow the membership path on the finding and cut the link that brings the broad "
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
                "The owner of an object can rewrite that object's permissions whenever they like, "
                + "and ownership does not appear in the permission list. You can review every "
                + "entry on this object, find nothing wrong, and still miss that its owner can "
                + "replace the whole list at will. Microsoft is blunt about it: no matter what "
                + "permissions are set on an object, the owner can always change them. Objects "
                + "created by an administrator are owned by the Administrators group; an object "
                + "created by anybody else is owned by that person personally, and stays that way "
                + "for the life of the object.",
            WhatToDo:
                "Decide whether this owner should hold that standing. Where they should not, "
                + "change the owner to a privileged and monitored principal - which is what "
                + "Microsoft prescribes for the one case it covers directly. Where the owner is a "
                + "service account or an application identity that your organisation manages "
                + "deliberately, accept the finding rather than changing anything: that leaves a "
                + "record, where a silent exclusion would not. Where the owning account no longer "
                + "exists the object is orphaned and nobody can be asked to hand ownership over, "
                + "so an administrator must take ownership before anything else can be done.",
            About:
                "Reports an object whose owner is not an administrative principal.\n\nThis is latent "
                + "authority and not evidence of wrongdoing - the ordinary cause is that somebody "
                + "was allowed to create the object, they created it, and they became its owner.\n\n"
                + "An owner accepted through group membership is not reported within that "
                + "acceptance's scope. The forest-root Schema Admins group and its members are "
                + "accepted only in that forest's schema partition. Membership is consulted rather "
                + "than the identifier alone.\n\nThe rule stays silent where the owner would not "
                + "actually keep the power - an OWNER RIGHTS entry on the object switches off the "
                + "owner's implicit rights, and so does the forest setting that blocks them, which "
                + "applies to computer objects owned by non-administrators.\n\nObjects that "
                + "AdminSDHolder protects are reported by SEC-032 instead and never by both, so no "
                + "object appears twice.\n\nExpect this rule to be plentiful in a forest where "
                + "delegated creation is normal; a large count is information about the estate "
                + "rather than a defect.",
            MicrosoftReference:
                "https://learn.microsoft.com/windows/win32/secauthz/owner-of-a-new-object"),

        new RuleGuidance(
            "SEC-032",
            "Permissions",
            MitreTechnique: null,
            WhyItMatters:
                "This object is one AdminSDHolder protects, which means the directory treats it as "
                + "conferring privilege - a member of Domain Admins, Enterprise Admins, "
                + "Administrators or an operator group. Its owner is not an administrative "
                + "principal, and an owner can rewrite an object's permissions whenever they like. "
                + "What makes this worth your attention is that it should not have been possible "
                + "to observe: AdminSDHolder restores the owner of a protected object roughly "
                + "every hour, so finding a non-administrative one in a capture means either the "
                + "change was made within about the last hour, or AdminSDHolder is not running at "
                + "all. The second case is the serious one, because every privileged object in "
                + "the domain would then be sitting unrepaired.",
            WhatToDo:
                "Look at this promptly, and expect the owner may already have been restored by "
                + "the time you do - that does not mean the finding was wrong. First check "
                + "whether AdminSDHolder is running: compare the owner now against the one "
                + "reported here, and if it has been put back then the protection mechanism is "
                + "working and what you are looking at is a recent change worth explaining. If "
                + "the owner is still non-administrative an hour or more after the capture, "
                + "treat AdminSDHolder itself as the problem and check the domain controller "
                + "holding the PDC emulator role, because a stalled SDProp affects every "
                + "privileged object at once. Either way, check how the owner came to hold that "
                + "standing: an object created inside a privileged container by a delegated "
                + "administrator is the usual route, and the delegation that allowed it will "
                + "still be in place.",
            About:
                "Reports an object protected by AdminSDHolder whose owner is not an administrative "
                + "principal.\n\nIt applies the same test as SEC-031 and covers the objects SEC-031 "
                + "deliberately leaves alone, so the two never report the same object. Where the "
                + "protection closure is incomplete neither rule reports, because an object that "
                + "might be protected must not be quietly reported at the lower severity.\n\nThe "
                + "owner is judged by membership as well as by identifier, and the rule stays "
                + "silent where the owner would not actually keep the power to rewrite the list. "
                + "Schema Admins and its members are accepted as owners only within the captured "
                + "forest's schema, not on protected objects elsewhere unless independently accepted.\n\n"
                + "This finding is time-sensitive in a way the other rules are not: because "
                + "AdminSDHolder repairs ownership on its own schedule, the same object may be "
                + "reported in one run and absent from the next without anybody having fixed "
                + "anything. It does not check whether AdminSDHolder is running - it can only "
                + "tell you that something it should have repaired had not been repaired when "
                + "the directory was read.",
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
