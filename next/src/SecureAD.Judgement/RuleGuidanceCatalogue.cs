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
                + "unconstrained delegation. It reads that one setting and nothing else: it does "
                + "not report constrained delegation or resource-based constrained delegation, "
                + "which are the safer forms and are not judged here at all, and it cannot say "
                + "whether anyone has ever actually authenticated to this account. An account "
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
                + "controller. Domain controllers are excluded deliberately, because the setting "
                + "is normal on them; a controller identified by any of three independent signals "
                + "is left alone, and a machine that looks like one by some signals and not others "
                + "is reported with that disagreement recorded rather than resolved. As with "
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
                "Reports an account whose account options waive Kerberos pre-authentication. It "
                + "judges the setting, not the risk: a long random password makes the offline "
                + "attack impractical without changing anything this rule can see, so a reported "
                + "account is not necessarily crackable and an unreported one is not necessarily "
                + "safe from anything else. It also cannot tell whether the weakness is being used "
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
                + "AdminSDHolder protects it now. It does not prove the object was ever "
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
                + "and their like. It ranks a value by the number at the end of it, which it can "
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
                + "password length. It does not report accounts with no password, and the "
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
                "Reports an account set to store its password using reversible encryption. It "
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
                "Reports an account restricted to DES encryption by its account options. It reads "
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
                + "password. Because the account is privileged, cracking it offline hands over "
                + "administration of the domain in a single step - with no foothold on a privileged "
                + "machine first. The request is ordinary protocol traffic, the account is never "
                + "contacted, and the cracking leaves no failed logons, so nothing about it looks "
                + "like an attack while it is happening.",
            WhatToDo:
                "If the account does not actually run a service, remove the service name - a stale "
                + "name left from a test is the commonest case and the only one where the exposure "
                + "goes away rather than getting more expensive. If it does run a service, replace "
                + "it with a group managed service account, whose password Windows generates and "
                + "rotates itself; where that is not possible, give it a long random password. "
                + "Consider whether the account needs its privilege at all. Removing the service "
                + "name closes this route to the account and says nothing about any other.",
            About:
                "Reports a service name registered on an account that AdminSDHolder protects. "
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
            WhyItMatters:
                "A principal that is broad in every organisation - Everyone, Authenticated Users, "
                + "Domain Users, Domain Computers, Guests or Anonymous - can read this machine's "
                + "local administrator password. That yields administrative control of the "
                + "machine, and the access is local, so no domain authentication is involved and "
                + "nothing is logged centrally. The principal is usually not the one named in the "
                + "permission: it falls out of the group nesting underneath it, which is why "
                + "nobody notices. Microsoft describes finding delegations that, expanded, reveal "
                + "thousands of accounts holding local administrator rights.",
            WhatToDo:
                "Follow the membership path on the finding and cut the link that brings the broad "
                + "principal into the delegated group, or narrow the permission so it names only "
                + "the administrators who need it. Do not simply remove the delegation: this "
                + "product cannot know which principals your organisation intended to hold LAPS "
                + "read access, and the group named may be entirely legitimate apart from what is "
                + "nested inside it. Where the permission carries no object type it reaches every "
                + "attribute on the object rather than only the password, and Microsoft's "
                + "Find-LapsADExtendedRights cmdlet is the way to review that on an "
                + "organizational unit.",
            About:
                "Reports a computer whose LAPS password attributes can be read by a principal that "
                + "is broad in every organisation, found by expanding whichever principal the "
                + "permission actually names all the way down. It reports only that, and "
                + "deliberately: nothing in the directory says which principals an organisation "
                + "intended to hold this access, so a rule firing on an 'unexpected' principal "
                + "would be imposing somebody else's idea of normal. The scope a permission is "
                + "inherited from is stated as a fact rather than as an error, because a "
                + "delegation made high in the tree may be deliberate. Every LAPS password "
                + "attribute is confidential, which Microsoft says requires both Read Property and "
                + "Control Access to read - this rule requires both before reporting anyone, so it "
                + "names fewer principals than a tool testing Control Access alone, and every one "
                + "it names can genuinely read the password. A Control Access grant on its own is "
                + "recorded as a fact and is not reported as an exposure. Disabled computer "
                + "accounts are out of scope, having no running machine behind them, and a forest "
                + "whose schema carries no LAPS attribute is not reported at all. Where the "
                + "membership walk could not reach everything nested inside a delegated principal, "
                + "the finding says so rather than implying nothing else is inside.",
            MicrosoftReference:
                "https://learn.microsoft.com/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential"),

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
                + "Microsoft names for a successful deployment. Applications or scripts that sign "
                + "in with a shared local administrator password will stop working once it starts "
                + "rotating, so find those before you deploy. This rule reads Active Directory "
                + "only: a machine whose password is backed up to Microsoft Entra ID carries no "
                + "directory attribute and cannot be told apart from an unmanaged one here.",
            About:
                "Reports a computer carrying neither LAPS expiration timestamp, so nothing "
                + "visible in this directory is rotating its local administrator password. "
                + "It reads Active Directory only. A machine whose password is backed up to "
                + "Microsoft Entra ID instead carries no directory attribute at all and looks "
                + "exactly like an unmanaged one - the likeliest false finding in a real estate, "
                + "and one the product cannot detect while an administrator can. Domain "
                + "controllers are out of scope, having no ordinary local administrator account to "
                + "manage, and so are disabled accounts, which have no running machine behind "
                + "them. A forest whose schema was never extended for either LAPS product is not "
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
                + "names for a successful deployment. It states what was observed and never "
                + "which cause produced it, because the three causes are identical in the "
                + "directory and what separates them is on the machine: a policy that is not "
                + "reaching it, a deliberate legacy emulation-mode configuration, or a machine "
                + "that never took the April 2023 update. Machines too old for Windows LAPS are "
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
                + "distinguishable. If the machine has simply been switched off or is out of "
                + "service, no action is needed and the finding will clear on its own once it "
                + "comes back and completes one policy cycle. To force a rotation once the machine "
                + "is healthy, Microsoft's Set-LapsADPasswordExpirationTime sets the expiration to "
                + "now and the next cycle does the rest.",
            About:
                "Reports a computer whose stored LAPS expiration time passed more than a day ago, "
                + "so the password it governs has not rotated. The one-day grace is deliberate: "
                + "Microsoft's own way of forcing an early rotation sets the expiration to the "
                + "current time and lets the next policy cycle act, and a policy cycle can take "
                + "two hours, so a healthy machine is briefly past due by design. It never asserts "
                + "a cause, because a policy that stopped reaching the machine, a failed agent, a "
                + "machine that cannot reach a controller and a machine switched off for a month "
                + "are identical in the directory - the finding gives the date and how far overdue "
                + "it is so that a transient fault can be told from a machine nobody has managed "
                + "in years. A machine carrying both timestamps is reported only if neither has "
                + "rotated, since a fresh value proves something is still doing the job. Domain "
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
