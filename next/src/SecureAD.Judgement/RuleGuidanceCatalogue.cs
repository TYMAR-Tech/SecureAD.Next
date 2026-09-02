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
            MicrosoftReference:
                "https://learn.microsoft.com/defender-for-identity/alerts-mdi-classic#credential-access-alerts"),

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
            MicrosoftReference:
                "https://learn.microsoft.com/windows-server/identity/laps/laps-scenarios-migration"),
    ];

    /// <summary>The guidance for one rule, or null where none is written.</summary>
    /// <param name="ruleId">The rule identifier.</param>
    public static RuleGuidance? For(string ruleId) =>
        All.FirstOrDefault(g => string.Equals(g.RuleId, ruleId, StringComparison.Ordinal));
}
