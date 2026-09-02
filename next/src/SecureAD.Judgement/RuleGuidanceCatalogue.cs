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
    ];

    /// <summary>The guidance for one rule, or null where none is written.</summary>
    /// <param name="ruleId">The rule identifier.</param>
    public static RuleGuidance? For(string ruleId) =>
        All.FirstOrDefault(g => string.Equals(g.RuleId, ruleId, StringComparison.Ordinal));
}
