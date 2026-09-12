using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;

namespace SecureAD.Judgement;

/// <summary>
/// SEC-094 - a computer capable of running Windows LAPS carrying only the legacy timestamp.
/// </summary>
/// <remarks>
/// <para>
/// <b>What it finds.</b> A machine that could be managed by the current version of LAPS, where the
/// directory shows no sign that it is. What it does show is a timestamp from the old product, which
/// may be live and may be a leftover.
/// </para>
/// <para>
/// <b>The old timestamp proves nothing on its own, and that is the whole rule.</b> Microsoft's
/// migration procedure disables or removes the legacy policy, then removes the legacy software, and
/// touches no directory attribute at any point - so <c>ms-Mcs-AdmPwdExpirationTime</c> persists
/// indefinitely as residue. From the directory alone, a live legacy deployment and a fossil from a
/// policy that stopped applying years ago are indistinguishable.
/// </para>
/// <para>
/// <b>Microsoft's own success signal is the modern attribute appearing</b>: <i>"When storing
/// passwords in Active Directory, you can look for the appearance of a new or updated
/// <c>msLAPS-PasswordExpirationTime</c> attribute on the managed device's AD computer object."</i>
/// This rule is that check, run across an estate rather than one machine at a time.
/// </para>
/// <para>
/// <b>It never asserts a cause.</b> <i>Legacy present, modern absent</i> has causes that are
/// identical in the directory: a Windows LAPS policy that is not reaching the machine, a deliberate
/// legacy emulation-mode configuration, or a machine that never took the April 2023 update.
/// Emulation mode is supported and is aimed squarely at organisations mid-migration - Microsoft:
/// <i>"You might use emulation mode if you migrate an existing deployment of legacy Microsoft LAPS
/// to Windows LAPS."</i> The evidence that separates them is the client-side extension registry key
/// and event 10023, both on the machine rather than in Active Directory, and
/// <c>docs/decisions/0008</c> fixes that boundary.
/// </para>
/// <para>
/// <b>Even the benign cause is worth surfacing</b>, which is what keeps this rule honest rather
/// than merely noisy: a machine in emulation mode stores passwords in clear text only. Microsoft:
/// <i>"when you run Windows LAPS in legacy Microsoft LAPS emulation mode, you can't configure
/// Windows LAPS to do tasks like encrypt passwords or save passwords to Microsoft Entra ID."</i>
/// </para>
/// <para>
/// Specified in
/// <c>docs/specs/rules/SEC-094-windows-laps-not-applied-on-capable-computer.md</c>.
/// </para>
/// </remarks>
public sealed class WindowsLapsNotAppliedOnCapableComputer : IRule
{
    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new(
        "SEC-094",
        "Windows LAPS expected, but only a legacy timestamp present",
        Severity.Low,
        Version: 1,
        SubjectClasses: ["computer"],
        RequiredAttributes:
        [
            LapsAttributes.WindowsLapsExpiration,
            LapsAttributes.LegacyLapsExpiration,
            "objectClass",
            "operatingSystem",
            "operatingSystemVersion",
            "userAccountControl",
            "primaryGroupID",
        ],
        RequiredDerivedFacts: [nameof(DerivedFactKind.AttributeVisibility)]);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) =>
        throw new InvalidOperationException(
            "SEC-094 reads derived facts and must be offered them. Judging refuses a bundle that "
            + "cannot supply them, so reaching this is a defect rather than a missing derivation.");

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);

        if (!LapsAttributes.IsComputer(subject))
            return RuleVerdict.Judged([]);

        // Through DomainControllerSignals and never by distinguished name. The predecessor matched
        // the Domain Controllers container, and its own backlog flagged that as brittle; worse, a
        // child domain's controller also holds a member-server computer account in the parent
        // domain, which a name-based test gets wrong.
        if (DomainControllerSignals.Of(subject).IsDomainController)
            return RuleVerdict.Judged([]);

        // Excluded for the reason SEC-091 gives: a disabled computer account has no running machine
        // behind it, so there is nothing for a policy to reach and nothing to migrate. An account
        // whose state could not be read is refused rather than silenced - see P-158.
        if (LapsAttributes.RefusalFor(subject) is { } accountState)
            return accountState;

        if (context.AttributeVisibility is not { } visibility)
            return RuleVerdict.CouldNotResolve([new UnresolvedInput(
                DerivedFactKind.AttributeVisibility, UnresolvedReason.NotDerived)]);

        // Checked before the object's own attributes, because no per-object answer means anything
        // while the forest may be withholding the attribute the answer rests on. This rule is the
        // reason the check exists: with the modern timestamp confidential, every modern-capable
        // machine carrying a legacy value would be reported and every finding would be false.
        var modern = LapsAttributes.Judgeability(visibility, LapsAttributes.WindowsLapsExpiration);
        if (modern is not LapsAttributes.Readability.Reportable)
        {
            return modern is LapsAttributes.Readability.NotInThisForest
                ? RuleVerdict.Judged([])
                : RuleVerdict.CouldNotJudge([LapsAttributes.WindowsLapsExpiration]);
        }

        // The legacy attribute decides this rule as much as the modern one does: withheld, a
        // machine carrying a legacy timestamp is indistinguishable from one carrying nothing, and
        // this rule would silently hand its whole population to SEC-091.
        var legacy = LapsAttributes.Judgeability(visibility, LapsAttributes.LegacyLapsExpiration);
        if (legacy is not LapsAttributes.Readability.Reportable)
        {
            return legacy is LapsAttributes.Readability.NotInThisForest
                ? RuleVerdict.Judged([])
                : RuleVerdict.CouldNotJudge([LapsAttributes.LegacyLapsExpiration]);
        }

        var modernValue = AttributeReading.Text(subject, LapsAttributes.WindowsLapsExpiration);
        var legacyValue = AttributeReading.Text(subject, LapsAttributes.LegacyLapsExpiration);

        // The confirmation Microsoft names is present. Whether it is stale is SEC-092's question.
        //
        // DECIDED ON THE RAW VALUE BEING THERE, NOT ON IT DECODING. A machine whose modern
        // timestamp is present but unreadable is still a machine Windows LAPS has written to, and
        // reporting it because this build could not parse a FILETIME would be a false finding
        // produced by our own decoder.
        if (!string.IsNullOrWhiteSpace(modernValue))
            return RuleVerdict.Judged([]);

        // Neither timestamp. That is SEC-091, and it is the more serious finding.
        if (string.IsNullOrWhiteSpace(legacyValue))
            return RuleVerdict.Judged([]);

        // The capability test is the whole exclusion, and it is why operatingSystemVersion is
        // captured. Unknown is excluded with LegacyLapsOnly and for a different reason: this rule's
        // entire claim is that this machine could be running Windows LAPS, and that cannot be said
        // about a machine nobody can identify. SEC-091 reports an unknown machine; this one does
        // not, and the asymmetry is deliberate.
        var capability = LapsCapability.Of(subject);
        if (capability.Kind is not LapsCapabilityKind.WindowsLapsCapable)
            return RuleVerdict.Judged([]);

        if (subject.ObjectGuid is not { } objectGuid)
            return RuleVerdict.CouldNotJudge(["objectGUID"]);

        var name = AttributeReading.Text(subject, "sAMAccountName") ?? subject.DistinguishedName;
        var evidence = new LapsDeploymentEvidence(modernValue, legacyValue, capability);

        return RuleVerdict.Judged(
        [
            new Finding(
                Definition.Id,
                Definition.Version,
                Definition.Severity,
                new FindingSubject(FindingSubjectKind.Account, name),
                objectGuid,
                subject.DistinguishedName,
                DnHelper.DnToFqdn(subject.DistinguishedName),
                LapsAttributes.ClassOf(subject),
                Detail(name, evidence),
                subject.Completeness,
                evidence),
        ]);
    }

    /// <summary>What the operator is told.</summary>
    /// <remarks>
    /// <b>It states what was observed and names the candidate causes.</b> Wording that said "Group
    /// Policy is not applying" would be a confident claim the evidence does not support, against an
    /// estate that may be configured exactly as it intends.
    /// </remarks>
    private static string Detail(string name, LapsDeploymentEvidence evidence)
    {
        var when = evidence.LegacyLapsExpiresUtc is { } expiry
            ? $" (last recorded expiry {expiry.UtcDateTime:yyyy-MM-dd})"
            : " (its value could not be decoded as a date)";

        return $"{name} runs {evidence.Capability.Name ?? "an operating system"} and could be "
            + "managed by Windows LAPS, but carries no msLAPS-PasswordExpirationTime - the "
            + "attribute Microsoft says to look for to confirm a machine is managed. It does carry "
            + $"the legacy Microsoft LAPS timestamp{when}, and that attribute is never cleared: "
            + "migrating away from legacy LAPS removes the policy and the software and leaves the "
            + "value behind, so its presence does not show that anything is still rotating this "
            + "password. Three things produce this state and the directory cannot tell them apart: "
            + "the Windows LAPS policy is not reaching the machine, Windows LAPS is deliberately "
            + "running in legacy emulation mode, or the machine has not taken the April 2023 "
            + "update that ships Windows LAPS. Check the machine itself - the Windows LAPS event "
            + "log records event 10023 when it is in emulation mode. Note that emulation mode "
            + "stores passwords in clear text and cannot encrypt them or back them up to Microsoft "
            + "Entra ID, so a machine deliberately left in it is in a weaker state than one "
            + "managed natively.";
    }
}
