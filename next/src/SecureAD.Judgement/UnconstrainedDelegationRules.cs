using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;

namespace SecureAD.Judgement;

/// <summary>Shared logic for the two unconstrained-delegation rules.</summary>
/// <remarks>
/// <para>
/// <b>What unconstrained delegation is.</b> An account trusted for it can impersonate anyone who
/// authenticates to it, to any service. Microsoft marks it "Supported (not recommended)" in every
/// topology it publishes, and resource-based constrained delegation is the only alternative
/// supported in all of them.
/// </para>
/// <para>
/// <b>The rules identify it rather than condemn it.</b> Removing the flag can break what depended on
/// it. The useful action is migrating to resource-based constrained delegation, so the wording names
/// the setting and the migration rather than claiming a safe automatic fix.
/// </para>
/// <para>
/// <b>The bit is Microsoft's and has been verified.</b> <c>0x80000</c> is
/// <c>ADS_UF_TRUSTED_FOR_DELEGATION</c>, pinned by the existing Microsoft anchor tests.
/// </para>
/// </remarks>
internal static class UnconstrainedDelegation
{
    internal const uint TrustedForDelegation = 0x00080000;

    internal static IReadOnlyList<string> RequiredAttributes { get; } =
        ["userAccountControl", "objectClass", "primaryGroupID"];

    internal static IReadOnlyList<string> SubjectClasses { get; } = ["user", "computer"];

    internal static bool IsComputer(ObjectAttributes subject) =>
        AttributeReading.ContainsText(subject, "objectClass", "computer");

    internal static RuleVerdict Judge(
        ObjectAttributes subject,
        RuleDefinition definition,
        bool wantComputer,
        Func<string, string> detail)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(definition);
        ArgumentNullException.ThrowIfNull(detail);

        var missing = definition.RequiredAttributes
            .Where(a => !AttributeReading.HasTextValue(subject, a))
            .ToArray();

        if (missing.Length > 0)
            return RuleVerdict.CouldNotJudge(missing);

        if (subject.ObjectGuid is not { } objectGuid)
            return RuleVerdict.Judged([]);

        if (AttributeReading.UnsignedInteger(subject, "userAccountControl") is not { } control)
            return RuleVerdict.CouldNotJudge(["userAccountControl"]);

        var isComputer = IsComputer(subject);

        if ((control & TrustedForDelegation) == 0 || isComputer != wantComputer)
            return RuleVerdict.Judged([]);

        var signals = DomainControllerSignals.Of(subject);
        if (signals.IsDomainController)
            return RuleVerdict.Judged([]);

        var name = AttributeReading.Text(subject, "sAMAccountName") ?? subject.DistinguishedName;
        var objectClass = AttributeReading.LastText(subject, "objectClass") ?? string.Empty;

        return RuleVerdict.Judged(
        [
            new Finding(
                definition.Id,
                definition.Version,
                definition.Severity,
                new FindingSubject(FindingSubjectKind.Account, name),
                objectGuid,
                subject.DistinguishedName,
                DnHelper.DnToFqdn(subject.DistinguishedName),
                objectClass,
                detail(name),
                subject.Completeness,
                new UnconstrainedDelegationEvidence(control, isComputer, signals)),
        ]);
    }
}

/// <summary>SEC-010 — a user or service account trusted for unconstrained delegation.</summary>
public sealed class UnconstrainedDelegationOnAccount : IObjectRule
{
    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new(
        "SEC-010",
        "Unconstrained delegation",
        Severity.High,
        Version: 1,
        UnconstrainedDelegation.SubjectClasses,
        UnconstrainedDelegation.RequiredAttributes,
        RequiredDerivedFacts: []);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) =>
        UnconstrainedDelegation.Judge(
            subject,
            Definition,
            wantComputer: false,
            name => $"{name} is trusted for unconstrained delegation, so any service running as it "
                + "can impersonate whoever authenticates to it, to any other service. Consider "
                + "resource-based constrained delegation, which lets each resource decide who may "
                + "impersonate to it.");
}

/// <summary>SEC-011 — a non-domain-controller computer trusted for unconstrained delegation.</summary>
public sealed class UnconstrainedDelegationOnNonDomainController : IObjectRule
{
    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new(
        "SEC-011",
        "Unconstrained delegation on a non-domain controller",
        Severity.High,
        Version: 1,
        UnconstrainedDelegation.SubjectClasses,
        UnconstrainedDelegation.RequiredAttributes,
        RequiredDerivedFacts: []);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) =>
        UnconstrainedDelegation.Judge(
            subject,
            Definition,
            wantComputer: true,
            name => $"{name} is a computer trusted for unconstrained delegation and is not a domain "
                + "controller. Anyone who compromises this host collects the Kerberos tickets of "
                + "everyone who authenticates to it. Consider resource-based constrained delegation.");
}
