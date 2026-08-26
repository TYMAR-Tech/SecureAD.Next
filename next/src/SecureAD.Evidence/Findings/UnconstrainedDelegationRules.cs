namespace SecureAD.Evidence.Findings;

/// <summary>
/// What an unconstrained delegation finding rests on.
/// </summary>
/// <param name="UserAccountControl">The value the flag was read from.</param>
/// <param name="IsComputer">Whether the object declared the computer class, which decides which rule applies.</param>
/// <param name="DomainController">How the domain controller question was answered for this object.</param>
public sealed record UnconstrainedDelegationEvidence(
    uint UserAccountControl,
    bool IsComputer,
    DomainControllerSignals DomainController) : FindingEvidence;

/// <summary>
/// Shared logic for the two unconstrained delegation rules.
/// </summary>
/// <remarks>
/// <para>
/// <b>What unconstrained delegation is.</b> An account trusted for it can impersonate anyone who
/// authenticates to it, to any service. Microsoft marks it "Supported (not recommended)" in every
/// topology it publishes, and resource-based constrained delegation is the only alternative
/// supported in all of them - classic constrained delegation does not work across domains or
/// forests. Credential Guard breaks unconstrained delegation outright on current Windows.
/// </para>
/// <para>
/// <b>The rules identify it rather than condemn it.</b> Removing the flag breaks whatever needed
/// it; the useful action is migrating to resource-based constrained delegation, which moves the
/// decision about who may impersonate from the front end to the resource owner. That is why the
/// wording names the setting and points at the migration.
/// </para>
/// <para>
/// <b>The bit is Microsoft's and has been verified.</b> <c>0x80000</c> is
/// <c>ADS_UF_TRUSTED_FOR_DELEGATION</c>, checked against three independently maintained Microsoft
/// pages and pinned by <c>UserAccountControlWordingMicrosoftAnchorTests</c>.
/// </para>
/// </remarks>
internal static class UnconstrainedDelegation
{
    internal const uint TrustedForDelegation = 0x00080000;

    /// <summary>The attributes both rules read. Declared per 0083.</summary>
    internal static IReadOnlyList<string> RequiredAttributes { get; } =
        ["userAccountControl", "objectClass", "primaryGroupID"];

    /// <summary>
    /// The classes both rules are about: security principals that can be trusted for delegation.
    /// </summary>
    /// <remarks>
    /// Nothing else in a directory can hold <c>TRUSTED_FOR_DELEGATION</c>. Declaring it keeps an
    /// organisational unit out of the rule's arithmetic entirely rather than counting it as an
    /// object the rule could not read - which is what the rules did until 2026-08-26, on three
    /// objects in four of a real forest.
    /// </remarks>
    internal static IReadOnlyList<string> SubjectClasses { get; } = ["user", "computer"];

    /// <summary>
    /// Whether this object is a computer, which is what partitions the two rules.
    /// </summary>
    /// <param name="subject">The object to test.</param>
    internal static bool IsComputer(ObjectAttributes subject) =>
        AttributeReading.AllText(subject, "objectClass")
            .Any(c => string.Equals(c, "computer", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// The verdict both rules reach, or a statement that they could not reach one.
    /// </summary>
    /// <param name="subject">The object to judge.</param>
    /// <param name="definition">The rule asking.</param>
    /// <param name="wantComputer">Whether the asking rule handles computers.</param>
    /// <param name="detail">How to word the finding once the object qualifies.</param>
    internal static RuleVerdict Judge(
        ObjectAttributes subject,
        RuleDefinition definition,
        bool wantComputer,
        Func<string, string> detail)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(definition);
        ArgumentNullException.ThrowIfNull(detail);

        // Silence has to mean one thing. An object missing what the rule declared it reads is not
        // an object the rule found nothing wrong with, and 0002 forbids rendering the second as
        // the first. Because 0083 made the rule name its inputs, it can say which were absent.
        var missing = definition.RequiredAttributes
            .Where(a => AttributeReading.AllText(subject, a).Count == 0)
            .ToArray();

        if (missing.Length > 0)
            return RuleVerdict.CouldNotJudge(missing);

        // An object with no GUID cannot be identified across runs, and 0023 makes objectGUID part
        // of a finding's identity. This is a judgement reached, not an input missing: the rule can
        // see the object and simply has nothing an acceptance could ever attach to.
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

        return RuleVerdict.Judged(
        [
            new Finding(
                definition.Id,
                definition.Version,
                definition.Severity,
                new FindingSubject(FindingSubjectKind.Account, name),
                objectGuid,
                subject.DistinguishedName,
                detail(name),
                subject.Completeness,
                new UnconstrainedDelegationEvidence(control, isComputer, signals)),
        ]);
    }
}

/// <summary>
/// SEC-010 - a user or service account trusted for unconstrained delegation.
/// </summary>
/// <remarks>
/// <b>Partitioned against <see cref="UnconstrainedDelegationOnNonDomainController"/> by object
/// class, not by one hiding the other.</b> An object is a computer or it is not, so exactly one of
/// the two rules can fire on it and neither has to know what the other did. That matters because
/// a rule which disappears when another fires leaves nothing at all behind on the day the other
/// one is the one that breaks.
/// </remarks>
public sealed class UnconstrainedDelegationOnAccount : IRule
{
    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new(
        "SEC-010",
        "Unconstrained delegation",
        Severity.High,
        Version: 1,
        UnconstrainedDelegation.SubjectClasses,
        UnconstrainedDelegation.RequiredAttributes);

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

/// <summary>
/// SEC-011 - a computer that is not a domain controller, trusted for unconstrained delegation.
/// </summary>
/// <remarks>
/// <b>Domain controllers are excluded because they require this.</b> Microsoft's own assessment
/// scopes the equivalent question to "non-domain controller entities". The exclusion is not a
/// convenience: a domain controller has nothing to migrate to, so a finding against one is an
/// instruction that cannot be followed. <see cref="DomainControllerSignals"/> decides it, and
/// records when the three ways of asking disagreed.
/// </remarks>
public sealed class UnconstrainedDelegationOnNonDomainController : IRule
{
    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new(
        "SEC-011",
        "Unconstrained delegation on a non-domain controller",
        Severity.High,
        Version: 1,
        UnconstrainedDelegation.SubjectClasses,
        UnconstrainedDelegation.RequiredAttributes);

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
