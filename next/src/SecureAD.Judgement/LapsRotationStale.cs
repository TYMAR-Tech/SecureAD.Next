using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;

namespace SecureAD.Judgement;

/// <summary>
/// SEC-092 - a computer whose LAPS password expiration has passed and stayed passed.
/// </summary>
/// <remarks>
/// <para>
/// <b>What it finds.</b> A machine that LAPS is managing, or was, whose stored expiration time has
/// lapsed. The password should have rotated by now and did not, so the local administrator password
/// on that machine has become a fixed value while the directory records it as one being cycled.
/// </para>
/// <para>
/// <b>This is the case the other two LAPS rules pass over in silence.</b> SEC-091 fires when a
/// computer carries neither timestamp; SEC-094 fires when a capable machine carries only the legacy
/// one. A machine that was onboarded correctly and has since stopped rotating satisfies both: the
/// timestamp is present, so SEC-091 says nothing, and it is the right timestamp, so SEC-094 says
/// nothing. Without this rule the product reports a clean bill on a machine whose local
/// administrator password is now a static secret.
/// </para>
/// <para>
/// <b>Microsoft states the mechanism, which is what makes a past date evidence rather than
/// decoration.</b> <i>"Windows LAPS reads the password expiration time from Windows Server Active
/// Directory during each policy processing cycle. If the password is expired, a new password is
/// generated and stored immediately."</i> In a working deployment the value is therefore always in
/// the future, because the moment it is not, the next cycle replaces it. A value in the past is a
/// statement that no cycle has completed since it lapsed.
/// </para>
/// <para>
/// <b>It never asserts a cause.</b> A policy that stopped reaching the machine, a failed agent, a
/// machine that cannot reach a controller and a machine that has been switched off all look
/// identical from the directory. The finding says what is true - the password has not rotated - and
/// names where the operator can tell those apart, which is the machine's own event log.
/// </para>
/// <para>
/// Specified in <c>docs/layers/judgement/rules/SEC-092-laps-rotation-stale.md</c>.
/// </para>
/// </remarks>
public sealed class LapsRotationStale : IRule
{
    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new(
        "SEC-092",
        "LAPS password rotation has stopped",
        Severity.Medium,
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

    /// <summary>
    /// How far past its expiration a timestamp must be before the machine is reported.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The owner's decision of 2026-09-04, and it is not zero for two documented reasons.</b>
    /// Microsoft's own procedure for forcing an early rotation, <c>Set-LapsADPasswordExpirationTime</c>,
    /// sets the expiration to the current time and lets the next policy cycle do the work - so a
    /// healthy machine is legitimately past due between those two moments. And a policy cycle is
    /// not instant: Group Policy refreshes every 90 minutes with up to 30 minutes of random offset,
    /// so a working machine can sit past due for two hours by design.
    /// </para>
    /// <para>
    /// <b>Twenty-four hours costs a day and buys every false finding those two cases would
    /// produce.</b> A machine that has genuinely stopped rotating is still stopped tomorrow.
    /// </para>
    /// <para>
    /// <b>It cannot be derived from the machine's own policy.</b> <c>PasswordAgeDays</c> lives in
    /// policy rather than in the directory, so a rule judging sealed evidence cannot know what any
    /// individual machine was configured with. This is a fixed span, and the finding states how far
    /// past the machine actually is so that one day can be told from one year.
    /// </para>
    /// </remarks>
    public static TimeSpan Grace => TimeSpan.FromHours(24);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) =>
        throw new InvalidOperationException(
            "SEC-092 reads derived facts and must be offered them. Judging refuses a bundle that "
            + "cannot supply them, so reaching this is a defect rather than a missing derivation.");

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);

        if (!LapsAttributes.IsComputer(subject))
            return RuleVerdict.Judged([]);

        // Through DomainControllerSignals and never by distinguished name. The predecessor card for
        // this rule excluded controllers with a DN matched against OU=Domain Controllers, having
        // just replaced a sAMAccountName subquery that leaked when the name was null. Both are
        // string matching; this product replaced both with the object's own attributes.
        if (DomainControllerSignals.Of(subject).IsDomainController)
            return RuleVerdict.Judged([]);

        // The owner's decision of 2026-09-03, and it applies here more plainly than anywhere: a
        // disabled computer account has no running machine, so nothing is failing to rotate.
        if (LapsAttributes.IsDisabled(subject))
            return RuleVerdict.Judged([]);

        if (context.AttributeVisibility is not { } visibility)
            return RuleVerdict.CouldNotResolve([new UnresolvedInput(
                DerivedFactKind.AttributeVisibility, UnresolvedReason.NotDerived)]);

        // Read before the object's own values, for the reason SEC-094 gives. A withheld attribute
        // is returned as absent by the directory without saying so, and this rule reads a present
        // value - so withholding turns every stale machine silent rather than noisy. A false
        // negative on a security control is worse than a refusal, because nothing reports it.
        var modern = Readable(visibility, LapsAttributes.WindowsLapsExpiration);
        if (modern is Reading.Withheld)
            return RuleVerdict.CouldNotJudge([LapsAttributes.WindowsLapsExpiration]);

        var legacy = Readable(visibility, LapsAttributes.LegacyLapsExpiration);
        if (legacy is Reading.Withheld)
            return RuleVerdict.CouldNotJudge([LapsAttributes.LegacyLapsExpiration]);

        // Neither attribute exists in this forest's schema, so no object in it can carry a value and
        // absence is not evidence about any machine. SEC-091 owns that population.
        if (modern is Reading.Absent && legacy is Reading.Absent)
            return RuleVerdict.Judged([]);

        var modernValue = modern is Reading.Present
            ? AttributeReading.Text(subject, LapsAttributes.WindowsLapsExpiration)
            : null;

        var legacyValue = legacy is Reading.Present
            ? AttributeReading.Text(subject, LapsAttributes.LegacyLapsExpiration)
            : null;

        // WHAT COUNTS AS STALE IS "NOTHING HERE HAS ROTATED", NOT "THIS ONE VALUE IS OLD". A
        // machine mid-migration carries both timestamps, and if either is fresh then something is
        // demonstrably rotating its password and the machine is not the subject of this rule.
        // Deciding on the modern value alone would report a machine whose legacy agent is doing the
        // job, which is a finding an operator would check and reject.
        //
        // A DECODED DATE, A FRESH DATE AND NO DATE AT ALL ARE THREE DIFFERENT THINGS. Collapsing
        // the last two - by treating "not stale" and "not present" alike - reports a machine whose
        // only good timestamp is the one that stopped it being reported.
        var deadline = context.AsOf - Grace;

        var dates = new[] { modernValue, legacyValue }
            .Select(raw => LapsTimestamp.Of(raw).ExpiresUtc)
            .OfType<DateTimeOffset>()
            .ToList();

        // Nothing decoded to a date at all. That is either a machine carrying no timestamp, which is
        // SEC-091's, or one carrying a sentinel - a null, a zero or a negative FILETIME, all of
        // which LapsTimestamp already refuses. A password that expired in 1601 is a value written
        // empty, not a password four centuries overdue, and reporting it as stale would put an
        // absurdity in front of an operator.
        if (dates.Count == 0)
            return RuleVerdict.Judged([]);

        // Strictly later, so a machine exactly at the grace is given the benefit of it.
        if (dates.Exists(d => d >= deadline))
            return RuleVerdict.Judged([]);

        // The older of the two is the longer outage, and the one an operator should be told about.
        var expired = dates.Min();

        if (subject.ObjectGuid is not { } objectGuid)
            return RuleVerdict.CouldNotJudge(["objectGUID"]);

        var capability = LapsCapability.Of(subject);
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
                Detail(name, expired, context.AsOf),
                subject.Completeness,
                evidence),
        ]);
    }

    /// <summary>What this forest's schema permits the rule to conclude about one attribute.</summary>
    private enum Reading
    {
        /// <summary>Readable here, so the object's value means what it says.</summary>
        Present,

        /// <summary>Not in this forest's schema, so no object can carry it.</summary>
        Absent,

        /// <summary>Withheld, or nobody read the schema, so silence proves nothing.</summary>
        Withheld,
    }

    /// <summary>Narrows the shared schema answer to the three cases this rule acts on.</summary>
    /// <param name="visibility">What the derivation read out of the schema partition.</param>
    /// <param name="ldapDisplayName">The attribute.</param>
    private static Reading Readable(StoredAttributeVisibility visibility, string ldapDisplayName) =>
        LapsAttributes.Judgeability(visibility, ldapDisplayName) switch
        {
            LapsAttributes.Readability.Reportable => Reading.Present,
            LapsAttributes.Readability.NotInThisForest => Reading.Absent,
            _ => Reading.Withheld,
        };

    /// <summary>What the operator is told.</summary>
    /// <remarks>
    /// <b>It gives the age rather than only the date.</b> A date alone makes the reader do the
    /// arithmetic, and the difference between a machine three days overdue and one three years
    /// overdue is the difference between a transient fault and a machine nobody has managed since it
    /// was built.
    /// </remarks>
    /// <param name="name">What to call the machine.</param>
    /// <param name="expired">When the password was due to rotate.</param>
    /// <param name="asOf">The reference time this judging was evaluated against.</param>
    private static string Detail(string name, DateTimeOffset expired, DateTimeOffset asOf)
    {
        var days = (int)(asOf - expired).TotalDays;

        var overdue = days >= 1
            ? $"{days} day{(days == 1 ? string.Empty : "s")} overdue"
            : "overdue";

        return $"{name} has a LAPS password expiration of {expired:yyyy-MM-dd HH:mm} UTC, which is "
            + $"{overdue} as at {asOf:yyyy-MM-dd HH:mm} UTC. Windows LAPS reads this time on every "
            + "policy cycle and rotates the password the moment it has passed, so a time still in "
            + "the past means no cycle has completed since then and the local administrator "
            + "password has not changed. It is still unique to this machine, which is worth "
            + "something, but it is now a fixed secret: whatever exposure it has had since it was "
            + "last set, it keeps. The directory cannot say which of the causes applies - a policy "
            + "no longer reaching the machine, a failed agent, or a machine that cannot reach a "
            + "domain controller - and a machine simply switched off for a long period looks the "
            + "same here. Check that the LAPS policy still applies to this computer and read the "
            + "LAPS event log on the machine itself, where those causes are distinguishable.";
    }
}
