using System.Globalization;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// SEC-092 against the cases its specification names.
/// </summary>
/// <remarks>
/// <para>
/// <b>These run the whole stage rather than calling the rule directly</b>, for the reason SEC-091's
/// and SEC-094's tests give: a test handing the rule a fabricated <c>JudgingContext</c> would prove
/// the rule agrees with itself. Each builds a sealed bundle carrying a schema partition, derives it,
/// judges it and reads the judgement back.
/// </para>
/// <para>
/// <b>The reference time is passed to judging and never taken from the clock</b>, which is what
/// makes these tests able to state an expected outcome at all. A rule reading
/// <c>DateTimeOffset.UtcNow</c> would make every one of them a different test tomorrow.
/// </para>
/// <para>
/// <b>The tests most likely to catch a wrong rule are the two boundaries and the both-timestamps
/// case.</b> A rule with the comparison inverted, or the grace dropped, still passes a test that
/// only checks a years-stale machine is reported.
/// </para>
/// </remarks>
public sealed class LapsRotationStaleTests
{
    /// <summary>When judging ran. Deliberately different from the reference time below.</summary>
    private static readonly DateTimeOffset Started = new(2026, 9, 4, 9, 0, 0, TimeSpan.Zero);

    /// <summary>What the rule judges against, and what the judgement records.</summary>
    private static readonly DateTimeOffset AsOf = new(2026, 9, 4, 12, 0, 0, TimeSpan.Zero);

    /// <summary>Windows Server 2022, which Microsoft supports Windows LAPS on.</summary>
    private const string ModernServer = "Windows Server 2022 Datacenter";
    private const string ModernServerBuild = "10.0 (20348)";

    /// <summary>A timestamp a given span away from the reference time, as a FILETIME.</summary>
    /// <param name="fromAsOf">Negative for the past, positive for the future.</param>
    private static string At(TimeSpan fromAsOf) =>
        (AsOf + fromAsOf).ToFileTime().ToString(CultureInfo.InvariantCulture);

    /// <summary>Comfortably stale: a year past the reference time.</summary>
    private static string Stale => At(TimeSpan.FromDays(-365));

    /// <summary>Healthy: due to rotate in a fortnight.</summary>
    private static string Fresh => At(TimeSpan.FromDays(14));

    /// <summary>
    /// A machine whose Windows LAPS timestamp lapsed a year ago is reported, at Medium.
    /// </summary>
    [Fact]
    public void AMachineWhoseModernTimestampLapsedIsReported()
    {
        var finding = Assert.Single(Judge(Machine() with { WindowsLapsExpiration = Stale }));

        Assert.Equal("SEC-092", finding.RuleId);
        Assert.Equal(Severity.Medium, finding.Severity);

        var evidence = Assert.IsType<LapsDeploymentEvidence>(finding.Evidence);
        Assert.Equal(LapsTimestampReading.Present, evidence.WindowsLaps);

        // The age is stated, not left as arithmetic for the reader. A machine three days overdue
        // and one three years overdue need different responses.
        Assert.Contains("365 days overdue", finding.Detail, StringComparison.Ordinal);

        // It never asserts a cause, because the directory cannot tell them apart.
        Assert.Contains("cannot say which of the causes", finding.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// A machine whose legacy timestamp lapsed is reported too.
    /// </summary>
    /// <remarks>
    /// Legacy Microsoft LAPS rotates on the same stored expiration. A machine still running it, and
    /// no longer rotating, has the same static password as one running the modern product.
    /// </remarks>
    [Fact]
    public void AMachineWhoseLegacyTimestampLapsedIsReported() =>
        Assert.Single(Judge(Machine() with { LegacyLapsExpiration = Stale }));

    /// <summary>
    /// A machine whose timestamp is in the future is not reported.
    /// </summary>
    /// <remarks>
    /// <b>The healthy state, and the negative control for every positive test above.</b> A rule
    /// with its comparison inverted passes those and fails this.
    /// </remarks>
    [Fact]
    public void AMachineWithAFutureTimestampIsNotReported() =>
        Assert.Empty(Judge(Machine() with { WindowsLapsExpiration = Fresh }));

    /// <summary>
    /// A machine one hour past its expiration is not reported.
    /// </summary>
    /// <remarks>
    /// <b>This is the grace, and it is the owner's decision of 2026-09-03.</b> Microsoft's own way
    /// of forcing an early rotation sets the expiration to the current time and lets the next policy
    /// cycle act, and a Group Policy cycle can take two hours - so a healthy machine is legitimately
    /// past due for a short window. A rule with no tolerance reports every one of them.
    /// </remarks>
    [Fact]
    public void AMachineInsideTheGraceIsNotReported() =>
        Assert.Empty(Judge(Machine() with { WindowsLapsExpiration = At(TimeSpan.FromHours(-1)) }));

    /// <summary>
    /// Exactly at the grace is not reported, and a minute beyond it is.
    /// </summary>
    /// <remarks>
    /// <b>Both halves in one test on purpose.</b> A boundary test that only checks one side cannot
    /// tell a correct comparison from one that is off by the whole grace.
    /// </remarks>
    [Fact]
    public void TheGraceBoundaryIsExact()
    {
        Assert.Empty(Judge(Machine() with
        {
            WindowsLapsExpiration = At(-LapsRotationStale.Grace),
        }));

        Assert.Single(Judge(Machine() with
        {
            WindowsLapsExpiration = At(-LapsRotationStale.Grace - TimeSpan.FromMinutes(1)),
        }));
    }

    /// <summary>
    /// A machine whose legacy timestamp is stale but whose modern one is fresh is not reported.
    /// </summary>
    /// <remarks>
    /// <b>This is the migration case, and it is the one the rule most easily gets wrong.</b>
    /// Microsoft's migration procedure never clears <c>ms-Mcs-AdmPwdExpirationTime</c>, so a machine
    /// managed perfectly well by Windows LAPS carries a legacy value that stopped moving the day it
    /// migrated. A rule that reported any lapsed timestamp would report every successfully migrated
    /// machine in the estate - and would still pass every positive test above.
    /// </remarks>
    [Fact]
    public void AStaleLegacyTimestampBesideAFreshModernOneIsNotReported() =>
        Assert.Empty(Judge(Machine() with
        {
            WindowsLapsExpiration = Fresh,
            LegacyLapsExpiration = Stale,
        }));

    /// <summary>
    /// The mirror of the case above: a fresh legacy value beside a stale modern one is not reported.
    /// </summary>
    /// <remarks>
    /// Something is demonstrably rotating this password. Which product is doing it is a migration
    /// question and SEC-094's, not a statement that the password has gone static.
    /// </remarks>
    [Fact]
    public void AStaleModernTimestampBesideAFreshLegacyOneIsNotReported() =>
        Assert.Empty(Judge(Machine() with
        {
            WindowsLapsExpiration = Stale,
            LegacyLapsExpiration = Fresh,
        }));

    /// <summary>
    /// A machine where both timestamps have lapsed is reported once, and the age is measured from
    /// the newer.
    /// </summary>
    /// <remarks>
    /// <b>This test asserted the opposite until <c>ad.lab</c> corrected it on 2026-09-03.</b>
    /// <c>PHWK1</c> carried a modern timestamp 234 days past and a legacy one 503 days past, and the
    /// rule reported 503 - telling the operator the password had not rotated in over a year when it
    /// had been rotating until January. The legacy value is residue that stopped moving when the
    /// machine migrated, so only the newer expiration says when anything was last due to rotate.
    /// The first version of this test encoded the same wrong belief as the rule, which is exactly
    /// why a mutation swapping the two appeared to be caught.
    /// </remarks>
    [Fact]
    public void AMachineWhereBothTimestampsLapsedIsMeasuredFromTheNewer()
    {
        var finding = Assert.Single(Judge(Machine() with
        {
            WindowsLapsExpiration = At(TimeSpan.FromDays(-30)),
            LegacyLapsExpiration = At(TimeSpan.FromDays(-400)),
        }));

        Assert.Contains("30 days overdue", finding.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("400 days overdue", finding.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// A machine carrying no timestamp at all is not reported.
    /// </summary>
    /// <remarks>That is SEC-091's population, and reporting it here would double-count it.</remarks>
    [Fact]
    public void AMachineCarryingNoTimestampIsNotReported() =>
        Assert.Empty(Judge(Machine()));

    /// <summary>
    /// A zero FILETIME is not reported.
    /// </summary>
    /// <remarks>
    /// <b>Zero is the epoch in 1601, which is a value written empty rather than a password four
    /// centuries overdue.</b> A rule that decoded it as a date would report it as the stalest
    /// machine in the forest, and an operator would rightly stop believing the rule.
    /// </remarks>
    [Fact]
    public void AZeroTimestampIsNotReported() =>
        Assert.Empty(Judge(Machine() with { WindowsLapsExpiration = "0" }));

    /// <summary>A negative FILETIME is not reported, for the same reason.</summary>
    [Fact]
    public void ANegativeTimestampIsNotReported() =>
        Assert.Empty(Judge(Machine() with { WindowsLapsExpiration = "-1" }));

    /// <summary>
    /// A value that is not a number at all is not reported.
    /// </summary>
    /// <remarks>
    /// It came from the directory, so it is treated as unreadable rather than as a stale date. A
    /// finding produced by this product's own decoder failing would be a false one.
    /// </remarks>
    [Fact]
    public void AnUnreadableTimestampIsNotReported() =>
        Assert.Empty(Judge(Machine() with { WindowsLapsExpiration = "not-a-filetime" }));

    /// <summary>
    /// A disabled computer account with a long-lapsed timestamp is not reported.
    /// </summary>
    /// <remarks>
    /// The owner's decision of 2026-09-03. A disabled account has no running machine behind it, so
    /// nothing is failing to rotate. <c>ad.lab</c> holds two of these and they are exactly the
    /// pattern this rule looks for.
    /// </remarks>
    [Fact]
    public void ADisabledComputerAccountIsNotReported() =>
        Assert.Empty(Judge(Machine() with
        {
            UserAccountControl = 4098,
            WindowsLapsExpiration = Stale,
        }));

    /// <summary>
    /// An enabled machine with the same attributes is still reported, so the exclusion is not a
    /// blanket one.
    /// </summary>
    [Fact]
    public void AnEnabledMachineWithTheSameAttributesIsStillReported() =>
        Assert.Single(Judge(Machine() with
        {
            UserAccountControl = 0x1000,
            WindowsLapsExpiration = Stale,
        }));

    /// <summary>
    /// A domain controller with a long-lapsed timestamp is not reported.
    /// </summary>
    /// <remarks>
    /// <b>Excluded through <c>DomainControllerSignals</c> and never by distinguished name.</b> The
    /// predecessor card for this rule excluded controllers by matching the DN against
    /// <c>OU=Domain Controllers</c>, having just replaced a <c>sAMAccountName</c> subquery that
    /// leaked when the name was null. This subject sits in that container and must be excluded on
    /// its own attributes rather than its position.
    /// </remarks>
    [Fact]
    public void ADomainControllerIsNotReported() =>
        Assert.Empty(Judge(Machine() with
        {
            Dn = "CN=DC01,OU=Domain Controllers,DC=ad,DC=lab",
            UserAccountControl = 0x82000,
            WindowsLapsExpiration = Stale,
        }));

    /// <summary>
    /// A group managed service account with a lapsed timestamp is not reported.
    /// </summary>
    /// <remarks>
    /// <b>Its <c>objectClass</c> chain runs through <c>computer</c> and continues past it.</b> Three
    /// in <c>ad.lab</c> do. A rule asking whether "computer" appears anywhere in the chain reports
    /// all three; reading the most derived class is what keeps them out.
    /// </remarks>
    [Fact]
    public void AGroupManagedServiceAccountIsNotReported() =>
        Assert.Empty(Judge(Machine() with
        {
            ObjectClasses =
                ["top", "person", "organizationalPerson", "user", "computer", "msDS-GroupManagedServiceAccount"],
            WindowsLapsExpiration = Stale,
        }));

    /// <summary>
    /// Judging the same sealed bundle twice with the same reference time gives the same answer.
    /// </summary>
    /// <remarks>
    /// <b>The whole reason the reference time is recorded rather than read from the clock.</b> The
    /// two judgings below pass different start times, so anything reading the wrong one drifts. This
    /// is the property that lets a customer re-open a sealed run next year and see what it said.
    /// </remarks>
    [Fact]
    public void JudgingTheSameEvidenceTwiceGivesTheSameAnswer()
    {
        var subject = Machine() with { WindowsLapsExpiration = At(TimeSpan.FromDays(-3)) };

        var first = Judge(subject);
        var second = Judge(subject, startedUtc: Started.AddYears(2));

        Assert.Equal(
            Assert.Single(first).Detail,
            Assert.Single(second).Detail);
    }

    /// <summary>One object's shape, so each test states only what it changes.</summary>
    private sealed record Subject
    {
        public string Dn { get; init; } = "CN=FS01,OU=Servers,DC=ad,DC=lab";

        public IReadOnlyList<string> ObjectClasses { get; init; } =
            ["top", "person", "organizationalPerson", "user", "computer"];

        public string? OperatingSystem { get; init; } = ModernServer;
        public string? OperatingSystemVersion { get; init; } = ModernServerBuild;
        public string? WindowsLapsExpiration { get; init; }
        public string? LegacyLapsExpiration { get; init; }

        /// <summary>An ordinary member server: WORKSTATION_TRUST_ACCOUNT.</summary>
        public uint UserAccountControl { get; init; } = 0x1000;
    }

    private static Subject Machine() => new();

    private static IReadOnlyList<Finding> Judge(Subject subject) => Judge(subject, Started);

    private static IReadOnlyList<Finding> Judge(Subject subject, DateTimeOffset startedUtc)
    {
        var directory = LapsBundle.Build(
            subject.Dn,
            subject.ObjectClasses,
            subject.OperatingSystem,
            subject.OperatingSystemVersion,
            subject.WindowsLapsExpiration,
            subject.LegacyLapsExpiration,
            subject.UserAccountControl,
            confidential: false,
            windowsLapsInSchema: true,
            startedUtc);

        Assert.True(
            Stage2aRun.Derive(
                directory, ExpansionBudget.Bulk, startedUtc, Stage2aRun.Unwatched,
                RunLog.Discarded, CancellationToken.None).IsSuccess);

        var judged = JudgingRun.Judge(
            directory,
            [new LapsRotationStale()],
            startedUtc,
            AsOf,
            JudgingRun.NobodyIsWatching,
            RunLog.Discarded,
            CancellationToken.None);

        Assert.True(judged.IsSuccess, judged.Error?.Description);

        using var reader = JudgementReader.Open(directory).Value!;
        return reader.Read().Findings;
    }
}
