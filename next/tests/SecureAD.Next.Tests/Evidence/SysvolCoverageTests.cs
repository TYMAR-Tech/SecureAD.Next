using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// The record that says how much of the Group Policy on SYSVOL a run managed to read.
///
/// <para>
/// <b>The point of these tests is that the record can say more than one thing.</b> Three sessions
/// running have shipped a value that could only ever give one answer -
/// <c>AllDeclaredUnitsAreComplete</c>, which is true in every bundle a reader can open, is the
/// example this type is deliberately kept away from. Per <c>docs/decisions/0044</c> SYSVOL is the
/// one place in the product where partial coverage is genuinely expected, so it is the one place
/// the record is meant to vary - and a test suite that only ever exercised the happy path would
/// leave that unproven.
/// </para>
/// </summary>
public sealed class SysvolCoverageTests
{
    private static readonly Guid FirstPolicy = new("11111111-1111-1111-1111-111111111111");
    private static readonly Guid SecondPolicy = new("22222222-2222-2222-2222-222222222222");
    private const string FirstPath = @"\\contoso.com\SysVol\contoso.com\Policies\{11111111-1111-1111-1111-111111111111}";
    private const string SecondPath = @"\\contoso.com\SysVol\contoso.com\Policies\{22222222-2222-2222-2222-222222222222}";

    [Theory]
    [InlineData(nameof(GpoCoverage.Read))]
    [InlineData(nameof(GpoCoverage.PartiallyRead))]
    [InlineData(nameof(GpoCoverage.Unreadable))]
    [InlineData(nameof(GpoCoverage.Unlocatable))]
    public void OrdinaryPolicyCoverageKeepsTheOptionalPasswordScanUnrequested(string factory)
    {
        var policy = factory switch
        {
            nameof(GpoCoverage.Read) => GpoCoverage.Read(FirstPolicy, "Policy", FirstPath),
            nameof(GpoCoverage.PartiallyRead) => GpoCoverage.PartiallyRead(FirstPolicy, "Policy", FirstPath, "Access denied."),
            nameof(GpoCoverage.Unreadable) => GpoCoverage.Unreadable(FirstPolicy, "Policy", FirstPath, "Access denied."),
            nameof(GpoCoverage.Unlocatable) => GpoCoverage.Unlocatable(FirstPolicy, "Policy", "Path was not captured."),
            _ => throw new ArgumentOutOfRangeException(nameof(factory)),
        };

        Assert.Equal(GppPasswordScanOutcome.NotRequested, policy.GppPasswordScanOutcome);
        Assert.Null(policy.GppPasswordScanReason);
    }

    [Fact]
    public void ARunThatReadEveryPolicyReportsItReadThemAll()
    {
        var coverage = SysvolCoverage.Of(
        [
            GpoCoverage.Read(FirstPolicy, "Default Domain Policy", FirstPath),
            GpoCoverage.Read(SecondPolicy, "Workstation Lockdown", SecondPath),
        ]);

        Assert.Equal(SysvolReadOutcome.Read, coverage.Outcome);
        Assert.True(coverage.AllDeclaredPoliciesAreComplete);
        Assert.Empty(coverage.UnreadablePolicies);
    }

    /// <summary>
    /// The state the whole session exists for: some policies read, some refused, and a bundle
    /// sealed anyway.
    /// </summary>
    [Fact]
    public void APolicyThatCouldNotBeReadMakesTheReadPartial()
    {
        var coverage = SysvolCoverage.Of(
        [
            GpoCoverage.Read(FirstPolicy, "Default Domain Policy", FirstPath),
            GpoCoverage.Unreadable(SecondPolicy, "Workstation Lockdown", SecondPath, "Access denied."),
        ]);

        Assert.Equal(SysvolReadOutcome.PartiallyRead, coverage.Outcome);
        Assert.False(coverage.AllDeclaredPoliciesAreComplete);
    }

    /// <summary>
    /// A policy read in part is not a policy read. The middle outcome exists because a policy is a
    /// folder tree: its settings can be readable while the permissions on its scripts folder are
    /// not, and reporting that as <c>Read</c> would tell a customer his policy was examined when a
    /// third of it was not.
    /// </summary>
    [Fact]
    public void APolicyReadOnlyInPartAlsoMakesTheReadPartial()
    {
        var coverage = SysvolCoverage.Of(
        [
            GpoCoverage.PartiallyRead(
                FirstPolicy, "Default Domain Policy", FirstPath, "The scripts folder was refused."),
        ]);

        Assert.Equal(SysvolReadOutcome.PartiallyRead, coverage.Outcome);
        Assert.False(coverage.AllDeclaredPoliciesAreComplete);
    }

    /// <summary>
    /// Everything refused usually means the share itself was, rather than one folder, and an
    /// operator's remedy is different. It is kept apart from <c>PartiallyRead</c> for that reason.
    /// </summary>
    [Fact]
    public void AForestWhosePoliciesWereAllRefusedReportsNothingWasRead()
    {
        var coverage = SysvolCoverage.Of(
        [
            GpoCoverage.Unreadable(FirstPolicy, "Default Domain Policy", FirstPath, "Access denied."),
            GpoCoverage.Unreadable(SecondPolicy, "Workstation Lockdown", SecondPath, "Access denied."),
        ]);

        Assert.Equal(SysvolReadOutcome.NotRead, coverage.Outcome);
    }

    /// <summary>
    /// Every outcome must be reachable, or the vocabulary describes states nothing produces. This
    /// is the check that three previous sessions each failed in a different place.
    /// </summary>
    [Fact]
    public void EveryOutcomeIsProducible()
    {
        var produced = new[]
        {
            SysvolCoverage.Of([GpoCoverage.Read(FirstPolicy, "a", FirstPath)]).Outcome,
            SysvolCoverage.Of(
            [
                GpoCoverage.Read(FirstPolicy, "a", FirstPath),
                GpoCoverage.Unreadable(SecondPolicy, "b", SecondPath, "why"),
            ]).Outcome,
            SysvolCoverage.Of([GpoCoverage.Unreadable(FirstPolicy, "a", FirstPath, "why")]).Outcome,
        };

        Assert.Equal(
            [SysvolReadOutcome.Read, SysvolReadOutcome.PartiallyRead, SysvolReadOutcome.NotRead],
            produced);
        Assert.Equal(3, Enum.GetValues<SysvolReadOutcome>().Length);
    }

    /// <summary>
    /// The condition <c>0044</c> widened <c>0035</c> on: the record must name what was missed, not
    /// merely report that something was. A bare <i>partial</i> fails the test the widening was
    /// granted under.
    /// </summary>
    [Fact]
    public void TheRecordNamesThePoliciesThatWereMissed()
    {
        var coverage = SysvolCoverage.Of(
        [
            GpoCoverage.Read(FirstPolicy, "Default Domain Policy", FirstPath),
            GpoCoverage.Unreadable(
                SecondPolicy, "Workstation Lockdown", SecondPath, "Access denied."),
        ]);

        var missed = Assert.Single(coverage.UnreadablePolicies);

        Assert.Equal(SecondPolicy, missed.GpoGuid);
        Assert.Equal("Workstation Lockdown", missed.DisplayName);
        Assert.Equal("Access denied.", missed.Reason);
    }

    /// <summary>
    /// The figure a report puts in front of a reader: <i>one of two policies was examined</i>.
    /// </summary>
    [Fact]
    public void TheCountsAreTheDenominatorAndTheNumerator()
    {
        var coverage = SysvolCoverage.Of(
        [
            GpoCoverage.Read(FirstPolicy, "Default Domain Policy", FirstPath),
            GpoCoverage.Unreadable(SecondPolicy, "Workstation Lockdown", SecondPath, "Access denied."),
        ]);

        Assert.Equal(2, coverage.PoliciesDeclared);
        Assert.Equal(1, coverage.PoliciesRead);
    }

    /// <summary>
    /// A forest with no Group Policy has missed nothing. Calling that a failure would make every
    /// empty forest look broken, and would train a reader to ignore the state that matters.
    /// </summary>
    [Fact]
    public void AForestWithNoPoliciesHasMissedNothing()
    {
        var coverage = SysvolCoverage.Of([]);

        Assert.Equal(SysvolReadOutcome.Read, coverage.Outcome);
        Assert.Equal(0, coverage.PoliciesDeclared);
    }

    /// <summary>
    /// Two outcomes for one policy means the capture disagrees with itself, and picking one would
    /// be inventing an answer.
    /// </summary>
    [Fact]
    public void ReportingOnePolicyTwiceIsRefused()
    {
        Assert.Throws<ArgumentException>(() => SysvolCoverage.Of(
        [
            GpoCoverage.Read(FirstPolicy, "Default Domain Policy", FirstPath),
            GpoCoverage.Unreadable(FirstPolicy, "Default Domain Policy", FirstPath, "Access denied."),
        ]));
    }

    /// <summary>
    /// A policy that was read has nothing to explain; one that was not must say why, because that
    /// sentence is the only account of the failure an operator will ever get.
    /// </summary>
    [Fact]
    public void OnlyAPolicyThatWasReadCarriesNoReason()
    {
        Assert.Null(GpoCoverage.Read(FirstPolicy, "a", FirstPath).Reason);

        Assert.Throws<ArgumentException>(
            () => GpoCoverage.Unreadable(FirstPolicy, "a", FirstPath, "   "));
        Assert.Throws<ArgumentException>(
            () => GpoCoverage.PartiallyRead(FirstPolicy, "a", FirstPath, ""));
    }

    /// <summary>
    /// A policy the directory declared without saying where its files are stays in the denominator.
    /// Dropping it would shrink the count of what should have been read to the set of things that
    /// went well.
    /// </summary>
    [Fact]
    public void APolicyWithNoDeclaredPathIsStillCounted()
    {
        var coverage = SysvolCoverage.Of(
        [
            GpoCoverage.Unlocatable(FirstPolicy, "Default Domain Policy", "No gPCFileSysPath."),
        ]);

        Assert.Equal(1, coverage.PoliciesDeclared);
        Assert.Equal(0, coverage.PoliciesRead);
        Assert.Null(Assert.Single(coverage.Policies).FileSysPath);
    }
}
