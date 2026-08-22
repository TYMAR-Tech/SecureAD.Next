using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Evidence.Findings;

/// <summary>
/// What happens to a finding between one run and the next.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the question the evaluation core could not answer.</b> A rule reaching a verdict is
/// worth nothing to a customer who accepted a finding last month unless the same finding is
/// recognisable this month. <c>docs/decisions/0023</c> fixes identity as the rule, the subject and
/// the object by <c>objectGUID</c>, with the rule's version recorded beside it and deliberately
/// outside it, and these tests hold the storage to that.
/// </para>
/// <para>
/// <b>Identity is asserted field by field rather than through a type that expresses it.</b> There
/// is one statement of identity in the product - the <c>UNIQUE</c> constraint on <c>finding</c> -
/// and adding a second in C# that only these tests call would be a component built, tested and
/// never reached by anything a customer runs. When comparison is built it will need to say
/// "the same finding" out loud, and that is the point at which the type earns its place.
/// </para>
/// </remarks>
public sealed class FindingStorageTests : IDisposable
{
    private readonly List<string> _directories = [];

    private static readonly DateTimeOffset Started = new(2026, 8, 21, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 8, 21, 11, 30, 0, TimeSpan.Zero);

    private static readonly Guid TheObject =
        Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

    // ---------------------------------------------------------------------------------------
    // It survives the round trip at all
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void AFindingComesBackFromASealedBundle()
    {
        var directory = WriteBundleWith(SomeFinding());

        var findings = ReadFindings(directory);

        var stored = Assert.Single(findings);
        Assert.Equal("SEC-010", stored.RuleId);
        Assert.Equal(TheObject, stored.ObjectGuid);
        Assert.Equal(Severity.High, stored.Severity);
    }

    [Fact]
    public void TheEvidenceAFindingRestsOnComesBackWithIt()
    {
        var directory = WriteBundleWith(SomeFinding());

        var stored = Assert.Single(ReadFindings(directory));

        var evidence = Assert.IsType<UnconstrainedDelegationEvidence>(stored.Evidence);
        Assert.Equal(0x80000u, evidence.UserAccountControl);
        Assert.False(evidence.IsComputer);
    }

    /// <summary>
    /// The two answers on <see cref="DomainControllerSignals"/> are computed, not stored, so they
    /// cannot drift out of agreement with the three signals they come from.
    /// </summary>
    [Fact]
    public void TheDomainControllerSignalsAreRebuiltFromWhatWasStored()
    {
        var directory = WriteBundleWith(
            SomeFinding(signals: new DomainControllerSignals(true, false, false)));

        var stored = Assert.Single(ReadFindings(directory));
        var evidence = Assert.IsType<UnconstrainedDelegationEvidence>(stored.Evidence);

        Assert.True(evidence.DomainController.ServerTrustAccountBit);
        Assert.True(evidence.DomainController.IsDomainController);
        Assert.True(evidence.DomainController.SignalsDisagree);
    }

    // ---------------------------------------------------------------------------------------
    // Identity across runs - what 0023 exists for
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The gap this session was opened to close. Two separate runs, two separate bundles, and the
    /// same finding recognisable in both.
    /// </summary>
    [Fact]
    public void TheSameFindingFromTwoRunsKeepsOneIdentity()
    {
        var first = Assert.Single(ReadFindings(WriteBundleWith(SomeFinding())));
        var second = Assert.Single(ReadFindings(WriteBundleWith(SomeFinding())));

        Assert.Equal(first.RuleId, second.RuleId);
        Assert.Equal(first.Subject, second.Subject);
        Assert.Equal(first.ObjectGuid, second.ObjectGuid);
    }

    /// <summary>
    /// The reason the object is identified by <c>objectGUID</c> and not by its name or its place:
    /// both change, and an acceptance made against the finding must not evaporate when they do.
    /// </summary>
    [Fact]
    public void AnObjectThatWasRenamedAndMovedIsStillTheSameFinding()
    {
        var before = Assert.Single(ReadFindings(WriteBundleWith(
            SomeFinding(distinguishedName: "CN=Alice,OU=Staff,DC=contoso,DC=com"))));

        var after = Assert.Single(ReadFindings(WriteBundleWith(
            SomeFinding(distinguishedName: "CN=Alice Smith,OU=Leavers,DC=contoso,DC=com"))));

        Assert.NotEqual(before.DistinguishedName, after.DistinguishedName);

        Assert.Equal(before.RuleId, after.RuleId);
        Assert.Equal(before.Subject, after.Subject);
        Assert.Equal(before.ObjectGuid, after.ObjectGuid);
    }

    /// <summary>
    /// Tightening a rule must not orphan every acceptance ever made against it, so the version is
    /// recorded beside the identity and takes no part in it.
    /// </summary>
    [Fact]
    public void TighteningARuleDoesNotChangeTheIdentityOfItsFindings()
    {
        var before = Assert.Single(ReadFindings(WriteBundleWith(SomeFinding(ruleVersion: 1))));
        var after = Assert.Single(ReadFindings(WriteBundleWith(SomeFinding(ruleVersion: 2))));

        Assert.NotEqual(before.RuleVersion, after.RuleVersion);

        Assert.Equal(before.RuleId, after.RuleId);
        Assert.Equal(before.Subject, after.Subject);
        Assert.Equal(before.ObjectGuid, after.ObjectGuid);
    }

    /// <summary>
    /// The negative control. Without this, a comparison that treated everything as one finding
    /// would pass every test above.
    /// </summary>
    [Fact]
    public void TwoRulesAboutOneObjectAreTwoFindings()
    {
        var directory = WriteBundleWith(
            SomeFinding(ruleId: "SEC-010"),
            SomeFinding(ruleId: "SEC-011"));

        var findings = ReadFindings(directory);

        Assert.Equal(2, findings.Count);
        Assert.NotEqual(findings[0].RuleId, findings[1].RuleId);
        Assert.Equal(findings[0].ObjectGuid, findings[1].ObjectGuid);
    }

    /// <summary>
    /// And the other half of the negative control: one rule against two objects is two findings,
    /// so identity is not collapsing on the rule alone.
    /// </summary>
    [Fact]
    public void OneRuleAgainstTwoObjectsIsTwoFindings()
    {
        var other = Guid.Parse("11111111-2222-3333-4444-555555555555");

        var directory = WriteBundleWith(
            SomeFinding(),
            SomeFinding(objectGuid: other, subjectKey: "bob"));

        var findings = ReadFindings(directory);

        Assert.Equal(2, findings.Count);
        Assert.NotEqual(findings[0].ObjectGuid, findings[1].ObjectGuid);
    }

    /// <summary>
    /// Identity is enforced by the schema rather than by whichever code is writing, so a second
    /// write of the same finding fails rather than producing a duplicate a screen would show twice.
    /// </summary>
    [Fact]
    public void TheSameFindingCannotBeStoredTwiceInOneBundle()
    {
        var directory = NewDirectory();

        using var writer = BundleWriter.Create(directory, Started);
        writer.WriteFinding(SomeFinding());

        Assert.Throws<SqliteException>(() => writer.WriteFinding(SomeFinding()));
    }

    // ---------------------------------------------------------------------------------------
    // Coverage - the distinction that must survive to disk
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A finding read over an unencrypted connection may rest on values a controller stripped
    /// without saying so. That must still be visible after the round trip, because a finding that
    /// forgets it is a finding claiming more than it knows.
    /// </summary>
    [Fact]
    public void AFindingWhoseEvidenceMayBeIncompleteDoesNotComeBackComplete()
    {
        var directory = WriteBundleWith(
            SomeFinding(coverage: EvidenceCompleteness.MayBeMissingConfidentialValues));

        var stored = Assert.Single(ReadFindings(directory));

        Assert.Equal(EvidenceCompleteness.MayBeMissingConfidentialValues, stored.Coverage);
        Assert.NotEqual(EvidenceCompleteness.Complete, stored.Coverage);
    }

    /// <summary>
    /// The same assertion in the other direction, so the test above cannot pass by a reader that
    /// returns <c>MayBeMissingConfidentialValues</c> for everything.
    /// </summary>
    [Fact]
    public void AFindingWhoseEvidenceWasCompleteComesBackComplete()
    {
        var directory = WriteBundleWith(SomeFinding(coverage: EvidenceCompleteness.Complete));

        var stored = Assert.Single(ReadFindings(directory));

        Assert.Equal(EvidenceCompleteness.Complete, stored.Coverage);
    }

    // ---------------------------------------------------------------------------------------
    // What the writer refuses
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// An evidence kind with no table is refused at the write, naming the type. The predecessor's
    /// schemaless blob accepted anything and lost whatever nothing knew how to read.
    /// </summary>
    [Fact]
    public void AnEvidenceKindWithNoTableIsRefusedRatherThanDropped()
    {
        var directory = NewDirectory();

        using var writer = BundleWriter.Create(directory, Started);

        var error = Assert.Throws<ArgumentException>(
            () => writer.WriteFinding(SomeFinding() with { Evidence = new UnstorableEvidence() }));

        Assert.Contains(nameof(UnstorableEvidence), error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A finding cannot be added to a sealed bundle. There is no reason to want to:
    /// <c>docs/decisions/0021</c> makes a capture judged again produce a new bundle.
    /// </summary>
    [Fact]
    public void AFindingCannotBeAddedAfterTheBundleIsSealed()
    {
        var directory = NewDirectory();

        using var writer = BundleWriter.Create(directory, Started);
        writer.Complete(OneDomainRead(), Finished);

        Assert.Throws<InvalidOperationException>(() => writer.WriteFinding(SomeFinding()));
    }

    // ---------------------------------------------------------------------------------------
    // Nothing found, and nobody looked - which must never read the same
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A bundle captured and never judged. It has no findings, and that says nothing whatever
    /// about the forest.
    /// </summary>
    [Fact]
    public void ABundleNoRuleWasRunOverSaysSoRatherThanLookingClean()
    {
        var directory = NewDirectory();

        using (var writer = BundleWriter.Create(directory, Started))
        {
            writer.Complete(OneDomainRead(), Finished);
        }

        var stored = ReadStored(directory);

        Assert.Empty(stored.Findings);
        Assert.True(stored.DidNotRun);
    }

    /// <summary>
    /// And the case it must not be confused with: rules ran, and nothing matched. Same empty list,
    /// opposite meaning. Without both of these the storage could report a clean forest for a
    /// bundle nobody had judged.
    /// </summary>
    [Fact]
    public void ABundleWhereRulesRanAndNothingMatchedIsNotTheSameThing()
    {
        var stored = ReadStored(WriteBundleWith());

        Assert.Empty(stored.Findings);
        Assert.False(stored.DidNotRun);
    }

    [Fact]
    public void TheRulesThatRanAreRecordedWithTheVersionThatRan()
    {
        var directory = NewDirectory();

        using (var writer = BundleWriter.Create(directory, Started))
        {
            writer.WriteEvaluatedRule("SEC-010", 3);
            writer.Complete(OneDomainRead(), Finished);
        }

        var rule = Assert.Single(ReadStored(directory).RulesRun);

        Assert.Equal("SEC-010", rule.RuleId);
        Assert.Equal(3, rule.RuleVersion);
    }

    // ---------------------------------------------------------------------------------------

    private sealed record UnstorableEvidence : FindingEvidence;

    private static Finding SomeFinding(
        string ruleId = "SEC-010",
        int ruleVersion = 1,
        Guid? objectGuid = null,
        string subjectKey = "alice",
        string distinguishedName = "CN=Alice,DC=contoso,DC=com",
        EvidenceCompleteness coverage = EvidenceCompleteness.Complete,
        DomainControllerSignals? signals = null) =>
        new(
            ruleId,
            ruleVersion,
            Severity.High,
            new FindingSubject(FindingSubjectKind.Account, subjectKey),
            objectGuid ?? TheObject,
            distinguishedName,
            "The account is trusted for unconstrained delegation.",
            coverage,
            new UnconstrainedDelegationEvidence(
                0x80000u,
                false,
                signals ?? new DomainControllerSignals(false, false, false)));

    private string WriteBundleWith(params Finding[] findings)
    {
        var directory = NewDirectory();

        using (var writer = BundleWriter.Create(directory, Started))
        {
            writer.WriteEvaluatedRule("SEC-010", 1);
            writer.WriteEvaluatedRule("SEC-011", 1);

            foreach (var finding in findings)
                writer.WriteFinding(finding);

            writer.Complete(OneDomainRead(), Finished);
        }

        return directory;
    }

    private static IReadOnlyList<Finding> ReadFindings(string directory) =>
        ReadStored(directory).Findings;

    private static StoredFindings ReadStored(string directory)
    {
        var opened = BundleReader.Open(directory);
        Assert.True(opened.IsSuccess, "Expected the bundle to open.");

        using var reader = opened.Value;
        return reader.ReadFindings();
    }

    private string NewDirectory()
    {
        var directory = Path.Combine(
            Path.GetTempPath(), "securead-findings-" + Guid.NewGuid().ToString("N"));

        _directories.Add(directory);
        return directory;
    }

    private static RunCoverage OneDomainRead() =>
        RunCoverage.Of(
            CoverageId.ForDomains("contoso.com", ["contoso.com"]),
            [DomainCoverage.Read("contoso.com")],
            [
                ForestPartitionCoverage.Read(
                    "CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
                ForestPartitionCoverage.Read(
                    "CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema),
            ],
            SysvolCoverage.Of([]));

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();

        foreach (var directory in _directories.Where(Directory.Exists))
            Directory.Delete(directory, recursive: true);
    }
}
