using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// What makes a finding the same finding, and what makes it a different one.
/// </summary>
/// <remarks>
/// <para>
/// <b>These are the claims stage 1 deleted and stage 3 owes back.</b> They were proven against the
/// evidence schema until the finding tables were moved out of the sealed bundle, and the roadmap
/// carried them as a debt in the meantime. What is asserted here is the same behaviour against the
/// judgement store.
/// </para>
/// <para>
/// Identity matters because an acceptance is written against a finding and has to still be attached
/// to it months later, after the object has been renamed and the rule tightened.
/// </para>
/// </remarks>
public sealed class JudgementIdentityTests
{
    private const string ThisCapture = "0f9c1d2e3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5";

    private static readonly Guid TheObject = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private static readonly Guid AnotherObject = Guid.Parse("99999999-8888-7777-6666-555555555555");
    private static readonly DateTimeOffset Started = new(2026, 8, 25, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 8, 25, 9, 5, 0, TimeSpan.Zero);

    /// <summary>
    /// The same finding from two separate judgings keeps one identity.
    /// </summary>
    /// <remarks>
    /// Identity is the rule, the subject and the object - never a row number, which would be
    /// meaningless in the next store.
    /// </remarks>
    [Fact]
    public void TheSameFindingFromTwoRunsKeepsOneIdentity()
    {
        var first = Judged(SomeFinding());
        var second = Judged(SomeFinding());

        Assert.Equal(IdentityIn(first), IdentityIn(second));
    }

    /// <summary>
    /// A finding stays the same finding after its object was renamed and moved.
    /// </summary>
    /// <remarks>
    /// <c>objectGUID</c> is immutable in Active Directory and survives both, which is why identity
    /// rests on it rather than on the distinguished name a reader is shown.
    /// </remarks>
    [Fact]
    public void AnObjectThatWasRenamedAndMovedIsStillTheSameFinding()
    {
        var before = Judged(SomeFinding());

        var moved = SomeFinding() with
        {
            DistinguishedName = "CN=svc-web-retired,OU=Decommissioned,DC=contoso,DC=com",
        };

        var after = Judged(moved);

        Assert.Equal(IdentityIn(before), IdentityIn(after));
    }

    /// <summary>
    /// Tightening a rule does not change the identity of the findings made under it.
    /// </summary>
    /// <remarks>
    /// The version is recorded beside the finding and is deliberately outside its identity, because
    /// every acceptance ever made against a rule would otherwise be orphaned by improving it.
    /// </remarks>
    [Fact]
    public void TighteningARuleDoesNotChangeTheIdentityOfItsFindings()
    {
        var before = Judged(SomeFinding(), Sec010);
        var after = Judged(SomeFinding(), Sec010 with { Version = 2 });

        Assert.Equal(IdentityIn(before), IdentityIn(after));
        Assert.Equal(2, Single(after).RuleVersion);
    }

    /// <summary>
    /// Two rules about one object are two findings.
    /// </summary>
    [Fact]
    public void TwoRulesAboutOneObjectAreTwoFindings()
    {
        var directory = NewBundle();

        using (var writer = NewWriter(directory))
        {
            writer.Write(RuleExecution.Judged(Sec010, 1, [SomeFinding()]));
            writer.Write(RuleExecution.Judged(Sec011, 1, [SomeFinding("SEC-011")]));
            writer.Complete(Finished);
        }

        Assert.Equal(2, Read(directory).Findings.Count);
    }

    /// <summary>
    /// One rule against two objects is two findings.
    /// </summary>
    [Fact]
    public void OneRuleAgainstTwoObjectsIsTwoFindings()
    {
        var other = SomeFinding() with
        {
            ObjectGuid = AnotherObject,
            Subject = new FindingSubject(FindingSubjectKind.Account, "svc-batch"),
        };

        var directory = NewBundle();

        using (var writer = NewWriter(directory))
        {
            writer.Write(RuleExecution.Judged(Sec010, 2, [SomeFinding(), other]));
            writer.Complete(Finished);
        }

        Assert.Equal(2, Read(directory).Findings.Count);
    }

    /// <summary>
    /// One finding cannot be stored twice, and so cannot be shown twice.
    /// </summary>
    /// <remarks>
    /// The identity is a constraint in the schema rather than a rule in whichever code happens to
    /// be writing, so a duplicate is refused by the store itself.
    /// </remarks>
    [Fact]
    public void TheSameFindingCannotBeStoredTwiceInOneJudgement()
    {
        var directory = NewBundle();
        using var writer = NewWriter(directory);

        Assert.Throws<SqliteException>(
            () => writer.Write(RuleExecution.Judged(Sec010, 1, [SomeFinding(), SomeFinding()])));
    }

    /// <summary>
    /// Evidence that may be missing confidential values does not come back complete.
    /// </summary>
    /// <remarks>
    /// An unencrypted search against a current controller has confidential attributes removed with
    /// no error returned, so a finding made on that evidence must not claim more than it saw.
    /// </remarks>
    [Fact]
    public void AFindingWhoseEvidenceMayBeIncompleteDoesNotComeBackComplete()
    {
        var partial = SomeFinding() with
        {
            Coverage = EvidenceCompleteness.MayBeMissingConfidentialValues,
        };

        Assert.Equal(
            EvidenceCompleteness.MayBeMissingConfidentialValues,
            Single(Judged(partial)).Coverage);
    }

    /// <summary>
    /// And evidence that was complete comes back complete, so the check above is not passing by
    /// saying the same thing of everything.
    /// </summary>
    [Fact]
    public void AFindingWhoseEvidenceWasCompleteComesBackComplete()
    {
        Assert.Equal(EvidenceCompleteness.Complete, Single(Judged(SomeFinding())).Coverage);
    }

    /// <summary>
    /// An evidence kind the schema has no table for is refused rather than quietly dropped.
    /// </summary>
    /// <remarks>
    /// The predecessor carried a schemaless context blob that accepted anything and lost the parts
    /// nothing knew how to read. A type per kind means the gap arrives here, at the write, naming
    /// the type.
    /// </remarks>
    [Fact]
    public void AnEvidenceKindWithNoTableIsRefusedRatherThanDropped()
    {
        var directory = NewBundle();
        using var writer = NewWriter(directory);

        var unstorable = SomeFinding() with { Evidence = new UnstorableEvidence() };

        Assert.Throws<ArgumentException>(
            () => writer.Write(RuleExecution.Judged(Sec010, 1, [unstorable])));
    }

    /// <summary>
    /// A kind of evidence no table exists for. Declared here rather than in the product, because
    /// the product having one would be the defect this test exists to catch.
    /// </summary>
    private sealed record UnstorableEvidence : FindingEvidence;

    private static readonly RuleDefinition Sec010 = new(
        "SEC-010", "Unconstrained delegation on an account", Severity.High, 1,
        ["userAccountControl", "objectClass", "primaryGroupID"]);

    private static readonly RuleDefinition Sec011 = new(
        "SEC-011", "Unconstrained delegation on a member computer", Severity.High, 1,
        ["userAccountControl", "objectClass", "primaryGroupID"]);

    private static Finding SomeFinding(string ruleId = "SEC-010") =>
        new(
            ruleId,
            1,
            Severity.High,
            new FindingSubject(FindingSubjectKind.Account, "svc-web"),
            TheObject,
            "CN=svc-web,OU=Service Accounts,DC=contoso,DC=com",
            "svc-web is trusted for unconstrained delegation.",
            EvidenceCompleteness.Complete,
            new UnconstrainedDelegationEvidence(
                0x80000, false, new DomainControllerSignals(false, false, false)));

    /// <summary>
    /// The identity of the single finding in a judgement: its rule, its subject and its object.
    /// </summary>
    private static (string Rule, FindingSubjectKind Kind, string Key, Guid Object) IdentityIn(
        StoredJudgement judgement)
    {
        var finding = Assert.Single(judgement.Findings);
        return (finding.RuleId, finding.Subject.Kind, finding.Subject.Key, finding.ObjectGuid);
    }

    private static Finding Single(StoredJudgement judgement) => Assert.Single(judgement.Findings);

    private static StoredJudgement Judged(Finding finding, RuleDefinition? rule = null)
    {
        var directory = NewBundle();

        using (var writer = NewWriter(directory))
        {
            writer.Write(RuleExecution.Judged(rule ?? Sec010, 1, [finding]));
            writer.Complete(Finished);
        }

        return Read(directory);
    }

    private static StoredJudgement Read(string directory)
    {
        var opened = JudgementReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);

        using var reader = opened.Value!;
        return reader.Read();
    }

    private static JudgementWriter NewWriter(string directory) =>
        JudgementWriter.Create(directory, ThisCapture, Started, Started);

    private static string NewBundle()
    {
        var directory = Path.Combine(
            Path.GetTempPath(), "securead-judgement-tests", Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(directory);

        File.WriteAllText(
            BundleLayout.SealPath(directory),
            JsonSerializer.Serialize(
                new BundleSealContents(BundleSealing.Algorithm, ThisCapture)));

        return directory;
    }
}
