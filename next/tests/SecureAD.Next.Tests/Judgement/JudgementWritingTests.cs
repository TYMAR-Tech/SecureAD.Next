using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// The judgement store's write contract: what is on disk at each moment, and what the writer
/// refuses to record.
/// </summary>
/// <remarks>
/// <para>
/// <b>These are about the artefact, not the API.</b> Each one asserts what a bundle directory holds
/// after some sequence of calls, because that is what an operator and a future reader actually
/// meet. A store that is well formed in memory and wrong on disk has failed at the only point that
/// matters.
/// </para>
/// <para>
/// The store is read here with raw SQL rather than through a reader, deliberately: the writer's
/// contract should hold whether or not a reader ever agrees with it.
/// </para>
/// </remarks>
public sealed class JudgementWritingTests
{
    private const string EvidenceSeal = "0f9c1d2e3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5";

    private static readonly DateTimeOffset Started = new(2026, 8, 25, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 8, 25, 9, 5, 0, TimeSpan.Zero);

    /// <summary>
    /// While judging is in progress there is no file by the name a reader asks for.
    /// </summary>
    /// <remarks>
    /// A half-judged bundle presenting the findings it managed to write looks exactly like a forest
    /// with fewer problems than it has, which is the more dangerous direction to be wrong in.
    /// </remarks>
    [Fact]
    public void AJudgementInProgressHasNoNameAReaderAsksFor()
    {
        var directory = NewBundle();
        using var writer = NewWriter(directory);

        writer.Write(RuleExecution.Judged(Sec010, 1, 0, [SomeFinding()]));

        Assert.True(File.Exists(BundleLayout.JudgementPartialPath(directory)));
        Assert.False(File.Exists(BundleLayout.JudgementPath(directory)));
    }

    /// <summary>
    /// Completing gives the store its name and seals it.
    /// </summary>
    [Fact]
    public void CompletingNamesTheStoreAndSealsIt()
    {
        var directory = NewBundle();

        using (var writer = NewWriter(directory))
        {
            writer.Write(RuleExecution.Judged(Sec010, 1, 0, [SomeFinding()]));
            writer.Complete(Finished);
        }

        Assert.True(File.Exists(BundleLayout.JudgementPath(directory)));
        Assert.True(File.Exists(BundleLayout.JudgementSealPath(directory)));
        Assert.False(File.Exists(BundleLayout.JudgementPartialPath(directory)));
    }

    /// <summary>
    /// A judging that never finished leaves the previous judgement untouched.
    /// </summary>
    /// <remarks>
    /// Re-judging replaces the store, and the replacement happens at the rename. So the answer a
    /// bundle already had survives a judging that died, rather than being destroyed by one that
    /// produced nothing.
    /// </remarks>
    [Fact]
    public void AJudgingThatDidNotFinishLeavesTheEarlierOneIntact()
    {
        var directory = NewBundle();

        using (var first = NewWriter(directory))
        {
            first.Write(RuleExecution.Judged(Sec010, 1, 0, [SomeFinding()]));
            first.Complete(Finished);
        }

        var sealedBytes = File.ReadAllBytes(BundleLayout.JudgementPath(directory));

        using (var abandoned = NewWriter(directory))
        {
            abandoned.Write(RuleExecution.Threw(Sec011, "the coordinator fell over"));
            abandoned.Abandon(Finished);
        }

        Assert.Equal(sealedBytes, File.ReadAllBytes(BundleLayout.JudgementPath(directory)));
    }

    /// <summary>
    /// A judging whose coordinator failed produces nothing a reader can open.
    /// </summary>
    [Fact]
    public void AnAbandonedJudgingIsNotGivenAReadableName()
    {
        var directory = NewBundle();

        using (var writer = NewWriter(directory))
        {
            writer.Write(RuleExecution.Judged(Sec010, 1, 0, []));
            writer.Abandon(Finished);
        }

        Assert.False(File.Exists(BundleLayout.JudgementPath(directory)));
        Assert.True(File.Exists(BundleLayout.JudgementPartialPath(directory)));
    }

    /// <summary>
    /// Every rule reaching every verdict is a completed judging.
    /// </summary>
    [Fact]
    public void EveryRuleReachingEveryVerdictIsCompleted()
    {
        var directory = NewBundle();

        using (var writer = NewWriter(directory))
        {
            writer.Write(RuleExecution.Judged(Sec010, 4, 0, [SomeFinding()]));
            writer.Write(RuleExecution.Judged(Sec011, 9, 0, []));
            writer.Complete(Finished);
        }

        Assert.Equal("Completed", StateOf(directory));
    }

    /// <summary>
    /// One rule that could not read its inputs degrades the whole judging.
    /// </summary>
    /// <remarks>
    /// The forest has not been shown to be clean of what that rule looks for, and a run that
    /// reported itself completed would be saying it had been.
    /// </remarks>
    [Fact]
    public void OneRuleThatCouldNotReadItsInputsDegradesTheJudging()
    {
        var directory = NewBundle();

        using (var writer = NewWriter(directory))
        {
            writer.Write(RuleExecution.Judged(Sec010, 4, 0, []));
            writer.Write(RuleExecution.Indeterminate(
                Sec011, 2, 0, 40, [new MissingInput("primaryGroupID", 40)], []));
            writer.Complete(Finished);
        }

        Assert.Equal("CompletedDegraded", StateOf(directory));
    }

    /// <summary>
    /// A rule that threw does not stop the rules around it being recorded.
    /// </summary>
    [Fact]
    public void ARuleThatThrewDoesNotCostTheRulesAroundIt()
    {
        var directory = NewBundle();

        using (var writer = NewWriter(directory))
        {
            writer.Write(RuleExecution.Threw(Sec010, "object reference not set"));
            writer.Write(RuleExecution.Judged(Sec011, 9, 0, [SomeFinding("SEC-011")]));
            writer.Complete(Finished);
        }

        Assert.Equal(2, CountOf(directory, "SELECT COUNT(*) FROM rule_execution"));
        Assert.Equal(1, CountOf(directory, "SELECT COUNT(*) FROM finding"));
    }

    /// <summary>
    /// The store records the evidence it judged.
    /// </summary>
    [Fact]
    public void TheStoreRecordsTheEvidenceItJudged()
    {
        var directory = NewBundle();

        using (var writer = NewWriter(directory))
            writer.Complete(Finished);

        Assert.Equal(EvidenceSeal, ScalarOf(directory, "SELECT evidence_seal FROM judgement"));
    }

    /// <summary>
    /// A rule that succeeded cannot also have failed to judge objects.
    /// </summary>
    [Fact]
    public void ARuleThatReachedEveryVerdictCannotAlsoHaveMissedObjects()
    {
        var directory = NewBundle();
        using var writer = NewWriter(directory);

        var contradiction = new RuleExecution(
            Sec010, RuleExecutionOutcome.Succeeded, 4, 0, 40, [], [], null);

        Assert.Throws<ArgumentException>(() => writer.Write(contradiction));
    }

    /// <summary>
    /// A rule that could not reach a verdict must say what was missing.
    /// </summary>
    [Fact]
    public void ARuleThatCouldNotReachAVerdictMustSayWhatWasMissing()
    {
        var directory = NewBundle();
        using var writer = NewWriter(directory);

        var unexplained = new RuleExecution(
            Sec010, RuleExecutionOutcome.Indeterminate, 4, 0, 40, [], [], null);

        Assert.Throws<ArgumentException>(() => writer.Write(unexplained));
    }

    /// <summary>
    /// A finding cannot be filed under a rule that did not make it.
    /// </summary>
    [Fact]
    public void AFindingCannotBeFiledUnderAnotherRule()
    {
        var directory = NewBundle();
        using var writer = NewWriter(directory);

        var misfiled = RuleExecution.Judged(Sec011, 1, 0, [SomeFinding("SEC-010")]);

        Assert.Throws<ArgumentException>(() => writer.Write(misfiled));
    }

    /// <summary>
    /// A rule that threw carries no findings, because a rule that failed part way has no verdict.
    /// </summary>
    [Fact]
    public void ARuleThatThrewCannotAlsoCarryFindings()
    {
        var directory = NewBundle();
        using var writer = NewWriter(directory);

        var partial = new RuleExecution(
            Sec010, RuleExecutionOutcome.Error, 0, 0, 0, [], [SomeFinding()], "fell over");

        Assert.Throws<ArgumentException>(() => writer.Write(partial));
    }

    /// <summary>
    /// One rule is recorded once, because a second record would be a second answer.
    /// </summary>
    [Fact]
    public void OneRuleCannotBeRecordedTwice()
    {
        var directory = NewBundle();
        using var writer = NewWriter(directory);

        writer.Write(RuleExecution.Judged(Sec010, 1, 0, []));

        Assert.Throws<InvalidOperationException>(
            () => writer.Write(RuleExecution.Judged(Sec010, 1, 0, [])));
    }

    /// <summary>
    /// Nothing may be added to a judgement that has been sealed.
    /// </summary>
    [Fact]
    public void NothingCanBeAddedAfterTheJudgementIsSealed()
    {
        var directory = NewBundle();
        using var writer = NewWriter(directory);

        writer.Complete(Finished);

        Assert.Throws<InvalidOperationException>(
            () => writer.Write(RuleExecution.Judged(Sec010, 1, 0, [])));
    }

    /// <summary>
    /// A rule that did not run is recorded, because an absent row cannot say it was skipped.
    /// </summary>
    [Fact]
    public void ARuleThatDidNotRunIsStillRecorded()
    {
        var directory = NewBundle();

        using (var writer = NewWriter(directory))
        {
            writer.Write(RuleExecution.DidNotRun(Sec010));
            writer.Complete(Finished);
        }

        Assert.Equal("DidNotRun", ScalarOf(directory, "SELECT outcome FROM rule_execution"));
    }

    /// <summary>
    /// What was missing is recorded by name, not merely counted.
    /// </summary>
    [Fact]
    public void WhatWasMissingIsRecordedByName()
    {
        var directory = NewBundle();

        using (var writer = NewWriter(directory))
        {
            writer.Write(RuleExecution.Indeterminate(
                Sec010, 2, 0, 40, [new MissingInput("primaryGroupID", 40)], []));
            writer.Complete(Finished);
        }

        Assert.Equal(
            "primaryGroupID",
            ScalarOf(directory, "SELECT attribute FROM rule_execution_missing_input"));
    }

    private static readonly RuleDefinition Sec010 = new(
        "SEC-010", "Unconstrained delegation on an account", Severity.High, 1,
        ["user", "computer"],
        ["userAccountControl", "objectClass", "primaryGroupID"]);

    private static readonly RuleDefinition Sec011 = new(
        "SEC-011", "Unconstrained delegation on a member computer", Severity.High, 1,
        ["user", "computer"],
        ["userAccountControl", "objectClass", "primaryGroupID"]);

    private static Finding SomeFinding(string ruleId = "SEC-010") =>
        new(
            ruleId,
            1,
            Severity.High,
            new FindingSubject(FindingSubjectKind.Account, "svc-web"),
            Guid.Parse("11111111-2222-3333-4444-555555555555"),
            "CN=svc-web,OU=Service Accounts,DC=contoso,DC=com",
            "svc-web is trusted for unconstrained delegation.",
            EvidenceCompleteness.Complete,
            new UnconstrainedDelegationEvidence(
                0x80000, false, new DomainControllerSignals(false, false, false)));

    private static JudgementWriter NewWriter(string directory) =>
        JudgementWriter.Create(directory, EvidenceSeal, Started, Started);

    /// <summary>
    /// A fresh bundle directory. Not cleaned up, so a failure can be opened and looked at.
    /// </summary>
    private static string NewBundle()
    {
        var directory = Path.Combine(
            Path.GetTempPath(), "securead-judgement-tests", Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(directory);
        return directory;
    }

    private static string StateOf(string directory) =>
        ScalarOf(directory, "SELECT state FROM judgement");

    private static string ScalarOf(string directory, string sql) =>
        Read(directory, sql)?.ToString() ?? throw new InvalidOperationException($"'{sql}' read nothing.");

    private static long CountOf(string directory, string sql) =>
        Convert.ToInt64(Read(directory, sql), System.Globalization.CultureInfo.InvariantCulture);

    private static object? Read(string directory, string sql)
    {
        var path = File.Exists(BundleLayout.JudgementPath(directory))
            ? BundleLayout.JudgementPath(directory)
            : BundleLayout.JudgementPartialPath(directory);

        using var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ToString());

        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }
}
