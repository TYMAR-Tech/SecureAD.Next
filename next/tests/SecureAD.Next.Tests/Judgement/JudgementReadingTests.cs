using System.Text.Json;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// Reading a judgement back: what survives the round trip, and what the reader refuses.
/// </summary>
/// <remarks>
/// The refusals matter more than the round trip. A judgement is an ordinary file in an ordinary
/// directory, so nothing stops one being moved into a bundle it was not made from - and two
/// captures of one forest hold mostly the same objects, so the findings would resolve and be wrong.
/// </remarks>
public sealed class JudgementReadingTests
{
    private const string ThisCapture = "0f9c1d2e3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5";
    private const string AnotherCapture = "ffffffff11112222333344445555666677778888999900001111222233334444";

    private static readonly DateTimeOffset Started = new(2026, 8, 25, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 8, 25, 9, 5, 0, TimeSpan.Zero);

    /// <summary>
    /// A finding survives being written and comes back with the evidence it rests on.
    /// </summary>
    [Fact]
    public void AFindingComesBackFromASealedJudgement()
    {
        var directory = NewJudgedBundle(
            writer => writer.Write(RuleExecution.Judged(Sec010, 1, 0, [SomeFinding()])));

        using var reader = Opened(directory);
        var finding = Assert.Single(reader.Read().Findings);

        Assert.Equal("SEC-010", finding.RuleId);
        Assert.Equal("svc-web", finding.Subject.Key);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal(
            "CN=svc-web,OU=Service Accounts,DC=contoso,DC=com", finding.DistinguishedName);
    }

    /// <summary>
    /// The evidence a finding rests on comes back with it, signals and all.
    /// </summary>
    [Fact]
    public void TheEvidenceAFindingRestsOnComesBackWithIt()
    {
        var directory = NewJudgedBundle(
            writer => writer.Write(RuleExecution.Judged(Sec010, 1, 0, [SomeFinding()])));

        using var reader = Opened(directory);
        var finding = Assert.Single(reader.Read().Findings);

        var evidence = Assert.IsType<UnconstrainedDelegationEvidence>(finding.Evidence);
        Assert.Equal(0x80000u, evidence.UserAccountControl);
        Assert.False(evidence.IsComputer);
        Assert.False(evidence.DomainController.IsDomainController);
    }

    /// <summary>
    /// The two derived answers are recomputed from the stored signals rather than read.
    /// </summary>
    /// <remarks>
    /// A stored copy of a derived value can disagree with the values it was derived from, and
    /// nothing would say which was right.
    /// </remarks>
    [Fact]
    public void TheDomainControllerSignalsAreRebuiltFromWhatWasStored()
    {
        var disagreeing = SomeFinding() with
        {
            Evidence = new UnconstrainedDelegationEvidence(
                0x80000, true, new DomainControllerSignals(false, true, false)),
        };

        var directory = NewJudgedBundle(
            writer => writer.Write(RuleExecution.Judged(Sec010, 1, 0, [disagreeing])));

        using var reader = Opened(directory);
        var evidence = Assert.IsType<UnconstrainedDelegationEvidence>(
            Assert.Single(reader.Read().Findings).Evidence);

        Assert.True(evidence.DomainController.IsDomainController);
        Assert.True(evidence.DomainController.SignalsDisagree);
    }

    /// <summary>
    /// A finding carries the version of the rule that made it, taken from the execution record.
    /// </summary>
    [Fact]
    public void AFindingCarriesTheVersionOfTheRuleThatMadeIt()
    {
        var tightened = Sec010 with { Version = 7 };

        var directory = NewJudgedBundle(
            writer => writer.Write(RuleExecution.Judged(tightened, 1, 0, [SomeFinding()])));

        using var reader = Opened(directory);

        Assert.Equal(7, Assert.Single(reader.Read().Findings).RuleVersion);
    }

    /// <summary>
    /// A bundle nobody judged is told apart from one where every rule ran and nothing matched.
    /// </summary>
    [Fact]
    public void ABundleNoRuleWasRunOverSaysSoRatherThanLookingClean()
    {
        var directory = NewJudgedBundle(_ => { });

        using var reader = Opened(directory);

        Assert.Empty(reader.Read().Findings);
        Assert.Empty(reader.Read().RulesRun);
    }

    /// <summary>
    /// And that distinction is not made by a reader that says it of everything.
    /// </summary>
    [Fact]
    public void ABundleWhereRulesRanAndNothingMatchedIsNotTheSameThing()
    {
        var directory = NewJudgedBundle(
            writer => writer.Write(RuleExecution.Judged(Sec010, 4000, 0, [])));

        using var reader = Opened(directory);

        Assert.Empty(reader.Read().Findings);
        Assert.Single(reader.Read().RulesRun);
    }

    /// <summary>
    /// What a rule could not read comes back named.
    /// </summary>
    [Fact]
    public void WhatARuleCouldNotReadComesBackNamed()
    {
        var directory = NewJudgedBundle(
            writer => writer.Write(RuleExecution.Indeterminate(
                Sec010, 2, 0, 40, [new MissingInput("primaryGroupID", 40)], [])));

        using var reader = Opened(directory);
        var execution = Assert.Single(reader.Read().RulesRun);

        Assert.Equal(RuleExecutionOutcome.Indeterminate, execution.Outcome);
        Assert.Equal(40, execution.ObjectsNotJudged);
        Assert.Equal("primaryGroupID", Assert.Single(execution.MissingInputs).Attribute);
    }

    /// <summary>
    /// The judging says which capture it was made against.
    /// </summary>
    [Fact]
    public void TheJudgementNamesTheCaptureItWasMadeAgainst()
    {
        var directory = NewJudgedBundle(_ => { });

        using var reader = Opened(directory);

        Assert.Equal(ThisCapture, reader.Description.EvidenceSeal);
        Assert.Equal(JudgementRunState.Completed, reader.Description.State);
    }

    [Fact]
    public void EvidenceOnlyJudgingRecordsNoDerivationDependency()
    {
        var directory = NewJudgedBundle(_ => { });

        using var reader = Opened(directory);

        Assert.Null(reader.Description.DerivationGenerationId);
    }

    [Fact]
    public void AJudgementBoundToAnotherDerivationGenerationIsRefused()
    {
        var directory = NewBundle();
        using (var writer = JudgementWriter.Create(
            directory,
            ThisCapture,
            Guid.NewGuid(),
            Started,
            Started))
        {
            writer.Complete(Finished);
        }

        var opened = JudgementReader.Open(directory);

        Assert.Equal("Evidence.JudgementIsNotForThisDerivation", opened.Error!.Code);
    }

    /// <summary>
    /// A judgement made against another capture is refused rather than believed.
    /// </summary>
    /// <remarks>
    /// This is the whole reason the store records a fingerprint. The findings inside it would
    /// resolve against this bundle's objects and be wrong about every one of them.
    /// </remarks>
    [Fact]
    public void AJudgementMadeAgainstAnotherCaptureIsRefused()
    {
        var directory = NewJudgedBundle(
            writer => writer.Write(RuleExecution.Judged(Sec010, 1, 0, [SomeFinding()])));

        WriteEvidenceSeal(directory, AnotherCapture);

        var opened = JudgementReader.Open(directory);

        Assert.False(opened.IsSuccess);
        Assert.Equal("Evidence.JudgementIsNotForThisEvidence", opened.Error!.Code);
    }

    /// <summary>
    /// A judgement with no evidence seal to check against is refused too.
    /// </summary>
    /// <remarks>
    /// Unverifiable is not the same as verified, and treating a missing seal as a pass would make
    /// the check optional in exactly the case where the bundle is already odd.
    /// </remarks>
    [Fact]
    public void AJudgementWithNoEvidenceSealToCheckAgainstIsRefused()
    {
        var directory = NewJudgedBundle(_ => { });

        File.Delete(BundleLayout.SealPath(directory));

        var opened = JudgementReader.Open(directory);

        Assert.False(opened.IsSuccess);
        Assert.Equal("Evidence.JudgementIsNotForThisEvidence", opened.Error!.Code);
    }

    /// <summary>
    /// A judging that never finished cannot be opened.
    /// </summary>
    [Fact]
    public void AJudgingThatNeverFinishedCannotBeOpened()
    {
        var directory = NewBundle();

        using (var writer = JudgementWriter.Create(directory, ThisCapture, derivationGenerationId: null, Started, Started))
        {
            writer.Write(RuleExecution.Judged(Sec010, 1, 0, [SomeFinding()]));
            writer.Abandon(Finished);
        }

        var opened = JudgementReader.Open(directory);

        Assert.False(opened.IsSuccess);
        Assert.Equal("Evidence.judgementManifestAbsent", opened.Error!.Code);
    }

    /// <summary>
    /// A judgement whose bytes changed after sealing is refused.
    /// </summary>
    [Fact]
    public void AJudgementThatWasEditedAfterSealingIsRefused()
    {
        var directory = NewJudgedBundle(
            writer => writer.Write(RuleExecution.Judged(Sec010, 1, 0, [SomeFinding()])));

        File.AppendAllText(DataPath(directory, Current(directory)), " ");

        var opened = JudgementReader.Open(directory);

        Assert.False(opened.IsSuccess);
        Assert.Equal("Evidence.JudgementSealMismatch", opened.Error!.Code);
    }

    [Fact]
    public void AMalformedSealedJudgementHeaderReturnsATypedFailure()
    {
        var directory = NewJudgedBundle(_ => { });
        var generation = Current(directory);
        var path = DataPath(directory, generation);
        using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path}"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE judgement SET judgement_generation_id = 'not-a-guid'";
            command.ExecuteNonQuery();
        }
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        BundleSealing.Seal(
            path,
            BundleLayout.AnalysisGenerationSealPath(
                directory, generation.Kind, generation.GenerationId));

        var opened = JudgementReader.Open(directory);

        Assert.Equal("Evidence.JudgementUnreadable", opened.Error!.Code);
    }

    private static readonly RuleDefinition Sec010 = new(
        "SEC-010", "Unconstrained delegation on an account", Severity.High, 1,
        ["user", "computer"],
        ["userAccountControl", "objectClass", "primaryGroupID"]);

    private static Finding SomeFinding() =>
        new(
            "SEC-010",
            1,
            Severity.High,
            new FindingSubject(FindingSubjectKind.Account, "svc-web"),
            Guid.Parse("11111111-2222-3333-4444-555555555555"),
            "CN=svc-web,OU=Service Accounts,DC=contoso,DC=com",
            "contoso.com",
            "user",
            "svc-web is trusted for unconstrained delegation.",
            EvidenceCompleteness.Complete,
            new UnconstrainedDelegationEvidence(
                0x80000, false, new DomainControllerSignals(false, false, false)));

    private static AnalysisStoreGeneration Current(string directory) =>
        AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value!;

    private static string DataPath(string directory, AnalysisStoreGeneration generation) =>
        BundleLayout.AnalysisGenerationDataPath(
            directory, generation.Kind, generation.GenerationId);

    /// <summary>
    /// Severity is stored so that the worst can be ordered first.
    /// </summary>
    /// <remarks>
    /// <b>Found 2026-08-26 by reading the predecessor.</b> Ordering on the stored word gives
    /// Critical, High, Low, Medium - alphabetical, putting Low above Medium - and it looks like a
    /// working screen. A findings grid orders on the rank, and this proves the rank agrees with the
    /// word about which is worse.
    /// </remarks>
    [Fact]
    public void SeverityIsStoredSoThatTheWorstSortsFirst()
    {
        var directory = NewJudgedBundle(writer => writer.Write(RuleExecution.Judged(
            Sec010,
            4,
            0,
            [
                SomeFinding() with { Severity = Severity.Medium, ObjectGuid = Guid.NewGuid() },
                SomeFinding() with { Severity = Severity.Critical, ObjectGuid = Guid.NewGuid() },
                SomeFinding() with { Severity = Severity.Low, ObjectGuid = Guid.NewGuid() },
                SomeFinding() with { Severity = Severity.High, ObjectGuid = Guid.NewGuid() },
            ])));

        using var reader = Opened(directory);

        var worstFirst = reader.Read().Findings
            .OrderByDescending(f => f.Severity)
            .Select(f => f.Severity);

        Assert.Equal(
            [Severity.Critical, Severity.High, Severity.Medium, Severity.Low],
            worstFirst);
    }

    private static JudgementReader Opened(string directory)
    {
        var opened = JudgementReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        return opened.Value!;
    }

    /// <summary>
    /// A bundle whose evidence seal says <see cref="ThisCapture"/>, judged and completed.
    /// </summary>
    /// <remarks>
    /// The evidence seal is written directly rather than by capturing a forest, because what is
    /// under test is whether the judgement names the right capture - not whether capture produces
    /// the hash it says it does, which <c>BundleSealing</c>'s own tests cover.
    /// </remarks>
    private static string NewJudgedBundle(Action<JudgementWriter> judging)
    {
        var directory = NewBundle();

        using (var writer = JudgementWriter.Create(directory, ThisCapture, derivationGenerationId: null, Started, Started))
        {
            judging(writer);
            writer.Complete(Finished);
        }

        return directory;
    }

    private static string NewBundle()
    {
        var directory = Path.Combine(
            Path.GetTempPath(), "securead-judgement-tests", Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(directory);
        WriteEvidenceSeal(directory, ThisCapture);
        return directory;
    }

    private static void WriteEvidenceSeal(string directory, string hash) =>
        File.WriteAllText(
            BundleLayout.SealPath(directory),
            JsonSerializer.Serialize(new BundleSealContents(BundleSealing.Algorithm, hash)));
}
