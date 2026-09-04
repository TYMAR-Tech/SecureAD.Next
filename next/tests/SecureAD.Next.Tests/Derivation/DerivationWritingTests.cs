using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

/// <summary>
/// The derivation store's write contract: what is on disk at each moment, and what the writer
/// refuses to record.
/// </summary>
/// <remarks>
/// <para>
/// <b>These are about the artefact, not the API</b>, for the reason the judgement writing tests
/// give. They also execute the schema, which nothing else does: DDL is a string until SQLite
/// parses it, so a table these tests never create is a table nobody has proved is valid.
/// </para>
/// <para>
/// The store is read with raw SQL rather than through a reader, deliberately: the writer's
/// contract should hold whether or not a reader ever agrees with it.
/// </para>
/// </remarks>
public sealed class DerivationWritingTests
{
    private const string EvidenceSeal = "0f9c1d2e3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5";

    private static readonly DateTimeOffset Started = new(2026, 8, 25, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 8, 25, 9, 5, 0, TimeSpan.Zero);

    /// <summary>
    /// The schema is valid SQL and a store can be created from nothing.
    /// </summary>
    [Fact]
    public void Stage2a_ADerivationCanBeCreated()
    {
        var directory = NewBundle();
        using var writer = DerivationWriter.Create(directory, EvidenceSeal, Started);

        Assert.True(File.Exists(BundleLayout.DerivationPartialPath(directory)));
    }

    /// <summary>
    /// While deriving is in progress there is no file by the name a reader asks for.
    /// </summary>
    /// <remarks>
    /// A half-built closure consulted as a whole one reports a principal as not a member of
    /// something it is in, and a rule resting on it has no way to notice.
    /// </remarks>
    [Fact]
    public void Stage2a_ADerivationInProgressHasNoNameAReaderAsksFor()
    {
        var directory = NewBundle();
        using var writer = DerivationWriter.Create(directory, EvidenceSeal, Started);

        writer.WriteSids(["S-1-5-21-1-2-3-512"], [null]);

        Assert.False(AnalysisStoreLifecycle.Resolve(
            directory, AnalysisStoreKind.Derivation).IsSuccess);
    }

    /// <summary>
    /// Completing gives the store its name and seals it.
    /// </summary>
    [Fact]
    public void Stage2a_CompletingNamesTheStoreAndSealsIt()
    {
        var directory = NewBundle();

        using (var writer = DerivationWriter.Create(directory, EvidenceSeal, Started))
        {
            writer.WriteSids(["S-1-5-21-1-2-3-512"], [null]);
            writer.RecordPhase("MembershipAndNesting", DerivationPhaseOutcome.Succeeded, error: null);
            writer.Complete(Finished);
        }

        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation).Value!;
        Assert.True(File.Exists(DataPath(directory, generation)));
        Assert.True(File.Exists(SealPath(directory, generation)));
        Assert.False(File.Exists(BundleLayout.DerivationPartialPath(directory)));
    }

    /// <summary>
    /// A completed derivation verifies against its own seal.
    /// </summary>
    [Fact]
    public void Stage2a_ACompletedDerivationVerifies()
    {
        var directory = NewBundle();

        using (var writer = DerivationWriter.Create(directory, EvidenceSeal, Started))
        {
            writer.WriteSids(["S-1-5-21-1-2-3-512"], [null]);
            writer.RecordPhase("MembershipAndNesting", DerivationPhaseOutcome.Succeeded, error: null);
            writer.Complete(Finished);
        }

        Assert.Equal(SealState.Intact, BundleSealing.VerifyDerivation(directory).State);
    }

    [Fact]
    public void Stage2a_APublishedReplacementDoesNotOverwriteTheEarlierGeneration()
    {
        var directory = NewBundle();

        using (var first = DerivationWriter.Create(directory, EvidenceSeal, Started))
        {
            first.WriteSids(["S-1-5-21-1-2-3-512"], [null]);
            first.RecordPhase("MembershipAndNesting", DerivationPhaseOutcome.Succeeded, error: null);
            first.Complete(Finished);
        }

        var earlierPath = DataPath(directory, Current(directory));
        using (var locked = File.Open(
            earlierPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read))
        using (var replacement = DerivationWriter.Create(directory, EvidenceSeal, Started.AddHours(1)))
        {
            replacement.WriteSids(["S-1-5-21-1-2-3-513"], [null]);
            replacement.RecordPhase(
                "MembershipAndNesting", DerivationPhaseOutcome.Succeeded, error: null);

            replacement.Complete(Finished.AddHours(1));
        }

        Assert.Equal(SealState.Intact, BundleSealing.VerifyDerivation(directory).State);
        Assert.NotEqual(earlierPath, DataPath(directory, Current(directory)));
        Assert.True(File.Exists(earlierPath));
    }

    /// <summary>
    /// A phase that degraded leaves the run degraded, not complete.
    /// </summary>
    /// <remarks>
    /// This is the one that matters. A rule resting on a partial closure has not established a
    /// clean result, and the run saying so is the only way that reaches it.
    /// </remarks>
    [Fact]
    public void Stage2a_ADegradedPhaseLeavesTheRunDegraded()
    {
        var directory = NewBundle();

        using (var writer = DerivationWriter.Create(directory, EvidenceSeal, Started))
        {
            writer.WriteSids(["S-1-5-21-1-2-3-512"], [null]);
            writer.RecordPhase("MembershipAndNesting", DerivationPhaseOutcome.Degraded, error: null);
            writer.Complete(Finished);
        }

        Assert.Equal(
            DerivationRunState.CompletedDegraded.ToString(),
            ScalarOf(directory, "SELECT state FROM derivation"));
    }

    /// <summary>
    /// The dictionary, the principals and the edges survive a round trip to disk.
    /// </summary>
    [Fact]
    public void Stage2a_TheNestingFactsSurviveARoundTrip()
    {
        var directory = NewBundle();
        var domainAdmins = 0;
        var alice = 1;

        using (var writer = DerivationWriter.Create(directory, EvidenceSeal, Started))
        {
            writer.WriteSids(["S-1-5-21-1-2-3-512", "S-1-5-21-1-2-3-1104"], [null, null]);
            writer.WriteSidIdentities(
            [
                new SidIdentityRow(domainAdmins, domainAdmins, SidIdentityKind.Current),
                new SidIdentityRow(alice, alice, SidIdentityKind.Current),
            ]);
            writer.WritePrincipals(
            [
                new PrincipalRow(domainAdmins, Guid.NewGuid(), IsGroup: true, GroupType: -2147483646, PrimaryGroupSidId: null),
                new PrincipalRow(alice, Guid.NewGuid(), IsGroup: false, GroupType: null, PrimaryGroupSidId: domainAdmins),
            ]);
            writer.WriteNestingEdges([new NestingEdge(domainAdmins, alice)]);
            writer.RecordPhase("MembershipAndNesting", DerivationPhaseOutcome.Succeeded, error: null);
            writer.Complete(Finished);
        }

        Assert.Equal(2, CountOf(directory, "SELECT COUNT(*) FROM sid"));
        Assert.Equal(2, CountOf(directory, "SELECT COUNT(*) FROM principal"));
        Assert.Equal(1, CountOf(directory, "SELECT COUNT(*) FROM nesting_edge"));
        Assert.Equal(
            1,
            CountOf(directory, "SELECT COUNT(*) FROM principal WHERE primary_group_sid_id IS NOT NULL"));
    }

    /// <summary>
    /// The same relationship seen twice is one edge, not a failure.
    /// </summary>
    /// <remarks>
    /// A group's <c>member</c> and the member's <c>memberOf</c> describe one relationship. The
    /// directory agreeing with itself must not end a derivation.
    /// </remarks>
    [Fact]
    public void Stage2a_ARelationshipSeenTwiceIsOneEdge()
    {
        var directory = NewBundle();

        using (var writer = DerivationWriter.Create(directory, EvidenceSeal, Started))
        {
            writer.WriteSids(["S-1-5-21-1-2-3-512", "S-1-5-21-1-2-3-1104"], [null, null]);
            writer.WriteNestingEdges([new NestingEdge(0, 1), new NestingEdge(0, 1)]);
            writer.RecordPhase("MembershipAndNesting", DerivationPhaseOutcome.Succeeded, error: null);
            writer.Complete(Finished);
        }

        Assert.Equal(1, CountOf(directory, "SELECT COUNT(*) FROM nesting_edge"));
    }

    /// <summary>
    /// Naming a principal before the dictionary exists is refused.
    /// </summary>
    [Fact]
    public void Stage2a_WritingPrincipalsBeforeTheDictionaryIsRefused()
    {
        var directory = NewBundle();
        using var writer = DerivationWriter.Create(directory, EvidenceSeal, Started);

        Assert.Throws<InvalidOperationException>(
            () => writer.WritePrincipals(
                [new PrincipalRow(0, Guid.NewGuid(), IsGroup: true, GroupType: null, PrimaryGroupSidId: null)]));
    }

    /// <summary>
    /// A phase recorded as failed with no error is refused.
    /// </summary>
    [Fact]
    public void Stage2a_AFailedPhaseWithoutAnErrorIsRefused()
    {
        var directory = NewBundle();
        using var writer = DerivationWriter.Create(directory, EvidenceSeal, Started);

        Assert.Throws<ArgumentException>(
            () => writer.RecordPhase("MembershipAndNesting", DerivationPhaseOutcome.Failed, error: null));
    }

    /// <summary>
    /// One phase records once.
    /// </summary>
    [Fact]
    public void Stage2a_APhaseRecordedTwiceIsRefused()
    {
        var directory = NewBundle();
        using var writer = DerivationWriter.Create(directory, EvidenceSeal, Started);

        writer.RecordPhase("MembershipAndNesting", DerivationPhaseOutcome.Succeeded, error: null);

        Assert.Throws<InvalidOperationException>(
            () => writer.RecordPhase("MembershipAndNesting", DerivationPhaseOutcome.Succeeded, error: null));
    }

    /// <summary>
    /// An abandoned derivation is not renamed and not sealed.
    /// </summary>
    [Fact]
    public void Stage2a_AnAbandonedDerivationIsNotGivenAName()
    {
        var directory = NewBundle();

        using (var writer = DerivationWriter.Create(directory, EvidenceSeal, Started))
        {
            writer.Abandon(Finished);
        }

        Assert.False(AnalysisStoreLifecycle.Resolve(
            directory, AnalysisStoreKind.Derivation).IsSuccess);
        Assert.True(File.Exists(BundleLayout.DerivationPartialPath(directory)));
    }

    /// <summary>
    /// A derivation that covered everything still records its completeness.
    /// </summary>
    /// <remarks>
    /// <b>An absent row would mean two opposite things.</b> "Nothing was missing" and "nobody
    /// recorded whether anything was" would look identical, and the second one would read as the
    /// first - which is the conversion of a missing input into a clean result that this stage is
    /// shaped against.
    /// </remarks>
    [Fact]
    public void Stage2a_ACompleteDerivationStillRecordsThatItIsComplete()
    {
        var directory = NewBundle();

        using (var writer = DerivationWriter.Create(directory, EvidenceSeal, Started))
        {
            writer.WriteSids(["S-1-5-21-1-2-3-512"], [null]);
            writer.RecordCompleteness(Complete(writer.GenerationId));
            writer.Complete(Finished);
        }

        Assert.Equal("1", ScalarOf(directory, "SELECT is_complete FROM derivation_completeness"));
    }

    /// <summary>
    /// One derivation records its coverage once.
    /// </summary>
    /// <remarks>
    /// All three products come from one graph built by one pass over one bundle, so a second record
    /// would be a second answer about a single fact, and two answers that can disagree are worse
    /// than none.
    /// </remarks>
    [Fact]
    public void Stage2a_CompletenessCannotBeRecordedTwice()
    {
        var directory = NewBundle();

        using var writer = DerivationWriter.Create(directory, EvidenceSeal, Started);
        writer.WriteSids(["S-1-5-21-1-2-3-512"], [null]);
        writer.RecordCompleteness(Complete(writer.GenerationId));

        Assert.Throws<InvalidOperationException>(
            () => writer.RecordCompleteness(Complete(writer.GenerationId)));
    }

    /// <summary>
    /// A domain that was not read is stored with why, not only that it is missing.
    /// </summary>
    /// <remarks>
    /// An operator told only that a domain is absent cannot act on it: raising a credential and
    /// reaching a network are different remedies.
    /// </remarks>
    [Fact]
    public void Stage2a_AMissingDomainIsStoredWithItsReason()
    {
        var directory = NewBundle();

        using (var writer = DerivationWriter.Create(directory, EvidenceSeal, Started))
        {
            writer.WriteSids(["S-1-5-21-1-2-3-512"], [null]);

            writer.RecordCompleteness(Complete(writer.GenerationId) with
            {
                IsComplete = false,
                MissingPartitions = [DomainCoverage.NotRead("ba.ad.lab", "no controller answered")],
            });

            writer.Complete(Finished);
        }

        Assert.Equal(
            "no controller answered",
            ScalarOf(directory, "SELECT reason FROM completeness_missing_partition"));
    }

    /// <summary>What a derivation that covered everything records.</summary>
    private static DerivationCompleteness Complete(Guid generationId) =>
        new(
            IsComplete: true,
            PartialGroups: [],
            MissingPartitions: [],
            UnresolvedTrustees: [],
            DerivationGenerationId: generationId,
            Limit: ExpansionLimit.None);

    private static string NewBundle()
    {
        var directory = TempDirectories.Create("derivation-tests");

        Directory.CreateDirectory(directory);
        return directory;
    }

    private static string ScalarOf(string directory, string sql) =>
        Read(directory, sql)?.ToString() ?? throw new InvalidOperationException($"'{sql}' read nothing.");

    private static long CountOf(string directory, string sql) =>
        Convert.ToInt64(Read(directory, sql), System.Globalization.CultureInfo.InvariantCulture);

    private static object? Read(string directory, string sql)
    {
        var current = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation);
        var path = current.IsSuccess
            ? DataPath(directory, current.Value!)
            : BundleLayout.DerivationPartialPath(directory);

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

    private static AnalysisStoreGeneration Current(string directory) =>
        AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation).Value!;

    private static string DataPath(string directory, AnalysisStoreGeneration generation) =>
        BundleLayout.AnalysisGenerationDataPath(
            directory, generation.Kind, generation.GenerationId);

    private static string SealPath(string directory, AnalysisStoreGeneration generation) =>
        BundleLayout.AnalysisGenerationSealPath(
            directory, generation.Kind, generation.GenerationId);
}
