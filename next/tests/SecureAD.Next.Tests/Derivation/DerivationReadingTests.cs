using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

/// <summary>
/// Reading a derivation back, and refusing one this build does not understand.
/// </summary>
/// <remarks>
/// <para>
/// <b>The refusal matters more than the reading.</b> Schema version 2 gave the SID dictionary a
/// scope, because a SID is unique within its scope and not within a forest. A version 1 store keys
/// principals by SID alone, so every domain's <c>BUILTIN\Administrators</c> is one principal in it
/// with all their memberships merged. Reading one as though it were current hands back the
/// fabricated cross-domain privilege path that
/// <c>docs/decisions/0087-a-sid-is-unique-within-its-scope.md</c> was written to remove.
/// </para>
/// <para>
/// These build a store through <c>DerivationWriter</c> rather than by hand, so the reader is tested
/// against what the product actually writes.
/// </para>
/// </remarks>
public sealed class DerivationReadingTests
{
    private static readonly DateTimeOffset Started = new(2026, 8, 28, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 8, 28, 9, 5, 0, TimeSpan.Zero);

    /// <summary>
    /// A completed derivation reads back what it recorded about itself.
    /// </summary>
    /// <remarks>
    /// <b>The state is the writer's, derived from the phases rather than asserted by a caller.</b>
    /// This fixture has one failed phase, so the store says <c>CompletedDegraded</c> without
    /// anybody telling it to - which is the property worth pinning: a caller cannot record a
    /// derivation as whole when part of it did not finish.
    /// </remarks>
    [Fact]
    public void Stage2a_ADerivationReadsBackItsOwnDescription()
    {
        var directory = Derived();

        var opened = DerivationReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);

        using var reader = opened.Value!;

        Assert.Equal(DerivationSchema.Version, reader.Description.SchemaVersion);
        Assert.Equal(EvidenceSealOf(directory), reader.Description.EvidenceSeal);
        Assert.Equal(DerivationRunState.CompletedDegraded, reader.Description.State);
        Assert.NotEqual(Guid.Empty, reader.Description.GenerationId);
    }

    /// <summary>
    /// Every phase comes back, whatever became of it.
    /// </summary>
    /// <remarks>
    /// A phase that failed and one that never ran are different sentences, and a reader that
    /// returned only the successful ones would let a caller report a partial derivation as whole.
    /// </remarks>
    [Fact]
    public void Stage2a_EveryPhaseComesBackWithWhatBecameOfIt()
    {
        var directory = Derived();

        using var reader = DerivationReader.Open(directory).Value!;
        var stored = reader.Read();

        Assert.Equal(3, stored.Phases.Count);
        Assert.Contains(stored.Phases, p => p.Outcome == DerivationPhaseOutcome.Succeeded);
        Assert.Contains(stored.Phases, p => p.Outcome == DerivationPhaseOutcome.DidNotRun);
        Assert.Contains(stored.Phases, p => p.Error == "it fell over");
    }

    /// <summary>
    /// A membership cycle written to the store comes back as the same set of principals.
    /// </summary>
    /// <remarks>
    /// <b>The expansion has always found these and always discarded them.</b> Microsoft states that
    /// group membership may have loops, and two groups in one are permanently the same group as far
    /// as authorization is concerned - so a delegation to the narrower-looking one reaches whatever
    /// it is looped with. Nothing could report that until the store carried it.
    /// </remarks>
    [Fact]
    public void Stage2a_AMembershipCycleSurvivesTheStore()
    {
        var directory = NewBundle();

        using (var writer = DerivationWriter.Create(directory, EvidenceSealOf(directory), Started))
        {
            writer.WriteSids(["S-1-5-21-1-2-3-1101", "S-1-5-21-1-2-3-1102", "S-1-5-21-1-2-3-1103"],
                ["ad.lab", "ad.lab", "ad.lab"]);

            writer.WriteNestingCycles([[0, 1, 2]]);
            writer.RecordPhase(
                "ExpansionPhase", DerivationPhaseOutcome.Succeeded, error: null);

            writer.RecordCompleteness(new DerivationCompleteness(
                IsComplete: true,
                PartialGroups: [],
                MissingPartitions: [],
                UnresolvedTrustees: [],
                DerivationGenerationId: writer.GenerationId,
                Limit: ExpansionLimit.None));

            writer.Complete(Finished);
        }

        using var reader = DerivationReader.Open(directory).Value!;
        var cycles = reader.Read().NestingCycles;

        Assert.Equal(NestingCycleAvailability.Available, cycles.Availability);
        Assert.Equal([0, 1, 2], Assert.Single(cycles.Cycles!));
    }

    /// <summary>
    /// Two cycles stay two cycles rather than merging into one set.
    /// </summary>
    /// <remarks>
    /// The rows carry a cycle identifier for exactly this reason. Without it the store would say
    /// which principals are in <i>some</i> loop and not which loop, and an operator told that six
    /// groups are tangled cannot act on it the way one told there are two separate pairs can.
    /// </remarks>
    [Fact]
    public void Stage2a_TwoCyclesDoNotMergeIntoOne()
    {
        var directory = NewBundle();

        using (var writer = DerivationWriter.Create(directory, EvidenceSealOf(directory), Started))
        {
            writer.WriteSids(
                ["S-1-5-21-1-2-3-1101", "S-1-5-21-1-2-3-1102",
                 "S-1-5-21-1-2-3-1103", "S-1-5-21-1-2-3-1104"],
                ["ad.lab", "ad.lab", "ad.lab", "ad.lab"]);

            writer.WriteNestingCycles([[0, 1], [2, 3]]);
            writer.RecordPhase("ExpansionPhase", DerivationPhaseOutcome.Succeeded, error: null);

            writer.RecordCompleteness(new DerivationCompleteness(
                IsComplete: true,
                PartialGroups: [],
                MissingPartitions: [],
                UnresolvedTrustees: [],
                DerivationGenerationId: writer.GenerationId,
                Limit: ExpansionLimit.None));

            writer.Complete(Finished);
        }

        using var reader = DerivationReader.Open(directory).Value!;
        var cycles = reader.Read().NestingCycles.Cycles!;

        Assert.Equal(2, cycles.Count);
        Assert.All(cycles, c => Assert.Equal(2, c.Count));
    }

    /// <summary>
    /// A store whose expansion never ran says so, and hands back no list at all.
    /// </summary>
    /// <remarks>
    /// <b>This is the whole reason the product carries an availability beside the answer.</b> A
    /// forest with no loops and a bundle nobody expanded both leave the table empty. Returning an
    /// empty list for the second would report a clean directory on the strength of a phase that
    /// never happened - the shape <c>docs/decisions/0002</c> forbids.
    /// </remarks>
    [Fact]
    public void Stage2a_NoExpansionMeansNoAnswerAboutCyclesRatherThanNone()
    {
        var directory = NewBundle();

        using (var writer = DerivationWriter.Create(directory, EvidenceSealOf(directory), Started))
        {
            writer.WriteSids([], []);
            writer.RecordPhase("ExpansionPhase", DerivationPhaseOutcome.DidNotRun, error: null);

            writer.RecordCompleteness(new DerivationCompleteness(
                IsComplete: true,
                PartialGroups: [],
                MissingPartitions: [],
                UnresolvedTrustees: [],
                DerivationGenerationId: writer.GenerationId,
                Limit: ExpansionLimit.None));

            writer.Complete(Finished);
        }

        using var reader = DerivationReader.Open(directory).Value!;
        var cycles = reader.Read().NestingCycles;

        Assert.Equal(NestingCycleAvailability.DidNotRun, cycles.Availability);
        Assert.Null(cycles.Cycles);
    }

    /// <summary>
    /// An expansion that stopped at a budget hands back what it found, marked as a floor.
    /// </summary>
    /// <remarks>
    /// Every cycle it found is real, so withholding them would lose true findings; but there may be
    /// more, so calling the answer complete would be a different lie. <c>Partial</c> is the only
    /// honest reading and it is why the enum has more than two members.
    /// </remarks>
    [Fact]
    public void Stage2a_ABudgetStoppedExpansionReportsItsCyclesAsAFloor()
    {
        var directory = NewBundle();

        using (var writer = DerivationWriter.Create(directory, EvidenceSealOf(directory), Started))
        {
            writer.WriteSids(["S-1-5-21-1-2-3-1101", "S-1-5-21-1-2-3-1102"], ["ad.lab", "ad.lab"]);
            writer.WriteNestingCycles([[0, 1]]);
            writer.RecordPhase("ExpansionPhase", DerivationPhaseOutcome.Degraded, error: null);

            writer.RecordCompleteness(new DerivationCompleteness(
                IsComplete: false,
                PartialGroups: [],
                MissingPartitions: [],
                UnresolvedTrustees: [],
                DerivationGenerationId: writer.GenerationId,
                Limit: ExpansionLimit.MaxClosureEntriesReached));

            writer.Complete(Finished);
        }

        using var reader = DerivationReader.Open(directory).Value!;
        var cycles = reader.Read().NestingCycles;

        Assert.Equal(NestingCycleAvailability.Partial, cycles.Availability);
        Assert.Single(cycles.Cycles!);
    }

    /// <summary>
    /// A phase that did not run does not count against the ones that did.
    /// </summary>
    /// <remarks>
    /// It had no input, which is not the same as having misbehaved. Counting it as a failure sends
    /// whoever reads it looking in the wrong place.
    /// </remarks>
    [Fact]
    public void Stage2a_APhaseThatDidNotRunIsNotAFailure()
    {
        var directory = NewBundle();

        using (var writer = DerivationWriter.Create(directory, EvidenceSealOf(directory), Started))
        {
            writer.WriteSids([], []);
            writer.RecordPhase("Ran", DerivationPhaseOutcome.Succeeded, error: null);
            writer.RecordPhase("Never", DerivationPhaseOutcome.DidNotRun, error: null);

            writer.RecordCompleteness(new DerivationCompleteness(
                IsComplete: true,
                PartialGroups: [],
                MissingPartitions: [],
                UnresolvedTrustees: [],
                DerivationGenerationId: writer.GenerationId,
                Limit: ExpansionLimit.None));

            writer.Complete(Finished);
        }

        using var reader = DerivationReader.Open(directory).Value!;

        Assert.True(reader.Read().EveryPhaseThatRanSucceeded);
    }

    /// <summary>
    /// How much the store holds is read from the store rather than tallied by whoever wrote it.
    /// </summary>
    [Fact]
    public void Stage2a_TheSizeIsReadFromTheStore()
    {
        var directory = Derived();

        using var reader = DerivationReader.Open(directory).Value!;
        var size = reader.Read().Size;

        Assert.Equal(2, size.Principals);
        Assert.Equal(2, size.Identities);
        Assert.Equal(1, size.NestingEdges);
    }

    /// <summary>
    /// A store written by a build with a different schema is refused, not read.
    /// </summary>
    /// <remarks>
    /// <b>This is the test this class exists for.</b> Version 1 stores are on disk in lab bundles
    /// today. In one, every domain's built-in groups are a single principal holding the union of
    /// their members - so a reader that shrugged at the version would report one domain's local
    /// Administrators as containing another's Domain Admins.
    /// </remarks>
    [Theory]
    [InlineData(1)]
    [InlineData(8)]
    [InlineData(9)]
    public void Stage2a_AStoreFromAnotherSchemaIsRefused(int storedVersion)
    {
        var directory = Derived();

        // Rewrite the version in place, then seal it again so the refusal is about the schema
        // rather than about a broken seal.
        var generation = Current(directory);
        var path = DataPath(directory, generation);

        using (var connection = new SqliteConnection($"Data Source={path}"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE derivation SET schema_version = $version";
            command.Parameters.AddWithValue("$version", storedVersion);
            command.ExecuteNonQuery();
        }

        SqliteConnection.ClearAllPools();
        BundleSealing.Seal(path, SealPath(directory, generation));

        var opened = DerivationReader.Open(directory);

        Assert.False(opened.IsSuccess);
        Assert.Equal("Evidence.DerivationSchemaNotUnderstood", opened.Error!.Code);
        Assert.Contains("without its scope", opened.Error.Description, StringComparison.Ordinal);
        Assert.Contains($"schema version {storedVersion}", opened.Error.Description, StringComparison.Ordinal);
        Assert.Contains($"reads version {DerivationSchema.Version}", opened.Error.Description, StringComparison.Ordinal);
    }

    /// <summary>
    /// A derivation whose seal does not verify is refused before it is opened.
    /// </summary>
    [Fact]
    public void Stage2a_ADerivationWhoseSealIsBrokenIsRefused()
    {
        var directory = Derived();

        File.AppendAllText(DataPath(directory, Current(directory)), "tampered");

        var opened = DerivationReader.Open(directory);

        Assert.False(opened.IsSuccess);
        Assert.Equal("Evidence.DerivationSealNotIntact", opened.Error!.Code);
    }

    [Fact]
    public void Stage2a_AMalformedSealedHeaderReturnsATypedFailure()
    {
        var directory = Derived();
        var generation = Current(directory);
        var path = DataPath(directory, generation);
        using (var connection = new SqliteConnection($"Data Source={path}"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE derivation SET derivation_generation_id = 'not-a-guid'";
            command.ExecuteNonQuery();
        }
        SqliteConnection.ClearAllPools();
        BundleSealing.Seal(path, SealPath(directory, generation));

        var opened = DerivationReader.Open(directory);

        Assert.Equal("Evidence.DerivationUnreadable", opened.Error!.Code);
    }

    /// <summary>
    /// A bundle nothing has derived is refused rather than read as an empty derivation.
    /// </summary>
    /// <remarks>
    /// <b>Never derived and derived to nothing are opposite facts.</b> Handing back an empty store
    /// for the first would tell a caller the forest has no nesting.
    /// </remarks>
    [Fact]
    public void Stage2a_ABundleThatWasNeverDerivedIsRefused()
    {
        var opened = DerivationReader.Open(NewBundle());

        Assert.False(opened.IsSuccess);
    }

    [Fact]
    public void Stage2a_ADerivationCopiedBesideDifferentEvidenceIsRefused()
    {
        var source = NewBundleWithEvidence("source evidence");
        var destination = NewBundleWithEvidence("destination evidence");
        var sourceSeal = BundleSealing.ReadSeal(BundleLayout.SealPath(source))!.Hash;

        using (var writer = DerivationWriter.Create(source, sourceSeal, Started))
        {
            writer.WriteSids([], []);
            writer.RecordCompleteness(new DerivationCompleteness(
                IsComplete: true,
                PartialGroups: [],
                MissingPartitions: [],
                UnresolvedTrustees: [],
                DerivationGenerationId: writer.GenerationId,
                Limit: ExpansionLimit.None));
            writer.Complete(Finished);
        }

        var sourceGeneration = Current(source);
        var destinationGeneration = AnalysisStoreLifecycle.Generation(
            destination, AnalysisStoreKind.Derivation, sourceGeneration.GenerationId);
        var root = AnalysisStoreLifecycle.ResolveRoot(source, AnalysisStoreKind.Derivation).Value;
        Assert.Equal(new[] { StoreSegmentRole.Derivation, StoreSegmentRole.Membership },
            root.Segments.Select(segment => segment.Role));
        var sourceOpened = DerivationReader.Open(source);
        Assert.True(sourceOpened.IsSuccess, sourceOpened.Error?.Description);
        using (var original = sourceOpened.Value)
            Assert.Equal(sourceSeal, original.Description.EvidenceSeal);
        foreach (var segment in root.Segments)
        {
            var sourcePath = BundleLayout.AnalysisSegmentDataPath(source, sourceGeneration, segment.Role);
            var destinationPath = BundleLayout.AnalysisSegmentDataPath(destination, destinationGeneration, segment.Role);
            File.Copy(sourcePath, destinationPath);
            File.Copy(sourcePath + ".seal", destinationPath + ".seal");
        }
        File.Copy(
            AnalysisStoreLifecycle.ManifestPath(source, AnalysisStoreKind.Derivation),
            AnalysisStoreLifecycle.ManifestPath(destination, AnalysisStoreKind.Derivation));

        var opened = DerivationReader.Open(destination);

        Assert.False(opened.IsSuccess);
        Assert.Equal("Evidence.DerivationIsNotForThisEvidence", opened.Error!.Code);
    }

    private static AnalysisStoreGeneration Current(string directory) =>
        AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation).Value!;

    private static string DataPath(string directory, AnalysisStoreGeneration generation) =>
        BundleLayout.AnalysisGenerationDataPath(
            directory, generation.Kind, generation.GenerationId);

    private static string SealPath(string directory, AnalysisStoreGeneration generation) =>
        BundleLayout.AnalysisGenerationSealPath(
            directory, generation.Kind, generation.GenerationId);

    /// <summary>
    /// A derivation that did not cover everything reads back saying so.
    /// </summary>
    /// <remarks>
    /// <b>This is the property the completeness tables exist for.</b> Without them a store built
    /// under a budget that ran out is indistinguishable from one that reached everything, and the
    /// judgement specification requires that a partial answer is never serialized as a complete
    /// closure.
    /// </remarks>
    [Fact]
    public void Stage2a_APartialDerivationReadsBackAsPartial()
    {
        var directory = Derived();

        using var reader = DerivationReader.Open(directory).Value!;
        var stored = reader.Read();

        Assert.False(stored.Completeness.IsComplete);
    }

    /// <summary>
    /// Which budget stopped the expansion comes back with it.
    /// </summary>
    /// <remarks>
    /// An operator who knows the answer is a floor still has to decide what to do about it, and
    /// raising a budget and reaching an unreachable domain are different remedies.
    /// </remarks>
    [Fact]
    public void Stage2a_TheLimitThatStoppedTheExpansionComesBack()
    {
        var directory = Derived();

        using var reader = DerivationReader.Open(directory).Value!;
        var stored = reader.Read();

        Assert.Equal(ExpansionLimit.MaxTimeReached, stored.Completeness.Limit);
    }

    /// <summary>
    /// A group whose membership was never worked out is named.
    /// </summary>
    [Fact]
    public void Stage2a_AGroupLeftUnexpandedIsNamed()
    {
        var directory = Derived();

        using var reader = DerivationReader.Open(directory).Value!;
        var stored = reader.Read();

        Assert.Equal([1], stored.Completeness.PartialGroups);
    }

    /// <summary>
    /// A member no captured object answers to is named.
    /// </summary>
    [Fact]
    public void Stage2a_AnUnresolvedTrusteeIsNamed()
    {
        var directory = Derived();

        using var reader = DerivationReader.Open(directory).Value!;
        var stored = reader.Read();

        Assert.Equal(["CN=Gone,DC=ad,DC=lab"], stored.Completeness.UnresolvedTrustees);
    }

    /// <summary>
    /// A domain nobody could reach does not read back as one left out by choice.
    /// </summary>
    /// <remarks>
    /// <b>This is <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c> surviving a
    /// round trip.</b> Both domains are absent from the graph, and reducing the missing partitions
    /// to a list of names would make them the same fact - but one is a decision the operator
    /// already knows about and the other may be the most important thing the run found.
    /// </remarks>
    [Fact]
    public void Stage2a_ADomainThatCouldNotBeReachedDoesNotReadBackAsOneLeftOut()
    {
        var directory = Derived();

        using var reader = DerivationReader.Open(directory).Value!;
        var stored = reader.Read();

        var unreachable = stored.Completeness.MissingPartitions
            .Single(p => p.DomainFqdn == "ba.ad.lab");

        Assert.Equal(DomainReadOutcome.NotRead, unreachable.Outcome);
    }

    /// <summary>
    /// A domain the operator left out says so, and says what he stated.
    /// </summary>
    [Fact]
    public void Stage2a_ADomainLeftOutByChoiceKeepsTheReasonGiven()
    {
        var directory = Derived();

        using var reader = DerivationReader.Open(directory).Value!;
        var stored = reader.Read();

        var excluded = stored.Completeness.MissingPartitions
            .Single(p => p.DomainFqdn == "ph.ad.lab");

        Assert.Equal("the operator left it out", excluded.Reason);
    }

    /// <summary>
    /// The completeness names the run that wrote it.
    /// </summary>
    /// <remarks>
    /// Taken from the header rather than a column of its own, so this pins that the two agree by
    /// construction rather than by being kept in step.
    /// </remarks>
    [Fact]
    public void Stage2a_CompletenessNamesTheRunThatWroteIt()
    {
        var directory = Derived();

        using var reader = DerivationReader.Open(directory).Value!;
        var stored = reader.Read();

        Assert.Equal(
            stored.Description.GenerationId,
            stored.Completeness.DerivationGenerationId);
    }

    /// <summary>A bundle with a completed derivation in it.</summary>
    private static string Derived()
    {
        var directory = NewBundle();

        using (var writer = DerivationWriter.Create(directory, EvidenceSealOf(directory), Started))
        {
            writer.WriteSids(["S-1-5-32-544", "S-1-5-21-1-2-3-512"], ["ad.lab", null]);

            writer.WriteSidIdentities(
            [
                new SidIdentityRow(0, 0, SidIdentityKind.Current),
                new SidIdentityRow(1, 1, SidIdentityKind.Current),
            ]);

            writer.WritePrincipals(
            [
                new PrincipalRow(0, Guid.NewGuid(), IsGroup: true, GroupType: -2147483644, null),
                new PrincipalRow(1, Guid.NewGuid(), IsGroup: true, GroupType: -2147483646, null),
            ]);

            writer.WriteNestingEdges([new NestingEdge(0, 1)]);

            writer.RecordPhase("MembershipAndNesting", DerivationPhaseOutcome.Succeeded, error: null);
            writer.RecordPhase("ExpansionPhase", DerivationPhaseOutcome.Failed, "it fell over");
            writer.RecordPhase("LatentPrivilegePaths", DerivationPhaseOutcome.DidNotRun, error: null);

            // A derivation with a hole of each kind, so the reader is tested against a store that
            // has something to say rather than one whose lists are all empty.
            writer.RecordCompleteness(new DerivationCompleteness(
                IsComplete: false,
                PartialGroups: [1],
                MissingPartitions:
                [
                    DomainCoverage.NotRead("ba.ad.lab", "no controller answered"),
                    DomainCoverage.Excluded(
                        "ph.ad.lab", ExclusionKind.ByChoice, "the operator left it out"),
                ],
                UnresolvedTrustees: ["CN=Gone,DC=ad,DC=lab"],
                DerivationGenerationId: writer.GenerationId,
                Limit: ExpansionLimit.MaxTimeReached,
                CollapsedStubs: 4,
                UnscopedBuiltins: 0));

            writer.Complete(Finished);
        }

        return directory;
    }

    private static string NewBundle()
    {
        var directory = Path.Combine(
            Path.GetTempPath(), "derivation-read-" + Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(directory);
        var evidencePath = BundleLayout.EvidencePath(directory);
        File.WriteAllText(evidencePath, "test evidence");
        BundleSealing.Seal(evidencePath, BundleLayout.SealPath(directory));
        return directory;
    }

    private static string NewBundleWithEvidence(string content)
    {
        var directory = NewBundle();
        var evidencePath = BundleLayout.EvidencePath(directory);
        File.WriteAllText(evidencePath, content);
        BundleSealing.Seal(evidencePath, BundleLayout.SealPath(directory));
        return directory;
    }

    private static string EvidenceSealOf(string directory) =>
        BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!.Hash;
}
