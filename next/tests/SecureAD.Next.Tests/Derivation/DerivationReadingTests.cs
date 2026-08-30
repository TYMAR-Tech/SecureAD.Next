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
    private const string EvidenceSeal = "0f9c1d2e3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5";

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
        Assert.Equal(EvidenceSeal, reader.Description.EvidenceSeal);
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

        using (var writer = DerivationWriter.Create(directory, EvidenceSeal, Started))
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
    [Fact]
    public void Stage2a_AStoreFromAnotherSchemaIsRefused()
    {
        var directory = Derived();

        // Rewrite the version in place, then seal it again so the refusal is about the schema
        // rather than about a broken seal.
        var path = BundleLayout.DerivationPath(directory);

        using (var connection = new SqliteConnection($"Data Source={path}"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE derivation SET schema_version = 1";
            command.ExecuteNonQuery();
        }

        SqliteConnection.ClearAllPools();
        BundleSealing.Seal(path, BundleLayout.DerivationSealPath(directory));

        var opened = DerivationReader.Open(directory);

        Assert.False(opened.IsSuccess);
        Assert.Equal("Evidence.DerivationSchemaNotUnderstood", opened.Error!.Code);
        Assert.Contains("without its scope", opened.Error.Description, StringComparison.Ordinal);
    }

    /// <summary>
    /// A derivation whose seal does not verify is refused before it is opened.
    /// </summary>
    [Fact]
    public void Stage2a_ADerivationWhoseSealIsBrokenIsRefused()
    {
        var directory = Derived();

        File.AppendAllText(BundleLayout.DerivationPath(directory), "tampered");

        var opened = DerivationReader.Open(directory);

        Assert.False(opened.IsSuccess);
        Assert.Equal("Evidence.DerivationSealNotIntact", opened.Error!.Code);
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

        File.Copy(
            BundleLayout.DerivationPath(source),
            BundleLayout.DerivationPath(destination));
        File.Copy(
            BundleLayout.DerivationSealPath(source),
            BundleLayout.DerivationSealPath(destination));

        var opened = DerivationReader.Open(destination);

        Assert.False(opened.IsSuccess);
    }

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

        using (var writer = DerivationWriter.Create(directory, EvidenceSeal, Started))
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
}
