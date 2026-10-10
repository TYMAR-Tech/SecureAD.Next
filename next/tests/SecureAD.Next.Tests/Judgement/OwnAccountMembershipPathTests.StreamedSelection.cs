using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Theory]
    [InlineData("both-permissions")]
    [InlineData("deny-before")]
    [InlineData("disabled")]
    [InlineData("missing-schema")]
    [InlineData("unsupported-group")]
    [InlineData("no-membership-continuation")]
    public void StreamedSelectionKeepsThePriorQuestionsReasonsAndWitnessOrdering(string variant)
    {
        using var fixture = PrerequisiteFixtureFor(variant);
        var expected = RequesterSelectionEvaluation.Select(fixture.Sources.Bundle.ReadObjectAttributes,
            fixture.Sources.Bundle.ReadPermissions, fixture.Inputs, fixture.Nodes,
            fixture.Sources.ReadNamingContexts().Value, CancellationToken.None, null, fixture.Memberships);

        RewriteRequesterWork(fixture);

        var manifest = PathCalculationStorage.Read(fixture.Connection, fixture.Description, CancellationToken.None)!;
        var actual = PathCalculationStorage.ReadSelection(fixture.Connection, fixture.Description, manifest, CancellationToken.None);
        Assert.Equal(WorkJson(expected), WorkJson(actual));
        Assert.Equal(expected.Candidates.Count, manifest.Work.Count);
        PathCalculationStorage.RequirePublishable(fixture.Connection, fixture.Description, CancellationToken.None);
    }

    [Fact]
    public void StreamedSelectionDeduplicatesQuestionsWithoutLosingFirstWitnessOccurrences()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        using var writing = new StreamedSelectionStore(fixture);
        var first = SelectionCandidate("CN=First,DC=contoso,DC=com");
        var seven = first.Witnesses[0] with { PermissionOrdinal = 7 };
        var three = seven with { PermissionOrdinal = 3 };
        var nine = seven with { PermissionOrdinal = 9 };
        var collector = new RequesterSelectionEvaluation.Collector();
        PathRequesterCandidate[] emissions = [
            first with { Witnesses = [seven, three, seven] },
            first with { Witnesses = [three, nine, seven] },
        ];
        foreach (var emission in emissions)
        {
            Assert.Equal(collector.Include(emission), writing.Storage.Include(emission));
        }
        var scan = writing.Scan();
        var saved = writing.Storage.Complete(scan);
        var actual = PathCalculationStorage.ReadRecords<PathRequesterCandidate>(fixture.Connection,
            fixture.Description, "Candidates", saved.Candidates, CancellationToken.None);

        Assert.Equal(WorkJson(collector.Finish(scan).Candidates), WorkJson(actual));
        Assert.Equal(new[] { 7, 3, 7, 9 }, Assert.Single(actual).Witnesses.Select(value => value.PermissionOrdinal));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void StreamedSelectionPreservesMembershipCollectionEqualityRatherThanMergingContent(bool immutable)
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        using var writing = new StreamedSelectionStore(fixture);
        var member = fixture.Identities[UserDn];
        var group = fixture.Identities[HolderDn];
        var link = new RequesterMembershipLink(member, group, -2147483646, Started,
            new(group, "member", 0, UserDn), new string('b', 64));
        var evidence = new RequesterMembershipEvidence(PrincipalExpansionOutcome.Expanded, new string('c', 64),
            immutable ? ImmutableArray.Create(link) : new[] { link },
            immutable ? ImmutableArray<PathRequesterSelectionReason>.Empty : Array.Empty<PathRequesterSelectionReason>());
        var copied = evidence with { };
        var separate = evidence with { Links = immutable ? ImmutableArray.Create(link) : new[] { link } };
        Assert.Equal(evidence, copied);
        Assert.NotEqual(evidence, separate);
        var candidate = SelectionCandidate(UserDn);
        var collector = new RequesterSelectionEvaluation.Collector();
        foreach (var membership in new[] { evidence, copied, separate })
        {
            var emission = candidate with { Witnesses = [candidate.Witnesses[0] with { Membership = membership }] };
            Assert.Equal(collector.Include(emission), writing.Storage.Include(emission));
        }
        var scan = writing.Scan();
        var saved = writing.Storage.Complete(scan);
        var actual = PathCalculationStorage.ReadRecords<PathRequesterCandidate>(fixture.Connection,
            fixture.Description, "Candidates", saved.Candidates, CancellationToken.None);

        Assert.Equal(WorkJson(collector.Finish(scan).Candidates), WorkJson(actual));
        Assert.Equal(2, Assert.Single(actual).Witnesses.Count);
    }

    [Fact]
    public void StreamedSelectionSharesWitnessPreparationAcrossDistinctQuestions()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        using var writing = new StreamedSelectionStore(fixture);
        using var trace = new JudgingInputReuseTests.Statements(fixture.Connection);
        for (var index = 0; index < 128; index++)
        {
            var emission = SelectionCandidate($"CN=Streamed{index:D3},DC=contoso,DC=com");
            Assert.True(writing.Storage.Include(emission));
            Assert.False(writing.Storage.Include(emission with { Witnesses = emission.Witnesses.ToArray() }));
        }
        var prepared = trace.Sql.Count(value => value.Contains("FROM path_shared_proof WHERE kind='SelectionWitness'", StringComparison.Ordinal));
        var work = writing.Storage.Questions().ToArray();
        var saved = writing.Storage.Complete(writing.Scan());
        var actual = PathCalculationStorage.ReadRecords<PathRequesterCandidate>(fixture.Connection,
            fixture.Description, "Candidates", saved.Candidates, CancellationToken.None);

        Assert.Equal(1, prepared);
        Assert.Equal(128, work.Length);
        Assert.Equal(128, saved.Candidates.Count);
        Assert.All(actual, value => Assert.Single(value.Witnesses));
    }

    [Fact]
    public void StreamedSelectionDoesNotRetainExpandedCandidateWitnessArrays()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        using var writing = new StreamedSelectionStore(fixture);
        var weak = WriteEphemeralSelection(writing.Storage);

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        Assert.False(weak.IsAlive);
        Assert.Single(writing.Storage.Questions());
        GC.KeepAlive(writing.Storage);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static WeakReference WriteEphemeralSelection(PathRequesterSelectionStorage storage)
    {
        var candidate = SelectionCandidate(UserDn) with
        { Witnesses = Enumerable.Range(0, 32).Select(index => new PathRequesterSelectionWitness(
            CoreDn, index, 0x40000, HolderDn, UserDn)).ToArray() };
        storage.Include(candidate);
        return new(candidate.Witnesses);
    }

    [Fact]
    public void StreamedSelectionKeepsOrdinalQuestionOrderingForSupplementaryNamesAndFamilies()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        using var writing = new StreamedSelectionStore(fixture);
        var emissions = new[] { "\uE000", "\U00010000", "z", "A", "\u00e9" }.SelectMany(name =>
            Enum.GetValues<PathRequesterFamily>().Select(family => SelectionCandidate($"CN={name},DC=contoso,DC=com") with
            {
                Family = family,
                GroupDn = family == PathRequesterFamily.MembershipDacl ? TargetDn : null,
                PermissionKind = family == PathRequesterFamily.RequesterDacl ? null : OwnAccountMembershipPermissionKind.SelfMembership,
            })).Reverse().ToArray();
        var collector = new RequesterSelectionEvaluation.Collector();
        foreach (var emission in emissions)
        {
            writing.Storage.Include(emission);
            collector.Include(emission);
        }
        var questions = writing.Storage.Questions().ToArray();
        var scan = writing.Scan();
        var expected = collector.Finish(scan);
        var expectedWork = PathRequesterSelector.Requests(expected).Select(RequesterDaclProofs.Key)
            .Concat(PathRequesterSelector.OwnAccounts(expected).Select(OwnAccountMembershipProofs.Key))
            .Concat(PathRequesterSelector.MembershipDacls(expected).Select(MembershipDaclProofs.Key)).ToArray();
        var actualWork = questions.Select(question => question.Family switch
        {
            PathRequesterFamily.RequesterDacl => RequesterDaclProofs.Key(new(question.RequesterDn, question.TargetDn)),
            PathRequesterFamily.OwnAccountMembership => OwnAccountMembershipProofs.Key(new(question.RequesterDn, question.TargetDn)
                { PermissionKind = question.PermissionKind!.Value }),
            PathRequesterFamily.MembershipDacl => MembershipDaclProofs.Key(new(question.RequesterDn, question.GroupDn!, question.TargetDn)
                { PermissionKind = question.PermissionKind!.Value }),
            _ => throw new InvalidDataException("Unrecognized family in the saved work plan."),
        }).ToArray();
        var saved = writing.Storage.Complete(scan);
        var actual = PathCalculationStorage.ReadRecords<PathRequesterCandidate>(fixture.Connection,
            fixture.Description, "Candidates", saved.Candidates, CancellationToken.None);

        Assert.Equal(expectedWork, actualWork);
        Assert.Equal(WorkJson(expected.Candidates), WorkJson(actual));
        Assert.Equal(Enumerable.Range(1, questions.Length).Select(value => (long)value), questions.Select(value => value.Id));
    }

    [Theory]
    [InlineData("UPDATE temp.path_selection_pending SET header=json_set(header,'$.RequesterFingerprint','ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')")]
    [InlineData("UPDATE temp.path_selection_pending SET candidate_sort=X'00'")]
    [InlineData("UPDATE temp.path_selection_pending SET work_sort=X'00'")]
    [InlineData("UPDATE temp.path_selection_use SET ordinal=ordinal+4")]
    [InlineData("UPDATE temp.path_selection_use SET fingerprint=zeroblob(32)")]
    [InlineData("UPDATE temp.path_selection_use SET identity='substituted'")]
    public void StreamedSelectionRefusesSubstitutedHeadersOrderAndWitnessBindings(string sql)
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        using var writing = new StreamedSelectionStore(fixture);
        writing.Storage.Include(SelectionCandidate(UserDn));
        using var corrupt = fixture.Connection.CreateCommand();
        corrupt.Transaction = writing.Transaction;
        corrupt.CommandText = sql;
        Assert.True(corrupt.ExecuteNonQuery() > 0);

        Assert.Throws<InvalidDataException>(() => writing.Storage.Complete(writing.Scan()));
    }

    [Fact]
    public void StreamedSelectionCancellationRollsBackPreviouslyWrittenSourcesAndWitnesses()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        var before = SelectionProofRows(fixture.Connection);
        using var stopping = new CancellationTokenSource();
        using (var writing = new StreamedSelectionStore(fixture, stopping.Token))
        {
            writing.Storage.Include(SelectionCandidate(UserDn));
            writing.Storage.Source(new(CoreDn, new string('d', 64)));
            stopping.Cancel();
            Assert.Throws<OperationCanceledException>(() => writing.Storage.Complete(writing.Scan()));
        }

        Assert.Equal(before, SelectionProofRows(fixture.Connection));
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("version")]
    [InlineData("fingerprint-shape")]
    public void StreamedSelectionCannotCompleteUnderAnotherScanBinding(string change)
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        using var writing = new StreamedSelectionStore(fixture);
        writing.Storage.Include(SelectionCandidate(UserDn));
        var scan = writing.Scan();
        scan = change switch
        {
            "generation" => scan with { JudgementGenerationId = Guid.NewGuid() },
            "version" => scan with { Version = 0 },
            _ => scan with { InputFingerprint = "unbound" },
        };

        Assert.Throws<InvalidDataException>(() => writing.Storage.Complete(scan));
    }

    [Fact]
    public void StreamedSelectionReleasesStagedSelectionBeforeAnyRequesterEvaluation()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        using (var clear = fixture.Connection.CreateCommand())
        {
            clear.CommandText = """
                DELETE FROM tier0_best_route; DELETE FROM tier0_distance; DELETE FROM tier0_distance_product;
                DELETE FROM path_requester_risk; DELETE FROM path_risk_product;
                DELETE FROM tier0_path_node; DELETE FROM tier0_path_calculation;
                """;
            clear.ExecuteNonQuery();
        }
        using var statements = new PreparedStatements(fixture.Connection);
        var selectionObserved = false;
        var evaluationObserved = false;
        Tier0PathStorage.Write(fixture.Connection, fixture.Description, fixture.Sources, [], [], CancellationToken.None,
            [], true, phase =>
            {
                if (phase is not (PathRequesterWorkPhase.SelectingQuestions or PathRequesterWorkPhase.OwnAccountMembership)) return;
                using var query = fixture.Connection.CreateCommand();
                query.CommandText = "SELECT COUNT(*) FROM sqlite_temp_master WHERE type='table' AND name LIKE 'path_selection_%'";
                var tables = (long)query.ExecuteScalar()!;
                if (phase == PathRequesterWorkPhase.SelectingQuestions) { Assert.Equal(4L, tables); selectionObserved = true; }
                else { Assert.Equal(0L, tables); evaluationObserved = true; }
            }, null, statements);

        Assert.True(selectionObserved);
        Assert.True(evaluationObserved);
        PathCalculationStorage.RequirePublishable(fixture.Connection, fixture.Description, CancellationToken.None);
    }

    private static PathRequesterCandidate SelectionCandidate(string requester) =>
        new(PathRequesterFamily.RequesterDacl, requester, CoreDn, null, null, new string('a', 64),
            [new(CoreDn, 0, 0x40000, HolderDn, UserDn)]);

    private static long SelectionProofRows(SqliteConnection connection)
    {
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT (SELECT COUNT(*) FROM path_proof)+(SELECT COUNT(*) FROM path_calculation_record)";
        return (long)query.ExecuteScalar()!;
    }

    private sealed class StreamedSelectionStore : IDisposable
    {
        private readonly PrerequisiteFixture _fixture;
        private readonly PreparedStatements _statements;
        private readonly PathProofStorage.Writer _proofs;
        internal SqliteTransaction Transaction { get; }
        internal PathRequesterSelectionStorage Storage { get; }

        internal StreamedSelectionStore(PrerequisiteFixture fixture, CancellationToken token = default)
        {
            _fixture = fixture;
            Transaction = fixture.Connection.BeginTransaction();
            _statements = new(fixture.Connection);
            _proofs = new(fixture.Connection, Transaction, token);
            var shared = new PathSharedProofStorage(fixture.Connection, fixture.Description, token, _proofs, Transaction, _statements);
            Storage = new(fixture.Connection, Transaction, fixture.Description, fixture.Sources, shared, _statements, token);
        }

        internal PathRequesterSelectionScan Scan() => new(PathRequesterSelector.Version, _fixture.Description.GenerationId,
            Tier0PathCalculation.Fingerprint(_fixture.Inputs), true);

        public void Dispose()
        {
            Storage.Dispose();
            _proofs.Dispose();
            _statements.Dispose();
            Transaction.Dispose();
        }
    }
}
