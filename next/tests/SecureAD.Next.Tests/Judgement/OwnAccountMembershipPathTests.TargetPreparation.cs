using System.Text.Json;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Theory]
    [InlineData("captured")]
    [InlineData("obtained-self")]
    [InlineData("obtained-write")]
    [InlineData("mixed-contexts")]
    [InlineData("different-groups")]
    [InlineData("duplicate-questions")]
    [InlineData("exact-name-lookups")]
    [InlineData("missing-inputs")]
    [InlineData("wrong-generation")]
    [InlineData("wrong-evidence")]
    [InlineData("wrong-requester")]
    public void TargetPreparationPreservesPriorAnswersVersionedFingerprintsAndInputOrder(string variant)
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        var memberships = fixture.Prerequisites.Create(fixture.Nodes,
            [new(UserDn, TargetDn), new(OtherRequesterDn, TargetDn), new(UserDn, OtherGroupDn),
                new(UserDn, TargetDn) { PermissionKind = OwnAccountMembershipPermissionKind.WriteMembers }],
            membershipContinuation: false);
        var own = memberships.Single(proof => proof.Assessment.Request == new OwnAccountMembershipRequest(UserDn, TargetDn)).Assessment;
        var other = memberships.Single(proof => proof.Assessment.Request == new OwnAccountMembershipRequest(OtherRequesterDn, TargetDn)).Assessment;
        var inputs = fixture.Inputs;
        RequesterDaclProofs.Question[] questions =
        [
            new(new(UserDn, CoreDn), null),
            new(new(OtherRequesterDn, "DC=contoso,DC=com"), null),
            new(new(OtherRequesterDn, CoreDn), null),
            new(new(UserDn, "DC=contoso,DC=com"), null),
        ];
        if (variant != "captured")
            questions = questions.Select(question => question with
            { ObtainedMembership = question.Request.RequesterDn == UserDn ? own : other }).ToArray();
        switch (variant)
        {
            case "obtained-write":
                questions[0] = questions[0] with { ObtainedMembership = memberships.Single(proof =>
                    proof.Assessment.Request.PermissionKind == OwnAccountMembershipPermissionKind.WriteMembers).Assessment };
                break;
            case "mixed-contexts":
                questions = [questions[0] with { ObtainedMembership = null }, questions[0], .. questions];
                break;
            case "different-groups":
                questions = [.. questions, questions[0] with { ObtainedMembership = memberships.Single(proof =>
                    proof.Assessment.Request.TargetDn == OtherGroupDn).Assessment }];
                break;
            case "duplicate-questions":
                questions = [.. questions, questions[0], questions[2], questions[0]];
                break;
            case "exact-name-lookups":
                questions = [.. questions, new(new(UserDn.ToUpperInvariant(), CoreDn.ToUpperInvariant()), own),
                    new(new(UserDn, UnicodeGroupDn), null), new(new(UserDn, UnicodeGroupDn.ToUpperInvariant()), null)];
                break;
            case "missing-inputs":
                inputs = inputs with { Availability = PathInputAvailability.RequiredInputsUnavailable, Input = null };
                break;
            case "wrong-generation": questions[0] = questions[0] with { ObtainedMembership = own with { GenerationId = Guid.NewGuid() } }; break;
            case "wrong-evidence": questions[0] = questions[0] with { ObtainedMembership = own with { EvidenceSeal = new string('f', 64) } }; break;
            case "wrong-requester": questions[0] = questions[0] with { ObtainedMembership = other }; break;
        }
        var expected = questions.Select(question => Assert.Single(TargetPermissionReference.Create(fixture.Connection,
            fixture.Description, fixture.Sources, fixture.Identities, inputs, [question.Request], CancellationToken.None,
            question.ObtainedMembership, fixture.Memberships, currentSourceFingerprints: true))).ToArray();

        var actual = RequesterDaclProofs.Create(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, inputs, questions, CancellationToken.None, fixture.Memberships);

        Assert.Equal(JsonSerializer.Serialize(expected, ProofSerialization.Options), JsonSerializer.Serialize(actual, ProofSerialization.Options));
        Assert.Equal(questions.Select(question => question.Request), actual.Select(proof => proof.Assessment.Request));
        Assert.Equal(questions.Length, actual.Count);
    }

    [Theory]
    [InlineData(false, 2)]
    [InlineData(false, 16)]
    [InlineData(true, 2)]
    [InlineData(true, 16)]
    public void TargetPreparationReadsTwoResourcesInsteadOfOnePerQuestion(bool obtained, int accounts)
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions", accounts);
        var memberships = fixture.Prerequisites.Create(fixture.Nodes, Enumerable.Range(0, accounts)
            .Select(index => new OwnAccountMembershipRequest(PrerequisiteUser(index), TargetDn)).ToArray(), membershipContinuation: false)
            .ToDictionary(proof => proof.Assessment.Request.RequesterDn, StringComparer.Ordinal);
        var questions = Enumerable.Range(0, accounts).SelectMany(index => new[] { CoreDn, "DC=contoso,DC=com" }
            .Select(target => new RequesterDaclProofs.Question(new(PrerequisiteUser(index), target),
                obtained ? memberships[PrerequisiteUser(index)].Assessment : null))).ToArray();
        using var evidence = new JudgingInputReuseTests.Statements(PrerequisiteEvidenceConnection(fixture.Sources.Bundle));
        using var judgement = new JudgingInputReuseTests.Statements(fixture.Connection);
        evidence.Sql.Clear();
        judgement.Sql.Clear();

        var answers = RequesterDaclProofs.Create(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, fixture.Inputs, questions, CancellationToken.None, memberships: null);

        Assert.Equal(accounts * 2, answers.Count);
        Assert.Equal(2, DescriptorReads(evidence.Sql));
        Assert.Equal(2, judgement.Sql.Count(IsDaclEdgeQuery));
        Assert.Equal(1, AttributeReads(evidence, CoreDn));
        Assert.Equal(1, AttributeReads(evidence, "DC=contoso,DC=com"));
        Assert.Equal(2, AttributeReads(evidence, UserDn));
        Assert.Equal(3, judgement.Sql.Count(sql => sql.Contains("FROM control_ace a LEFT JOIN permission_entry", StringComparison.Ordinal)));
        Assert.All(answers.Where(proof => proof.Assessment.Request.TargetDn == "DC=contoso,DC=com"),
            proof => Assert.NotEqual(ControlEvaluationState.Established, proof.Assessment.Authorization));
        Assert.Equal(obtained ? accounts : 1, answers.Count(proof => proof.Assessment.Authorization == ControlEvaluationState.Established));
    }

    [Theory]
    [InlineData("both-permissions")]
    [InlineData("disabled")]
    [InlineData("no-membership-continuation")]
    public void CombinedTargetPreparationRetainsEveryPriorContextAndDuplicate(string variant)
    {
        using var fixture = PrerequisiteFixtureFor(variant);
        MembershipDaclRequest[] requests =
        [
            new(UserDn, TargetDn, CoreDn),
            new(OtherRequesterDn, TargetDn, CoreDn),
            new(UserDn, TargetDn, "DC=contoso,DC=com"),
            new(UserDn, OtherGroupDn, CoreDn),
            new(UserDn, TargetDn, CoreDn) { PermissionKind = OwnAccountMembershipPermissionKind.WriteMembers },
            new(UserDn, TargetDn, CoreDn),
        ];
        var expected = MembershipPrerequisiteReference.Combined(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, fixture.Inputs, fixture.Nodes, requests, CancellationToken.None, fixture.Memberships, currentSourceFingerprints: true);

        var actual = fixture.Combined(requests);

        Assert.Equal(JsonSerializer.Serialize(expected, ProofSerialization.Options), JsonSerializer.Serialize(actual, ProofSerialization.Options));
        Assert.Equal(requests.Length, actual.Count);
    }

    [Fact]
    public void NormalPathWritingBatchesBothRequesterPermissionFamiliesByTarget()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions", 4,
            coreDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})(A;;WD;;;{HolderSid})");
        using (var clear = fixture.Connection.CreateCommand())
        {
            clear.CommandText = "DELETE FROM path_requester_risk; DELETE FROM path_risk_product; DELETE FROM tier0_path_node; DELETE FROM tier0_path_calculation";
            clear.ExecuteNonQuery();
        }
        using var trace = new JudgingInputReuseTests.Statements(fixture.Connection);
        using var statements = new PreparedStatements(fixture.Connection);
        var starts = new Dictionary<PathRequesterWorkPhase, int>();
        Tier0PathStorage.Write(fixture.Connection, fixture.Description, fixture.Sources, [], [], CancellationToken.None,
            [], true, phase => starts[phase] = trace.Sql.Count, null, statements);
        var saved = PathRequesterRiskStorage.ReadProofs(fixture.Connection, fixture.Description, CancellationToken.None);
        var directQueries = trace.Sql.Skip(starts[PathRequesterWorkPhase.RequesterDacl])
            .Take(starts[PathRequesterWorkPhase.OwnAccountMembership] - starts[PathRequesterWorkPhase.RequesterDacl]).Count(IsDaclEdgeQuery);
        var combinedQueries = trace.Sql.Skip(starts[PathRequesterWorkPhase.MembershipDacl])
            .Take(starts[PathRequesterWorkPhase.WritingProofs] - starts[PathRequesterWorkPhase.MembershipDacl]).Count(IsDaclEdgeQuery);
        var directTargets = saved.Requesters.Select(proof => proof.Assessment.Request.TargetDn).Distinct(StringComparer.Ordinal).Count();
        var combinedTargets = saved.MembershipDacls.Where(proof => proof.Assessment.Dacl is not null)
            .Select(proof => proof.Assessment.Request.TargetDn).Distinct(StringComparer.Ordinal).Count();

        Assert.True(saved.Requesters.Count > directTargets);
        Assert.True(saved.MembershipDacls.Count(proof => proof.Assessment.Dacl is not null) > combinedTargets);
        Assert.Equal(directTargets, directQueries);
        Assert.Equal(combinedTargets, combinedQueries);
        Assert.Equal(saved.Requesters.OrderBy(proof => RequesterDaclProofs.Key(proof.Assessment.Request), StringComparer.Ordinal), saved.Requesters);
    }

    [Fact]
    public void TargetPreparationDoesNotRetainSourcesBetweenBatches()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        RequesterDaclProofs.Question[] questions = [new(new(UserDn, CoreDn), null)];
        using var evidence = new JudgingInputReuseTests.Statements(PrerequisiteEvidenceConnection(fixture.Sources.Bundle));
        evidence.Sql.Clear();
        var first = RequesterDaclProofs.Create(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, fixture.Inputs, questions, CancellationToken.None, memberships: null);
        var firstReads = DescriptorReads(evidence.Sql);
        evidence.Sql.Clear();

        var second = RequesterDaclProofs.Create(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, fixture.Inputs, questions, CancellationToken.None, memberships: null);

        Assert.Equal(1, firstReads);
        Assert.Equal(firstReads, DescriptorReads(evidence.Sql));
        Assert.Equal(JsonSerializer.Serialize(first, ProofSerialization.Options), JsonSerializer.Serialize(second, ProofSerialization.Options));
    }

    [Theory]
    [InlineData("cancelled")]
    [InlineData("disposed")]
    [InlineData("replaced-derivation")]
    public void TargetPreparationRefusesInterruptedOrChangedSourceInputs(string change)
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        using var stopping = new CancellationTokenSource();
        if (change == "cancelled") stopping.Cancel();
        else if (change == "disposed") fixture.Sources.Dispose();
        else Derive(fixture.Reader.BundleDirectory);

        var error = Record.Exception(() => RequesterDaclProofs.Create(fixture.Connection, fixture.Description,
            fixture.Sources, fixture.Identities, fixture.Inputs, [new(new(UserDn, CoreDn), null)], stopping.Token, fixture.Memberships));

        Assert.NotNull(error);
        if (change == "cancelled") Assert.IsType<OperationCanceledException>(error);
        else if (change == "disposed") Assert.IsType<ObjectDisposedException>(error);
        else Assert.IsType<InvalidOperationException>(error);
    }

    [Fact]
    public void NoRequesterQuestionsDoNotPrepareTargetEvidence()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        using var evidence = new JudgingInputReuseTests.Statements(PrerequisiteEvidenceConnection(fixture.Sources.Bundle));
        using var judgement = new JudgingInputReuseTests.Statements(fixture.Connection);
        evidence.Sql.Clear();
        judgement.Sql.Clear();

        Assert.Empty(RequesterDaclProofs.Create(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, fixture.Inputs, [], CancellationToken.None, fixture.Memberships));

        Assert.Empty(evidence.Sql);
        Assert.Empty(judgement.Sql);
    }

    [Fact]
    public void TargetPreparationCanCancelWhileGroupingQuestions()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        using var stopping = new CancellationTokenSource();
        var questions = new TargetPermissionReference.CancellingList<RequesterDaclProofs.Question>(new(new(UserDn, CoreDn), null), stopping);

        Assert.Throws<OperationCanceledException>(() => RequesterDaclProofs.Create(fixture.Connection, fixture.Description,
            fixture.Sources, fixture.Identities, fixture.Inputs, questions, stopping.Token, fixture.Memberships));
        Assert.Equal(2, questions.Visits);
    }

    private static int DescriptorReads(IEnumerable<string> statements) =>
        statements.Count(sql => sql.StartsWith("SELECT s.descriptor_id,", StringComparison.Ordinal));

    private static bool IsDaclEdgeQuery(string sql) => sql.StartsWith("SELECT id FROM control_edge WHERE target=", StringComparison.Ordinal)
        && sql.Contains("capability='CanWriteDacl'", StringComparison.Ordinal);
}
