using System.Reflection;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    private const string OtherRequesterDn = "CN=Bob,DC=contoso,DC=com";
    private const string OtherGroupDn = "CN=OtherGroup,DC=contoso,DC=com";
    private const string UnicodeGroupDn = "CN=\u00e9quipe,DC=contoso,DC=com";

    [Theory]
    [InlineData("both-permissions")]
    [InlineData("deny-before")]
    [InlineData("allow-before-deny")]
    [InlineData("disabled")]
    [InlineData("existing-membership")]
    [InlineData("missing-schema")]
    [InlineData("missing-account-status")]
    [InlineData("unsupported-group")]
    [InlineData("no-membership-continuation")]
    [InlineData("different-requests")]
    [InlineData("exact-name-lookups")]
    public void SharedPrerequisitesKeepEveryPriorAnswerAndVersionedSourceFingerprint(string variant)
    {
        using var fixture = PrerequisiteFixtureFor(variant);
        OwnAccountMembershipRequest[] requests = [
            new(UserDn, TargetDn),
            new(UserDn, TargetDn) { PermissionKind = OwnAccountMembershipPermissionKind.WriteMembers },
        ];
        if (variant == "different-requests")
            requests = [.. requests, requests[0], new(OtherRequesterDn, TargetDn), new(UserDn, OtherGroupDn)];
        if (variant == "exact-name-lookups")
            requests = [.. requests, new(UserDn.ToUpperInvariant(), TargetDn.ToUpperInvariant()),
                new(UserDn, UnicodeGroupDn), new(UserDn, UnicodeGroupDn.ToUpperInvariant())];
        var combined = requests.Select(request => new MembershipDaclRequest(request.RequesterDn, request.TargetDn, CoreDn)
            { PermissionKind = request.PermissionKind }).ToArray();
        var expectedOwn = MembershipPrerequisiteReference.OwnAccounts(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, fixture.Inputs, fixture.Nodes, requests, CancellationToken.None, currentSourceFingerprints: true);
        var expectedCombined = MembershipPrerequisiteReference.Combined(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, fixture.Inputs, fixture.Nodes, combined, CancellationToken.None, fixture.Memberships, currentSourceFingerprints: true);

        var actualOwn = fixture.Prerequisites.Create(fixture.Nodes, requests);
        Assert.Equal(JsonSerializer.Serialize(expectedOwn, ProofSerialization.Options), JsonSerializer.Serialize(actualOwn, ProofSerialization.Options));
        var actualCombined = fixture.Combined(combined);
        Assert.Equal(JsonSerializer.Serialize(expectedCombined, ProofSerialization.Options), JsonSerializer.Serialize(actualCombined, ProofSerialization.Options));
        Assert.Equal(requests.Length, actualOwn.Count);
        Assert.Equal(combined.Length, actualCombined.Count);
        Assert.All(actualOwn, proof => Assert.Equal(fixture.Description.GenerationId, proof.Assessment.GenerationId));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void SharedPrerequisitesReuseTheAnswerWithoutLeakingAContinuationIssue(bool membershipContinuation)
    {
        using var fixture = PrerequisiteFixtureFor(membershipContinuation ? "both-permissions" : "no-membership-continuation");
        var request = new OwnAccountMembershipRequest(UserDn, TargetDn);
        var own = Assert.Single(fixture.Prerequisites.Create(fixture.Nodes, [request]));
        var combined = Assert.Single(fixture.Combined([new(UserDn, TargetDn, CoreDn)]));

        Assert.Equal(ControlEvaluationState.Established, combined.Assessment.Authorization);
        Assert.Same(own.Assessment.Permission, combined.Assessment.Membership.Permission);
        Assert.Same(own.Assessment.SchemaEvidence, combined.Assessment.Membership.SchemaEvidence);
        Assert.DoesNotContain(OwnAccountMembershipIssue.MembershipContinuationUnresolved, combined.Assessment.Membership.Issues);
        if (membershipContinuation)
        {
            Assert.Same(own.Assessment, combined.Assessment.Membership);
            Assert.NotEmpty(own.Steps);
        }
        else
        {
            Assert.Contains(OwnAccountMembershipIssue.MembershipContinuationUnresolved, own.Assessment.Issues);
            Assert.Empty(own.Steps);
        }
        var again = Assert.Single(fixture.Prerequisites.Create(fixture.Nodes, [request], membershipContinuation: false));
        Assert.Same(combined.Assessment.Membership, again.Assessment);
        Assert.Empty(again.Steps);
        Assert.Equal(own.SourceFingerprint, again.SourceFingerprint);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(16)]
    public void SharedPreparationReadsEachGroupAndItsHoldersOncePerBatch(int accounts)
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions", accounts);
        var requests = Enumerable.Range(0, accounts).SelectMany(index =>
            new[] { TargetDn, OtherGroupDn }.SelectMany(group =>
                Enum.GetValues<OwnAccountMembershipPermissionKind>().Select(kind =>
                    new OwnAccountMembershipRequest(PrerequisiteUser(index), group) { PermissionKind = kind }))).ToArray();
        using var evidence = new JudgingInputReuseTests.Statements(PrerequisiteEvidenceConnection(fixture.Sources.Bundle));
        using var judgement = new JudgingInputReuseTests.Statements(fixture.Connection);
        evidence.Sql.Clear();
        judgement.Sql.Clear();
        fixture.Identities.Reset();

        var answers = fixture.Prerequisites.Create(fixture.Nodes, requests, membershipContinuation: false);

        Assert.Equal(accounts * 4, answers.Count);
        Assert.Equal(1, fixture.Identities.ValuesRead);
        Assert.Equal(2, evidence.Sql.Count(sql => sql.StartsWith("SELECT s.descriptor_id,", StringComparison.Ordinal)));
        Assert.Equal(1, AttributeReads(evidence, TargetDn));
        Assert.Equal(1, AttributeReads(evidence, OtherGroupDn));
        Assert.Equal(2, AttributeReads(evidence, HolderDn));
        Assert.Equal(1, AttributeReads(evidence, "DC=contoso,DC=com"));
        Assert.All(Enumerable.Range(0, accounts), index => Assert.Equal(2, AttributeReads(evidence, PrerequisiteUser(index))));
        Assert.Equal(4, judgement.Sql.Count(IsMembershipEdgeQuery));
        Assert.All(answers, proof => Assert.Equal(ControlEvaluationState.Established, proof.Assessment.Obtainability));

        evidence.Sql.Clear();
        judgement.Sql.Clear();
        var reused = fixture.Prerequisites.Create(fixture.Nodes, requests.Reverse().ToArray(), membershipContinuation: false);
        Assert.Empty(evidence.Sql);
        Assert.Empty(judgement.Sql);
        Assert.Equal(JsonSerializer.Serialize(answers, ProofSerialization.Options), JsonSerializer.Serialize(reused, ProofSerialization.Options));
    }

    [Fact]
    public void SharedPreparationKeepsCommonInputsAcrossDifferentGroupBatches()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        using var evidence = new JudgingInputReuseTests.Statements(PrerequisiteEvidenceConnection(fixture.Sources.Bundle));
        fixture.Identities.Reset();
        var first = Assert.Single(fixture.Prerequisites.Create(fixture.Nodes, [new(UserDn, TargetDn)], membershipContinuation: false));
        evidence.Sql.Clear();

        var second = Assert.Single(fixture.Prerequisites.Create(fixture.Nodes, [new(UserDn, OtherGroupDn)], membershipContinuation: false));

        Assert.Equal(ControlEvaluationState.Established, second.Assessment.Obtainability);
        Assert.Same(first.Assessment.SchemaEvidence, second.Assessment.SchemaEvidence);
        Assert.Equal(1, fixture.Identities.ValuesRead);
        Assert.Equal(0, AttributeReads(evidence, "DC=contoso,DC=com"));
        Assert.DoesNotContain(evidence.Sql, sql => sql.Contains(" IS NOT NULL OR ", StringComparison.Ordinal)
            && sql.Contains(BundleSchema.ColumnNameFor("schemaIDGUID"), StringComparison.Ordinal));
        Assert.Equal(1, AttributeReads(evidence, OtherGroupDn));
    }

    [Fact]
    public void NormalPathWritingSharesPreChangeWorkBetweenTheTwoFamilies()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        using (var clear = fixture.Connection.CreateCommand())
        {
            clear.CommandText = "DELETE FROM tier0_best_route; DELETE FROM tier0_distance; DELETE FROM tier0_distance_product; DELETE FROM path_requester_risk; DELETE FROM path_risk_product; DELETE FROM tier0_path_node; DELETE FROM tier0_path_calculation";
            clear.ExecuteNonQuery();
        }
        using var trace = new JudgingInputReuseTests.Statements(fixture.Connection);
        using var statements = new PreparedStatements(fixture.Connection);
        var ownStart = 0;
        var combinedStart = 0;
        var storageStart = 0;
        Tier0PathStorage.Write(fixture.Connection, fixture.Description, fixture.Sources, [], [], CancellationToken.None, [], true,
            phase =>
            {
                if (phase == PathRequesterWorkPhase.OwnAccountMembership) ownStart = trace.Sql.Count;
                if (phase == PathRequesterWorkPhase.MembershipDacl) combinedStart = trace.Sql.Count;
                if (phase == PathRequesterWorkPhase.WritingProofs) storageStart = trace.Sql.Count;
            }, null, statements);

        Assert.True(combinedStart > ownStart);
        Assert.True(storageStart > combinedStart);
        Assert.Contains(trace.Sql.Skip(ownStart).Take(combinedStart - ownStart), IsMembershipEdgeQuery);
        Assert.DoesNotContain(trace.Sql.Skip(combinedStart).Take(storageStart - combinedStart), IsMembershipEdgeQuery);
        var proofs = PathRequesterRiskStorage.ReadProofs(fixture.Connection, fixture.Description, CancellationToken.None);
        Assert.NotEmpty(proofs.OwnAccounts);
        Assert.NotEmpty(proofs.MembershipDacls);
        var coverage = PathRequesterRiskStorage.ReadCoverage(fixture.Connection, fixture.Description, CancellationToken.None);
        Assert.Equal(proofs.OwnAccounts.Count, coverage.Families.Single(value => value.Family == PathRequesterFamily.OwnAccountMembership).Questions);
        Assert.Equal(proofs.MembershipDacls.Count, coverage.Families.Single(value => value.Family == PathRequesterFamily.MembershipDacl).Questions);
    }

    [Fact]
    public void SharedPrerequisitesDoNotReuseTheLaterPermissionVerdictAcrossResources()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        fixture.Prerequisites.Create(fixture.Nodes, [new(UserDn, TargetDn)]);
        var combined = fixture.Combined([new(UserDn, TargetDn, CoreDn), new(UserDn, TargetDn, "DC=contoso,DC=com")]);

        Assert.Equal(ControlEvaluationState.Established, combined.Single(proof => proof.Assessment.Request.TargetDn == CoreDn).Assessment.Authorization);
        Assert.NotEqual(ControlEvaluationState.Established,
            combined.Single(proof => proof.Assessment.Request.TargetDn == "DC=contoso,DC=com").Assessment.Authorization);
        Assert.Same(combined[0].Assessment.Membership, combined[1].Assessment.Membership);
    }

    [Theory]
    [InlineData("connection")]
    [InlineData("generation")]
    [InlineData("derivation")]
    [InlineData("evidence")]
    [InlineData("evaluation")]
    [InlineData("sources")]
    [InlineData("identities")]
    [InlineData("inputs")]
    [InlineData("cancellation")]
    public void SharedPrerequisitesCannotCrossTheirAttemptBinding(string changed)
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        fixture.Prerequisites.Create(fixture.Nodes, [new(UserDn, TargetDn)]);
        using var otherConnection = RiskDatabase(fixture.Reader, writableCopy: false);
        using var otherSources = ControlProofVerification.OpenSources(fixture.Reader);
        using var stopping = new CancellationTokenSource();
        var description = changed switch
        {
            "generation" => fixture.Description with { GenerationId = Guid.NewGuid() },
            "derivation" => fixture.Description with { DerivationGenerationId = Guid.NewGuid() },
            "evidence" => fixture.Description with { EvidenceSeal = new string('f', 64) },
            "evaluation" => fixture.Description with { EvaluationAsOf = fixture.Description.EvaluationAsOf.AddDays(1) },
            _ => fixture.Description,
        };

        Assert.Throws<InvalidDataException>(() => fixture.Prerequisites.RequireFor(
            changed == "connection" ? otherConnection : fixture.Connection, description,
            changed == "sources" ? otherSources : fixture.Sources,
            changed == "identities" ? new Dictionary<string, Tier0Target>(fixture.Identities, StringComparer.OrdinalIgnoreCase) : fixture.Identities,
            changed == "inputs" ? fixture.Inputs with { } : fixture.Inputs,
            changed == "cancellation" ? stopping.Token : CancellationToken.None));
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("evidence")]
    [InlineData("derivation")]
    public void SharedPrerequisitesRefuseInputsFromAnotherGeneration(string changed)
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        var inputs = changed switch
        {
            "generation" => fixture.Inputs with { JudgementGenerationId = Guid.NewGuid() },
            "evidence" => fixture.Inputs with { Input = fixture.Inputs.Input! with { EvidenceSeal = new string('f', 64) } },
            _ => fixture.Inputs with { Input = fixture.Inputs.Input! with { DerivationGenerationId = Guid.NewGuid() } },
        };
        var prerequisites = new OwnAccountMembershipProofs(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, inputs, CancellationToken.None);

        Assert.Throws<InvalidDataException>(() =>
        {
            if (changed == "generation") prerequisites.Create(fixture.Nodes, [new(UserDn, TargetDn)]);
            else prerequisites.RequireFor(fixture.Connection, fixture.Description, fixture.Sources, fixture.Identities, inputs, CancellationToken.None);
        });
    }

    [Theory]
    [InlineData("cancelled")]
    [InlineData("disposed")]
    [InlineData("replaced-derivation")]
    public void ReusingAMembershipAnswerStillChecksCancellationAndProtectedSources(string change)
    {
        using var stopping = new CancellationTokenSource();
        using var fixture = PrerequisiteFixtureFor("both-permissions", token: stopping.Token);
        fixture.Prerequisites.Create(fixture.Nodes, [new(UserDn, TargetDn)]);
        if (change == "cancelled") stopping.Cancel();
        else if (change == "disposed") fixture.Sources.Dispose();
        else Derive(fixture.Reader.BundleDirectory);

        var error = Record.Exception(() => fixture.Prerequisites.Create(fixture.Nodes, [new(UserDn, TargetDn)]));

        Assert.NotNull(error);
        if (change == "cancelled") Assert.IsType<OperationCanceledException>(error);
        else if (change == "disposed") Assert.IsType<ObjectDisposedException>(error);
        else Assert.IsType<InvalidOperationException>(error);
    }

    [Fact]
    public void NoMembershipQuestionsDoNotPrepareOrReadSources()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        using var evidence = new JudgingInputReuseTests.Statements(PrerequisiteEvidenceConnection(fixture.Sources.Bundle));
        using var judgement = new JudgingInputReuseTests.Statements(fixture.Connection);
        evidence.Sql.Clear();
        judgement.Sql.Clear();
        fixture.Identities.Reset();

        Assert.Empty(fixture.Prerequisites.Create(fixture.Nodes, []));
        Assert.Empty(fixture.Combined([]));

        Assert.Empty(evidence.Sql);
        Assert.Empty(judgement.Sql);
        Assert.Equal(0, fixture.Identities.ValuesRead);
    }

    [Theory]
    [InlineData(PathInputAvailability.NotProduced)]
    [InlineData(PathInputAvailability.RequiredInputsUnavailable)]
    public void SharedPrerequisitesPreserveUnavailableInputsWithoutInventingAnAnswer(PathInputAvailability availability)
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        var inputs = fixture.Inputs with { Availability = availability, Input = null };
        OwnAccountMembershipRequest[] requests = [new(UserDn, TargetDn)];
        var expected = MembershipPrerequisiteReference.OwnAccounts(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, inputs, fixture.Nodes, requests, CancellationToken.None, membershipContinuation: false, currentSourceFingerprints: true);
        var prerequisites = new OwnAccountMembershipProofs(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, inputs, CancellationToken.None);

        var actual = Assert.Single(prerequisites.Create(fixture.Nodes, requests, membershipContinuation: false));
        var reused = Assert.Single(prerequisites.Create(fixture.Nodes, requests, membershipContinuation: false));

        Assert.Equal(JsonSerializer.Serialize(expected[0], ProofSerialization.Options), JsonSerializer.Serialize(actual, ProofSerialization.Options));
        Assert.Equal(ControlEvaluationState.Unknown, actual.Assessment.Obtainability);
        Assert.Contains(OwnAccountMembershipIssue.PathInputsUnavailable, actual.Assessment.Issues);
        Assert.Same(actual.Assessment, reused.Assessment);
    }

    private PrerequisiteFixture PrerequisiteFixtureFor(string variant, int accounts = 2, CancellationToken token = default,
        string? coreDescriptor = null)
    {
        var grant = $"(OA;;SW;{MemberGuid};;{HolderSid})(OA;;WP;{MemberGuid};;{HolderSid})";
        var deny = $"(OD;;SW;{MemberGuid};;{UserSid})(OD;;WP;{MemberGuid};;{UserSid})";
        var directory = Capture("O:SYG:SYD:" + (variant == "deny-before" ? deny + grant
                : variant == "allow-before-deny" ? grant + deny : grant),
            members: variant == "existing-membership" ? [UserDn] : [],
            groupType: variant == "unsupported-group" ? -2147483644 : -2147483646,
            schema: variant != "missing-schema", membershipTail: variant != "no-membership-continuation",
            coreMembers: variant == "no-membership-continuation" ? [] : [TargetDn, OtherGroupDn, UnicodeGroupDn],
            userAttributes: variant == "disabled" ? Account("514", "513")
                : variant == "missing-account-status" ? Account(null, "513") : null,
            holderMembers: Enumerable.Range(0, accounts).Select(PrerequisiteUser).ToArray(),
            coreDescriptor: coreDescriptor ?? $"O:SYG:SYD:(A;;WD;;;{TargetSid})(A;;WD;;;{UserSid})",
            additional: (writer, coverage) =>
            {
                for (var index = 1; index < accounts; index++)
                    Write(writer, coverage, PrerequisiteUser(index), ["top", "person", "organizationalPerson", "user"],
                        $"S-1-5-21-1-2-3-{2100 + index}", Account("512", "513"), "O:SYG:SYD:");
                Write(writer, coverage, OtherGroupDn, ["top", "group"], "S-1-5-21-1-2-3-2200",
                    [Text("groupType", "-2147483646")], "O:SYG:SYD:" + grant);
                Write(writer, coverage, UnicodeGroupDn, ["top", "group"], "S-1-5-21-1-2-3-2201",
                    [Text("groupType", "-2147483646")], "O:SYG:SYD:" + grant);
            });
        Derive(directory);
        Judge(directory, []);
        return new(directory, token);
    }

    private static string PrerequisiteUser(int index) => index == 0 ? UserDn : index == 1 ? OtherRequesterDn : $"CN=User{index},DC=contoso,DC=com";

    private static bool IsMembershipEdgeQuery(string sql) => sql.StartsWith("SELECT id FROM control_edge WHERE target=", StringComparison.Ordinal)
        && (sql.Contains(nameof(ControlCapability.CanAddSelfToGroup), StringComparison.Ordinal)
            || sql.Contains(nameof(ControlCapability.CanModifyGroupMembership), StringComparison.Ordinal));

    private static int AttributeReads(JudgingInputReuseTests.Statements trace, string dn) => trace.Sql.Count(sql =>
        sql.StartsWith("SELECT o.object_id, o.distinguished_name,", StringComparison.Ordinal)
        && sql.Contains("WHERE o.distinguished_name = '" + dn + "' COLLATE NOCASE", StringComparison.Ordinal));

    private static SqliteConnection PrerequisiteEvidenceConnection(BundleReader bundle) => Assert.IsType<SqliteConnection>(
        typeof(BundleReader).GetField("_connection", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(bundle));

    private sealed class PrerequisiteFixture : IDisposable
    {
        internal JudgementReader Reader { get; }
        internal JudgementDescription Description => Reader.Description;
        internal SqliteConnection Connection { get; }
        internal JudgingInputs Sources { get; }
        internal ObtainedIdentityVisits Identities { get; }
        internal PathInputs Inputs { get; }
        internal Dictionary<string, Tier0PathNode> Nodes { get; } = new(StringComparer.OrdinalIgnoreCase);
        internal RequesterMembershipContext? Memberships { get; }
        internal OwnAccountMembershipProofs Prerequisites { get; }
        private readonly CancellationToken _token;

        internal PrerequisiteFixture(string directory, CancellationToken token)
        {
            _token = token;
            Reader = Open(directory);
            Connection = RiskDatabase(Reader, writableCopy: true);
            Sources = ControlProofVerification.OpenSources(Reader);
            Identities = new(OwnershipAuditStorage.Targets(Connection).ToDictionary(value => value.Identity.DistinguishedName,
                value => value.Identity, StringComparer.OrdinalIgnoreCase));
            Inputs = Reader.ReadPathInputs();
            Memberships = RequesterMembershipContext.Create(Sources, Identities, Inputs, token);
            using var command = Connection.CreateCommand();
            command.CommandText = "SELECT proof,fingerprint FROM tier0_path_node";
            using var read = command.ExecuteReader();
            while (read.Read())
            {
                var node = PathProofStorage.Read<Tier0PathNode>(Connection, read.GetInt64(0),
                    Convert.ToHexString((byte[])read.GetValue(1)), token);
                Nodes.Add(node.Subject.DistinguishedName, node);
            }
            Prerequisites = new(Connection, Description, Sources, Identities, Inputs, token);
        }

        internal IReadOnlyList<SavedMembershipDaclProof> Combined(IReadOnlyList<MembershipDaclRequest> requests) =>
            MembershipDaclProofs.Create(Connection, Description, Sources, Identities, Inputs, Nodes, requests,
                _token, Memberships, Prerequisites);

        public void Dispose()
        {
            Sources.Dispose();
            Connection.Dispose();
            Reader.Dispose();
        }
    }
}
