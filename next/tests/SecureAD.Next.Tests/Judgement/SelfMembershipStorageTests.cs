using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class SelfMembershipStorageTests
{
    private const string Seal = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Requester = "CN=Alice,DC=contoso,DC=com";
    private const string Target = "CN=Target,DC=contoso,DC=com";
    private const string RequesterSid = "S-1-5-21-1-2-3-1200";
    private const string TargetSid = "S-1-5-21-1-2-3-1300";
    private static readonly Guid RequesterGuid = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid TargetGuid = Guid.Parse("22222222-2222-2222-2222-222222222222");

    public static IEnumerable<object[]> InvalidRows()
    {
        foreach (var column in new[] { "issues_json", "evidence_json", "holder_edges_json" })
            foreach (var value in new[] { "null", "{}", "[", "[null]" })
                yield return [column + ":" + value, column, value];
        foreach (var column in new[] { "operation", "authorization", "own_account", "readiness" })
            foreach (var value in new[] { "999", "NotAnEnum" })
                yield return [column + ":" + value, column, value];
        foreach (var column in new[] { "generation", "derivation_generation", "requester_guid", "target_guid", "member_guid", "requester_captured_utc" })
            yield return [column, column, "not-a-value"];
        foreach (var column in new[] { "requester_dn", "target_dn", "descriptor_outcome" })
            yield return [column, column, " "];
        yield return ["issue enum", "issues_json", "[999]"];
        yield return ["nonboolean member state", "member_present", "2"];
        yield return ["fractional member state", "member_present", "1.5"];
        yield return ["text member state", "member_present", "not-a-value"];
        yield return ["text account state", "user_account_control", "not-a-value"];
        yield return ["missing edge", "holder_edges_json", "[42]"];
        yield return ["zero edge", "holder_edges_json", "[0]"];
        yield return ["negative edge", "holder_edges_json", "[-1]"];
        yield return ["duplicate edge", "holder_edges_json", "[1,1]"];
        yield return ["wrong seal", "evidence_seal", new string('b', 64)];
        yield return ["wrong generation", "generation", Guid.Empty.ToString("D")];
        yield return ["wrong derivation", "derivation_generation", Guid.Empty.ToString("D")];
        foreach (var (path, fields) in new (string Path, string[] Fields)[]
        {
            ("", ["Entry", "Scope", "Trustee"]),
            ("Entry", ["Ordinal", "AceType", "Trustee", "AccessMask", "ObjectTypeGuid", "InheritedObjectTypeGuid", "IsInherited", "InheritanceFlags", "PropagationFlags", "HasObjectType", "HasInheritedObjectType", "ApplicationData"]),
            ("Entry.Trustee", ["Sid", "Name", "DistinguishedName", "DomainFqdn", "UnresolvedReason", "WellKnownRole", "Meaning"]),
            ("Trustee", ["TrusteeSid", "State", "Reason", "HolderGuid", "HolderDn", "HolderDomain", "GroupType", "CapturedUtc", "DirectMemberDn"]),
        })
            foreach (var field in fields)
                yield return ["missing " + path + "." + field, "evidence_json", MutatedEvidence(path, field, null, remove: true)];
        foreach (var (path, field) in new[]
        {
            ("", "Entry"), ("", "Trustee"), ("Entry", "AceType"), ("Entry", "Trustee"),
            ("Entry", "ApplicationData"), ("Entry.Trustee", "Sid"), ("Trustee", "TrusteeSid"),
        })
            yield return ["null " + path + "." + field, "evidence_json", MutatedEvidence(path, field, null)];
        foreach (var (path, field) in new[]
        {
            ("", "Scope"), ("Trustee", "State"), ("Trustee", "Reason"),
            ("Entry.Trustee", "UnresolvedReason"), ("Entry.Trustee", "WellKnownRole"),
        })
            foreach (var value in new JsonNode?[] { JsonValue.Create(999), JsonValue.Create("NotAnEnum") })
                yield return ["enum " + path + "." + field + ":" + value, "evidence_json", MutatedEvidence(path, field, value)];
        foreach (var field in new[] { "HolderGuid", "CapturedUtc" })
            yield return ["invalid " + field, "evidence_json", MutatedEvidence("Trustee", field, JsonValue.Create("not-a-value"))];
        foreach (var (path, field) in new[] { ("Entry", "AceType"), ("Entry.Trustee", "Sid"), ("Trustee", "TrusteeSid") })
            yield return ["blank " + path + "." + field, "evidence_json", MutatedEvidence(path, field, JsonValue.Create(" "))];
        yield return ["inapplicable trustee", "evidence_json", MutatedEvidence("Trustee", "State", JsonValue.Create((int)RequesterTrusteeState.DoesNotMatch))];
        yield return ["mismatched trustee", "evidence_json", MutatedEvidence("Trustee", "TrusteeSid", JsonValue.Create(TargetSid))];
        yield return ["negative ordinal", "evidence_json", MutatedEvidence("Entry", "Ordinal", JsonValue.Create(-1))];
    }

    [Theory]
    [MemberData(nameof(InvalidRows))]
    public void MalformedSealedRowIsRejectedInBothDirections(string mutation, string column, string value)
    {
        var directory = Store(connection => SetRow(connection, column, value));
        using var reader = Open(directory);
        var error = Assert.Throws<InvalidDataException>(() => reader.ReadSelfMembershipAssessments(column == "target_dn" ? value : Target, null));
        Assert.Contains("Self-Membership assessment", error.Message);
        Assert.Contains(column == "evidence_json" && mutation == "inapplicable trustee" ? "holder_edges_json" : column, error.Message);
        Assert.Throws<InvalidDataException>(() => reader.ReadSelfMembershipAssessments(null, column == "requester_dn" ? value : Requester));
        Assert.False(string.IsNullOrWhiteSpace(mutation));
    }

    [Theory]
    [MemberData(nameof(InvalidRows))]
    public void ShellReportsMalformedSealedRowsAsReadFailures(string mutation, string column, string value)
    {
        var directory = Store(connection => SetRow(connection, column, value));
        using var source = new BundleAssetSource();
        foreach (var byTarget in new[] { true, false })
        {
            var result = source.ReadSelfMembershipAssessments(directory,
                byTarget ? column == "target_dn" ? value : Target : null,
                byTarget ? null : column == "requester_dn" ? value : Requester);
            Assert.False(result.IsSuccess, mutation);
            Assert.Equal("Shell.SelfMembershipAssessmentsUnreadable", result.Error.Code);
        }
    }

    [Theory]
    [InlineData("DELETE FROM control_product")]
    [InlineData("UPDATE control_product SET completed=0")]
    [InlineData("UPDATE control_product SET engine_version=999")]
    [InlineData("INSERT INTO control_object SELECT 'CN=Other,DC=contoso,DC=com',principal_sid,principal_scope,descriptor_outcome,uncertainty,is_complete FROM control_object; UPDATE control_edge SET target='CN=Other,DC=contoso,DC=com'")]
    [InlineData("UPDATE control_edge SET target_guid='99999999-9999-9999-9999-999999999999'")]
    [InlineData("UPDATE control_edge SET target_guid=NULL")]
    [InlineData("UPDATE control_edge SET target_guid='not-a-guid'")]
    [InlineData("UPDATE control_edge SET capability='CanWriteDacl'")]
    [InlineData("UPDATE control_edge SET holder_sid='S-1-5-21-1-2-3-9999'")]
    [InlineData("UPDATE control_edge SET holder_scope='other.com'")]
    [InlineData("UPDATE control_edge SET generation='99999999-9999-9999-9999-999999999999'")]
    [InlineData("UPDATE control_edge SET derivation_generation=NULL")]
    [InlineData("UPDATE control_edge SET derivation_generation='99999999-9999-9999-9999-999999999999'")]
    [InlineData("UPDATE control_edge SET generation='not-a-guid'")]
    [InlineData("UPDATE control_edge SET counted=0")]
    public void HolderReferencesRequireMatchingCompletedControlProduct(string sql)
    {
        var directory = Store(connection => Execute(connection, sql));
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.ReadSelfMembershipAssessments(Target, null));
        Assert.Throws<InvalidDataException>(() => reader.ReadSelfMembershipAssessments(null, Requester));
        using var source = new BundleAssetSource();
        Assert.False(source.ReadSelfMembershipAssessments(directory, Target, null).IsSuccess);
    }

    [Theory]
    [InlineData("DELETE FROM self_membership_product")]
    [InlineData("UPDATE self_membership_product SET completed=0")]
    [InlineData("UPDATE self_membership_product SET evaluator_version=999")]
    public void OrphanedOrIncompleteRequesterProductCannotLookComplete(string sql)
    {
        var directory = Store(connection => Execute(connection, sql));
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.ReadSelfMembershipAssessments(Target, null));
        Assert.Throws<InvalidDataException>(() => reader.ReadSelfMembershipAssessments(null, Requester));
        Assert.Throws<InvalidDataException>(() => reader.ReadSelfMembershipAssessments("CN=Unrequested,DC=contoso,DC=com", null));
        using var source = new BundleAssetSource();
        Assert.Equal("Shell.SelfMembershipAssessmentsUnreadable", source.ReadSelfMembershipAssessments(directory, Target, null).Error.Code);
    }

    [Theory]
    [InlineData("contoso.com", true)]
    [InlineData("CONTOSO.COM", true)]
    [InlineData("other.com", false)]
    [InlineData(null, false)]
    public void BuiltinReferencesRequireTheTargetResourceScope(string? scope, bool valid)
    {
        var directory = Store(connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE control_edge SET holder_scope=$scope";
            command.Parameters.AddWithValue("$scope", (object?)scope ?? DBNull.Value);
            command.ExecuteNonQuery();
        }, builtin: true);
        using var reader = Open(directory);
        using var source = new BundleAssetSource();
        foreach (var byTarget in new[] { true, false })
        {
            if (valid)
                Assert.Equal(2, reader.ReadSelfMembershipAssessments(byTarget ? Target : null, byTarget ? null : Requester).Assessments.Count);
            else
                Assert.Throws<InvalidDataException>(() => reader.ReadSelfMembershipAssessments(byTarget ? Target : null, byTarget ? null : Requester));
            Assert.Equal(valid, source.ReadSelfMembershipAssessments(directory, byTarget ? Target : null, byTarget ? null : Requester).IsSuccess);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ValidDirectAndSelfReferencesPreserveBothOperationsAndCounts(bool self)
    {
        var directory = Store(self: self);
        using var reader = Open(directory);
        var byTarget = reader.ReadSelfMembershipAssessments(Target.ToUpperInvariant(), null);
        var byRequester = reader.ReadSelfMembershipAssessments(null, Requester.ToUpperInvariant());
        Assert.True(byTarget.ProductWasDerived);
        Assert.Equal(2, byTarget.Assessments.Count);
        Assert.Equal(JsonSerializer.Serialize(byTarget), JsonSerializer.Serialize(byRequester));
        var edge = Assert.Single(reader.ReadControlEdges(Target, null, null, true, 0).Edges);
        foreach (var assessment in byTarget.Assessments)
        {
            Assert.Equal([edge.Id], assessment.HolderEdgeIds);
            Assert.NotNull(assessment.DerivationGenerationId);
            Assert.Equal(reader.Description.DerivationGenerationId, assessment.DerivationGenerationId);
            Assert.Equal(Seal, assessment.EvidenceSeal);
            Assert.Equal(self ? "S-1-5-10" : RequesterSid, Assert.Single(assessment.Evidence).Entry.Trustee.Sid);
        }
        using var source = new BundleAssetSource();
        Assert.True(source.ReadSelfMembershipAssessments(directory, Target, null).IsSuccess);
        Assert.True(source.ReadSelfMembershipAssessments(directory, null, Requester).IsSuccess);
    }

    [Fact]
    public void ExplicitMissingEvidenceAndEmptyCollectionsRemainValidUnknowns()
    {
        var directory = Store(connection => Execute(connection, """
            UPDATE self_membership_assessment SET requester_guid=NULL,requester_sid=NULL,target_guid=NULL,target_sid=NULL,
                member_guid=NULL,member_sid=NULL,requester_captured_utc=NULL,user_account_control=NULL,member_present=NULL,
                authorization='Unknown',own_account='Unknown',readiness='Unknown',descriptor_outcome='DescriptorNotRead',
                issues_json='[0,3,5]',evidence_json='[]',holder_edges_json='[]';
            DELETE FROM control_product;
            """));
        using var reader = Open(directory);
        var values = reader.ReadSelfMembershipAssessments(Target, null).Assessments;
        Assert.Equal(2, values.Count);
        Assert.All(values, value =>
        {
            Assert.Equal(ControlEvaluationState.Unknown, value.Authorization);
            Assert.Null(value.RequesterGuid);
            Assert.Null(value.MemberPresent);
            Assert.Empty(value.Evidence);
            Assert.Empty(value.HolderEdgeIds);
        });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EmptyAndUnscheduledProductsKeepTheirDistinctMeanings(bool derived)
    {
        var directory = Store(connection => Execute(connection, "DELETE FROM self_membership_assessment;"
            + (derived ? "" : "DELETE FROM self_membership_discovery; DELETE FROM self_membership_product;")));
        using var reader = Open(directory);
        var result = reader.ReadSelfMembershipAssessments(Target, null);
        Assert.Equal(derived, result.ProductWasDerived);
        Assert.Empty(result.Assessments);
        Assert.Equal(derived, result.GenerationId.HasValue);
    }

    private static string MutatedEvidence(string path, string field, JsonNode? value, bool remove = false)
    {
        var root = JsonSerializer.SerializeToNode(new[] { Evidence(false) })!;
        var node = root[0]!;
        if (path.Length != 0)
            foreach (var part in path.Split('.')) node = node[part]!;
        if (remove) Assert.True(node.AsObject().Remove(field));
        else node[field] = value;
        return root.ToJsonString();
    }

    private static SelfMembershipAceEvidence Evidence(bool self, bool builtin = false)
    {
        var entry = GroupMembershipControlTests.Scoped(0, 0x08);
        entry = entry with { Trustee = entry.Trustee with { Sid = builtin ? "S-1-5-32-544" : self ? "S-1-5-10" : RequesterSid, DistinguishedName = self || builtin ? null : Requester } };
        return new(entry, ControlEvaluationState.Established, new(entry.Trustee.Sid, builtin ? RequesterTrusteeState.Unknown : RequesterTrusteeState.Matches,
            builtin ? RequesterTrusteeReason.UnsupportedIdentity : self ? RequesterTrusteeReason.DirectGlobalMembership : RequesterTrusteeReason.DirectIdentity,
            self ? TargetGuid : RequesterGuid, self ? Target : Requester, "contoso.com", self ? -2147483646L : null,
            DateTimeOffset.UnixEpoch, self ? Requester : null));
    }

    private static string Store(Action<SqliteConnection>? mutate = null, bool self = false, bool builtin = false)
    {
        var directory = TempDirectories.Create("self-membership-storage");
        File.WriteAllText(BundleLayout.SealPath(directory), JsonSerializer.Serialize(new BundleSealContents(BundleSealing.Algorithm, Seal)));
        Guid derivation;
        using (var derived = DerivationWriter.Create(directory, Seal, DateTimeOffset.UnixEpoch))
        {
            derivation = derived.GenerationId;
            derived.WriteSids([], []);
            derived.RecordCompleteness(new(true, [], [], [], derivation, ExpansionLimit.None));
            derived.Complete(DateTimeOffset.UnixEpoch.AddSeconds(1));
        }
        using var writer = JudgementWriter.Create(directory, Seal, derivation, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
        var evidence = Evidence(self, builtin);
        var target = GroupMembershipControlTests.Group with
        {
            DistinguishedName = Target, ObjectGuid = TargetGuid,
            Attributes = [.. GroupMembershipControlTests.Group.Attributes,
                new("objectSid", AttributeCardinality.SingleValued, [new(0, TargetSid, null)])],
        };
        var edges = GroupMembershipControlTests.Membership(ControlEdgeDeriverTests.Permissions(evidence.Entry), subject: target);
        writer.StartControlEdges(true);
        writer.WriteControlEdges(edges with { Edges = edges.Edges.Select(edge => edge with { GenerationId = writer.GenerationId, DerivationGenerationId = derivation }).ToArray() }, ownershipTarget: null);
        writer.CompleteControlEdges();
        var ids = writer.SelfMembershipEdgeIds(Target, [self ? TargetSid : evidence.Entry.Trustee.Sid]);
        Assert.Single(ids);
        writer.StartSelfMembershipAssessments();
        foreach (var operation in Enum.GetValues<SelfMembershipOperation>())
            writer.WriteSelfMembershipAssessment(new(new(Requester, Target, operation, null), writer.GenerationId, derivation, Seal,
                RequesterGuid, RequesterSid, TargetGuid, TargetSid, RequesterGuid, RequesterSid,
                ControlEvaluationState.Established, ControlEvaluationState.Established, ControlEvaluationState.Unknown,
                "Computed", DateTimeOffset.UnixEpoch, 512, null, [SelfMembershipIssue.LiveOperationNotEvaluated], [evidence], ids));
        writer.CompleteSelfMembershipAssessments(null);
        if (mutate is not null)
        {
            using var connection = new SqliteConnection("Data Source=" + BundleLayout.JudgementPartialPath(directory) + ";Pooling=False");
            connection.Open();
            mutate(connection);
        }
        writer.Complete(DateTimeOffset.UnixEpoch.AddMinutes(1));
        return directory;
    }

    private static void SetRow(SqliteConnection connection, string column, string value)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"UPDATE self_membership_assessment SET {column}=$value WHERE operation='Remove'";
        command.Parameters.AddWithValue("$value", value);
        Assert.Equal(1, command.ExecuteNonQuery());
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static JudgementReader Open(string directory)
    {
        var opened = JudgementReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        return opened.Value!;
    }
}
