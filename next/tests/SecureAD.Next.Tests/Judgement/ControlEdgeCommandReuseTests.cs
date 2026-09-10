using System.Security.AccessControl;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class ControlEdgeCommandReuseTests
{
    [Fact]
    public void EveryParameterIsReboundAcrossRowsEdgesAndObjects()
    {
        using var connection = OpenMemory();
        var seed = ControlEdgeDeriverTests.Derive(ControlEdgeDeriverTests.Permissions(
            ControlEdgeDeriverTests.Ace(0, ControlEdgeDeriverTests.Holder, 0x40000))).Edges.Single();
        var expected = new List<ControlEdge>();
        for (var objectIndex = 0; objectIndex < 2; objectIndex++)
        {
            var target = $"OU=Object{objectIndex},DC=contoso,DC=com";
            var edges = Enumerable.Range(0, 3).Select(index => seed with
            {
                Target = target,
                TargetGuid = index == 1 ? null : Guid.NewGuid(),
                TargetClass = index == 1 ? null : "organizationalUnit",
                HolderSid = $"S-1-5-21-1-2-3-{1200 + objectIndex * 10 + index}",
                HolderName = index == 1 ? null : "Holder" + index,
                HolderScope = index == 1 ? null : "contoso.com",
                Capability = index == 0 ? ControlCapability.CanWriteDacl : index == 1 ? ControlCapability.CanResetPassword : ControlCapability.CanModifyGroupMembership,
                EvaluationState = (ControlEvaluationState)index,
                Uncertainty = index == 1 ? ControlUncertainty.None : ControlUncertainty.CrossTrusteeDeny,
                Expectedness = (ControlExpectedness)index,
                ExpectednessReason = index == 1 ? ControlExpectednessReason.UnknownAuthorityScope : ControlExpectednessReason.UnexpectedNotControlPlane,
                PrincipalCatalogueVersion = index + 1,
                GenerationId = Guid.NewGuid(),
                DerivationGenerationId = index == 1 ? null : Guid.NewGuid(),
                IsCounted = index != 1,
                Evidence = index == 1 ? [] : [Entry(0, true), Entry(1, false), Entry(2, true)],
                Preconditions = index == 1 ? [] :
                [new("First", ControlEvaluationState.Established, "proof-" + index),
                    new("Second", ControlEvaluationState.Unknown, ""), new("Third", ControlEvaluationState.NotEstablished, "other-" + index)],
            }).ToArray();
            ControlEdgeStorage.Write(connection, new(target, null, null, "Computed", ControlUncertainty.CrossTrusteeDeny, edges));
            expected.AddRange(edges);
        }

        AssertRows(connection, "SELECT * FROM control_edge ORDER BY id", expected.Select((edge, index) => new object?[]
        {
            index + 1, edge.Target, edge.TargetGuid?.ToString("D"), edge.TargetClass, edge.HolderSid,
            edge.HolderName, edge.HolderScope, edge.Capability.ToString(), edge.EdgeClass.ToString(),
            edge.EvaluationState.ToString(), (int)edge.Uncertainty, edge.Expectedness.ToString(), edge.ExpectednessReason.ToString(),
            edge.PrincipalCatalogueVersion, edge.GenerationId.ToString("D"), edge.DerivationGenerationId?.ToString("D"),
            edge.IsCounted, edge.Evidence.Count, edge.Preconditions.Count,
        }).ToArray());
        AssertRows(connection, "SELECT a.edge_id,a.ordinal,p.ace_type,p.sid,p.name,p.dn,p.domain,p.role,p.mask,p.object_type,p.inherited_object_type,p.inherited,p.inheritance_flags,p.propagation_flags,p.has_object_type,p.has_inherited_object_type,p.application_data FROM control_ace a JOIN permission_entry p ON p.id=a.entry_id ORDER BY a.edge_id,a.ordinal", expected.SelectMany((edge, index) => edge.Evidence.Select(ace => new object?[]
        {
            index + 1, ace.Ordinal, ace.AceType, ace.Trustee.Sid, ace.Trustee.Name, ace.Trustee.DistinguishedName,
            ace.Trustee.DomainFqdn, ace.Trustee.WellKnownRole?.ToString(), ace.AccessMask, ace.ObjectTypeGuid,
            ace.InheritedObjectTypeGuid, ace.IsInherited, (int)ace.InheritanceFlags, (int)ace.PropagationFlags,
            ace.HasObjectType, ace.HasInheritedObjectType, ace.ApplicationData,
        })).ToArray());
        AssertRows(connection, "SELECT * FROM control_precondition ORDER BY edge_id,ordinal", expected.SelectMany((edge, index) => edge.Preconditions.Select((condition, ordinal) => new object?[]
        {
            index + 1, ordinal, condition.Name, condition.State.ToString(), condition.EvidenceSource,
        })).ToArray());
        Assert.Equal(0, Count(connection, "SELECT COUNT(*) FROM pragma_foreign_key_check"));
    }

    [Fact]
    public void LateProofFailureRollsBackOnlyTheCurrentObjectAndAllowsAnotherWrite()
    {
        using var connection = OpenMemory();
        var subject = ControlEdgeDeriverTests.Subject with { DistinguishedName = "OU=Saved,DC=contoso,DC=com" };
        var earlier = ControlEdgeDeriver.Derive(subject, ControlEdgeDeriverTests.Permissions(
            ControlEdgeDeriverTests.Ace(0, ControlEdgeDeriverTests.Holder, 0x40000)), JudgingContext.At(DateTimeOffset.UnixEpoch),
            Guid.Empty, null, ControlEdgeDeriverTests.DomainSid);
        ControlEdgeStorage.Write(connection, earlier);
        var tables = new[] { "control_object", "control_edge", "control_ace", "permission_entry", "control_precondition", "membership_route_summary", "full_control_manifest", "full_control_source", "full_control_source_entry", "full_control_assessment", "full_control_support" };
        var before = tables.Select(table => Count(connection, "SELECT COUNT(*) FROM " + table)).ToArray();
        var complete = FullControlStorageTests.Evaluation(FullControlEvaluatorTests.Allow(0), FullControlEvaluatorTests.Allow(1));
        var invalid = complete with { FullControlAssessments = [complete.FullControlAssessments[0] with { SupportingCapabilities = [] }] };
        Assert.Throws<InvalidOperationException>(() => ControlEdgeStorage.Write(connection, invalid));
        Assert.Equal(before, tables.Select(table => Count(connection, "SELECT COUNT(*) FROM " + table)).ToArray());
        Assert.Equal(1, Count(connection, "SELECT COUNT(*) FROM control_object WHERE target='OU=Saved,DC=contoso,DC=com'"));
        ControlEdgeStorage.Write(connection, complete);
        Assert.Equal(2, Count(connection, "SELECT COUNT(*) FROM control_object"));
        Assert.Equal(0, Count(connection, "SELECT COUNT(*) FROM pragma_foreign_key_check"));
        Assert.True(Count(connection, "SELECT COUNT(*) FROM full_control_support") > 0);
    }

    [Fact]
    public void CancellationAfterOneThousandWrittenObjectsPreservesThePublishedGeneration()
    {
        var directory = CreateBundle();
        var first = JudgingRun.Judge(directory, [], DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(first.IsSuccess, first.Error?.Description);
        var database = Directory.GetFiles(directory, "judgement.*.db").Single();
        var hash = FileHash(database);
        var seal = File.ReadAllBytes(database + ".seal");
        var manifest = File.ReadAllBytes(Path.Combine(directory, "judgement.current.json"));
        var evidenceHash = FileHash(Path.Combine(directory, "evidence.db"));
        using var cancellation = new CancellationTokenSource();
        var sawWrittenProof = false;
        var progress = new Watching(value =>
        {
            if (value.ObjectsRead < 1000 || sawWrittenProof) return;
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = BundleLayout.JudgementPartialPath(directory), Mode = SqliteOpenMode.ReadOnly, Pooling = false,
            }.ToString());
            connection.Open();
            Assert.True(Count(connection, "SELECT COUNT(*) FROM control_object") >= 1000);
            Assert.True(Count(connection, "SELECT COUNT(*) FROM control_ace") >= 1000);
            sawWrittenProof = true;
            cancellation.Cancel();
        });
        Assert.Throws<OperationCanceledException>(() => JudgingRun.Judge(directory, [], DateTimeOffset.UtcNow,
            DateTimeOffset.UnixEpoch, progress, RunLog.Discarded, cancellation.Token));
        Assert.True(sawWrittenProof);
        Assert.Equal(manifest, File.ReadAllBytes(Path.Combine(directory, "judgement.current.json")));
        Assert.Equal(hash, FileHash(database));
        Assert.Equal(seal, File.ReadAllBytes(database + ".seal"));
        Assert.Equal(evidenceHash, FileHash(Path.Combine(directory, "evidence.db")));
        using var reader = FullControlStorageTests.Open(directory);
        Assert.Equal(first.Value, reader.Read().Description.State);
    }

    private static PermissionEntry Entry(int ordinal, bool populated) => new(ordinal,
        populated ? "AccessAllowedCallbackObject" : "AccessDenied",
        new(populated ? "S-1-5-18" : ControlEdgeDeriverTests.Holder,
            populated ? "SYSTEM" : null, populated ? "CN=System,DC=contoso,DC=com" : null,
            populated ? "contoso.com" : null, null, populated ? WellKnownSidRole.Principal : null, null),
        populated ? unchecked((int)0x80040000) : 0x40000,
        populated ? "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" : null,
        populated ? "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" : null,
        populated, populated ? (byte)3 : (byte)0, populated ? (byte)2 : (byte)0,
        populated, populated, populated ? [0, 255, 1, (byte)ordinal] : []);

    private static SqliteConnection OpenMemory()
    {
        var connection = new SqliteConnection("Data Source=:memory:;Foreign Keys=True");
        connection.Open();
        JudgementSchema.CreateTables(connection);
        return connection;
    }

    private static void AssertRows(SqliteConnection connection, string sql, IReadOnlyList<object?[]> expected)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        using var reader = command.ExecuteReader();
        foreach (var row in expected)
        {
            Assert.True(reader.Read());
            Assert.Equal(row.Length, reader.FieldCount);
            for (var i = 0; i < row.Length; i++)
            {
                var value = row[i] switch { bool flag => flag ? 1L : 0L, int number => (long)number, var other => other };
                if (value is byte[] bytes) Assert.Equal(bytes, (byte[])reader.GetValue(i));
                else Assert.Equal(value, reader.IsDBNull(i) ? null : reader.GetValue(i));
            }
        }
        Assert.False(reader.Read());
    }

    private static long Count(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return (long)command.ExecuteScalar()!;
    }

    private static string FileHash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string CreateBundle()
    {
        var directory = TempDirectories.Create("command-reuse-cancellation");
        var coverage = new PartitionCoverage("DC=contoso,DC=com", NamingContextKind.Domain, "dc01.contoso.com",
            ConnectionSecurityLevel.SignedAndSealed, 1, 1001, 1, [], false);
        using var writer = BundleWriter.Create(directory, DateTimeOffset.UnixEpoch);
        writer.WriteCoverage(coverage);
        var descriptor = new RawSecurityDescriptor("D:(A;;WD;;;S-1-5-21-1-2-3-1200)");
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        for (var i = 0; i < 1001; i++)
        {
            var subject = new EvidenceObject(coverage, i == 0 ? "DC=contoso,DC=com" : $"OU=Object{i},DC=contoso,DC=com", Guid.NewGuid(),
                [new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(i == 0 ? "domainDNS" : "organizationalUnit")])], DateTimeOffset.UnixEpoch);
            var id = writer.WriteObject(subject);
            writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(subject.ObjectGuid!.Value, SecurityDescriptorParser.Parse(bytes)));
        }
        writer.Complete(RunCoverage.Of(CoverageId.ForDomains("contoso.com", ["contoso.com"]), [DomainCoverage.Read("contoso.com")],
            [ForestPartitionCoverage.Read("CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
                ForestPartitionCoverage.Read("CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema)], SysvolCoverage.Of([])), DateTimeOffset.UnixEpoch.AddMinutes(1));
        return directory;
    }

    private sealed class Watching(Action<JudgingRun.JudgingProgress> action) : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value) => action(value);
    }
}
