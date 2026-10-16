using System.Buffers.Binary;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Next.Tests.Evidence;
using SecureAD.Next.Tests.Kernel.Security;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    private const string ServingHolder = "S-1-5-21-1-2-3-1100";

    [Theory]
    [InlineData(DelegationPermission.All, false)]
    [InlineData(DelegationPermission.All, true)]
    [InlineData(DelegationPermission.ResetPassword, false)]
    [InlineData(DelegationPermission.ResetPassword, true)]
    [InlineData(DelegationPermission.CreateUser, false)]
    [InlineData(DelegationPermission.CreateUser, true)]
    [InlineData(DelegationPermission.WriteUserProperties, false)]
    [InlineData(DelegationPermission.WriteUserProperties, true)]
    public void OrdinaryDelegationsPreserveEveryOriginalOccurrenceAndQualificationWithoutEvidenceBulk(
        DelegationPermission permission, bool inherited)
    {
        using var fixture = new DelegationLookupTests.Fixture();
        fixture.Principal("Help%desk", ServingHolder);
        var sid = Sid.ToBytes(ServingHolder)!;
        var user = new Guid("bf967aba-0de6-11d0-a285-00aa003049e2");
        byte[][] entries = [SdBytes.AllowAce(sid, 0x100), SdBytes.AllowAce(sid, 0x100),
            SdBytes.DenyAce(sid, 0x100), SdBytes.AllowAce(sid, 0x40000000),
            SdBytes.AllowObjectAce(sid, 1, user, null),
            SdBytes.AllowObjectAce(sid, 0x100, new("00299570-246d-11d0-a768-00aa006e0529"), user, 0x1A)];
        for (var index = 0; index < 25; index++) fixture.Target("User" + index, entries, ["top", "person", "user"]);
        byte[] payload = [0x61, 0x72, 0x74, 0x78, 1, 0, 254, 127];
        var callback = SdBytes.SimpleAce(0x09, 0, 0x100, sid).Concat(payload).ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(callback.AsSpan(2), (ushort)callback.Length);
        byte[][] qualifiedEntries = [callback, SdBytes.AllowAce(sid, 0x20)];
        fixture.Target("Qualified", qualifiedEntries,
            [], recordedCompleteness: DaclCompleteness.Unknown);
        fixture.SysvolOnly(mismatchedIndex: true);
        var original = fixture.Open(partial: true);
        var principal = Assert.Single(original.FindDelegationPrincipals("help%desk", null).Principals);
        var query = new DelegationQuery(principal, permission, inherited);
        Assert.NotEmpty(original.ReadDelegations(query, null).Entries);
        var expected = ReadAll(after => original.ReadDelegations(query, after));
        fixture.CloseCapturedReader();
        using var blocked = new FileStream(BundleLayout.EvidencePath(fixture.DirectoryPath),
            FileMode.Open, FileAccess.Read, FileShare.None);
        using var counts = new ReadbackCounts(fixture.DirectoryPath);
        using var source = new BundleAssetSource();
        var actualPrincipal = source.FindDelegationPrincipals(fixture.DirectoryPath, "help%desk", null);
        Assert.Equal(principal, Assert.Single(actualPrincipal.Value.Principals));
        Assert.True(source.ReadSchemaGuids(fixture.DirectoryPath).IsSuccess);
        Assert.Equal(0L, counts.DelegationVerifications);

        var returned = new List<DelegationEntry>();
        var actual = ReadAll(after =>
        {
            var page = source.ReadDelegations(fixture.DirectoryPath, query, after);
            Assert.True(page.IsSuccess, page.Error?.Description);
            returned.AddRange(page.Value.Entries);
            return page.Value;
        });

        int[] userOrdinals = permission switch
        {
            DelegationPermission.All => inherited ? [0, 1, 2, 3, 4, 5] : [0, 1, 2, 3, 4],
            DelegationPermission.ResetPassword => inherited ? [0, 1, 2, 5] : [0, 1, 2],
            DelegationPermission.CreateUser => [4],
            DelegationPermission.WriteUserProperties => [3],
            _ => throw new ArgumentOutOfRangeException(nameof(permission)),
        };
        int[] qualifiedOrdinals = permission switch
        {
            DelegationPermission.All => [0, 1],
            DelegationPermission.ResetPassword => [0],
            DelegationPermission.CreateUser => [],
            _ => [1],
        };
        Assert.Equal(25 * userOrdinals.Length + qualifiedOrdinals.Length, returned.Count);
        foreach (var target in returned.GroupBy(row => row.DistinguishedName, StringComparer.Ordinal))
        {
            var qualified = target.Key.StartsWith("CN=Qualified,", StringComparison.Ordinal);
            Assert.Equal(qualified ? qualifiedOrdinals : userOrdinals, target.Select(row => row.Entry.Ordinal));
            foreach (var row in target)
            {
                var raw = (qualified ? qualifiedEntries : entries)[row.Entry.Ordinal];
                Assert.Equal(BinaryPrimitives.ReadInt32LittleEndian(raw.AsSpan(4, 4)), row.Entry.AccessMask);
                Assert.Equal((raw[1] & 16) != 0, row.Entry.IsInherited);
                Assert.Equal((byte)(raw[1] & 3), row.Entry.InheritanceFlags);
                Assert.Equal((byte)(raw[1] & 12), row.Entry.PropagationFlags);
                if (!qualified) continue;
                Assert.Equal(DaclCompleteness.Unknown, row.DaclCompleteness);
                if (row.Entry.Ordinal == 0) Assert.Equal(payload, row.Entry.ApplicationData);
                else if (permission == DelegationPermission.WriteUserProperties)
                    Assert.Contains("class was not captured", row.ScopeQualification, StringComparison.Ordinal);
                else Assert.Null(row.ScopeQualification);
            }
        }
        Assert.NotEmpty(actual);
        Assert.Equal(expected, actual);
        Assert.Equal((0L, 0L, 0L, 1L, 1L), (counts.EvidenceVerifications, counts.DerivationVerifications,
            counts.JudgementVerifications, counts.NavigationVerifications, counts.DelegationVerifications));
        var root = AnalysisStoreLifecycle.ResolveCapture(fixture.DirectoryPath).Value;
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        { DataSource = Path.Combine(fixture.DirectoryPath, root.Segment(StoreSegmentRole.Delegations).FileName),
            Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM security_descriptor";
        Assert.Equal(2L, command.ExecuteScalar());
        command.CommandText = "EXPLAIN QUERY PLAN " + CapturedDelegationStorage.CandidateSql;
        command.Parameters.AddWithValue("$sid", ServingHolder);
        command.Parameters.AddWithValue("$after", 0);
        command.Parameters.AddWithValue("$mask", 0x100);
        command.Parameters.AddWithValue("$inherited", 1);
        using var plan = command.ExecuteReader();
        var lines = new List<string>();
        while (plan.Read()) lines.Add(plan.GetString(3));
        Assert.Contains(lines, line => line.Contains("SEARCH delegation_candidate USING PRIMARY KEY", StringComparison.Ordinal));
        Assert.DoesNotContain(lines, line => line.StartsWith("SCAN ", StringComparison.Ordinal));
    }

    [Fact]
    public void TheRealLibraryReadsAuthoritativeHeadersWhileEveryRunPayloadIsInaccessible()
    {
        using var fixture = new DelegationLookupTests.Fixture();
        fixture.Principal("Helpdesk", ServingHolder);
        var expected = fixture.Open().ReadScope().Value;
        fixture.CloseCapturedReader();
        var library = TempDirectories.Create("header-library");
        var run = Path.Combine(library, "saved-run");
        Directory.Move(fixture.DirectoryPath, run);
        var locks = new List<FileStream>();
        try
        {
            var root = AnalysisStoreLifecycle.ResolveCapture(run).Value;
            foreach (var segment in root.Segments)
                locks.Add(new(Path.Combine(run, segment.FileName), FileMode.Open, FileAccess.Read, FileShare.None));
            var listed = new RunCatalog().List(library, CancellationToken.None);
            Assert.True(listed.IsSuccess, listed.Error?.Description);
            var row = Assert.Single(listed.Value);
            Assert.Equal(run, row.Path);
            Assert.Equal(expected.Identity, row.Scope?.Identity);
            Assert.Equal(expected.ReadCount, row.Scope?.ReadCount);
            Assert.Equal(JsonSerializer.Serialize(expected.Domains), JsonSerializer.Serialize(row.Scope!.Domains));
        }
        finally
        {
            foreach (var file in locks) file.Dispose();
            Directory.Delete(run, recursive: true);
        }
    }

    [Theory]
    [InlineData(StoreSegmentRole.Delegations)]
    [InlineData(StoreSegmentRole.Membership)]
    public void OrdinaryDelegationsRefuseCorruptSelectedProductsRatherThanFallingBackToBulk(StoreSegmentRole role)
    {
        using var fixture = new DelegationLookupTests.Fixture();
        fixture.Principal("Helpdesk", ServingHolder);
        fixture.Target("People", [SdBytes.AllowAce(Sid.ToBytes(ServingHolder)!, 0x100)]);
        fixture.Open();
        fixture.CloseCapturedReader();
        Assert.True(Stage2aRun.Derive(fixture.DirectoryPath, ExpansionBudget.Bulk, DateTimeOffset.UnixEpoch,
            Stage2aRun.Unwatched, RunLog.Discarded, CancellationToken.None).IsSuccess);
        var capture = AnalysisStoreLifecycle.ResolveCapture(fixture.DirectoryPath).Value;
        var derived = AnalysisStoreLifecycle.ResolveRoot(fixture.DirectoryPath, AnalysisStoreKind.Derivation).Value;
        var selected = role == StoreSegmentRole.Delegations ? capture : derived;
        ChangeSameLength(Path.Combine(fixture.DirectoryPath, selected.Segment(role).FileName));
        using var blockedEvidence = new FileStream(BundleLayout.EvidencePath(fixture.DirectoryPath),
            FileMode.Open, FileAccess.Read, FileShare.None);
        using var blockedDerivation = new FileStream(Path.Combine(fixture.DirectoryPath, derived.Segment(StoreSegmentRole.Derivation).FileName),
            FileMode.Open, FileAccess.Read, FileShare.None);
        using var counts = new ReadbackCounts(fixture.DirectoryPath);
        using var source = new BundleAssetSource();
        var principal = Assert.Single(source.FindDelegationPrincipals(fixture.DirectoryPath, "Helpdesk", null).Value.Principals);

        var result = source.ReadDelegations(fixture.DirectoryPath, new(principal, DelegationPermission.All, false)
            { IncludeGroupHeldPermissions = role == StoreSegmentRole.Membership }, null);

        Assert.False(result.IsSuccess);
        Assert.NotNull(result.Error);
        Assert.Equal((0L, 0L), (counts.EvidenceVerifications, counts.DerivationVerifications));
        Assert.Equal(role == StoreSegmentRole.Delegations ? 1L : 0L, counts.DelegationVerifications);
        Assert.Equal(role == StoreSegmentRole.Membership ? 1L : 0L, counts.MembershipVerifications);
    }

    [Fact]
    public void GroupInclusiveOrdinaryReadsUseOnlyTheSavedDirectRelationshipProduct()
    {
        using var fixture = new DelegationLookupTests.Fixture();
        fixture.Principal("Helpdesk", ServingHolder);
        fixture.Target("People", [SdBytes.AllowAce(Sid.ToBytes(ServingHolder)!, 0x100)]);
        fixture.Open(partial: true);
        fixture.CloseCapturedReader();
        Assert.True(Stage2aRun.Derive(fixture.DirectoryPath, ExpansionBudget.Bulk, DateTimeOffset.UnixEpoch,
            Stage2aRun.Unwatched, RunLog.Discarded, CancellationToken.None).IsSuccess);
        var derived = AnalysisStoreLifecycle.ResolveRoot(fixture.DirectoryPath, AnalysisStoreKind.Derivation).Value;
        using var blockedEvidence = new FileStream(BundleLayout.EvidencePath(fixture.DirectoryPath),
            FileMode.Open, FileAccess.Read, FileShare.None);
        using var blockedDerivation = new FileStream(Path.Combine(fixture.DirectoryPath, derived.Segment(StoreSegmentRole.Derivation).FileName),
            FileMode.Open, FileAccess.Read, FileShare.None);
        using var counts = new ReadbackCounts(fixture.DirectoryPath);
        using var source = new BundleAssetSource();
        var principal = Assert.Single(source.FindDelegationPrincipals(fixture.DirectoryPath, "Helpdesk", null).Value.Principals);
        var query = new DelegationQuery(principal, DelegationPermission.All, false) { IncludeGroupHeldPermissions = true };
        var result = source.ReadDelegations(fixture.DirectoryPath, query, null);
        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.Single(result.Value.Entries);
        Assert.Single(result.Value.Membership!.Nodes);
        Assert.Contains(result.Value.Membership.Warnings, text => text.Contains("did not cover all declared scope", StringComparison.Ordinal));
        Assert.Equal((0L, 0L, 1L, 1L), (counts.EvidenceVerifications, counts.DerivationVerifications,
            counts.MembershipVerifications, counts.DelegationVerifications));
    }

    [Theory]
    [InlineData(StoreSegmentRole.Delegations, "generation")]
    [InlineData(StoreSegmentRole.Delegations, "schema")]
    [InlineData(StoreSegmentRole.Delegations, "source")]
    [InlineData(StoreSegmentRole.Membership, "generation")]
    [InlineData(StoreSegmentRole.Membership, "schema")]
    [InlineData(StoreSegmentRole.Membership, "source")]
    public void OrdinaryServingHeadersMustMatchTheirExactSavedSourceAndGeneration(StoreSegmentRole role, string defect)
    {
        using var fixture = new DelegationLookupTests.Fixture();
        fixture.Principal("Helpdesk", ServingHolder);
        fixture.Target("People", [SdBytes.AllowAce(Sid.ToBytes(ServingHolder)!, 0x100)]);
        fixture.Open();
        fixture.CloseCapturedReader();
        Assert.True(Stage2aRun.Derive(fixture.DirectoryPath, ExpansionBudget.Bulk, DateTimeOffset.UnixEpoch,
            Stage2aRun.Unwatched, RunLog.Discarded, CancellationToken.None).IsSuccess);
        var root = role == StoreSegmentRole.Delegations ? AnalysisStoreLifecycle.ResolveCapture(fixture.DirectoryPath).Value
            : AnalysisStoreLifecycle.ResolveRoot(fixture.DirectoryPath, AnalysisStoreKind.Derivation).Value;
        var path = Path.Combine(fixture.DirectoryPath, root.Segment(role).FileName);
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = (role, defect) switch
            {
                (StoreSegmentRole.Delegations, "generation") => "UPDATE delegation_product SET generation=$value",
                (StoreSegmentRole.Delegations, "schema") => "UPDATE delegation_product SET schema_version=999",
                (StoreSegmentRole.Delegations, "source") => "UPDATE bundle SET coverage_id=$value",
                (StoreSegmentRole.Membership, "generation") => "UPDATE derivation SET derivation_generation_id=$value",
                (StoreSegmentRole.Membership, "schema") => "UPDATE derivation SET schema_version=999",
                _ => "UPDATE derivation SET evidence_seal=$value",
            };
            command.Parameters.AddWithValue("$value", Guid.NewGuid().ToString("D"));
            Assert.Equal(1, command.ExecuteNonQuery());
        }
        if (role == StoreSegmentRole.Membership)
            TestSealing.ResealAnalysis(fixture.DirectoryPath, new(AnalysisStoreKind.Derivation, root.GenerationId));
        else
        {
            BundleSealing.Seal(path, path + ".seal");
            var changed = root with { Segments = root.Segments.Select(segment => segment.Role == role
                ? segment with { Hash = BundleSealing.ReadSeal(path + ".seal")!.Hash, ByteLength = new FileInfo(path).Length } : segment).ToArray() };
            File.WriteAllText(BundleLayout.CaptureManifestPath(fixture.DirectoryPath),
                JsonSerializer.Serialize(changed with { Hash = changed.ComputeHash() }));
        }
        using var source = new BundleAssetSource();
        var principal = Assert.Single(source.FindDelegationPrincipals(fixture.DirectoryPath, "Helpdesk", null).Value.Principals);

        var result = source.ReadDelegations(fixture.DirectoryPath, new(principal, DelegationPermission.All, false)
            { IncludeGroupHeldPermissions = role == StoreSegmentRole.Membership }, null);

        Assert.False(result.IsSuccess);
        Assert.NotNull(result.Error);
    }

    private static void ChangeSameLength(string path)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        file.Position = 80;
        var value = file.ReadByte();
        Assert.True(value >= 0);
        file.Position = 80;
        file.WriteByte((byte)(value ^ 64));
    }

    private static string[] ReadAll(Func<DelegationPageMark?, DelegationPage> read)
    {
        var pages = new List<string>();
        DelegationPageMark? after = null;
        do
        {
            var page = read(after);
            pages.Add(JsonSerializer.Serialize(page));
            after = page.Next;
        } while (after is not null);
        return pages.ToArray();
    }
}
