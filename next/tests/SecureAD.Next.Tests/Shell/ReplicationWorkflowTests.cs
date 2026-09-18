using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using System.Security.AccessControl;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.ReplicationControlTests;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class ReplicationWorkflowTests
{
    private const string DcSid = "S-1-5-21-1-2-3-1500";
    private const string DcDn = "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com";
    private static string Grants(string sid) => $"O:SYG:SYD:(OA;;CR;{ChangesGuid};;{sid})(OA;;CR;{AllGuid};;{sid})(OA;;CR;{FilteredGuid};;{sid})";

    [Theory]
    [InlineData(Root, false)]
    [InlineData(TargetDn, true)]
    public void StoredPermissionAndOriginalProofReachBothScreenDirections(string dn, bool byHolder)
    {
        var directory = Prepared(Grants(TargetSid));
        using var source = new BundleAssetSource();
        var section = Open(source, directory, dn, byHolder);
        Assert.Collection(section.Rows,
            row => Assert.Equal("Secret-data replication permission", row.Capability),
            row => Assert.Equal("Filtered-attribute replication permission", row.Capability));
        Assert.Single(section.Rows.Select(row => row.Group).Distinct());
        Assert.Contains("Naming context: DC=contoso,DC=com (Domain).", section.Rows[0].Evidence);
        Assert.Contains("Category: ReplicationControl.", section.Rows[0].Evidence);
        Assert.Contains(ChangesGuid, section.Rows[0].Evidence);
        Assert.Contains(AllGuid, section.Rows[1].Evidence);
        Assert.Contains(FilteredGuid, section.Rows[1].Evidence);
        Assert.Contains("Permission evidence only. No replication operation or credential extraction was performed.", section.Rows[0].Evidence);
        Assert.Contains("This does not establish account takeover or a completed path to Tier 0.", section.Rows[0].Evidence);
    }

    [Theory]
    [InlineData("0x000f01ff", 2)]
    [InlineData("GA", 0)]
    [InlineData("CR", 2)]
    [InlineData("GW", 0)]
    [InlineData("WP", 0)]
    [InlineData("SW", 0)]
    [InlineData("RP", 0)]
    [InlineData("WD", 0)]
    [InlineData("WO", 0)]
    public void RealPermissionReaderUsesStoredControlAccessBits(string mask, int count)
    {
        var directory = Prepared($"O:SYG:SYD:(A;;{mask};;;{TargetSid})");
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Equal(count, reader.ReadControlEdges(Root, null, null, true, 0).Edges.Count(edge => edge.EdgeClass == ControlEdgeClass.ReplicationControl));
    }

    [Fact]
    public void DuplicateRightsAndMembersDoNotMultiplyTheTwoCapabilities()
    {
        var directory = Prepared(Grants(TargetSid) + $"(OA;;CR;{AllGuid};;{TargetSid})");
        using var reader = JudgementReader.Open(directory).Value;
        var page = reader.ReadControlEdges(Root, null, null, true, 0);
        Assert.Equal(2L, page.ExpectedCount + page.UnexpectedCount + page.UnknownCount);
    }

    [Fact]
    public void BothFilteredAlternativesAndEveryOriginalEntrySurviveStorage()
    {
        var directory = Prepared(Grants(TargetSid));
        using var reader = JudgementReader.Open(directory).Value;
        var edge = reader.ReadControlEdges(Root, null, null, true, 0).Edges.Single(item => item.Capability == ControlCapability.CanReplicateFilteredAttributes);
        Assert.Equal(new[] { ChangesGuid, AllGuid, FilteredGuid }, edge.Evidence.Select(item => item.ObjectTypeGuid));
        Assert.Collection(edge.Preconditions.Take(3).Where(item => item.State == ControlEvaluationState.Established),
            item => Assert.Equal("DS-Replication-Get-Changes", item.Name),
            item => Assert.Equal("DS-Replication-Get-Changes-All", item.Name),
            item => Assert.Equal("DS-Replication-Get-Changes-In-Filtered-Set", item.Name));
    }

    [Fact]
    public void ReaderReturnsTheExactCapturedRootAndDoesNotModifyEvidence()
    {
        var directory = Bundle(sddl: "O:SYG:SYD:", rootDescriptor: Grants(TargetSid), tier0Route: true);
        var before = Hash(directory);
        Judge(directory);
        using var bundle = BundleReader.Open(directory).Value;
        var roots = bundle.ReadNamingContexts();
        Assert.True(roots.IsSuccess, roots.Error?.Description);
        Assert.Equal(new[] { new KeyValuePair<string, NamingContextKind>(Root, NamingContextKind.Domain) }, roots.Value);
        Assert.Equal(before, Hash(directory));
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Equal("NotStarted", reader.ReadSelfMembershipSummary()!.Verdict);
    }

    [Fact]
    public void RightsOnAChildDoNotBecomeRootReplication()
    {
        var directory = Bundle(sddl: Grants(UserSid));
        Judge(directory);
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Empty(reader.ReadControlEdges(TargetDn, null, null, true, 0).Edges);
    }

    [Fact]
    public void ExpectedSystemEdgesRemainStoredWhenHidden()
    {
        var directory = Prepared(Grants("SY"));
        using var reader = JudgementReader.Open(directory).Value;
        var hidden = reader.ReadControlEdges(Root, null, null, false, 0);
        Assert.Equal((2L, 0), (hidden.ExpectedCount, hidden.Edges.Count));
        Assert.Equal(2, reader.ReadControlEdges(Root, null, null, true, 0).Edges.Count);
    }

    [Theory]
    [InlineData("8192", "516", true)]
    [InlineData("512", "516", false)]
    [InlineData(null, "516", false)]
    [InlineData("8192", null, false)]
    [InlineData("invalid", "516", false)]
    public void DomainControllerEvidenceDoesNotSuppressReplicationOrHideOtherCapabilities(string? uac, string? primary, bool established)
    {
        var directory = Prepared(Grants(DcSid) + $"(A;;WD;;;{DcSid})", (writer, coverage) =>
            writer.WriteObject(new(coverage, DcDn, Guid.NewGuid(),
                [Text("objectClass", "top", "user", "computer"), Bytes("objectSid", Sid.ToBytes(DcSid)!),
                    Text("userAccountControl", uac is null ? [] : [uac]), Text("primaryGroupID", primary is null ? [] : [primary])], Started)));
        using var source = new BundleAssetSource();
        var section = Open(source, directory, Root, false);
        Assert.Equal(3, section.Rows.Count);
        Assert.Equal(2, section.Rows.Select(row => row.Group).Distinct().Count());
        var row = section.Rows.Single(item => item.Capability == "Secret-data replication permission");
        Assert.Contains(established ? "Domain controller asset" : "Domain-controller classification is unconfirmed", row.Evidence);
        Assert.DoesNotContain("expected (hidden)", section.Counts.Replace("0 expected (hidden)", "", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("UPDATE control_product SET engine_version=4", "not derived")]
    [InlineData("UPDATE control_edge SET edge_class='DirectoryControl'", "could not be read")]
    [InlineData("DELETE FROM control_ace", "could not be read")]
    [InlineData("UPDATE permission_entry SET mask=16 WHERE id IN (SELECT entry_id FROM control_ace)", "could not be read")]
    [InlineData("DELETE FROM control_precondition WHERE name='NamingContextRoot'", "could not be read")]
    [InlineData("UPDATE control_precondition SET evidence='CN=Child,DC=contoso,DC=com' WHERE name='NamingContextRoot'", "could not be read")]
    [InlineData("UPDATE control_precondition SET state='NotEstablished' WHERE name='DS-Replication-Get-Changes'", "could not be read")]
    [InlineData("UPDATE control_precondition SET evidence='DomainSecrets' WHERE name='NamingContextKind'", "could not be read")]
    [InlineData("UPDATE control_edge SET generation='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'", "could not be read")]
    public void DamagedOrOlderProductsClearScreenRowsAndSelectedProof(string mutation, string notice)
    {
        var directory = Prepared(Grants(TargetSid));
        using var source = new BundleAssetSource();
        var section = Open(source, directory, Root, false);
        Assert.Equal(2, section.Rows.Count);
        source.CloseRun();
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = mutation;
            Assert.True(command.ExecuteNonQuery() > 0);
        });
        source.SelectRun(directory);
        section.FirstPageCommand.Execute(null);
        Assert.Empty(section.Rows);
        Assert.Null(section.SelectedEdge);
        Assert.Contains(notice, section.Coverage);
    }

    [Fact]
    public void Schema20DoesNotClaimThatReplicationWasEvaluated()
    {
        var directory = Prepared(Grants(TargetSid));
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE judgement SET schema_version=20";
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        Assert.False(JudgementReader.Open(directory).IsSuccess);
    }

    [Fact]
    public void MissingCapturedRootRemainsAnUnansweredObjectForHolderQueries()
    {
        var directory = Bundle(sddl: "O:SYG:SYD:", rootObject: false);
        Judge(directory);
        using var reader = JudgementReader.Open(directory).Value;
        var page = reader.ReadControlEdges(null, TargetSid, null, false, 0);
        Assert.Equal((1L, false), (page.UnansweredObjects, page.IsComplete));
    }

    [Fact]
    public void PagingKeepsEveryReplicationEdgeAndIdentifiesAPartialGroup()
    {
        var sids = Enumerable.Range(1600, 51).Select(rid => $"S-1-5-21-1-2-3-{rid}").ToArray();
        var descriptor = $"O:SYG:SYD:(A;;WD;;;{TargetSid})" + string.Concat(sids.Select(sid =>
            $"(OA;;CR;{ChangesGuid};;{sid})(OA;;CR;{AllGuid};;{sid})"));
        var directory = Prepared(descriptor, (writer, coverage) =>
        {
            foreach (var sid in sids)
                writer.WriteObject(new(coverage, "CN=" + sid + "," + Root, Guid.NewGuid(),
                    [Text("objectClass", "top", "group"), Bytes("objectSid", Sid.ToBytes(sid)!), Text("groupType", "-2147483646")], Started));
        });
        using var reader = JudgementReader.Open(directory).Value;
        var first = reader.ReadControlEdges(Root, null, null, false, 0);
        var last = reader.ReadControlEdges(Root, null, null, false, first.LastId);
        Assert.Equal((100, 3, true, false, 103), (first.Edges.Count, last.Edges.Count, first.HasMore, last.HasMore,
            first.Edges.Concat(last.Edges).Select(edge => edge.Id).Distinct().Count()));
        using var source = new BundleAssetSource();
        var section = Open(source, directory, Root, false);
        var partialGroup = section.Rows[^1].Group;
        section.SelectedEdge = section.Rows[^1];
        section.NextPageCommand.Execute(null);
        Assert.Equal(partialGroup, section.Rows[0].Group);
        Assert.Same(section.Rows[0], section.SelectedEdge);
        Assert.Contains("groups cover this page only", section.SupportedScope);
    }

    [Theory]
    [InlineData(NamingContextKind.Configuration, "CN=Configuration,DC=contoso,DC=com", "configuration")]
    [InlineData(NamingContextKind.Schema, "CN=Schema,CN=Configuration,DC=contoso,DC=com", "dMD")]
    public void RealReaderPreservesNonDomainScopeWithoutClaimingDomainSecrets(NamingContextKind kind, string dn, string objectClass)
    {
        var directory = Prepared("O:SYG:SYD:", (writer, coverage) =>
        {
            var partition = coverage with { NamingContextDn = dn, Kind = kind };
            writer.WriteCoverage(partition);
            var guid = Guid.NewGuid();
            var id = writer.WriteObject(new(partition, dn, guid, [Text("objectClass", "top", objectClass)], Started));
            var raw = new RawSecurityDescriptor(Grants(TargetSid));
            var bytes = new byte[raw.BinaryLength];
            raw.GetBinaryForm(bytes, 0);
            writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));

            // Replication rights on the configuration or schema root reach that partition's secrets,
            // so this root is a route into Tier 0 in its own right. Expressed as an owned Tier-0
            // group for the same reason as the shared fixture's: ownership adds no counted edge.
            var owned = Guid.NewGuid();
            var ownedId = writer.WriteObject(new(partition, "CN=Tier0Partition," + dn, owned,
            [
                Text("objectClass", "top", "group"),
                Bytes("objectSid", Sid.ToBytes("S-1-5-21-1-2-3-517")!),
                Text("groupType", "-2147483646"),
            ], Started));
            var ownedRaw = new RawSecurityDescriptor($"O:{TargetSid}G:SYD:");
            var ownedBytes = new byte[ownedRaw.BinaryLength];
            ownedRaw.GetBinaryForm(ownedBytes, 0);
            writer.WriteSecurityDescriptor(ownedId, ownedBytes, AceNormalizer.Normalize(owned, SecurityDescriptorParser.Parse(ownedBytes)));
        });
        using var source = new BundleAssetSource();
        var section = Open(source, directory, dn, false);
        Assert.Collection(section.Rows, row => Assert.Equal("Unknown", row.Evaluation), row => Assert.Equal("Unknown", row.Evaluation));
        Assert.Contains($"Naming context: {dn} ({kind}).", section.Rows[0].Evidence);
        Assert.Equal("Secret-data replication permission", section.Rows[0].Capability);
    }

    [Fact]
    public void ConflictingCapturedRootKindsRefuseJudgingRatherThanReturnEmptyScope()
    {
        var directory = Bundle(sddl: "O:SYG:SYD:", writeAdditional: (writer, coverage) =>
            writer.WriteCoverage(coverage with { Kind = NamingContextKind.Configuration, Controller = "dc02.contoso.com" }));
        using var bundle = BundleReader.Open(directory).Value;
        Assert.False(bundle.ReadNamingContexts().IsSuccess);
        var result = JudgingRun.Judge(directory, [], Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.False(result.IsSuccess);
        Assert.Contains("naming-context identity", result.Error!.Description);
    }

    private static string Prepared(string descriptor, Action<BundleWriter, PartitionCoverage>? extra = null)
    {
        // Replication rights on the naming-context root are a route to every secret in the domain,
        // which is what makes them worth assessing.
        var directory = Bundle(sddl: "O:SYG:SYD:", rootDescriptor: descriptor, users: 4, tier0Route: true,
            writeAdditional: (writer, coverage) =>
        {
            writer.WriteObject(new(coverage, "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=contoso,DC=com", Guid.NewGuid(),
                [Text("objectClass", "top", "nTDSService"), Text("dSHeuristics")], Started));
            extra?.Invoke(writer, coverage);
        });
        Derive(directory);
        Judge(directory, [new AdminCountWithoutProtection()]);
        return directory;
    }

    private static void Judge(string directory, IRule[]? rules = null)
    {
        var result = JudgingRun.Judge(directory, rules ?? [], Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }
    private static EvidenceAttribute Text(string name, params string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
    private static EvidenceAttribute Bytes(string name, byte[] value) => new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(value)]);
    private static ControlEdgesSectionViewModel Open(BundleAssetSource source, string directory, string dn, bool byHolder)
    {
        var screen = new AssetsViewModel(source);
        screen.Show(directory, false);
        var attributes = Assert.IsType<ObjectAttributes>(source.ReadObjectAttributes(directory, dn).Value);
        screen.OpenObject(new(new(dn, dn, attributes.ObjectGuid, attributes.Find("objectClass")?.Values[^1].Text, Root)));
        var opened = Assert.IsType<ObjectViewModel>(screen.Opened);
        opened.Show(ObjectSectionCatalog.ControlEdges);
        var section = Assert.IsType<ControlEdgesSectionViewModel>(opened.Selected);
        section.ByHolder = byHolder;
        return section;
    }
}
