using System.Security.AccessControl;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class OwnershipWorkflowTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExistingOwnerProofReachesBothDirectionsWithoutAClaimedOperation(bool byHolder)
    {
        var directory = Prepared($"O:{UserSid}G:SYD:");
        using var source = new BundleAssetSource();
        var section = Open(source, directory, byHolder ? UserDn : TargetDn, byHolder);
        var row = Assert.Single(section.Rows);
        Assert.Equal("Existing-owner permission control", row.Capability);
        Assert.Equal("Established", row.Evaluation);
        Assert.Contains("No owner or permission change was performed.", row.Evidence);
        Assert.Contains("AddWholeObjectWriteDaclAllowForOwner", row.Evidence);
        Assert.Contains(UserSid, row.Evidence);
    }

    [Theory]
    [InlineData("(A;;WD;;;S-1-3-4)", ControlEvaluationState.Established, true)]
    [InlineData("(D;;WD;;;S-1-3-4)", ControlEvaluationState.NotEstablished, false)]
    [InlineData("(A;;RP;;;S-1-3-4)", ControlEvaluationState.NotEstablished, false)]
    [InlineData("(A;CIIO;RP;;;S-1-3-4)", ControlEvaluationState.Established, true)]
    [InlineData("(A;;WD;;;S-1-3-4)(D;;WD;;;S-1-3-4)", ControlEvaluationState.Established, true)]
    [InlineData("(D;;WD;;;S-1-3-4)(A;;WD;;;S-1-3-4)", ControlEvaluationState.NotEstablished, false)]
    public void RealReaderRetainsOwnerRightsOrderAndCounting(string entries, ControlEvaluationState state, bool counted)
    {
        var directory = Prepared($"O:{UserSid}G:SYD:{entries}");
        using var reader = JudgementReader.Open(directory).Value;
        var edge = Assert.Single(reader.ReadControlEdges(TargetDn, null, null, true, 0).Edges);
        Assert.Equal((state, counted), (edge.EvaluationState, edge.IsCounted));
    }

    [Fact]
    public void ImplicitOwnerEvidenceDoesNotInventAGrantingAce()
    {
        var directory = Prepared($"O:{UserSid}G:SYD:");
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Empty(Assert.Single(reader.ReadControlEdges(TargetDn, null, null, true, 0).Edges).Evidence);
    }

    [Fact]
    public void MissingDerivationIsAnUncountedUnansweredOwnerAssessment()
    {
        var directory = Prepared($"O:{UserSid}G:SYD:", derive: false);
        using var reader = JudgementReader.Open(directory).Value;
        var page = reader.ReadControlEdges(TargetDn, null, null, true, 0);
        var edge = Assert.Single(page.Edges);
        Assert.Equal((ControlEvaluationState.Unknown, false, false), (edge.EvaluationState, edge.IsCounted, page.IsComplete));
    }

    [Theory]
    [InlineData("SY")]
    [InlineData("BA")]
    [InlineData("S-1-5-21-1-2-3-9999")]
    public void AcceptedOrProvenAbsentOwnersDoNotProduceOwnershipEdges(string owner)
    {
        var directory = Prepared($"O:{owner}G:SYD:");
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Empty(reader.ReadControlEdges(TargetDn, null, null, true, 0).Edges);
    }

    [Fact]
    public void GroupOwnershipIsCountedAtTheGroupNotItsMember()
    {
        var directory = Prepared($"O:{TargetSid}G:SYD:");
        using var reader = JudgementReader.Open(directory).Value;
        var page = reader.ReadControlEdges(TargetDn, null, null, true, 0);
        Assert.Equal((TargetSid, 1L), (Assert.Single(page.Edges).HolderSid, page.UnexpectedCount + page.UnknownCount + page.ExpectedCount));
        Assert.Empty(reader.ReadControlEdges(null, UserSid, null, true, 0).Edges);
    }

    [Fact]
    public void MissingOwnerDoesNotBecomeCompleteSilenceInEitherDirection()
    {
        var directory = Prepared("G:SYD:");
        using var reader = JudgementReader.Open(directory).Value;
        Assert.False(reader.ReadControlEdges(TargetDn, null, null, true, 0).IsComplete);
        Assert.False(reader.ReadControlEdges(null, UserSid, null, true, 0).IsComplete);
    }

    [Fact]
    public void OwnerTransitionRetainsProvenPrimitiveAndUncountedLaboratoryGate()
    {
        var directory = Prepared($"O:SYG:SYD:(A;;WO;;;{UserSid})(A;;WD;;;S-1-3-4)");
        using var reader = JudgementReader.Open(directory).Value;
        var page = reader.ReadControlEdges(TargetDn, null, null, true, 0);
        var primitive = Assert.Single(page.Edges.Where(edge => edge.IsCounted));
        Assert.Equal(ControlEvaluationState.Established, primitive.EvaluationState);
        var compound = Assert.Single(page.Edges.Where(edge => !edge.IsCounted));
        Assert.Equal(ControlEvaluationState.Unknown, compound.EvaluationState);
        Assert.Contains(compound.Preconditions, item => item.Name == "OwnerWouldReceiveWriteDacl" && item.State == ControlEvaluationState.Established);
        Assert.Contains(compound.Preconditions, item => item.Name == "CanSetTakeoverOwnerSid" && item.State == ControlEvaluationState.Unknown);
        using var source = new BundleAssetSource();
        Assert.Contains(Open(source, directory, TargetDn, false).Rows,
            row => row.Capability == "Owner-change permission control — not verified; not counted");
    }

    [Theory]
    [InlineData("UPDATE control_product SET engine_version=5", "not derived")]
    [InlineData("DELETE FROM control_precondition WHERE name='OwnerSource'", "could not be read")]
    [InlineData("UPDATE control_precondition SET evidence='{}' WHERE name='OwnerSource'", "could not be read")]
    [InlineData("UPDATE control_precondition SET state='NotEstablished' WHERE name='OwnerWouldReceiveWriteDacl'", "could not be read")]
    [InlineData("UPDATE control_edge SET holder_sid='S-1-5-21-1-2-3-9999'", "could not be read")]
    [InlineData("UPDATE control_edge SET target_class='computer'", "could not be read")]
    [InlineData("UPDATE control_edge SET counted=0", "could not be read")]
    [InlineData("UPDATE control_edge SET generation='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'", "could not be read")]
    [InlineData("UPDATE control_ace SET mask=16", "could not be read")]
    [InlineData("UPDATE control_precondition SET evidence=json_set(evidence,'$.Setting.Value',2) WHERE name='OwnerSource'; UPDATE control_precondition SET evidence='DefaultedByAbsence:0:2' WHERE name='BlockOwnerImplicitRights'", "could not be read")]
    public void DamagedProofOrPreviousEngineClearsBothRowsAndSelectedEvidence(string mutation, string notice)
    {
        var directory = Prepared($"O:{UserSid}G:SYD:(A;;WD;;;S-1-3-4)");
        using var source = new BundleAssetSource();
        var section = Open(source, directory, TargetDn, false);
        Assert.Single(section.Rows);
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = mutation;
            Assert.True(command.ExecuteNonQuery() > 0);
        });
        section.FirstPageCommand.Execute(null);
        Assert.Empty(section.Rows);
        Assert.Null(section.SelectedEdge);
        Assert.Contains(notice, section.Coverage);
    }

    [Fact]
    public void ReplicationSchema21DoesNotPretendToHaveEvaluatedOwnership()
    {
        var directory = Prepared($"O:{UserSid}G:SYD:");
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE judgement SET schema_version=21";
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        Assert.False(JudgementReader.Open(directory).IsSuccess);
    }

    [Fact]
    public void HolderPagingPreservesEveryDistinctOwnedTarget()
    {
        var directory = Prepared($"O:{UserSid}G:SYD:", extraTargets: 102);
        using var reader = JudgementReader.Open(directory).Value;
        var first = reader.ReadControlEdges(null, UserSid, null, true, 0);
        var last = reader.ReadControlEdges(null, UserSid, null, true, first.LastId);
        Assert.True(first.HasMore);
        Assert.False(last.HasMore);
        Assert.Equal(103, first.Edges.Concat(last.Edges).Select(edge => edge.Target).Distinct().Count());
    }

    internal static string Prepared(string descriptor, bool derive = true, int extraTargets = 0)
    {
        var directory = Bundle(sddl: descriptor, users: 0, members: [UserDn], writeAdditional: (writer, coverage) =>
        {
            Write(UserDn, [Text("objectClass", "top", "person", "organizationalPerson", "user"),
                Bytes("objectSid", Sid.ToBytes(UserSid)!), Text("userAccountControl", "512"), Text("primaryGroupID", "513")]);
            Write("CN=Domain Users,DC=contoso,DC=com", [Text("objectClass", "top", "group"),
                Bytes("objectSid", Sid.ToBytes("S-1-5-21-1-2-3-513")!), Text("groupType", "-2147483646"), Text("member")]);
            for (var index = 0; index < extraTargets; index++)
                Write($"OU=Owned{index},DC=contoso,DC=com", [Text("objectClass", "top", "organizationalUnit")], descriptor);
            writer.WriteObject(new(coverage, "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=contoso,DC=com", Guid.NewGuid(),
                [Text("objectClass", "top", "nTDSService"), Text("dSHeuristics")], Started));
            void Write(string dn, EvidenceAttribute[] attributes, string sddl = "O:SYG:SYD:")
            {
                var guid = Guid.NewGuid();
                var id = writer.WriteObject(new(coverage, dn, guid, attributes, Started));
                var raw = new RawSecurityDescriptor(sddl);
                var bytes = new byte[raw.BinaryLength];
                raw.GetBinaryForm(bytes, 0);
                writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
            }
        });
        if (derive) Derive(directory);
        var hash = Hash(directory);
        var judged = JudgingRun.Judge(directory, [], Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        Assert.Equal(hash, Hash(directory));
        return directory;
    }

    private static EvidenceAttribute Text(string name, params string[] values) => new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
    private static EvidenceAttribute Bytes(string name, byte[] value) => new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(value)]);

    private static ControlEdgesSectionViewModel Open(BundleAssetSource source, string directory, string dn, bool byHolder)
    {
        var screen = new AssetsViewModel(source);
        screen.Show(directory, false);
        var attributes = Assert.IsType<ObjectAttributes>(source.ReadObjectAttributes(directory, dn).Value);
        screen.OpenObject(new(new(dn, dn, attributes.ObjectGuid, attributes.Find("objectClass")?.Values[^1].Text, "DC=contoso,DC=com")));
        var opened = Assert.IsType<ObjectViewModel>(screen.Opened);
        opened.Show(ObjectSectionCatalog.ControlEdges);
        var section = Assert.IsType<ControlEdgesSectionViewModel>(opened.Selected);
        section.ByHolder = byHolder;
        return section;
    }
}
