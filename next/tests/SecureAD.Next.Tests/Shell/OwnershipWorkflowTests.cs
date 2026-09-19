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
    public async Task ExistingOwnerProofReachesBothDirectionsWithoutAClaimedOperation(bool byHolder)
    {
        var directory = Prepared($"O:{UserSid}G:SYD:");
        using var source = new BundleAssetSource();
        var section = await OpenAsync(source, directory, byHolder ? UserDn : TargetDn, byHolder);
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

    /// <summary>
    /// The state this describes belongs to decision 0114: every object received control products and
    /// only ownership assessment was scoped, so a target could be proven for control and still not
    /// assessed for ownership. Under 0116 control itself is scoped, and an unadmitted target has no
    /// edges to retain, so this is kept on the unscoped path where that state exists.
    /// <see cref="UnadmittedTargetIsNotAssessedAndSaysSoWithoutClaimingSafety"/> is its scope-aware
    /// counterpart.
    /// </summary>
    [Fact]
    public async Task UnselectedTargetRetainsProvenPrimitiveAndShowsNotAssessedStatus()
    {
        var directory = Prepared($"O:SYG:SYD:(A;;WO;;;{UserSid})(A;;WD;;;S-1-3-4)", tier0Route: false);
        using var reader = JudgementReader.Open(directory).Value;
        var page = reader.ReadControlEdges(TargetDn, null, null, true, 0);
        var primitive = Assert.Single(page.Edges.Where(edge => edge.IsCounted));
        Assert.Equal(ControlEvaluationState.Established, primitive.EvaluationState);
        Assert.DoesNotContain(page.Edges, edge => edge.Capability == ControlCapability.CanBecomeOwnerAndRewriteDacl);
        Assert.Equal(OwnershipAssessmentExecution.NotAssessed, page.OwnershipCoverage?.Execution);
        using var source = new BundleAssetSource();
        Assert.Contains("Not assessed automatically.", (await OpenAsync(source, directory, TargetDn, false)).Coverage);
    }

    /// <summary>
    /// The scope-aware replacement, per 0116: a target discovery never reached has no detailed
    /// products at all, and the screen says nothing assessed it rather than implying it is clean.
    /// </summary>
    [Fact]
    public async Task UnadmittedTargetIsNotAssessedAndSaysSoWithoutClaimingSafety()
    {
        var directory = Prepared($"O:SYG:SYD:(A;;WO;;;{UserSid})(A;;WD;;;S-1-3-4)", tier0Route: false);
        using var reader = JudgementReader.Open(directory).Value;
        var page = reader.ReadControlEdges(TargetDn, null, null, true, 0);
        using var source = new BundleAssetSource();
        Assert.Equal((OwnershipAssessmentExecution.NotAssessed, true),
            (page.OwnershipCoverage?.Execution,
             (await OpenAsync(source, directory, TargetDn, false)).Coverage.Contains("Not assessed automatically.", StringComparison.Ordinal)));
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
    [InlineData("UPDATE permission_entry SET mask=16 WHERE id IN (SELECT entry_id FROM control_ace)", "could not be read")]
    [InlineData("UPDATE control_precondition SET evidence=json_set(evidence,'$.Setting.Value',2) WHERE name='OwnerSource'; UPDATE control_precondition SET evidence='DefaultedByAbsence:0:2' WHERE name='BlockOwnerImplicitRights'", "could not be read")]
    public async Task DamagedProofOrPreviousEngineClearsBothRowsAndSelectedEvidence(string mutation, string notice)
    {
        var directory = Prepared($"O:{UserSid}G:SYD:(A;;WD;;;S-1-3-4)");
        using var source = new BundleAssetSource();
        var section = await OpenAsync(source, directory, TargetDn, false);
        Assert.Single(section.Rows);
        // Open results are protected; arrange corruption between reading lifetimes.
        source.CloseRun();
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = mutation;
            Assert.True(command.ExecuteNonQuery() > 0);
        });
        source.SelectRun(directory);
        section.Configure(true, false,
            (_, expected, after) => ControlProofVerification.ReadResult(directory, TargetDn, expected, after),
            _ => source.ReadSelfMembershipAssessments(directory, TargetDn, null));
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

    internal static string Prepared(string descriptor, bool derive = true, int extraTargets = 0, bool tier0Route = true)
    {
        // Ownership of an object is a route to controlling it, so these targets are worth assessing.
        //
        // extraTargets is the exception and stays off the gated path. Those objects exist to give the
        // reader enough rows to page through, and an ordinary organizational unit owned by an
        // ordinary user is precisely what discovery is right not to admit: the holder's outgoing
        // ownership of ordinary objects is not a route into Tier 0. Manufacturing a hundred Tier-0
        // groups to make them appear would be inventing evidence to restore a count.
        var directory = Bundle(sddl: descriptor, users: 0, members: [UserDn], tier0Route: tier0Route && extraTargets == 0,
            writeAdditional: (writer, coverage) =>
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

    private static async Task<ControlEdgesSectionViewModel> OpenAsync(BundleAssetSource source, string directory, string dn, bool byHolder)
    {
        var screen = new AssetsViewModel(source);
        screen.Show(directory, false);
        await screen.ReadCompletion;
        var attributes = Assert.IsType<ObjectAttributes>(source.ReadObjectAttributes(directory, dn).Value);
        screen.OpenObject(new(new(dn, dn, attributes.ObjectGuid, attributes.Find("objectClass")?.Values[^1].Text, "DC=contoso,DC=com")));
        await screen.ReadCompletion;
        var opened = Assert.IsType<ObjectViewModel>(screen.Opened);
        opened.Show(ObjectSectionCatalog.ControlEdges);
        await opened.ReadCompletion;
        var section = Assert.IsType<ControlEdgesSectionViewModel>(opened.Selected);
        section.ByHolder = byHolder;
        await section.ReadCompletion;
        return section;
    }
}
