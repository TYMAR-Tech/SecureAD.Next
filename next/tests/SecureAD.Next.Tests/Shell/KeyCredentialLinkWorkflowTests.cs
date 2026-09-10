using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.KeyCredentialLinkControlTests;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class KeyCredentialLinkWorkflowTests
{
    private const string OtherSet = "bbbbbbbb-1111-2222-3333-444444444444";
    private const string SchemaDn = "CN=Schema,CN=Configuration,DC=contoso,DC=com";

    [Theory]
    [InlineData(UserDn, false)]
    [InlineData(TargetDn, true)]
    public void PermissionAndOriginalProofReachBothScreenDirections(string dn, bool byHolder)
    {
        var directory = Prepared($"O:SYG:SYD:(OA;;WP;{AttributeGuid};;{TargetSid})");
        using var source = new BundleAssetSource();

        var section = Open(source, directory, dn, byHolder);
        var row = Assert.Single(section.Rows);

        Assert.Equal(("Key-credential write permission", "Established", row), (row.Capability, row.Evaluation, section.SelectedEdge));
        Assert.Contains("Attribute: msDS-KeyCredentialLink.", row.Evidence);
        Assert.Contains("Category: CredentialExposure; this does not classify the target as Tier 0.", row.Evidence);
        Assert.Contains(AttributeGuid, row.Evidence);
        Assert.Contains(TargetSid, row.Evidence);
        Assert.Contains("Permission evidence only. A key-credential write and subsequent sign-in have not been tested. This does not establish account takeover or a completed path to Tier 0.", row.Evidence);
    }

    [Theory]
    [InlineData("GA", 1)]
    [InlineData("GW", 1)]
    [InlineData("WP", 1)]
    [InlineData("CR", 0)]
    [InlineData("SW", 0)]
    [InlineData("RP", 0)]
    [InlineData("WD", 0)]
    [InlineData("WO", 0)]
    public void RealPermissionReaderUsesPropertyWriteGenericMappings(string rights, int count)
    {
        var directory = Prepared($"O:SYG:SYD:(A;;{rights};;;{TargetSid})");
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Equal(count, KeyEdges(reader, UserDn).Count());
    }

    [Theory]
    [InlineData("same", ControlEvaluationState.Established)]
    [InlineData("missing", ControlEvaluationState.Unknown)]
    [InlineData("unassigned", ControlEvaluationState.Unknown)]
    [InlineData("malformed", ControlEvaluationState.Unknown)]
    public void CapturedAttributeAssignmentDeterminesPropertySetGrant(string assignment, ControlEvaluationState expected)
    {
        var directory = Prepared($"O:SYG:SYD:(OA;;WP;{SetGuid};;{TargetSid})", assignment);
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Equal(expected, Assert.Single(KeyEdges(reader, UserDn)).EvaluationState);
    }

    [Fact]
    public void APositivelyCapturedDifferentSetDoesNotGrantTheAttribute()
    {
        var directory = Prepared($"O:SYG:SYD:(OA;;WP;{SetGuid};;{TargetSid})", "different");
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Empty(KeyEdges(reader, UserDn));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("unassigned")]
    [InlineData("malformed")]
    public void PartialSchemaDenyIsNotDroppedByTheRealReader(string assignment)
    {
        var directory = Prepared($"O:SYG:SYD:(OD;;WP;{SetGuid};;{TargetSid})(OA;;WP;{AttributeGuid};;{TargetSid})", assignment);
        using var reader = JudgementReader.Open(directory).Value;
        var edge = Assert.Single(KeyEdges(reader, UserDn));
        Assert.Equal((ControlEvaluationState.Unknown, 2, true),
            (edge.EvaluationState, edge.Evidence.Count, edge.Uncertainty.HasFlag(ControlUncertainty.KeyCredentialLinkScopeNotEvaluated)));
    }

    [Fact]
    public void ACompletePropertySetDenyPreventsTheStoredGrant()
    {
        var directory = Prepared($"O:SYG:SYD:(OD;;WP;{SetGuid};;{TargetSid})(OA;;WP;{AttributeGuid};;{TargetSid})", "same");
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Empty(KeyEdges(reader, UserDn));
    }

    [Fact]
    public void CapturedSchemaRoundTripPreservesTheAttributeToSetGuidJoin()
    {
        var directory = Prepared($"O:SYG:SYD:(OA;;WP;{SetGuid};;{TargetSid})", "same");
        using var reader = BundleReader.Open(directory).Value;
        Assert.Equal(true, reader.ReadSchemaGuids().AttributeBelongsToPropertySet(AttributeName, SetGuid));
    }

    [Fact]
    public void OriginalAcesScopeAndGenerationsSurviveBothStorageDirections()
    {
        var directory = Prepared($"O:SYG:SYD:(OA;ID;WP;{SetGuid};;{TargetSid})(OA;;WP;{AttributeGuid};;{TargetSid})", "same", [new AdminCountWithoutProtection()]);
        using var reader = JudgementReader.Open(directory).Value;
        var byObject = Assert.Single(KeyEdges(reader, UserDn));
        var byHolder = Assert.Single(reader.ReadControlEdges(null, TargetSid, null, true, 0).Edges);
        Assert.NotNull(byHolder.DerivationGenerationId);
        Assert.Equal((byObject.Id, reader.Description.GenerationId, reader.Description.DerivationGenerationId,
                ControlEdgeClass.CredentialExposure),
            (byHolder.Id, byHolder.GenerationId, byHolder.DerivationGenerationId, byHolder.EdgeClass));
        Assert.Equal(new[] { SetGuid, AttributeGuid }, byHolder.Evidence.Select(ace => ace.ObjectTypeGuid));
        Assert.Equal(new[] { 0, 1 }, byHolder.Evidence.Select(ace => ace.Ordinal));
        Assert.True(byHolder.Evidence[0].IsInherited);
        Assert.Contains(byHolder.Preconditions, condition => condition.EvidenceSource.Contains("Captured property set", StringComparison.Ordinal));
    }

    [Fact]
    public void SelfResolvesThroughTheRealReaderButOriginalSelfSidSurvives()
    {
        var directory = Prepared($"O:SYG:SYD:(OA;;WP;{AttributeGuid};;PS)");
        using var reader = JudgementReader.Open(directory).Value;
        var edge = Assert.Single(KeyEdges(reader, UserDn));
        Assert.Equal((UserSid, "S-1-5-10"), (edge.HolderSid, Assert.Single(edge.Evidence).Trustee.Sid));
    }

    [Fact]
    public void GroupMembersDoNotMultiplyHolderTargetCounts()
    {
        var directory = Bundle(userDescriptor: $"O:SYG:SYD:(OA;;WP;{AttributeGuid};;{TargetSid})(OA;;WP;{AttributeGuid};;{TargetSid})", users: 4,
            tier0Route: true);
        Derive(directory);
        Judge(directory);
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Equal((1, 4), (KeyEdges(reader, UserDn).Count(), reader.ReadControlEdges(null, TargetSid, null, true, 0).Edges.Count));
    }

    [Theory]
    [InlineData("S-1-5-21-1-2-3-526")]
    [InlineData("S-1-5-21-1-2-3-527")]
    public void KeyAdministratorGrantsRemainVisibleAfterRealDerivation(string sid)
    {
        var directory = Bundle(userDescriptor: $"O:SYG:SYD:(OA;;WP;{AttributeGuid};;{sid})", tier0Route: true,
            writeAdditional: (writer, coverage) =>
            {
                writer.WriteObject(new(coverage, "CN=KeyHolder,DC=contoso,DC=com", Guid.NewGuid(),
                    [Text("objectClass", "top", "group"), Bytes("objectSid", Sid.ToBytes(sid)!), Text("groupType", "-2147483646")], Started));
                writer.WriteObject(new(coverage, "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=contoso,DC=com", Guid.NewGuid(),
                    [Text("objectClass", "top", "nTDSService"), Text("dSHeuristics")], Started));
            });
        Derive(directory);
        Judge(directory, [new AdminCountWithoutProtection()]);
        using var reader = JudgementReader.Open(directory).Value;
        var page = reader.ReadControlEdges(UserDn, null, null, false, 0);
        Assert.Equal((1L, ControlExpectedness.Unexpected, sid), (page.UnexpectedCount, Assert.Single(page.Edges).Expectedness, page.Edges[0].HolderSid));
    }

    [Fact]
    public void ExpectedSystemGrantsRemainStoredAndCountedWhenHidden()
    {
        var directory = Prepared($"O:SYG:SYD:(OA;;WP;{AttributeGuid};;SY)");
        using var reader = JudgementReader.Open(directory).Value;
        var hidden = reader.ReadControlEdges(UserDn, null, null, false, 0);
        var shown = reader.ReadControlEdges(UserDn, null, null, true, 0);
        Assert.Equal((1L, 0, ControlExpectednessReason.ExpectedPlatformIdentityDirectAce),
            (hidden.ExpectedCount, hidden.Edges.Count, Assert.Single(shown.Edges).ExpectednessReason));
    }

    [Fact]
    public void JudgingPreservesTheSealedEvidenceAndLeavesDiscoveryInactive()
    {
        var directory = Bundle(userDescriptor: $"O:SYG:SYD:(OA;;WP;{AttributeGuid};;{TargetSid})");
        var hash = Hash(directory);
        Derive(directory);
        Judge(directory);
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Equal((hash, "NotStarted"), (Hash(directory), reader.ReadSelfMembershipSummary()!.Verdict));
    }

    [Theory]
    [InlineData("UPDATE control_product SET engine_version=3", "not derived")]
    [InlineData("UPDATE control_edge SET edge_class='DirectoryControl' WHERE capability='CanWriteKeyCredentialLink'", "could not be read")]
    [InlineData("DELETE FROM control_ace WHERE edge_id IN (SELECT id FROM control_edge WHERE capability='CanWriteKeyCredentialLink')", "could not be read")]
    public void UnsupportedOrDamagedProductsClearOldScreenProof(string mutation, string notice)
    {
        var directory = Prepared($"O:SYG:SYD:(OA;;WP;{AttributeGuid};;{TargetSid})");
        using var source = new BundleAssetSource();
        var section = Open(source, directory, UserDn, false);
        Assert.NotNull(section.SelectedEdge);
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = mutation;
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        section.FirstPageCommand.Execute(null);
        Assert.Empty(section.Rows);
        Assert.Null(section.SelectedEdge);
        Assert.Contains(notice, section.Coverage);
    }

    [Fact]
    public void Schema19CannotBeReadAsAnEvaluatedKeyCredentialProduct()
    {
        var directory = Prepared($"O:SYG:SYD:(OA;;WP;{AttributeGuid};;{TargetSid})");
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE judgement SET schema_version=19";
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        Assert.False(JudgementReader.Open(directory).IsSuccess);
    }

    private static string Prepared(string descriptor, string? assignment = null, IRule[]? rules = null)
    {
        // A key-credential write is a route to the account's credentials, so a target reachable from
        // Tier 0 is what makes these grants worth assessing at all.
        var directory = Bundle(userDescriptor: descriptor, tier0Route: true, writeAdditional: (writer, coverage) =>
        {
            if (assignment is null) return;
            writer.WriteObject(new(coverage, "CN=SomeSet,CN=Extended-Rights,CN=Configuration,DC=contoso,DC=com", Guid.NewGuid(),
                [Text("objectClass", "controlAccessRight"), Text("cn", "SomeSet"), Text("rightsGuid", SetGuid), Text("validAccesses", "48")], Started));
            writer.WriteObject(SchemaAttribute(coverage, "displayName", Guid.Parse("bf967953-0de6-11d0-a285-00aa003049e2"), Guid.Parse(SetGuid).ToByteArray()));
            if (assignment != "missing")
                writer.WriteObject(SchemaAttribute(coverage, AttributeName, Guid.Parse(AttributeGuid), assignment switch
                {
                    "same" => Guid.Parse(SetGuid).ToByteArray(),
                    "different" => Guid.Parse(OtherSet).ToByteArray(),
                    "malformed" => [1],
                    _ => null,
                }));
        });
        Derive(directory);
        Judge(directory, rules);
        return directory;
    }

    private static EvidenceObject SchemaAttribute(PartitionCoverage coverage, string name, Guid guid, byte[]? assignment) =>
        new(coverage, "CN=" + name + "," + SchemaDn, Guid.NewGuid(),
            [Text("objectClass", "attributeSchema"), Text("lDAPDisplayName", name), Bytes("schemaIDGUID", guid.ToByteArray()),
                Text("isSingleValued", "FALSE"), new("attributeSecurityGUID", StoredAttributeCompleteness.Complete,
                    assignment is null ? [] : [EvidenceValue.OfBytes(assignment)])], Started);

    private static EvidenceAttribute Text(string name, params string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());

    private static EvidenceAttribute Bytes(string name, byte[] value) => new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(value)]);

    private static IEnumerable<ControlEdge> KeyEdges(JudgementReader reader, string target) =>
        reader.ReadControlEdges(target, null, null, true, 0).Edges.Where(edge => edge.Capability == ControlCapability.CanWriteKeyCredentialLink);

    private static void Judge(string directory, IRule[]? rules = null)
    {
        var result = JudgingRun.Judge(directory, rules ?? [], Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

    private static ControlEdgesSectionViewModel Open(BundleAssetSource source, string directory, string dn, bool byHolder)
    {
        var screen = new AssetsViewModel(source);
        screen.Show(directory, false);
        var attributes = Assert.IsType<ObjectAttributes>(source.ReadObjectAttributes(directory, dn).Value);
        var objectClass = Assert.IsType<string>(attributes.Find("objectClass")?.Values.Last().Text);
        screen.OpenObject(new(new(dn, dn, attributes.ObjectGuid, objectClass, "DC=contoso,DC=com")));
        var opened = Assert.IsType<ObjectViewModel>(screen.Opened);
        opened.Show(ObjectSectionCatalog.ControlEdges);
        var section = Assert.IsType<ControlEdgesSectionViewModel>(opened.Selected);
        section.ByHolder = byHolder;
        return section;
    }
}
