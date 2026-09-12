using System.Security.AccessControl;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// The planted half of the P-145 behavioural gate: permissions whose classification was decided
/// from the stated policy before this fixture existed.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every expected answer here was written down before the deriver was run.</b> P-145 says asking
/// the laboratory whether a holder is philosophically expected is circular, because the expectedness
/// rule supplied the label. These cases avoid that by reading the policy - the control-plane scopes in
/// <see cref="PrincipalClassificationRegistry"/> and the arms of <c>ControlEdgeDeriver.Expected</c> -
/// and asserting the consequence a reader would see.
/// </para>
/// <para>
/// <b>What is under test is decision 0099's exclusions.</b> Microsoft names certain groups privileged
/// "such as" a list; this product inferred from that phrase that the five operator groups are not part
/// of the control plane, so the permissions they hold surface as unexpected. The inclusions are
/// anchored to Microsoft and the exclusions are this product's inference, which is why the inference
/// needs a gate measuring what it does rather than a test agreeing it exists.
/// </para>
/// <para>
/// <b>These are consequences, not volumes.</b> A synthetic bundle establishes that a planted permission
/// is classified as the policy says and stays visible. It says nothing about how many such permissions
/// a real forest holds; that is the exploratory half, which needs captured evidence.
/// </para>
/// </remarks>
public sealed class ControlEdgeExpectednessGateTests
{
    private const string DomainDn = "DC=contoso,DC=com";
    private const string DomainSid = "S-1-5-21-1-2-3";
    private const string OrdinaryDn = "CN=Ordinary,DC=contoso,DC=com";
    private const string OrdinarySid = "S-1-5-21-1-2-3-1100";
    private const string DomainAdminsDn = "CN=Domain Admins,DC=contoso,DC=com";
    private const string DomainAdminsSid = "S-1-5-21-1-2-3-512";
    private const string BackupOperatorsSid = "S-1-5-32-551";
    private const string AuthenticatedUsersSid = "S-1-5-11";
    private const string SystemSid = "S-1-5-18";
    private const string ResetPasswordGuid = "00299570-246d-11d0-a768-00aa006e0529";
    private const string KeyCredentialGuid = "5b47d60f-6090-40b2-9f37-2a4de88f3063";

    /// <summary>
    /// SYSTEM holding WRITE_DAC directly, on a complete descriptor, is the platform doing its job.
    /// </summary>
    /// <remarks>
    /// Predetermined from <c>ControlEdgeDeriver.Expected</c>: S-1-5-18 with a complete DACL and an
    /// effective direct ACE answers <c>ExpectedPlatformIdentityDirectAce</c> before any scope test runs.
    /// </remarks>
    [Fact]
    public void SystemHoldingWriteDaclIsExpectedAsAPlatformIdentity()
    {
        var edge = Planted($"(A;;WD;;;{SystemSid})", SystemSid, routesDecideTheAnswer: false);
        Assert.Equal((ControlExpectedness.Expected, ControlExpectednessReason.ExpectedPlatformIdentityDirectAce),
            (edge.Expectedness, edge.ExpectednessReason));
    }

    /// <summary>
    /// Domain Admins holding WRITE_DAC inside its own domain is within its authority.
    /// </summary>
    /// <remarks>
    /// Predetermined: RID 512 carries <c>PrincipalAuthorityScope.Domain</c>, and a domain-scoped holder
    /// against a target in the same domain answers <c>ExpectedSameDomainControlPlane</c>.
    /// </remarks>
    [Fact]
    public void DomainAdminsHoldingWriteDaclInItsOwnDomainIsExpected()
    {
        var edge = Planted($"(A;;WD;;;{DomainAdminsSid})", DomainAdminsSid);
        Assert.Equal((ControlExpectedness.Expected, ControlExpectednessReason.ExpectedSameDomainControlPlane),
            (edge.Expectedness, edge.ExpectednessReason));
    }

    /// <summary>
    /// <b>The 0099 exclusion itself.</b> Backup Operators holding WRITE_DAC is reported unexpected.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Predetermined: the registry gives S-1-5-32-551 a control-plane scope of
    /// <see cref="PrincipalAuthorityScope.None"/>, and <c>None</c> answers
    /// <c>UnexpectedNotControlPlane</c>. Only S-1-5-32-544 among the BUILTIN groups is control plane.
    /// </para>
    /// <para>
    /// <b>This is the inference the gate exists to measure, not merely to confirm.</b> Backup Operators
    /// holds permissions in every forest Microsoft has ever shipped, so whether this classification
    /// helps or buries a reader is a question about volume that only captured evidence can answer.
    /// This test fixes what the product says; it does not settle whether saying it is right.
    /// </para>
    /// </remarks>
    [Fact]
    public void BackupOperatorsHoldingWriteDaclIsUnexpectedBecauseItIsNotControlPlane()
    {
        var edge = Planted($"(A;;WD;;;{BackupOperatorsSid})", BackupOperatorsSid);
        Assert.Equal((ControlExpectedness.Unexpected, ControlExpectednessReason.UnexpectedNotControlPlane),
            (edge.Expectedness, edge.ExpectednessReason));
    }

    /// <summary>
    /// A broad principal is unexpected for being broad, before any scope question is asked.
    /// </summary>
    /// <remarks>
    /// Predetermined: <c>definition.IsBroad</c> is the first arm of <c>Expected</c>, so Authenticated
    /// Users answers <c>UnexpectedBroadPrincipal</c> rather than an authority-scope reason.
    /// </remarks>
    [Fact]
    public void AuthenticatedUsersHoldingWriteDaclIsUnexpectedAsABroadPrincipal()
    {
        var edge = Planted($"(A;;WD;;;{AuthenticatedUsersSid})", AuthenticatedUsersSid, routesDecideTheAnswer: false);
        Assert.Equal((ControlExpectedness.Unexpected, ControlExpectednessReason.UnexpectedBroadPrincipal),
            (edge.Expectedness, edge.ExpectednessReason));
    }

    /// <summary>
    /// An ordinary account holding WRITE_DAC is unexpected wherever it holds it.
    /// </summary>
    [Fact]
    public void AnOrdinaryAccountHoldingWriteDaclIsUnexpected()
    {
        var edge = Planted($"(A;;WD;;;{OrdinarySid})", OrdinarySid);
        Assert.Equal((ControlExpectedness.Unexpected, ControlExpectednessReason.UnexpectedNotControlPlane),
            (edge.Expectedness, edge.ExpectednessReason));
    }

    /// <summary>
    /// An ordinary account holding WRITE_OWNER is recorded as its own capability.
    /// </summary>
    /// <remarks>
    /// <c>CanSetOwner</c> is counted independently of any subsequent takeover, so this is the capability
    /// the permission establishes rather than the compound transition it might enable.
    /// </remarks>
    [Fact]
    public void AnOrdinaryAccountHoldingWriteOwnerIsAnUnexpectedSetOwnerCapability()
    {
        var edge = Planted($"(A;;WO;;;{OrdinarySid})", OrdinarySid, ControlCapability.CanSetOwner);
        Assert.Equal((ControlCapability.CanSetOwner, ControlExpectedness.Unexpected),
            (edge.Capability, edge.Expectedness));
    }

    /// <summary>
    /// Reset Password held by an ordinary account is unexpected; one of the capabilities added since
    /// the harness was first written.
    /// </summary>
    [Fact]
    public void AnOrdinaryAccountHoldingResetPasswordIsUnexpected()
    {
        var edge = Planted($"(OA;;CR;{ResetPasswordGuid};;{OrdinarySid})", OrdinarySid,
            ControlCapability.CanResetPassword, targetClass: "user");
        Assert.Equal((ControlCapability.CanResetPassword, ControlExpectedness.Unexpected),
            (edge.Capability, edge.Expectedness));
    }

    /// <summary>
    /// Key-credential write held by an ordinary account is unexpected; the shadow-credentials surface.
    /// </summary>
    [Fact]
    public void AnOrdinaryAccountHoldingKeyCredentialWriteIsUnexpected()
    {
        var edge = Planted($"(OA;;WP;{KeyCredentialGuid};;{OrdinarySid})", OrdinarySid,
            ControlCapability.CanWriteKeyCredentialLink, targetClass: "user");
        Assert.Equal((ControlCapability.CanWriteKeyCredentialLink, ControlExpectedness.Unexpected),
            (edge.Capability, edge.Expectedness));
    }

    /// <summary>
    /// The planted unexpected edge against a Tier-0 asset is visible, which is the case P-145 names.
    /// </summary>
    /// <remarks>
    /// An ordinary account holding WRITE_DAC on Domain Admins is the finding an operator opens the
    /// screen to find. It is asserted against the Tier-0 group by name rather than by count, so a
    /// forest full of other unexpected edges could not hide it.
    /// </remarks>
    [Fact]
    public void AnUnexpectedEdgeAgainstATierZeroAssetIsVisible()
    {
        var directory = Bundle(tier0Dacl: $"(A;;WD;;;{OrdinarySid})");
        var edge = Single(directory, DomainAdminsDn, OrdinarySid, ControlCapability.CanWriteDacl);
        Assert.Equal((DomainAdminsDn, ControlExpectedness.Unexpected, ControlExpectednessReason.UnexpectedNotControlPlane),
            (edge.Target, edge.Expectedness, edge.ExpectednessReason));
    }

    /// <summary>
    /// The negative control: without the planted entry the same fixture yields no edge at all.
    /// </summary>
    /// <remarks>
    /// <b>Without this the suite above could pass while measuring nothing.</b> Every assertion here reads
    /// an edge the fixture planted, so a fixture that silently produced edges regardless - or a query
    /// that matched the wrong row - would look identical to a working gate. This is the check
    /// <c>docs/next/README.md</c> requires of every gate, for the reason it has been needed twice.
    /// </remarks>
    [Fact]
    public void WithoutThePlantedEntryThereIsNoEdgeToClassify()
    {
        var directory = Bundle(tier0Dacl: string.Empty);
        using var reader = Open(directory);
        Assert.Empty(reader.ReadControlEdges(DomainAdminsDn, null, null, true, 0)
            .Edges.Where(edge => edge.HolderSid == OrdinarySid));
    }

    /// <summary>
    /// The operator groups are Tier-0 identities and are not control plane, which is deliberate.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>These two answers look contradictory and are not.</b> Account, Server, Print and Backup
    /// Operators are sensitive enough that an attacker reaching one has reached something that matters,
    /// so they are Tier-0 identities. They are still not entitled to administer the directory, so they
    /// carry no control-plane authority and their permissions surface as unexpected.
    /// </para>
    /// <para>
    /// Pinned because a later change could flatten one into the other by accident, and because the
    /// distinction is the whole substance of what 0099 excluded.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("S-1-5-32-548")]
    [InlineData("S-1-5-32-549")]
    [InlineData("S-1-5-32-550")]
    [InlineData("S-1-5-32-551")]
    public void AnOperatorGroupIsATierZeroIdentityWithoutControlPlaneAuthority(string sid)
    {
        var definition = PrincipalClassificationRegistry.For(sid);
        Assert.Equal((PrincipalAuthorityScope.None, true),
            (definition.ControlPlaneScope, definition.Tier0Scope is not null));
    }

    /// <summary>
    /// BUILTIN Administrators is the one BUILTIN group that is control plane, which is the boundary
    /// the four cases above are measured against.
    /// </summary>
    [Fact]
    public void BuiltinAdministratorsIsTheOneBuiltinGroupThatIsControlPlane() =>
        Assert.Equal(PrincipalAuthorityScope.Domain, PrincipalClassificationRegistry.For("S-1-5-32-544").ControlPlaneScope);

    private static ControlEdge Planted(string ace, string holderSid,
        ControlCapability capability = ControlCapability.CanWriteDacl, string targetClass = "group",
        bool routesDecideTheAnswer = true)
    {
        var directory = Bundle(plantedDacl: ace, plantedClass: targetClass);
        return Single(directory, PlantedDn, holderSid, capability, routesDecideTheAnswer);
    }

    private static ControlEdge Single(string directory, string target, string holderSid, ControlCapability capability,
        bool routesDecideTheAnswer = true)
    {
        using var reader = Open(directory);
        var edges = reader.ReadControlEdges(target, null, null, true, 0).Edges
            .Where(edge => string.Equals(edge.HolderSid, holderSid, StringComparison.OrdinalIgnoreCase)
                && edge.Capability == capability).ToArray();
        var edge = Assert.Single(edges);

        // Asserted rather than assumed, and only where it bears on the answer. A holder outside the
        // control plane reaches its verdict only once routes are known to be complete, so an unnoticed
        // incompleteness would turn those cases into tests of a missing input that still looked like
        // tests of the policy. A broad principal or a platform identity answers before routes are
        // consulted at all, and has no captured object to derive routes from.
        if (routesDecideTheAnswer)
            Assert.True(edge.MembershipRoutes.IsComplete,
                $"The fixture did not establish complete membership routes: {edge.MembershipRoutes.IncompleteReasons}.");
        return edge;
    }

    private static JudgementReader Open(string directory)
    {
        var result = JudgementReader.Open(directory);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return result.Value;
    }

    private const string PlantedDn = "CN=Planted,DC=contoso,DC=com";

    /// <summary>
    /// A minimal forest holding one ordinary account, one Tier-0 group and one planted target.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Derivation runs before judging because expectedness depends on it.</b> A holder outside the
    /// control plane only reaches <c>UnexpectedNotControlPlane</c> once membership routes are known to
    /// be complete; without derivation the same holder answers <c>UnknownMembershipIncomplete</c>, and
    /// every unexpected assertion here would be measuring an absent input rather than the policy.
    /// </para>
    /// <para>
    /// <b>The real rule catalogue is scheduled, and that is load-bearing rather than incidental.</b>
    /// <c>JudgeCore</c> opens the derivation only when a scheduled rule declares a derived fact it
    /// needs. Control edges are derived either way, so judging with no rules leaves their membership
    /// routes <c>NotDerived</c> and silently degrades every unexpected answer to unknown. That coupling
    /// cost this fixture six failures before it was understood, which is why it is written down here.
    /// </para>
    /// </remarks>
    private static string Bundle(string? plantedDacl = null, string plantedClass = "group", string? tier0Dacl = null)
    {
        var directory = TempDirectories.Create("control-edge-expectedness");
        var coverage = new PartitionCoverage(DomainDn, NamingContextKind.Domain, "dc01.contoso.com",
            ConnectionSecurityLevel.SignedAndSealed, 3, 100, 1, [], false);
        using (var writer = BundleWriter.Create(directory, Started))
        {
            writer.WriteCoverage(coverage);

            // THE FOREST'S ONE nTDSService OBJECT, without which membership routes are incomplete.
            // dSHeuristics carries the AdminSDHolder exclusion mask, and a forest whose mask cannot be
            // read reports ForestMaskUnreadable on every route - which would leave every unexpected
            // case here answering unknown for a reason that has nothing to do with the policy.
            // "0000000" is the documented default: every character absent means every character zero.
            Write(writer, coverage, "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=contoso,DC=com",
                "nTDSService", null,
                [new("dSHeuristics", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("0000000")])], "O:SYG:SYD:");
            Write(writer, coverage, DomainDn, "domainDNS", DomainSid, [], "O:SYG:SYD:");

            // CAPTURED BECAUSE A REAL FOREST HAS IT. A BUILTIN group that is not captured has no
            // derived membership routes, so its holder answers unknown for want of an object rather
            // than on the strength of the policy. Backup Operators exists in every domain Microsoft
            // has ever shipped, and the case this fixture plants is only meaningful against one.
            Write(writer, coverage, "CN=Backup Operators,CN=Builtin,DC=contoso,DC=com", "group", BackupOperatorsSid,
            [
                new("groupType", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("-2147483643")]),
                new("member", StoredAttributeCompleteness.Complete, []),
            ], "O:SYG:SYD:");
            Write(writer, coverage, OrdinaryDn, "user", OrdinarySid,
                [new("userAccountControl", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("512")])], "O:SYG:SYD:");
            Write(writer, coverage, DomainAdminsDn, "group", DomainAdminsSid,
            [
                new("groupType", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("-2147483646")]),
                new("member", StoredAttributeCompleteness.Complete, []),
            ], $"O:SYG:SYD:{tier0Dacl}");
            if (plantedDacl is not null)
                Write(writer, coverage, PlantedDn, plantedClass, "S-1-5-21-1-2-3-1200",
                    plantedClass == "group"
                        ? [new("groupType", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("-2147483646")]),
                           new("member", StoredAttributeCompleteness.Complete, [])]
                        : [new("userAccountControl", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("512")])],
                    $"O:SYG:SYD:{plantedDacl}");
            writer.Complete(RunCoverage.Of(CoverageId.ForDomains("contoso.com", ["contoso.com"]),
                [DomainCoverage.Read("contoso.com")],
                [ForestPartitionCoverage.Read("CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
                 ForestPartitionCoverage.Read("CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema)],
                SysvolCoverage.Of([])), Started.AddMinutes(1));
        }

        Derive(directory);
        var judged = JudgingRun.Judge(directory, RuleCatalogue.All, Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        return directory;
    }

    private static void Write(BundleWriter writer, PartitionCoverage coverage, string dn, string objectClass,
        string? sid, EvidenceAttribute[] extra, string descriptor)
    {
        var guid = Guid.NewGuid();
        var id = writer.WriteObject(new(coverage, dn, guid,
        [
            new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("top"), EvidenceValue.OfText(objectClass)]),
            .. sid is null ? Array.Empty<EvidenceAttribute>()
                : [new EvidenceAttribute("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)])],
            .. extra,
        ], Started));
        var raw = new RawSecurityDescriptor(descriptor);
        var bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
    }
}
