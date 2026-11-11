using System.Globalization;
using System.Text;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.GpoSecurityRun;

namespace SecureAD.Next.Tests.Judgement;

public sealed class GpoComputerApplicabilityTests
{
    private const string PolicyPath = @"\\example.test\SYSVOL\example.test\Policies\{11111111-1111-1111-1111-111111111111}";

    [Fact]
    public void GpoCombinedPositivePrerequisitesKeepKnownScopeAndUnresolvedWmiAndSite()
    {
        var result = Assess(Inputs());
        Assert.Equal(GpoApplicabilityState.Applies, result.DomainOuState);
        Assert.Equal(GpoApplicabilityState.Applies, result.PolicyState);
        Assert.Equal(GpoApplicabilityState.Applies, result.Protocol.State);
        Assert.Equal(GpoSecurityDecision.Included, result.Security.Decision);
        Assert.Equal(GpoApplicabilityState.Unknown, result.State);
        Assert.False(result.Hierarchy.SiteScopeResolved);
        Assert.True(result.Hierarchy.DomainOuEvidenceComplete);
        Assert.Single(result.PolicyLinks);
        Assert.Equal(result.Hierarchy.CaptureGenerationId, result.CaptureGenerationId);
        Assert.Equal(result.CaptureGenerationId, result.Security.CaptureGenerationId);
        Assert.Equal(result.CaptureGenerationId, result.Protocol.Inputs.CaptureGenerationId);
        Assert.Equal(result.Computer, result.Security.Computer);
        Assert.Equal(result.Policy, result.Protocol.Inputs.Policy);
        Assert.Equal(result.Policy, result.Wmi.Policy);
        Assert.Equal(result.EvidenceSeal, result.Security.EvidenceSeal);
        Assert.Equal(result.Security.DerivationGenerationId, result.DerivationGenerationId);
        Assert.Contains(result.Limitations, error => error.Code == "Evidence.GpoHierarchySiteUnresolved");
        Assert.Contains(result.Limitations, error => error.Code == "Evidence.GpoWmiReferenceNotReturned");
        Assert.Contains(result.Limitations, error => error.Code == "Evidence.GpoApplicabilityWmiUnresolved");
    }

    [Theory]
    [InlineData("2", true)]
    [InlineData("0", false)]
    [InlineData("3", false)]
    [InlineData("4294967295", false)]
    [InlineData(null, null)]
    [InlineData("unusable", null)]
    [InlineData("-1", null)]
    [InlineData("4294967296", null)]
    public void GpoCombinedFunctionalityRequiresOriginalVersionTwo(string? raw, bool? supported)
    {
        var result = Assess(Inputs(functionality: raw));
        Assert.Equal(supported, result.Protocol.FunctionalitySupported);
        Assert.Equal(raw, result.Protocol.Inputs.PolicyValues.Find("gPCFunctionalityVersion")!.OnlyValue?.Text);
        Assert.Equal(supported == false ? GpoApplicabilityState.DoesNotApply : GpoApplicabilityState.Unknown, result.State);
        if (supported is null)
            Assert.Contains(result.Protocol.Limitations, error => error.Code == (raw is null
                ? "Evidence.GpoApplicabilityInputMissing" : "Evidence.GpoApplicabilityInputUnsupported"));
    }

    [Theory]
    [InlineData("0", true)]
    [InlineData("1", true)]
    [InlineData("2", false)]
    [InlineData("3", false)]
    [InlineData("4", true)]
    [InlineData("6", false)]
    [InlineData("2147483648", true)]
    [InlineData("4294967295", false)]
    [InlineData(null, null)]
    [InlineData("unusable", null)]
    public void GpoCombinedComputerHalfUsesTheDisableBitAndIgnoresOtherBits(string? raw, bool? enabled)
    {
        var result = Assess(Inputs(flags: raw));
        Assert.Equal(enabled, result.Protocol.ComputerHalfEnabled);
        Assert.Equal(raw, result.Protocol.Inputs.PolicyValues.Find("flags")!.OnlyValue?.Text);
        Assert.Equal(enabled == false ? GpoApplicabilityState.DoesNotApply : GpoApplicabilityState.Unknown, result.State);
        if (enabled is null)
            Assert.Contains(result.Protocol.Limitations, error => error.Code == (raw is null
                ? "Evidence.GpoApplicabilityInputMissing" : "Evidence.GpoApplicabilityInputUnsupported"));
    }

    [Theory]
    [InlineData("0", 0u, false)]
    [InlineData("0", 1u, true)]
    [InlineData("1", 0u, true)]
    [InlineData("65536", 0u, true)]
    [InlineData("0", 65536u, true)]
    [InlineData("4294967295", 0u, true)]
    [InlineData("0", 4294967295u, true)]
    [InlineData(null, 0u, null)]
    [InlineData("0", null, null)]
    [InlineData(null, 1u, true)]
    [InlineData("1", null, true)]
    public void GpoCombinedEmptyPolicyUsesBothFullVersionsAndIndependentNonzeroEvidence(
        string? directoryVersion, uint? templateVersion, bool? nonEmpty)
    {
        var result = Assess(Inputs(directoryVersion: directoryVersion, templateVersion: templateVersion));
        Assert.Equal(nonEmpty, result.Protocol.NonEmpty);
        Assert.Equal(directoryVersion is null ? null : uint.Parse(directoryVersion, CultureInfo.InvariantCulture),
            result.Protocol.DirectoryVersion);
        Assert.Equal(templateVersion, result.Protocol.Inputs.TemplateVersion.Version);
        Assert.Equal(nonEmpty == false ? GpoApplicabilityState.DoesNotApply : GpoApplicabilityState.Unknown, result.State);
        if (templateVersion is { } version)
            Assert.Equal(Encoding.ASCII.GetBytes("[General]\r\nVersion=" + version.ToString(CultureInfo.InvariantCulture) + "\r\n"),
                result.Protocol.Inputs.TemplateVersion.OriginalBytes!.Value.ToArray());
    }

    [Theory]
    [InlineData(" 0 ")]
    [InlineData("0.0")]
    public void GpoCombinedUnqualifiedOriginalNumericValuesAreNotCoerced(string original)
    {
        var result = Assess(Inputs(flags: original));
        Assert.Null(result.Protocol.Flags);
        Assert.Null(result.Protocol.ComputerHalfEnabled);
        Assert.Equal(GpoApplicabilityState.Unknown, result.PolicyState);
        Assert.Contains(result.Protocol.Limitations, error => error.Code == "Evidence.GpoApplicabilityInputUnsupported");
        Assert.Equal(original, result.Protocol.Inputs.PolicyValues.Find("flags")!.OnlyValue!.Text);
    }

    [Theory]
    [InlineData(GpoTemplateVersionOutcome.NotCaptured)]
    [InlineData(GpoTemplateVersionOutcome.Unavailable)]
    [InlineData(GpoTemplateVersionOutcome.Missing)]
    [InlineData(GpoTemplateVersionOutcome.Unreadable)]
    [InlineData(GpoTemplateVersionOutcome.Invalid)]
    public void GpoCombinedUnavailableTemplateVersionsDoNotBecomeEmptyPolicies(GpoTemplateVersionOutcome outcome)
    {
        var options = Inputs(directoryVersion: "0", templateVersion: null);
        if (outcome != GpoTemplateVersionOutcome.NotCaptured)
            options = options with
            {
                TemplateVersion = (PolicyPath, new(outcome,
                    outcome == GpoTemplateVersionOutcome.Invalid ? Encoding.ASCII.GetBytes("invalid original") : null,
                    null, null, "Recorded acquisition failure")),
            };
        var result = Assess(options);
        Assert.Equal(outcome, result.Protocol.Inputs.TemplateVersion.Outcome);
        Assert.Null(result.Protocol.NonEmpty);
        Assert.Equal(GpoApplicabilityState.Unknown, result.Protocol.State);
        Assert.Equal(GpoApplicabilityState.Unknown, result.State);
        Assert.Contains(result.Protocol.Limitations, error => error == result.Protocol.Inputs.TemplateVersion.Error);
    }

    [Theory]
    [InlineData("functionality")]
    [InlineData("computer-half")]
    [InlineData("empty")]
    [InlineData("security")]
    public void GpoCombinedIndependentPolicyExclusionsSurviveUnrelatedUnavailableInputs(string exclusion)
    {
        var options = Inputs(functionality: null, flags: null, directoryVersion: null, templateVersion: null);
        options = exclusion switch
        {
            "functionality" => Inputs(functionality: "3", flags: null, directoryVersion: null, templateVersion: null),
            "computer-half" => Inputs(functionality: null, flags: "2", directoryVersion: null, templateVersion: null),
            "empty" => Inputs(functionality: null, flags: null, directoryVersion: "0", templateVersion: 0),
            "security" => options with { Entries = [] },
            _ => throw new ArgumentOutOfRangeException(nameof(exclusion)),
        };
        var result = Assess(options);
        Assert.Equal(GpoApplicabilityState.Applies, result.DomainOuState);
        Assert.Equal(GpoApplicabilityState.DoesNotApply, result.PolicyState);
        Assert.Equal(GpoApplicabilityState.DoesNotApply, result.State);
        Assert.NotEmpty(result.Protocol.Limitations);
        Assert.Contains(result.Limitations, error => error.Code == "Evidence.GpoApplicabilityWmiUnresolved");
    }

    [Fact]
    public void GpoCombinedOriginalRepeatedLinksAndKnownInclusionSurviveMalformedUnrelatedScope()
    {
        var original = "[LDAP://;0]" + Link("0") + Link("1") + Link("2") + Link("3");
        var result = Assess(Inputs() with { DomainLinks = original });
        Assert.Equal(4, result.PolicyLinks.Length);
        Assert.Equal([2, 3, 4, 5], result.PolicyLinks.Select(link => link.Link.Order));
        Assert.Equal(new int?[] { 1, null, 2, null }, result.PolicyLinks.Select(link => link.DomainOuProcessingOrder));
        Assert.Equal([GpoLinkHierarchyState.Included, GpoLinkHierarchyState.Excluded,
            GpoLinkHierarchyState.Included, GpoLinkHierarchyState.Excluded], result.PolicyLinks.Select(link => link.State));
        Assert.Equal(original, Assert.Single(result.Hierarchy.Containers).Values!.Find("gPLink")!.OnlyValue!.Text);
        Assert.False(result.Hierarchy.DomainOuEvidenceComplete);
        Assert.Equal(GpoApplicabilityState.Applies, result.DomainOuState);
        Assert.Equal(GpoApplicabilityState.Unknown, result.State);
    }

    [Theory]
    [InlineData(null, "DoesNotApply")]
    [InlineData("1", "DoesNotApply")]
    [InlineData("3", "DoesNotApply")]
    [InlineData("4", "Unknown")]
    [InlineData("unusable", "Unknown")]
    public void GpoCombinedDomainOuExclusionOrUncertaintyDoesNotInventAbsentSitePolicies(string? options, string domainOuState)
    {
        var result = Assess(Inputs() with { DomainLinks = options is null ? null : Link(options) });
        Assert.Equal(domainOuState, result.DomainOuState.ToString());
        Assert.Equal(GpoApplicabilityState.Applies, result.PolicyState);
        Assert.Equal(GpoApplicabilityState.Unknown, result.State);
        Assert.False(result.Hierarchy.SiteScopeResolved);
        Assert.Contains(result.Limitations, error => error.Code == "Evidence.GpoHierarchySiteUnresolved");
    }

    [Theory]
    [InlineData("included", "Included", "Applies", "Unknown")]
    [InlineData("excluded", "Excluded", "DoesNotApply", "DoesNotApply")]
    [InlineData("unresolved", "Unresolved", "Unknown", "Unknown")]
    public void GpoCombinedDirectorySecurityRetainsItsIndependentAnswer(
        string scenario, string security, string policyState, string state)
    {
        var options = Inputs();
        if (scenario == "excluded") options = options with { Entries = [new("S-1-5-11", GpoSecurityRun.Read)] };
        if (scenario == "unresolved") options = options with { NoDescriptor = true };
        var result = Assess(options);
        Assert.Equal(security, result.Security.Decision.ToString());
        Assert.Equal(policyState, result.PolicyState.ToString());
        Assert.Equal(state, result.State.ToString());
        Assert.Equal(GpoApplicabilityState.Applies, result.Protocol.State);
        Assert.Equal(GpoApplicabilityState.Applies, result.DomainOuState);
    }

    [Theory]
    [InlineData(null, "Evidence.GpoWmiReferenceNotReturned")]
    [InlineData("unusable", "Evidence.GpoWmiReferenceUnsupported")]
    [InlineData("[example.test;{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee};arbitrary]", "Evidence.GpoWmiFilterNotCaptured")]
    public void GpoCombinedWmiOriginalConditionsAndFailuresAreNotAnUnfilteredPolicy(string? reference, string reason)
    {
        var options = Inputs();
        if (reference is not null)
            options = options with { PolicyAttributes = [.. options.PolicyAttributes, Text("gPCWQLFilter", reference)] };
        var result = Assess(options);
        Assert.Equal(GpoApplicabilityState.Applies, result.PolicyState);
        Assert.Equal(GpoApplicabilityState.Unknown, result.State);
        Assert.Equal(reference, result.Wmi.PolicyValues.Find("gPCWQLFilter")!.OnlyValue?.Text);
        Assert.False(result.Wmi.Definition.IsSuccess);
        Assert.Equal(reason, result.Wmi.Definition.Error.Code);
        Assert.Contains(result.Limitations, error => error == result.Wmi.Definition.Error);
    }

    [Fact]
    public void GpoCombinedWrongTemplateResourceIsRefusedInsteadOfProducingAnAssessment()
    {
        var options = Inputs();
        var directory = Build(options with { TemplateVersion = (@"\\other.test\SYSVOL\other-policy", options.TemplateVersion!.Value.Observation) });
        using var reader = GpoComputerApplicabilityReader.Open(directory, CancellationToken.None).Value;
        var result = reader.Assess(reader.Bundle.ReadObjectIdentity(Computer)!, reader.Bundle.ReadObjectIdentity(Policy)!, CancellationToken.None);
        Assert.False(result.IsSuccess);
        Assert.Equal("Evidence.GpoTemplateVersionResourceMismatch", result.Error.Code);
    }

    [Theory]
    [InlineData("computer")]
    [InlineData("policy")]
    public void GpoCombinedSelectedIdentitiesCannotCrossCaptures(string foreign)
    {
        using var first = GpoComputerApplicabilityReader.Open(Build(Inputs()), CancellationToken.None).Value;
        using var second = GpoComputerApplicabilityReader.Open(Build(Inputs()), CancellationToken.None).Value;
        var computer = (foreign == "computer" ? first : second).Bundle.ReadObjectIdentity(Computer)!;
        var policy = (foreign == "policy" ? first : second).Bundle.ReadObjectIdentity(Policy)!;
        Assert.Throws<InvalidDataException>(() => second.Assess(computer, policy, CancellationToken.None));
    }

    [Fact]
    public void GpoCombinedOriginalSourcesHintsCancellationDisposalAndDerivationSelectionArePreserved()
    {
        var group = new Group("Delegated", 600, Global, false, [Computer], []);
        var directory = Build(Inputs() with
        {
            Derive = true, Groups = [group], Entries = [new("S-1-5-11", GpoSecurityRun.Read), new(group.Sid, Apply)],
        });
        var before = BundleSealing.HashFile(BundleLayout.EvidencePath(directory));
        using var reader = GpoComputerApplicabilityReader.Open(directory, CancellationToken.None).Value;
        var computer = reader.Bundle.ReadObjectIdentity(Computer)!;
        var policy = reader.Bundle.ReadObjectIdentity(Policy)!;
        var result = reader.Assess(computer with { DomainFqdn = "wrong.test", ObjectClass = "user" },
            policy with { DomainFqdn = "wrong.test", ObjectClass = "computer" }, CancellationToken.None).Value;
        Assert.Equal(computer, result.Computer);
        Assert.Equal(policy, result.Policy);
        Assert.Equal(GpoApplicabilityState.Applies, result.PolicyState);
        Assert.NotNull(result.DerivationGenerationId);
        Assert.Equal(before, BundleSealing.HashFile(BundleLayout.EvidencePath(directory)));
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        Assert.Throws<OperationCanceledException>(() => reader.Assess(computer, policy, cancelled.Token));
        Assert.Throws<OperationCanceledException>(() => GpoComputerApplicabilityReader.Open(directory, cancelled.Token));
        Derive(directory);
        Assert.Throws<InvalidOperationException>(() => reader.Assess(computer, policy, CancellationToken.None));
        reader.Dispose();
        Assert.Throws<ObjectDisposedException>(() => reader.Assess(computer, policy, CancellationToken.None));
    }

    [Fact]
    public void GpoCombinedChangedCaptureSelectionCannotReuseTheHeldSources()
    {
        var directory = Build(Inputs());
        var replacement = Build(Inputs());
        using var reader = GpoComputerApplicabilityReader.Open(directory, CancellationToken.None).Value;
        var computer = reader.Bundle.ReadObjectIdentity(Computer)!;
        var policy = reader.Bundle.ReadObjectIdentity(Policy)!;
        Assert.Equal(GpoApplicabilityState.Applies, reader.Assess(computer, policy, CancellationToken.None).Value.PolicyState);
        File.Copy(BundleLayout.CaptureManifestPath(replacement), BundleLayout.CaptureManifestPath(directory), true);
        Assert.Throws<InvalidOperationException>(() => reader.Assess(computer, policy, CancellationToken.None));
    }

    internal static Options Inputs(string? functionality = "2", string? flags = "0", string? directoryVersion = "1",
        uint? templateVersion = 1)
    {
        var attributes = new List<EvidenceAttribute> { Text("gPCFileSysPath", PolicyPath) };
        if (functionality is not null) attributes.Add(Text("gPCFunctionalityVersion", functionality));
        if (flags is not null) attributes.Add(Text("flags", flags));
        if (directoryVersion is not null) attributes.Add(Text("versionNumber", directoryVersion));
        var original = templateVersion?.ToString(CultureInfo.InvariantCulture);
        return new Options
        {
            Derive = false, DomainLinks = Link("0"), PolicyAttributes = attributes,
            TemplateVersion = original is null ? null : (PolicyPath, new(GpoTemplateVersionOutcome.Read,
                Encoding.ASCII.GetBytes("[General]\r\nVersion=" + original + "\r\n"), original, templateVersion, null)),
        };
    }

    private static string Link(string options) => "[LDAP://" + Policy + ";" + options + "]";
    private static EvidenceAttribute Text(string name, params string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
    private static GpoComputerApplicability Assess(Options options)
    {
        using var reader = GpoComputerApplicabilityReader.Open(Build(options), CancellationToken.None).Value;
        return reader.Assess(reader.Bundle.ReadObjectIdentity(Computer)!, reader.Bundle.ReadObjectIdentity(Policy)!, CancellationToken.None).Value;
    }
}
