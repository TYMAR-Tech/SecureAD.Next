using System.Collections.Immutable;
using System.Globalization;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using Xunit;
using static SecureAD.Next.Tests.Judgement.GpoSecurityRun;

namespace SecureAD.Next.Tests.Judgement;

public sealed class GpoDirectoryWmiAssessmentTests
{
    [Theory]
    [InlineData("10.0 (20348)", "10.0.20348")]
    [InlineData("10.0.20348", "10.0.20348")]
    [InlineData("6.3 (9600)", "6.3.9600")]
    public void DirectoryWmiCompleteVersionsRetainOriginalsRatherThanReusingTheLooseCapabilityParser(string raw, string expected)
    {
        var source = Values(version: raw);
        var facts = GpoDirectoryWmiAssessment.ReadFacts(source);
        Assert.Same(source, facts.OriginalValues);
        Assert.Equal(raw, facts.OriginalValues.Find("operatingSystemVersion")!.OnlyValue!.Text);
        Assert.Equal(expected, facts.Version);
        Assert.Equal(3u, facts.ProductType);
        Assert.Empty(facts.Limitations);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("10.0")]
    [InlineData("10.0 (20348) trailing")]
    [InlineData("10.0.20348.1")]
    [InlineData("010.0 (20348)")]
    [InlineData("10.0 (-20348)")]
    [InlineData("10.0 (4294967296)")]
    [InlineData("10.0 (0)")]
    public void DirectoryWmiIncompleteOrUnqualifiedVersionsRemainUnknown(string? raw)
    {
        var facts = GpoDirectoryWmiAssessment.ReadFacts(Values(version: raw));
        Assert.Null(facts.Version);
        Assert.Equal(3u, facts.ProductType);
        Assert.Contains(facts.Limitations, error => error.Code == "Evidence.GpoDirectoryWmiVersionUnavailable");
    }

    [Theory]
    [InlineData("Windows Server 2022 Datacenter", "4096", 3u)]
    [InlineData("Microsoft Windows Server 2019 Standard", "8192", 2u)]
    [InlineData("Windows Server 2022 Datacenter", "67112960", 2u)]
    [InlineData("Windows 11 Enterprise", "4096", 1u)]
    [InlineData("Windows 11 Enterprise", "8192", null)]
    [InlineData("Windows Server 2022 Datacenter", "12288", null)]
    [InlineData("Windows Server 2022 Datacenter", "4608", null)]
    [InlineData("Windows Server 2022 Datacenter", "0", null)]
    [InlineData("Windows Server 2022 Datacenter", null, null)]
    [InlineData("Windows Server 2022 Datacenter", "unusable", null)]
    [InlineData("Not Windows Server 2022", "4096", null)]
    [InlineData("Linux Server", "4096", null)]
    [InlineData(null, "4096", null)]
    public void DirectoryWmiProductTypesDistinguishControllersMembersAndClientsWithoutNameSubstringGuesses(
        string? name, string? flags, uint? expected)
    {
        var facts = GpoDirectoryWmiAssessment.ReadFacts(Values(name, flags: flags));
        Assert.Equal(expected, facts.ProductType);
        Assert.Equal(flags, facts.OriginalValues.Find("userAccountControl")?.OnlyValue?.Text);
        if (expected is null)
            Assert.Contains(facts.Limitations, error => error.Code == "Evidence.GpoDirectoryWmiProductTypeUnavailable");
    }

    [Theory]
    [InlineData("multiple")]
    [InlineData("binary")]
    [InlineData("wrong-ordinal")]
    public void DirectoryWmiPlatformFactsRequireOneOriginalTextValue(string defect)
    {
        var source = Values();
        var values = defect switch
        {
            "multiple" => new[] { new AttributeValue(0, "10.0 (20348)", null), new AttributeValue(1, "10.0 (17763)", null) },
            "binary" => [new AttributeValue(0, null, [1, 2])],
            "wrong-ordinal" => [new AttributeValue(1, "10.0 (20348)", null)],
            _ => throw new ArgumentOutOfRangeException(nameof(defect)),
        };
        source = source with { Attributes = source.Attributes.Select(attribute =>
            attribute.LdapDisplayName == "operatingSystemVersion" ? attribute with { Values = values } : attribute).ToArray() };
        var facts = GpoDirectoryWmiAssessment.ReadFacts(source);
        Assert.Null(facts.Version);
        Assert.Equal(values, facts.OriginalValues.Find("operatingSystemVersion")!.Values);
        Assert.NotEmpty(facts.Limitations);
    }

    [Theory]
    [InlineData("Version = '10.0.20348'", true)]
    [InlineData("Version <> '10.0.17763'", true)]
    [InlineData("Version > '10.0.17763'", true)]
    [InlineData("Version >= '10.0.20348'", true)]
    [InlineData("Version < '10.0.20348'", false)]
    [InlineData("Version <= '10.0.20348'", true)]
    [InlineData("Version = '10.0.17763'", false)]
    [InlineData("Version <> '10.0.20348'", false)]
    [InlineData("Version < '10.0.20349'", true)]
    [InlineData("Version > '10.0.20348'", false)]
    [InlineData("Version >= '10.0.20349'", false)]
    [InlineData("Version <= '10.0.20347'", false)]
    [InlineData("Version LIKE '10.0.%'", true)]
    [InlineData("Version LIKE '6.%'", false)]
    [InlineData("Version LIKE '10.0.20348'", true)]
    [InlineData("Version IS NULL", false)]
    [InlineData("Version IS NOT NULL", true)]
    public void DirectoryWmiVersionComparisonsAssessOnlyTheQualifiedRecordedPlatform(string clause, bool expected) =>
        AssertAssessment(Read("SELECT * FROM Win32_OperatingSystem WHERE " + clause), expected);

    [Fact]
    public void DirectoryWmiVersionOrderingUsesTheStringPropertyNotNumericallyParsedBuilds()
    {
        var result = Read("SELECT * FROM Win32_OperatingSystem WHERE Version > '10.0.10'", version: "10.0 (9)");
        AssertAssessment(result, true);
        Assert.Equal("10.0.9", result.DirectoryAssessment.Facts.Version);
    }

    [Theory]
    [InlineData("ProductType = 3", true)]
    [InlineData("ProductType = '3'", true)]
    [InlineData("ProductType <> 2", true)]
    [InlineData("ProductType < 3", false)]
    [InlineData("ProductType <= 3", true)]
    [InlineData("ProductType > 2", true)]
    [InlineData("ProductType >= 3", true)]
    [InlineData("ProductType = 2", false)]
    [InlineData("ProductType <> 3", false)]
    [InlineData("ProductType < 4", true)]
    [InlineData("ProductType < 10", true)]
    [InlineData("ProductType > 3", false)]
    [InlineData("ProductType >= 4", false)]
    [InlineData("ProductType <= 2", false)]
    [InlineData("ProductType IS NULL", false)]
    [InlineData("ProductType IS NOT NULL", true)]
    public void DirectoryWmiProductTypeComparisonsUseTheNumericPropertyIncludingPublishedQuotedExamples(string clause, bool expected) =>
        AssertAssessment(Read("SELECT * FROM Win32_OperatingSystem WHERE " + clause), expected);

    [Theory]
    [InlineData("(Version LIKE '10.%' AND ProductType = 3) OR ProductType = 1", true)]
    [InlineData("NOT (ProductType = 3 OR ProductType = 1)", false)]
    [InlineData("ProductType = 2 OR (Version = '10.0.20348' AND NOT ProductType = 1)", true)]
    [InlineData("ProductType = 3 AND Version = '10.0.17763'", false)]
    [InlineData("ProductType = 2 OR Version = '10.0.17763'", false)]
    public void DirectoryWmiLogicalGroupingRetainsTheNativeParsedExpression(string clause, bool expected) =>
        AssertAssessment(Read("SELECT * FROM Win32_OperatingSystem WHERE " + clause), expected);

    [Theory]
    [InlineData("SELECT * FROM Win32_OperatingSystem WHERE Caption = 'Windows Server'")]
    [InlineData("SELECT * FROM Win32_OperatingSystem WHERE Version >= 10")]
    [InlineData("SELECT * FROM Win32_OperatingSystem WHERE Version LIKE '10._%'")]
    [InlineData("SELECT * FROM Win32_OperatingSystem WHERE Version LIKE '10.[0-9]%'")]
    [InlineData("SELECT * FROM Win32_OperatingSystem WHERE ProductType = 3.5")]
    [InlineData("SELECT * FROM Win32_OperatingSystem WHERE ProductType = -1")]
    [InlineData("SELECT * FROM Win32_OperatingSystem WHERE ProductType = 3 OR Caption = 'unknown'")]
    [InlineData("SELECT * FROM Win32_OperatingSystem WHERE ProductType = 2 AND Caption = 'unknown'")]
    [InlineData("SELECT * FROM Win32_OperatingSystem")]
    [InlineData("SELECT * FROM Win32_ComputerSystem WHERE DomainRole = 5")]
    public void DirectoryWmiUnsupportedPredicatesCannotBecomeMatchesOrExclusions(string query)
    {
        var result = Read(query);
        Assert.Equal(GpoDirectoryWmiState.Unresolved, result.DirectoryAssessment.State);
        Assert.NotEmpty(result.DirectoryAssessment.Limitations);
        Assert.Equal(GpoApplicabilityState.Unknown, result.State);
    }

    [Theory]
    [InlineData("Version IS NULL", null)]
    [InlineData("Version IS NOT NULL", null)]
    [InlineData("Version >= '10.0.17763'", "10.0")]
    public void DirectoryWmiMissingVersionIsNotTheWmiNullValue(string clause, string? version)
    {
        var result = Read("SELECT * FROM Win32_OperatingSystem WHERE " + clause, version: version);
        Assert.Equal(GpoDirectoryWmiState.Unresolved, result.DirectoryAssessment.State);
        Assert.Contains(result.DirectoryAssessment.Facts.Limitations,
            error => error.Code == "Evidence.GpoDirectoryWmiVersionUnavailable");
    }

    [Fact]
    public void DirectoryWmiAnotherNamespaceCannotBorrowTheOperatingSystemMapping()
    {
        var result = Read("SELECT * FROM Win32_OperatingSystem WHERE ProductType = 3", nameSpace: @"root\Other");
        Assert.Equal(GpoDirectoryWmiState.Unresolved, result.DirectoryAssessment.State);
        Assert.Contains(result.DirectoryAssessment.Limitations, error => error.Code == "Evidence.GpoDirectoryWmiQueryUnsupported");
    }

    [Fact]
    public void DirectoryWmiEveryQueryMustBeQualifiedEvenIfAnotherQueryWouldExclude()
    {
        var result = Read("SELECT * FROM Win32_OperatingSystem WHERE ProductType = 2",
            secondQuery: "SELECT * FROM Win32_ComputerSystem WHERE DomainRole = 5");
        Assert.Equal(GpoDirectoryWmiState.Unresolved, result.DirectoryAssessment.State);
        Assert.Equal(2, result.DirectoryAssessment.Queries.Length);
        Assert.Equal(GpoDirectoryWmiState.DoesNotMatchRecordedPlatform, result.DirectoryAssessment.Queries[0].State);
        Assert.Equal(GpoDirectoryWmiState.Unresolved, result.DirectoryAssessment.Queries[1].State);
        Assert.Equal(GpoApplicabilityState.Unknown, result.State);
    }

    [Theory]
    [InlineData("ProductType = 3", true)]
    [InlineData("ProductType = 2", false)]
    public void DirectoryWmiMultipleSupportedQueriesRequireEveryResult(string clause, bool expected)
    {
        var result = Read("SELECT * FROM Win32_OperatingSystem WHERE Version LIKE '10.0.%'",
            secondQuery: "SELECT * FROM Win32_OperatingSystem WHERE " + clause);
        AssertAssessment(result, expected);
        Assert.Equal(2, result.DirectoryAssessment.Queries.Length);
    }

    [Theory]
    [InlineData("computer-guid")]
    [InlineData("computer-name")]
    [InlineData("policy-generation")]
    [InlineData("condition-seal")]
    [InlineData("condition-computer")]
    [InlineData("condition-filter")]
    public void DirectoryWmiForeignComputerOrFilterSourcesAreRefused(string defect)
    {
        var result = Read("SELECT * FROM Win32_OperatingSystem WHERE ProductType = 3");
        var hierarchy = result.Hierarchy;
        var wmi = result.Wmi;
        var conditional = result.Conditional;
        if (defect == "computer-guid") hierarchy = hierarchy with { ComputerValues = hierarchy.ComputerValues with { ObjectGuid = Guid.NewGuid() } };
        if (defect == "computer-name") hierarchy = hierarchy with { ComputerValues = hierarchy.ComputerValues with { DistinguishedName = "CN=Other," + Parent } };
        if (defect == "policy-generation") wmi = wmi with { Policy = wmi.Policy with { CaptureGenerationId = Guid.NewGuid() } };
        var key = conditional.Wmi!.Condition;
        if (defect == "condition-seal") key = key with { EvidenceSeal = "another seal" };
        if (defect == "condition-computer") key = key with { ComputerObjectId = key.ComputerObjectId + 1 };
        if (defect == "condition-filter") key = key with { FilterObjectId = key.FilterObjectId + 1 };
        conditional = conditional with { Wmi = conditional.Wmi with { Condition = key } };
        Assert.Throws<InvalidDataException>(() => GpoDirectoryWmiAssessment.Of(hierarchy, wmi, conditional, CancellationToken.None));
    }

    [Fact]
    public void DirectoryWmiAssessmentHonorsCancellation()
    {
        var result = Read("SELECT * FROM Win32_OperatingSystem WHERE ProductType = 3");
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        Assert.Throws<OperationCanceledException>(() =>
            GpoDirectoryWmiAssessment.Of(result.Hierarchy, result.Wmi, result.Conditional, stop.Token));
    }

    internal static IReadOnlyList<EvidenceAttribute> Platform(string? name = "Windows Server 2022 Datacenter",
        string? version = "10.0 (20348)") =>
        [.. name is null ? Array.Empty<EvidenceAttribute>() : [Text("operatingSystem", name)],
            .. version is null ? Array.Empty<EvidenceAttribute>() : [Text("operatingSystemVersion", version)]];

    internal static string Wrapper(params string[] queries) =>
        queries.Length.ToString(CultureInfo.InvariantCulture) + ";" + string.Concat(queries.Select(query =>
            FormattableString.Invariant($"3;10;{query.Length};WQL;root\\CIMv2;{query};")));

    private static GpoComputerApplicability Read(string query, string? version = "10.0 (20348)",
        string nameSpace = @"root\CIMv2", string? secondQuery = null)
    {
        const string filterId = "{33333333-3333-3333-3333-333333333333}";
        var definition = secondQuery is null ? Wrapper(query) : Wrapper(query, secondQuery);
        if (nameSpace != @"root\CIMv2")
            definition = FormattableString.Invariant($"1;3;{nameSpace.Length};{query.Length};WQL;{nameSpace};{query};");
        var options = GpoComputerApplicabilityTests.Inputs() with
        {
            ComputerAttributes = Platform(version: version),
            OtherObjects = [new("CN=" + filterId + ",CN=SOM,CN=WMIPolicy,CN=System," + Parent, Guid.NewGuid(),
                [Text("objectClass", "msWMI-Som"), Text("msWMI-ID", filterId), Text("msWMI-Parm2", definition)])],
        };
        options = options with { PolicyAttributes = [.. options.PolicyAttributes, Text("gPCWQLFilter", "[example.test;" + filterId + ";0]")] };
        using var reader = GpoComputerApplicabilityReader.Open(Build(options), CancellationToken.None).Value;
        return reader.Assess(reader.Bundle.ReadObjectIdentity(Computer)!, reader.Bundle.ReadObjectIdentity(Policy)!, CancellationToken.None).Value;
    }

    private static void AssertAssessment(GpoComputerApplicability result, bool expected)
    {
        var assessment = result.DirectoryAssessment;
        Assert.Equal(expected ? GpoDirectoryWmiState.MatchesRecordedPlatform : GpoDirectoryWmiState.DoesNotMatchRecordedPlatform, assessment.State);
        Assert.False(assessment.IsObservedWmiResult);
        Assert.Contains("represents", GpoDirectoryWmiAssessment.Assumption);
        Assert.Equal(result.CaptureGenerationId, assessment.CaptureGenerationId);
        Assert.Equal(result.EvidenceSeal, assessment.EvidenceSeal);
        Assert.Equal(result.Computer, assessment.Computer);
        Assert.Same(result.Hierarchy.ComputerValues, assessment.Facts.OriginalValues);
        Assert.Equal(result.Conditional.Wmi!.Condition, assessment.Condition);
        Assert.Equal(GpoApplicabilityState.Unknown, result.State);
        Assert.True(result.Conditional.HasOpenPolicyScope);
        Assert.Equal(GpoApplicabilityState.Applies, result.Conditional.Wmi.WhenMatches);
        Assert.Equal(GpoApplicabilityState.DoesNotApply, result.Conditional.Wmi.WhenDoesNotMatch);
        Assert.Empty(assessment.Limitations);
    }

    private static ObjectAttributes Values(string? name = "Windows Server 2022 Datacenter",
        string? version = "10.0 (20348)", string? flags = "4096") =>
        new(Computer, ComputerGuid, Captured, EvidenceCompleteness.Complete,
            [.. Platform(name, version).Select(attribute => new ObjectAttribute(attribute.LdapDisplayName,
                AttributeCardinality.SingleValued, attribute.Values.Select((value, index) =>
                    new AttributeValue(index, value.Text, value.Bytes)).ToArray())),
                .. flags is null ? Array.Empty<ObjectAttribute>() :
                    [new("userAccountControl", AttributeCardinality.SingleValued, [new(0, flags, null)])]], "example.test");

    private static EvidenceAttribute Text(string name, string value) =>
        new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(value)]);
}
