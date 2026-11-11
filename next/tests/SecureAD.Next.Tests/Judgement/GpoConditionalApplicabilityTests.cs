using System.Collections.Immutable;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using Xunit;
using static SecureAD.Next.Tests.Judgement.GpoComputerApplicabilityTests;
using static SecureAD.Next.Tests.Judgement.GpoSecurityRun;

namespace SecureAD.Next.Tests.Judgement;

public sealed class GpoConditionalApplicabilityTests
{
    private const string FilterId = "{22222222-2222-2222-2222-222222222222}";
    private const string Query = "SELECT * FROM Win32_OperatingSystem WHERE (Version >= '10.0.17763' AND ProductType = '3')";
    private const string Wrapper = "1;3;10;89;WQL;root\\CIMv2;" + Query + ";";
    private static readonly Guid FilterGuid = new("33333333-3333-3333-3333-333333333333");
    private const string SecondPolicy = "CN={55555555-5555-5555-5555-555555555555},CN=Policies,CN=System," + Parent;

    [Fact]
    public void GpoConditionalSupportedFilterHasTwoHypotheticalOutcomesWithoutChangingActualApplicability()
    {
        var result = Assess(Filtered());
        var alternatives = Qualified(result);
        Assert.Equal(GpoApplicabilityState.Applies, alternatives.WhenMatches);
        Assert.Equal(GpoApplicabilityState.DoesNotApply, alternatives.WhenDoesNotMatch);
        Assert.Equal(GpoApplicabilityState.Unknown, result.State);
        Assert.Equal(GpoApplicabilityState.Applies, result.PolicyState);
        Assert.True(result.Conditional.HasOpenPolicyScope);
        Assert.Equal(result.CaptureGenerationId, alternatives.Condition.CaptureGenerationId);
        Assert.Equal(result.EvidenceSeal, alternatives.Condition.EvidenceSeal);
        Assert.Equal(result.Computer.ObjectId, alternatives.Condition.ComputerObjectId);
        Assert.Equal(result.Wmi.Filter!.ObjectId, alternatives.Condition.FilterObjectId);
        Assert.NotEqual(Guid.Parse(FilterId), result.Wmi.Filter.ObjectGuid);
        Assert.Equal(Wrapper, result.Wmi.FilterValues!.Find("msWMI-Parm2")!.OnlyValue!.Text);
        Assert.Equal(Query, Assert.Single(result.Wmi.Definition.Value).Query);
        Assert.Contains(result.Limitations, error => error.Code == "Evidence.GpoApplicabilityWmiUnresolved");
    }

    [Theory]
    [InlineData("functionality")]
    [InlineData("computer-half")]
    [InlineData("empty")]
    [InlineData("security")]
    public void GpoConditionalAMatchingAssumptionCannotUndoAnIndependentPolicyExclusion(string exclusion)
    {
        var options = exclusion switch
        {
            "functionality" => Filtered(Inputs(functionality: "3", flags: null)),
            "computer-half" => Filtered(Inputs(functionality: null, flags: "2")),
            "empty" => Filtered(Inputs(functionality: null, directoryVersion: "0", templateVersion: 0)),
            "security" => Filtered(Inputs(functionality: null) with { Entries = [] }),
            _ => throw new ArgumentOutOfRangeException(nameof(exclusion)),
        };
        var result = Assess(options);
        var alternatives = Qualified(result);
        Assert.Equal(GpoApplicabilityState.DoesNotApply, result.State);
        Assert.Equal(GpoApplicabilityState.DoesNotApply, alternatives.WhenMatches);
        Assert.Equal(GpoApplicabilityState.DoesNotApply, alternatives.WhenDoesNotMatch);
        Assert.NotEmpty(result.Protocol.Limitations);
    }

    [Theory]
    [InlineData("functionality")]
    [InlineData("flags")]
    [InlineData("permissions")]
    [InlineData("no-domain-link")]
    [InlineData("unresolved-link")]
    public void GpoConditionalMatchingDoesNotEstablishOtherUnresolvedPrerequisites(string missing)
    {
        var options = missing switch
        {
            "functionality" => Filtered(Inputs(functionality: null)),
            "flags" => Filtered(Inputs(flags: null)),
            "permissions" => Filtered(Inputs() with { NoDescriptor = true }),
            "no-domain-link" => Filtered(Inputs() with { DomainLinks = null }),
            "unresolved-link" => Filtered(Inputs() with { DomainLinks = "[LDAP://" + Policy + ";unknown]" }),
            _ => throw new ArgumentOutOfRangeException(nameof(missing)),
        };
        var result = Assess(options);
        var alternatives = Qualified(result);
        Assert.Equal(GpoApplicabilityState.Unknown, alternatives.WhenMatches);
        Assert.Equal(GpoApplicabilityState.DoesNotApply, alternatives.WhenDoesNotMatch);
        Assert.Equal(GpoApplicabilityState.Unknown, result.State);
        Assert.NotEmpty(result.Limitations);
        Assert.True(result.Conditional.HasOpenPolicyScope);
    }

    [Theory]
    [InlineData("reference")]
    [InlineData("filter")]
    [InlineData("definition")]
    [InlineData("wrapper")]
    [InlineData("multiple-queries")]
    public void GpoConditionalMissingOrUnsupportedCapturedInputsDoNotBecomeQualifiedAlternatives(string gap)
    {
        var options = Filtered();
        options = gap switch
        {
            "reference" => options with { PolicyAttributes = options.PolicyAttributes.Where(value => value.LdapDisplayName != "gPCWQLFilter").ToArray() },
            "filter" => options with { OtherObjects = [] },
            "definition" => options with { OtherObjects = [Filter(definition: null)] },
            "wrapper" => options with { OtherObjects = [Filter(definition: "unusable")] },
            "multiple-queries" => options with { OtherObjects = [Filter(definition: "2;unqualified wrapper")] },
            _ => throw new ArgumentOutOfRangeException(nameof(gap)),
        };
        var result = Assess(options);
        Assert.Null(result.Conditional.Wmi);
        Assert.False(result.Wmi.Definition.IsSuccess);
        Assert.Equal(result.Wmi.Definition.Error, result.Conditional.UnavailableReason);
        Assert.Contains(result.Limitations, error => error == result.Conditional.UnavailableReason);
        Assert.Equal(GpoApplicabilityState.Unknown, result.State);
        Assert.True(result.Conditional.HasOpenPolicyScope);
    }

    [Theory]
    [InlineData("Unavailable")]
    [InlineData("Rejected")]
    [InlineData("Unsupported")]
    public void GpoConditionalAnUnqualifiedParserResultKeepsItsOriginalReason(string state)
    {
        var result = Assess(Filtered());
        var query = Assert.Single(result.Wmi.Definition.Value);
        var unavailable = WqlQueryReading.Failed(query.Query, Enum.Parse<WqlReadingState>(state),
            "RecordedParserReason", "Recorded parser limitation", 123);
        var wmi = result.Wmi with { Definition = Result<ImmutableArray<CapturedWmiQuery>>.Success([query with { Reading = unavailable }]) };
        var conditional = GpoConditionalApplicability.Of(result.Hierarchy, result.DomainOuState, result.PolicyState, wmi);
        Assert.Null(conditional.Wmi);
        Assert.Equal(unavailable.Error, conditional.UnavailableReason);
        Assert.Equal(123, wmi.Definition.Value[0].Reading.NativeCode);
        Assert.Equal(Query, wmi.Definition.Value[0].Reading.OriginalQuery);
    }

    [Fact]
    public void GpoConditionalTheSameComputerFilterSharesOneConditionAcrossPoliciesAndIgnoredFlags()
    {
        var options = Filtered();
        var directory = Build(options with
        {
            DomainLinks = options.DomainLinks + "[LDAP://" + SecondPolicy + ";0]",
            OtherObjects = [.. options.OtherObjects, AdditionalPolicy()],
        });
        using var reader = GpoComputerApplicabilityReader.Open(directory, CancellationToken.None).Value;
        var computer = reader.Bundle.ReadObjectIdentity(Computer)!;
        var first = reader.Assess(computer, reader.Bundle.ReadObjectIdentity(Policy)!, CancellationToken.None).Value;
        var second = reader.Assess(computer, reader.Bundle.ReadObjectIdentity(SecondPolicy)!, CancellationToken.None).Value;
        Assert.NotEqual(first.Policy.ObjectId, second.Policy.ObjectId);
        Assert.Equal(Qualified(first).Condition, Qualified(second).Condition);
        Assert.NotEqual(first.Wmi.Reference!.IgnoredFlags, second.Wmi.Reference!.IgnoredFlags);
        Assert.Equal(GpoApplicabilityState.Applies, Qualified(second).WhenMatches);
    }

    [Fact]
    public void GpoConditionalDifferentComputersDoNotShareFilterTruth()
    {
        var secondDn = "CN=Second computer," + Parent;
        var options = Filtered();
        var directory = Build(options with
        {
            OtherObjects = [.. options.OtherObjects, new(secondDn, Guid.NewGuid(),
                [Text("objectClass", "top", "person", "organizationalPerson", "user", "computer"),
                    new("objectSid", StoredAttributeCompleteness.Complete,
                        [EvidenceValue.OfBytes(SecureAD.Kernel.Security.Sid.ToBytes(ParentSid + "-1101")!)])])],
        });
        using var reader = GpoComputerApplicabilityReader.Open(directory, CancellationToken.None).Value;
        var policy = reader.Bundle.ReadObjectIdentity(Policy)!;
        var first = reader.Assess(reader.Bundle.ReadObjectIdentity(Computer)!, policy, CancellationToken.None).Value;
        var second = reader.Assess(reader.Bundle.ReadObjectIdentity(secondDn)!, policy, CancellationToken.None).Value;
        Assert.NotEqual(Qualified(first).Condition, Qualified(second).Condition);
        Assert.Equal(Qualified(first).Condition.FilterObjectId, Qualified(second).Condition.FilterObjectId);
        Assert.Equal(GpoApplicabilityState.Applies, Qualified(second).WhenMatches);
    }

    [Fact]
    public void GpoConditionalEqualLogicalIdsAndQueriesInDifferentDomainsDoNotAliasFilterRows()
    {
        var options = Filtered();
        var directory = Build(options with
        {
            DomainLinks = options.DomainLinks + "[LDAP://" + SecondPolicy + ";0]",
            OtherObjects = [Filter(), Filter(child: true), AdditionalPolicy(childFilter: true)],
        });
        using var reader = GpoComputerApplicabilityReader.Open(directory, CancellationToken.None).Value;
        var result = reader.Assess(reader.Bundle.ReadObjectIdentity(Computer)!, reader.Bundle.ReadObjectIdentity(Policy)!, CancellationToken.None).Value;
        var other = reader.Assess(reader.Bundle.ReadObjectIdentity(Computer)!, reader.Bundle.ReadObjectIdentity(SecondPolicy)!, CancellationToken.None).Value;
        Assert.NotEqual(Qualified(result).Condition, Qualified(other).Condition);
        Assert.Equal(result.Wmi.FilterValues!.Find("msWMI-ID")!.OnlyValue!.Text, other.Wmi.FilterValues!.Find("msWMI-ID")!.OnlyValue!.Text);
        Assert.Equal(result.Wmi.FilterValues.Find("msWMI-Parm2")!.OnlyValue!.Text, other.Wmi.FilterValues.Find("msWMI-Parm2")!.OnlyValue!.Text);
    }

    [Fact]
    public void GpoConditionalCaptureAndSealArePartOfTheConditionIdentity()
    {
        var first = Assess(Filtered());
        var second = Assess(Filtered());
        var key = Qualified(first).Condition;
        Assert.Equal(first.CaptureGenerationId, key.CaptureGenerationId);
        Assert.Equal(first.EvidenceSeal, key.EvidenceSeal);
        Assert.NotEqual(key, Qualified(second).Condition);
        Assert.NotEqual(key, key with { EvidenceSeal = "another exact seal" });
        Assert.NotEqual(key, key with { CaptureGenerationId = Guid.NewGuid() });
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void GpoConditionalScopeClosesOnlyWhenSiteAndDomainOuScopeAreBothResolved(bool siteResolved, bool domainOuComplete)
    {
        var result = Assess(Filtered());
        var hierarchy = result.Hierarchy with { SiteScopeResolved = siteResolved, DomainOuEvidenceComplete = domainOuComplete };
        var conditional = GpoConditionalApplicability.Of(hierarchy, result.DomainOuState, result.PolicyState, result.Wmi);
        Assert.Equal(!siteResolved || !domainOuComplete, conditional.HasOpenPolicyScope);
        Assert.Equal(GpoApplicabilityState.Applies, conditional.Wmi!.WhenMatches);
        Assert.Equal(GpoApplicabilityState.Unknown, result.State);
    }

    [Fact]
    public void GpoConditionalKnownClosedScopeExclusionSurvivesAMatchingAssumption()
    {
        var result = Assess(Filtered());
        var hierarchy = result.Hierarchy with { SiteScopeResolved = true };
        var conditional = GpoConditionalApplicability.Of(hierarchy, GpoApplicabilityState.DoesNotApply,
            result.PolicyState, result.Wmi);
        Assert.False(conditional.HasOpenPolicyScope);
        Assert.Equal(GpoApplicabilityState.DoesNotApply, conditional.Wmi!.WhenMatches);
        Assert.Equal(GpoApplicabilityState.DoesNotApply, conditional.Wmi.WhenDoesNotMatch);
        Assert.Equal(GpoApplicabilityState.Unknown, result.State);
    }

    [Theory]
    [InlineData("filter-generation")]
    [InlineData("policy-generation")]
    [InlineData("computer-generation")]
    [InlineData("filter-row")]
    [InlineData("filter-guid")]
    [InlineData("conditions")]
    [InlineData("empty-query-list")]
    [InlineData("multiple-qualified-queries")]
    [InlineData("capture-generation")]
    [InlineData("evidence-seal")]
    [InlineData("missing-parser-reason")]
    public void GpoConditionalForeignOrInconsistentQualifiedSourcesAreRefused(string defect)
    {
        var result = Assess(Filtered());
        var hierarchy = result.Hierarchy;
        var wmi = result.Wmi;
        if (defect == "filter-generation") wmi = wmi with { Filter = wmi.Filter! with { CaptureGenerationId = Guid.NewGuid() } };
        if (defect == "policy-generation") wmi = wmi with { Policy = wmi.Policy with { CaptureGenerationId = Guid.NewGuid() } };
        if (defect == "computer-generation") hierarchy = hierarchy with { Computer = hierarchy.Computer with { CaptureGenerationId = Guid.NewGuid() } };
        if (defect == "filter-row") wmi = wmi with { Filter = wmi.Filter! with { ObjectId = 0 } };
        if (defect == "filter-guid") wmi = wmi with { Filter = wmi.Filter! with { ObjectGuid = null } };
        if (defect == "capture-generation") hierarchy = hierarchy with { CaptureGenerationId = Guid.Empty };
        if (defect == "evidence-seal") hierarchy = hierarchy with { EvidenceSeal = "" };
        if (defect == "conditions")
        {
            var query = Assert.Single(wmi.Definition.Value);
            wmi = wmi with { Definition = Result<ImmutableArray<CapturedWmiQuery>>.Success([query with { Reading = query.Reading with { Conditions = null } }]) };
        }
        if (defect == "empty-query-list") wmi = wmi with { Definition = Result<ImmutableArray<CapturedWmiQuery>>.Success([]) };
        if (defect == "multiple-qualified-queries")
        {
            var query = Assert.Single(wmi.Definition.Value);
            wmi = wmi with { Definition = Result<ImmutableArray<CapturedWmiQuery>>.Success([query, query]) };
        }
        if (defect == "missing-parser-reason")
        {
            var query = Assert.Single(wmi.Definition.Value);
            wmi = wmi with { Definition = Result<ImmutableArray<CapturedWmiQuery>>.Success(
                [query with { Reading = query.Reading with { State = WqlReadingState.Unsupported, Conditions = null, Error = null } }]) };
        }
        Assert.Throws<InvalidDataException>(() => GpoConditionalApplicability.Of(hierarchy, result.DomainOuState, result.PolicyState, wmi));
    }

    [Theory]
    [InlineData("class")]
    [InlineData("guid")]
    [InlineData("row")]
    public void GpoConditionalUnqualifiedComputersHaveAnExplicitUnavailableReason(string defect)
    {
        var result = Assess(Filtered());
        var computer = defect switch
        {
            "class" => result.Computer with { ObjectClass = "user" },
            "guid" => result.Computer with { ObjectGuid = null },
            "row" => result.Computer with { ObjectId = 0 },
            _ => throw new ArgumentOutOfRangeException(nameof(defect)),
        };
        var conditional = GpoConditionalApplicability.Of(result.Hierarchy with { Computer = computer },
            result.DomainOuState, result.PolicyState, result.Wmi);
        Assert.Null(conditional.Wmi);
        Assert.Equal("Evidence.GpoConditionalComputerUnqualified", conditional.UnavailableReason!.Code);
    }

    private static Options Filtered(Options? basis = null)
    {
        basis ??= Inputs();
        return basis with
        {
            PolicyAttributes = [.. basis.PolicyAttributes, Text("gPCWQLFilter", "[example.test;" + FilterId + ";0]")],
            OtherObjects = [Filter()],
        };
    }
    private static OtherObject Filter(bool child = false, string? definition = Wrapper) =>
        new(FilterDn(child), child ? Guid.Parse("44444444-4444-4444-4444-444444444444") : FilterGuid,
            [Text("objectClass", "top", "msWMI-Som"), Text("msWMI-ID", FilterId), Text("msWMI-Name", "Captured condition"),
                .. definition is null ? Array.Empty<EvidenceAttribute>() : [Text("msWMI-Parm2", definition)]]);
    private static string FilterDn(bool child) => "CN=" + FilterId + ",CN=SOM,CN=WMIPolicy,CN=System," + (child ? Child : Parent);
    private static OtherObject AdditionalPolicy(bool childFilter = false) =>
        new(SecondPolicy, new("55555555-5555-5555-5555-555555555555"),
            [Text("objectClass", "top", "container", "groupPolicyContainer"),
                .. Inputs().PolicyAttributes.Where(value => value.LdapDisplayName != "gPCFileSysPath"),
                Text("gPCFileSysPath", @"\\example.test\SYSVOL\example.test\Policies\second"),
                Text("gPCWQLFilter", "[" + (childFilter ? "child.example.test" : "example.test") + ";" + FilterId + ";ignored]")], true);
    private static EvidenceAttribute Text(string name, params string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
    private static GpoWmiAlternatives Qualified(GpoComputerApplicability value)
    {
        Assert.True(value.Wmi.Definition.IsSuccess);
        Assert.Equal(WqlReadingState.ParsedConditions, Assert.Single(value.Wmi.Definition.Value).Reading.State);
        Assert.Null(value.Conditional.UnavailableReason);
        return Assert.IsType<GpoWmiAlternatives>(value.Conditional.Wmi);
    }
    private static GpoComputerApplicability Assess(Options options)
    {
        using var reader = GpoComputerApplicabilityReader.Open(Build(options), CancellationToken.None).Value;
        return reader.Assess(reader.Bundle.ReadObjectIdentity(Computer)!, reader.Bundle.ReadObjectIdentity(Policy)!, CancellationToken.None).Value;
    }
}
