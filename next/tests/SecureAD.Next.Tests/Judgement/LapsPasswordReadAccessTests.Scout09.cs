using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class LapsPasswordReadAccessTests
{
    private const string Scout09Set = "11111111-2222-3333-4444-555555555555";
    private const string Scout09ComputerClass = "bf967a86-0de6-11d0-a285-00aa003049e2";
    private const string Scout09GroupClass = "bf967a9c-0de6-11d0-a285-00aa003049e2";
    private static readonly (string Guid, string Name)[] Scout09Attributes =
        [(PasswordGuid, "msLAPS-Password"), (EncryptedGuid, "msLAPS-EncryptedPassword"), (LegacyGuid, "ms-Mcs-AdmPwd")];

    public static IEnumerable<object?[]> Scout09ConfidentialityCases()
    {
        (int? Search, int? System, int Mask, bool Finding, LapsReadState State, LapsConfidentiality Requirement)[] cases =
        [
            (0, 0, ReadProperty, true, LapsReadState.Established, LapsConfidentiality.NotConfidential),
            (128, 0, ReadProperty, false, LapsReadState.NotEstablished, LapsConfidentiality.Confidential),
            (128, 16, ReadProperty, true, LapsReadState.Established, LapsConfidentiality.NotConfidential),
            (null, 16, ReadProperty, true, LapsReadState.Established, LapsConfidentiality.NotConfidential),
            (null, 0, ReadProperty, true, LapsReadState.Unresolved, LapsConfidentiality.Unresolved),
            (128, null, ReadProperty, true, LapsReadState.Unresolved, LapsConfidentiality.Unresolved),
            (null, null, ReadProperty | ControlAccess, true, LapsReadState.Established, LapsConfidentiality.Unresolved),
            (128, 0, ControlAccess, false, LapsReadState.NotEstablished, LapsConfidentiality.Confidential),
            (0, 0, ControlAccess, false, LapsReadState.NotEstablished, LapsConfidentiality.NotConfidential),
        ];
        foreach (var attribute in Scout09Attributes)
            foreach (var row in cases)
                yield return [attribute.Guid, attribute.Name, row.Search, row.System, row.Mask, row.Finding, row.State, row.Requirement];
    }

    [Theory]
    [MemberData(nameof(Scout09ConfidentialityCases))]
    public void Scout09CapturedFlagsDecideTheAdditionalControlAccessRequirement(string guid, string name,
        int? search, int? system, int mask, bool expectedFinding, LapsReadState state, LapsConfidentiality requirement)
    {
        var result = new LapsPasswordReadAccess().Judge(Computer(),
            Scout09Context([Allow(AuthenticatedUsers, mask, guid)], search, system));
        if (!expectedFinding)
        {
            Assert.Empty(result.Findings);
            Assert.True(result.IsComplete);
            return;
        }
        var finding = Assert.Single(result.Findings);
        var evidence = Assert.IsType<LapsPasswordReaderEvidence>(finding.Evidence);
        var support = Assert.Single(evidence.SupportingExposures!);
        Assert.Equal((name, search, system, state),
            (support.Attribute, support.SearchFlags, support.SystemFlags, support.State));
        Assert.Equal(state == LapsReadState.Established ? 1 : 0, evidence.Assessment.EstablishedExposureCount);
        Assert.Equal(requirement, support.Confidentiality);
        Assert.Equal(state == LapsReadState.Established && requirement != LapsConfidentiality.Unresolved,
            evidence.IsComplete);
        Assert.Equal(2, finding.RuleVersion);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Contains(state == LapsReadState.Established ? "Read permission established" : "Read permission unresolved",
            finding.Detail, StringComparison.Ordinal);
    }

    public static IEnumerable<object?[]> Scout09AccountCases() =>
        Scout09Attributes.SelectMany(attribute => new uint?[] { null, 0, 4096, 4098 }
            .Select(control => new object?[] { attribute.Guid, control }));

    [Theory]
    [MemberData(nameof(Scout09AccountCases))]
    public void Scout09DirectoryAccountStateCannotHideAStoredPermissionReview(string guid, uint? control)
    {
        var subject = control.HasValue ? Computer(control.Value) : Computer() with
        {
            Attributes = Computer().Attributes.Where(value => value.LdapDisplayName != "userAccountControl").ToArray(),
        };
        var result = new LapsPasswordReadAccess().Judge(subject,
            Scout09Context([Allow(AuthenticatedUsers, ReadProperty | ControlAccess, guid)]));
        Assert.True(result.IsComplete);
        var finding = Assert.Single(result.Findings);
        Assert.Equal(subject.ObjectGuid, finding.ObjectGuid);
        var evidence = Assert.IsType<LapsPasswordReaderEvidence>(finding.Evidence);
        Assert.True(evidence.IsComplete);
        Assert.Equal(LapsReadState.Established, Assert.Single(evidence.SupportingExposures!).State);
        Assert.DoesNotContain("userAccountControl", new LapsPasswordReadAccess().Definition.RequiredAttributes);
    }

    public static IEnumerable<object[]> Scout09ScopeCases() =>
        Scout09Attributes.SelectMany(attribute => new[]
        {
            "attribute", "property-set", "class", "unscoped", "unrelated", "wrong-class", "missing-set", "missing-guid",
        }.Select(scope => new object[] { attribute.Guid, attribute.Name, scope }));

    [Theory]
    [MemberData(nameof(Scout09ScopeCases))]
    public void Scout09ReadScopeUsesTheCapturedAttributeHierarchy(string guid, string name, string scope)
    {
        var schema = Scout09Schema(name);
        var scoped = scope switch
        {
            "property-set" or "missing-set" => Scout09Set,
            "class" => Scout09ComputerClass,
            "wrong-class" => Scout09GroupClass,
            "unrelated" => UnrelatedGuid,
            "unscoped" => null,
            _ => guid,
        };
        var entry = Allow(AuthenticatedUsers, ReadProperty, scoped);
        if (scope == "missing-guid") entry = entry with { ObjectTypeGuid = null, HasObjectType = true };
        if (scope == "missing-set")
            schema = new(schema.Entries, new Dictionary<string, IReadOnlyList<string>>());
        var result = new LapsPasswordReadAccess().Judge(Computer(),
            Scout09Context([entry, Allow(AuthenticatedUsers, ControlAccess, null)], schema: schema));
        if (scope is "unrelated" or "wrong-class")
        {
            Assert.Empty(result.Findings);
            Assert.True(result.IsComplete);
            return;
        }
        var evidence = Assert.IsType<LapsPasswordReaderEvidence>(Assert.Single(result.Findings).Evidence);
        var support = Assert.Single(evidence.SupportingExposures!, value => value.Attribute == name);
        var expected = scope is "missing-set" or "missing-guid" ? LapsReadState.Unresolved : LapsReadState.Established;
        Assert.Equal(expected, support.State);
        Assert.Equal(expected == LapsReadState.Established, evidence.IsComplete);
        Assert.Equal(guid, support.AttributeGuid);
        Assert.Equal(Scout09ComputerClass, support.TargetClassGuid);
        if (scope == "property-set")
            Assert.Contains(support.Entries!, value => value.PropertySetMembers?.Contains(name) == true);
        if (scope == "class")
            Assert.Contains(support.Entries!, value => value.Definitions.Any(definition => definition.LdapName == "computer"));
    }

    [Theory]
    [InlineData("deny-before", false, LapsReadState.NotEstablished)]
    [InlineData("allow-before", true, LapsReadState.Established)]
    [InlineData("conditional-allow", true, LapsReadState.Unresolved)]
    [InlineData("conditional-deny-before", true, LapsReadState.Unresolved)]
    [InlineData("conditional-deny-after", true, LapsReadState.Established)]
    [InlineData("unknown-ace-before", true, LapsReadState.Unresolved)]
    [InlineData("inherit-only", false, LapsReadState.NotEstablished)]
    [InlineData("split", true, LapsReadState.Established)]
    [InlineData("everyone-deny", false, LapsReadState.NotEstablished)]
    [InlineData("unqualified-deny", true, LapsReadState.Unresolved)]
    [InlineData("conditional-then-independent", true, LapsReadState.Established)]
    [InlineData("short-positive", true, LapsReadState.Unresolved)]
    [InlineData("short-half", false, LapsReadState.Unresolved)]
    [InlineData("stored-generic", false, LapsReadState.NotEstablished)]
    public void Scout09OrderedProofDoesNotConvertUncertaintyIntoPermission(string kind, bool expectedFinding, LapsReadState expected)
    {
        var allow = Allow(AuthenticatedUsers, ReadProperty | ControlAccess, PasswordGuid);
        var deny = Deny(AuthenticatedUsers, ReadProperty | ControlAccess, PasswordGuid);
        var callbackAllow = allow with { AceType = "AccessAllowedCallbackObject", ApplicationData = [0x61, 0x72, 0x74, 0x78] };
        var callbackDeny = deny with { AceType = "AccessDeniedCallbackObject", ApplicationData = [0x61, 0x72, 0x74, 0x78] };
        PermissionEntry[] entries = kind switch
        {
            "deny-before" => [deny, allow],
            "allow-before" => [allow, deny],
            "conditional-allow" => [callbackAllow],
            "conditional-deny-before" => [callbackDeny, allow],
            "conditional-deny-after" => [allow, callbackDeny],
            "unknown-ace-before" => [allow with { AceType = "UnsupportedAce" }, allow],
            "inherit-only" => [allow with { PropagationFlags = 0x08 }],
            "split" => [Allow(AuthenticatedUsers, ReadProperty, PasswordGuid), Allow(AuthenticatedUsers, ControlAccess, PasswordGuid)],
            "everyone-deny" => [Deny(Everyone, ReadProperty | ControlAccess, PasswordGuid), allow],
            "unqualified-deny" => [Deny(Intermediate, ReadProperty | ControlAccess, PasswordGuid), allow],
            "conditional-then-independent" => [callbackAllow, allow],
            "short-half" => [Allow(AuthenticatedUsers, ReadProperty, PasswordGuid)],
            "stored-generic" => [Allow(AuthenticatedUsers, 0x10000000, PasswordGuid)],
            _ => [allow],
        };
        var shortDescriptor = kind.StartsWith("short", StringComparison.Ordinal);
        var result = new LapsPasswordReadAccess().Judge(Computer(),
            Scout09Context(entries, completeness: shortDescriptor ? DaclCompleteness.Unknown : DaclCompleteness.Complete));
        if (!expectedFinding)
        {
            Assert.Empty(result.Findings);
            Assert.Equal(!shortDescriptor, result.IsComplete);
            return;
        }
        var finding = Assert.Single(result.Findings);
        var evidence = Assert.IsType<LapsPasswordReaderEvidence>(finding.Evidence);
        var support = Assert.Single(evidence.SupportingExposures!);
        Assert.Equal(expected, support.State);
        Assert.Equal(!shortDescriptor, evidence.Assessment.DescriptorIsComplete);
        Assert.Equal(expected == LapsReadState.Established, evidence.IsComplete);
        Assert.Equal(entries.Length, support.Entries!.Count);
        Assert.Equal(Enumerable.Range(0, entries.Length), support.EntryOrdinals);
        if (expected == LapsReadState.Unresolved)
            Assert.Contains("The captured evidence is incomplete; further access may exist", finding.Detail, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Scout09OnlyAnOtherwisePositiveReviewNeedsAFindingIdentity(bool positive, bool empty)
    {
        var subject = Computer() with { ObjectGuid = empty ? Guid.Empty : null };
        var result = new LapsPasswordReadAccess().Judge(subject,
            Scout09Context([Allow(AuthenticatedUsers, positive ? ReadProperty | ControlAccess : ReadProperty, PasswordGuid)]));
        Assert.Empty(result.Findings);
        Assert.Equal(!positive, result.IsComplete);
        Assert.Equal(positive ? new[] { "objectGUID" } : [], result.InputsNotCaptured);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Scout09AllIndependentHolderAttributeExposuresSurviveOneFinding(bool twoHolders)
    {
        var roots = twoHolders ? new[] { Delegated, Intermediate } : [AuthenticatedUsers];
        var entries = roots.SelectMany(root => Scout09Attributes.Select(attribute =>
            Allow(root, ReadProperty | ControlAccess, attribute.Guid))).ToArray();
        Func<string, PrincipalExpansion> expand = sid => new(sid, PrincipalExpansionOutcome.Expanded,
            sid == AuthenticatedUsers ? [] : [new(AuthenticatedUsers, Forest, [sid, AuthenticatedUsers], true)]);
        var context = Scout09Context(entries) with { MembersOfPrincipal = (sid, _) => expand(sid) };
        var finding = Assert.Single(new LapsPasswordReadAccess().Judge(Computer(), context).Findings);
        var evidence = Assert.IsType<LapsPasswordReaderEvidence>(finding.Evidence);
        Assert.Equal(3 * roots.Length, evidence.Assessment.ExposureCount);
        Assert.Equal(evidence.Assessment.ExposureCount, evidence.SupportingExposures!.Count);
        Assert.Equal(3, evidence.SupportingExposures.Select(value => value.Attribute).Distinct().Count());
        Assert.Equal(roots.Length, evidence.SupportingExposures.Select(value => value.TrusteeSid).Distinct().Count());
        Assert.All(evidence.SupportingExposures, value => Assert.Equal(AuthenticatedUsers, value.MembershipPath[^1].Sid));
        Assert.All(evidence.SupportingExposures, value => Assert.Single(value.Entries!));
        Assert.Contains("Removing one displayed grant or membership route may not remove every way",
            finding.Detail, StringComparison.Ordinal);
        Assert.Contains("does not by itself grant permission to decrypt", finding.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Scout09InheritedClassScopeIsNeverAnInventedOriginContainer()
    {
        var entry = Allow(AuthenticatedUsers, ReadProperty | ControlAccess, PasswordGuid) with
        {
            IsInherited = true, HasInheritedObjectType = true, InheritedObjectTypeGuid = Scout09ComputerClass,
        };
        var finding = Assert.Single(new LapsPasswordReadAccess().Judge(Computer(), Scout09Context([entry])).Findings);
        var evidence = Assert.IsType<LapsPasswordReaderEvidence>(finding.Evidence);
        Assert.True(evidence.IsInherited);
        Assert.Equal(Scout09ComputerClass, evidence.InheritedClassGuid);
        Assert.Equal(Scout09ComputerClass, Assert.Single(evidence.SupportingExposures!).InheritedClassGuids.Single());
        Assert.Contains("The originating container was not captured", finding.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("inherited from OU=", finding.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Scout09ShippedAttributeIdentityDoesNotReplaceMissingCapturedSupport(bool independentPositive)
    {
        var schema = new SchemaGuidCatalog(
        [
            new(PasswordGuid, "msLAPS-Password", SchemaGuidKind.Attribute, SchemaGuidSource.Embedded),
            new(LegacyGuid, "ms-Mcs-AdmPwd", SchemaGuidKind.Attribute, SchemaGuidSource.Captured),
        ]);
        var entries = independentPositive
            ? new[] { Allow(AuthenticatedUsers, ReadProperty | ControlAccess, PasswordGuid),
                Allow(AuthenticatedUsers, ReadProperty | ControlAccess, LegacyGuid) }
            : [Allow(AuthenticatedUsers, ReadProperty | ControlAccess, PasswordGuid)];
        var result = new LapsPasswordReadAccess().Judge(Computer(), Scout09Context(entries, schema: schema));
        if (!independentPositive)
        {
            Assert.Empty(result.Findings);
            Assert.False(result.IsComplete);
            return;
        }
        var evidence = Assert.IsType<LapsPasswordReaderEvidence>(Assert.Single(result.Findings).Evidence);
        Assert.False(evidence.Assessment.SchemaIsComplete);
        Assert.False(evidence.IsComplete);
        Assert.Equal("ms-Mcs-AdmPwd", Assert.Single(evidence.SupportingExposures!).Attribute);
        Assert.Equal(1, evidence.Assessment.EstablishedExposureCount);
    }

    [Theory]
    [InlineData(0, LapsReadState.Established)]
    [InlineData(128, LapsReadState.Unresolved)]
    public void Scout09AConditionalUnneededRightDoesNotEraseIndependentReadPermission(int flags, LapsReadState state)
    {
        var entries = new[]
        {
            Allow(AuthenticatedUsers, ReadProperty, PasswordGuid),
            Allow(AuthenticatedUsers, ControlAccess, PasswordGuid) with
                { AceType = "AccessAllowedCallbackObject", ApplicationData = [0x61, 0x72, 0x74, 0x78] },
        };
        var result = new LapsPasswordReadAccess().Judge(Computer(), Scout09Context(entries, search: flags));
        var evidence = Assert.IsType<LapsPasswordReaderEvidence>(Assert.Single(result.Findings).Evidence);
        var support = Assert.Single(evidence.SupportingExposures!);
        Assert.Equal(state, support.State);
        Assert.Equal(LapsReadState.Established, support.ReadProperty.State);
        Assert.Equal(LapsReadState.Unresolved, support.ControlAccess.State);
        Assert.Equal(flags == 0, evidence.IsComplete);
    }

    private static SchemaGuidCatalog Scout09Schema(string attribute)
    {
        SchemaGuidEntry[] entries =
        [
            .. Schema().Entries,
            new(Scout09ComputerClass, "computer", SchemaGuidKind.ObjectClass, SchemaGuidSource.Captured),
            new(Scout09GroupClass, "group", SchemaGuidKind.ObjectClass, SchemaGuidSource.Captured),
            new(Scout09Set, "Synthetic-LAPS-Property-Set", SchemaGuidKind.PropertySet, SchemaGuidSource.Captured),
        ];
        return new(entries, new Dictionary<string, IReadOnlyList<string>>
        {
            [Scout09Set] = [attribute],
            ["22222222-3333-4444-5555-666666666666"] = Scout09Attributes
                .Where(value => value.Name != attribute).Select(value => value.Name).ToArray(),
        });
    }

    private static JudgingContext Scout09Context(IReadOnlyList<PermissionEntry> entries, int? search = 128,
        int? system = 0, SchemaGuidCatalog? schema = null, DaclCompleteness completeness = DaclCompleteness.Complete) =>
        Context(_ => Permissions(DescriptorAvailability.Read, entries, completeness),
            Nested(AuthenticatedUsers), schema ?? Scout09Schema("msLAPS-EncryptedPassword")) with
        {
            AttributeVisibility = new(Scout09Attributes.Select(attribute =>
                new AttributeVisibilityFact(attribute.Name, search, system)).ToArray()),
        };
}
