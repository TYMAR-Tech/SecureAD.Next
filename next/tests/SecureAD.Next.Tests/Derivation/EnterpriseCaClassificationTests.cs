using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

public sealed class EnterpriseCaClassificationTests
{
    [Fact]
    public void ADirectoryRegistrationQualifiesWithoutASid()
    {
        var evidence = new EnterpriseCaTestEvidence();

        var result = evidence.ClassifyRegistration();

        Assert.Equal(Tier0Basis.EnterpriseCaRegistration, Assert.Single(result.Supports).Basis);
    }

    [Theory]
    [InlineData("cahost.contoso.com")]
    [InlineData("CAHOST.CONTOSO.COM")]
    public void TheRecordedFullHostNameQualifiesOneCapturedComputer(string hostName)
    {
        var evidence = new EnterpriseCaTestEvidence();
        evidence.Registration = EnterpriseCaTestEvidence.Set(evidence.Registration, EnterpriseCaTestEvidence.HostAttribute(hostName));

        Assert.Equal(Tier0Basis.EnterpriseCaHost, Assert.Single(evidence.ClassifyHost().Supports).Basis);
    }

    [Theory]
    [InlineData(EnterpriseCaTestEvidence.RegistrationDn, "objectClass", 1, "pKIEnrollmentService")]
    [InlineData(EnterpriseCaTestEvidence.RegistrationDn, "dNSHostName", 0, EnterpriseCaTestEvidence.HostName)]
    [InlineData(EnterpriseCaTestEvidence.HostDn, "objectClass", 1, "computer")]
    [InlineData(EnterpriseCaTestEvidence.HostDn, "objectSid", 0, EnterpriseCaTestEvidence.HostSid)]
    [InlineData(EnterpriseCaTestEvidence.HostDn, "dNSHostName", 0, EnterpriseCaTestEvidence.HostName)]
    [InlineData(EnterpriseCaTestEvidence.ConfigurationDn, "objectClass", 1, "configuration")]
    [InlineData(EnterpriseCaTestEvidence.DomainDn, "objectSid", 0, "S-1-5-21-1-2-3")]
    public void HostQualificationRetainsOriginalAttributeWitnesses(string dn, string attribute, int ordinal, string value)
    {
        var result = new EnterpriseCaTestEvidence().ClassifyHost();

        Assert.Contains(result.Supports.Single().Evidence, witness =>
            (witness.Object.DistinguishedName, witness.Attribute, witness.Ordinal, witness.Value) == (dn, attribute, ordinal, value));
    }

    [Fact]
    public void TheHostNamesItsRegistrationAsTheIndependentSource()
    {
        var evidence = new EnterpriseCaTestEvidence();

        Assert.Equal(Tier0Target.From(evidence.Registration, EnterpriseCaTestEvidence.ConfigurationDn),
            evidence.ClassifyHost().Supports.Single().Root);
    }

    [Theory]
    [InlineData("wrong-container")]
    [InlineData("wrong-registration-class")]
    [InlineData("wrong-configuration-class")]
    [InlineData("missing-registration-guid")]
    [InlineData("duplicate-registration-guid")]
    [InlineData("deleted-registration")]
    public void AnUnqualifiedRegistrationCannotQualifyItsHost(string change)
    {
        var evidence = new EnterpriseCaTestEvidence();
        evidence.InvalidateRegistration(change);

        Assert.Empty(evidence.ClassifyHost().Supports);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(EnterpriseCaTestEvidence.DomainDn)]
    public void AConfigurationPartitionMustBeExplicitlyBound(string? context)
    {
        var evidence = new EnterpriseCaTestEvidence();
        evidence.Binding = evidence.Binding with { ConfigurationNamingContext = context };

        Assert.Empty(evidence.ClassifyHost().Supports);
    }

    [Fact]
    public void MissingConfigurationEvidenceKeepsInputCoverageIncomplete()
    {
        var evidence = new EnterpriseCaTestEvidence { Configuration = null };

        Assert.False(evidence.ClassifyRegistration().Coverage.InputsComplete);
    }

    [Theory]
    [InlineData("missing-attribute")]
    [InlineData("empty-attribute")]
    public void MissingHostEvidenceIsRecordedSeparatelyFromUnsupportedAnalysis(string change)
    {
        var evidence = new EnterpriseCaTestEvidence();
        evidence.ChangeHostEvidence(change);
        var coverage = evidence.ClassifyRegistration().Coverage;

        Assert.Equal((false, true), (coverage.InputsComplete, coverage.Limitations.HasFlag(Tier0Limitations.AssetHostEvidenceMissing)));
    }

    [Theory]
    [InlineData("missing-computer")]
    [InlineData("duplicate-host-name")]
    [InlineData("conflicting-registration-names")]
    [InlineData("conflicting-computer-names")]
    [InlineData("short-host-name")]
    [InlineData("address-not-name")]
    [InlineData("wrong-computer-class")]
    [InlineData("wrong-computer-domain")]
    [InlineData("missing-computer-sid")]
    [InlineData("spn-without-host-value")]
    public void AnUnresolvedHostKeepsItsOwnCoverageLimitation(string change)
    {
        var evidence = new EnterpriseCaTestEvidence();
        evidence.ChangeHostEvidence(change);

        Assert.True(evidence.ClassifyRegistration().Coverage.Limitations.HasFlag(Tier0Limitations.AssetHostIdentityUnresolved));
    }

    [Theory]
    [InlineData("missing-attribute")]
    [InlineData("duplicate-host-name")]
    public void AnUnresolvedHostDoesNotEraseTheRegistration(string change)
    {
        var evidence = new EnterpriseCaTestEvidence();
        evidence.ChangeHostEvidence(change);

        Assert.Equal(Tier0State.Established, evidence.ClassifyRegistration().State);
    }

    [Theory]
    [InlineData("duplicate-host-name")]
    [InlineData("wrong-computer-domain")]
    [InlineData("spn-without-host-value")]
    public void AnUnresolvedComputerDoesNotBecomeACaTarget(string change)
    {
        var evidence = new EnterpriseCaTestEvidence();
        evidence.ChangeHostEvidence(change);

        Assert.Empty(evidence.ClassifyHost().Supports);
    }

    [Fact]
    public void ConflictingHostValuesRemainInTheRegistrationEvidence()
    {
        var evidence = new EnterpriseCaTestEvidence();
        evidence.ChangeHostEvidence("conflicting-registration-names");

        Assert.Equal(new[] { EnterpriseCaTestEvidence.HostName, "other.contoso.com" },
            evidence.ClassifyRegistration().Supports.Single().Evidence.Where(item => item.Attribute == "dNSHostName").Select(item => item.Value));
    }

    [Fact]
    public void AnUnrelatedCaptureGapDoesNotRemoveTheQualifiedHost()
    {
        var evidence = new EnterpriseCaTestEvidence { CaptureComplete = false };

        Assert.Equal((Tier0State.Established, false), (evidence.ClassifyHost().State, evidence.ClassifyHost().Coverage.InputsComplete));
    }

    [Fact]
    public void SeveralRegistrationsForOneHostRetainIndependentSupports()
    {
        var evidence = new EnterpriseCaTestEvidence();
        var second = evidence.Registration with { ObjectGuid = Guid.NewGuid(),
            DistinguishedName = evidence.Registration.DistinguishedName.Replace("Contoso Issuing CA", "Second CA", StringComparison.Ordinal) };
        evidence.Additional.Add(second);

        Assert.Equal(new[] { evidence.Registration.DistinguishedName, second.DistinguishedName },
            evidence.ClassifyHost().Supports.Select(item => item.Root.DistinguishedName));
    }
}

internal sealed class EnterpriseCaTestEvidence
{
    internal const string DomainDn = "DC=contoso,DC=com";
    internal const string ConfigurationDn = "CN=Configuration," + DomainDn;
    internal const string RegistrationDn = "CN=Contoso Issuing CA,CN=Enrollment Services,CN=Public Key Services,CN=Services," + ConfigurationDn;
    internal const string HostDn = "CN=CAHOST," + DomainDn;
    internal const string HostName = "cahost.contoso.com";
    internal const string HostSid = "S-1-5-21-1-2-3-1400";
    private readonly Tier0TestEvidence evidence = new();

    internal EnterpriseCaTestEvidence()
    {
        Binding = evidence.Binding with { ConfigurationNamingContext = ConfigurationDn };
        Configuration = Object(ConfigurationDn, "configuration");
        Registration = Object(RegistrationDn, "pKIEnrollmentService", HostAttribute(HostName));
        Host = Object(HostDn, "computer", Attribute("objectSid", HostSid), HostAttribute(HostName));
    }

    internal Tier0InputBinding Binding { get; set; }
    internal ObjectAttributes Domain => evidence.Domain;
    internal ObjectAttributes? Configuration { get; set; }
    internal ObjectAttributes Registration { get; set; }
    internal ObjectAttributes? Host { get; set; }
    internal List<ObjectAttributes> Additional { get; } = [];
    internal bool CaptureComplete { get; set; } = true;
    internal CapturedMembershipInput Input => new(evidence.Generation, CaptureComplete, Sources().ToArray());

    internal Tier0Classification ClassifyRegistration() => Tier0Classifier.Qualify(Binding,
        Tier0Target.From(Registration, ConfigurationDn), Input, routes: null);

    internal Tier0Classification ClassifyHost(MembershipRouteSummary? routes = null) => Tier0Classifier.Qualify(Binding,
        Tier0Target.From(Host ?? throw new InvalidOperationException(), DomainDn), Input, routes);

    private IEnumerable<ObjectAttributes> Sources()
    {
        yield return Domain;
        if (Configuration is { } configuration) yield return configuration;
        yield return Registration;
        if (Host is { } host) yield return host;
        foreach (var source in Additional) yield return source;
    }

    internal static ObjectAttributes Object(string dn, string objectClass, params ObjectAttribute[] attributes) =>
        new(dn, Guid.NewGuid(), DateTimeOffset.UnixEpoch, default,
            [Attribute("objectClass", "top", objectClass), .. attributes], "contoso.com");

    internal static ObjectAttribute Attribute(string name, params string[] values) => Tier0TestEvidence.Attribute(name, values);

    internal static ObjectAttribute HostAttribute(params string[] values) =>
        Attribute("dNSHostName", values) with { Cardinality = AttributeCardinality.SingleValued };

    internal static ObjectAttributes Set(ObjectAttributes source, ObjectAttribute attribute) => source with
    {
        Attributes = [.. source.Attributes.Where(value => !string.Equals(value.LdapDisplayName,
            attribute.LdapDisplayName, StringComparison.OrdinalIgnoreCase)), attribute],
    };

    internal void InvalidateRegistration(string change)
    {
        switch (change)
        {
            case "wrong-container":
                Registration = Registration with { DistinguishedName = "CN=CA,CN=Other," + ConfigurationDn };
                break;
            case "wrong-registration-class":
                Registration = Set(Registration, Attribute("objectClass", "top", "pKIEnrollmentService", "container"));
                break;
            case "wrong-configuration-class":
                Configuration = Set(Configuration ?? throw new InvalidOperationException(), Attribute("objectClass", "top", "container"));
                break;
            case "missing-registration-guid":
                Registration = Registration with { ObjectGuid = null };
                break;
            case "duplicate-registration-guid":
                Additional.Add(Object("CN=Collision," + DomainDn, "user") with { ObjectGuid = Registration.ObjectGuid });
                break;
            case "deleted-registration":
                Registration = Set(Registration, Attribute("isDeleted", "TRUE"));
                break;
            default: throw new ArgumentOutOfRangeException(nameof(change));
        }
    }

    internal void ChangeHostEvidence(string change)
    {
        var host = Host ?? throw new InvalidOperationException();
        switch (change)
        {
            case "missing-attribute":
                Registration = Registration with { Attributes = Registration.Attributes.Where(item => item.LdapDisplayName != "dNSHostName").ToArray() };
                break;
            case "empty-attribute": Registration = Set(Registration, HostAttribute()); break;
            case "missing-computer": Host = null; break;
            case "duplicate-host-name":
                Additional.Add(Set(host with { ObjectGuid = Guid.NewGuid(), DistinguishedName = "CN=Other," + DomainDn },
                    Attribute("objectSid", "S-1-5-21-1-2-3-1401")));
                break;
            case "conflicting-registration-names": Registration = Set(Registration, HostAttribute(HostName, "other.contoso.com")); break;
            case "conflicting-computer-names": Host = Set(host, HostAttribute(HostName, "other.contoso.com")); break;
            case "short-host-name": Registration = Set(Registration, HostAttribute("CAHOST")); break;
            case "address-not-name": Registration = Set(Registration, HostAttribute("192.0.2.10")); break;
            case "wrong-computer-class": Host = Set(host, Attribute("objectClass", "top", "computer", "msDS-ManagedServiceAccount")); break;
            case "wrong-computer-domain": Host = Set(host, Attribute("objectSid", "S-1-5-21-4-5-6-1400")); break;
            case "missing-computer-sid": Host = Set(host, Attribute("objectSid")); break;
            case "spn-without-host-value":
                Host = Set(Set(host, HostAttribute()), Attribute("servicePrincipalName", "HOST/" + HostName));
                break;
            default: throw new ArgumentOutOfRangeException(nameof(change));
        }
    }
}
