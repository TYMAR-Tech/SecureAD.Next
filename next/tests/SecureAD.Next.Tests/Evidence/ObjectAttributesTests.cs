using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// Reading one object's attribute values back out of a bundle: text and bytes, one value and many,
/// and the difference between an attribute with nothing in it and an attribute this build never
/// asks for.
/// </summary>
public sealed class ObjectAttributesTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securead-attributes-" + Guid.NewGuid().ToString("N"));

    private static readonly DateTimeOffset Started = new(2026, 9, 13, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 9, 13, 11, 30, 0, TimeSpan.Zero);

    private const string DomainDn = "DC=contoso,DC=com";
    private const string AliceDn = "CN=Alice," + DomainDn;
    private const string AdminsDn = "CN=Domain Admins," + DomainDn;
    private const string AliceSid = "S-1-5-21-1111111111-2222222222-3333333333-1104";

    // ---------------------------------------------------------------------------------------
    // An object nothing captured
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// An object this bundle never saw is not an object whose attributes are all empty, and the two
    /// must not arrive as the same answer.
    /// </summary>
    [Fact]
    public void AnObjectTheBundleDoesNotHoldReadsAsNothing()
    {
        WriteObject(Alice());

        Assert.Null(Read("CN=Nobody," + DomainDn));
    }

    // ---------------------------------------------------------------------------------------
    // A single value
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void ASingleValuedAttributeCarriesTheTextTheDirectorySent()
    {
        WriteObject(Alice(Text("sAMAccountName", "alice")));

        Assert.Equal("alice", Attribute("sAMAccountName").OnlyValue!.Text);
    }

    /// <summary>
    /// The stored form is what the reveal shows beside the wording, so a number stays the
    /// characters the directory sent rather than becoming whatever this build believes they mean.
    /// </summary>
    [Fact]
    public void ASingleValuedAttributeIsNotInterpreted()
    {
        WriteObject(Alice(Text("userAccountControl", "514")));

        Assert.Equal("514", Attribute("userAccountControl").OnlyValue!.Stored);
    }

    [Fact]
    public void ASingleValuedAttributeHasOneValue()
    {
        WriteObject(Alice(Text("sAMAccountName", "alice")));

        Assert.Single(Attribute("sAMAccountName").Values);
    }

    // ---------------------------------------------------------------------------------------
    // Bytes
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A byte value stays bytes. Read back as text it is a mangled string that still looks like
    /// data, and <c>objectSid</c> is what a trustee is matched on.
    /// </summary>
    [Fact]
    public void AByteValuedAttributeCarriesTheBytesTheDirectorySent()
    {
        WriteObject(Alice(Bytes("objectSid", Sid.ToBytes(AliceSid)!)));

        Assert.Equal(Sid.ToBytes(AliceSid), Attribute("objectSid").OnlyValue!.Bytes);
    }

    [Fact]
    public void AByteValuedAttributeCarriesNoText()
    {
        WriteObject(Alice(Bytes("objectSid", Sid.ToBytes(AliceSid)!)));

        Assert.Null(Attribute("objectSid").OnlyValue!.Text);
    }

    /// <summary>
    /// Bytes become characters in exactly one place, and say so by being hexadecimal.
    /// </summary>
    [Fact]
    public void AByteValueIsStoredAsHexadecimal()
    {
        WriteObject(Alice(Bytes("objectSid", [0x01, 0x02, 0xAB])));

        Assert.Equal("0102AB", Attribute("objectSid").OnlyValue!.Stored);
    }

    // ---------------------------------------------------------------------------------------
    // Many values
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void AMultiValuedAttributeCarriesEveryValue()
    {
        WriteObject(Alice(Text("memberOf", AdminsDn, "CN=Backup Operators," + DomainDn)));

        Assert.Equal(
            [AdminsDn, "CN=Backup Operators," + DomainDn],
            Attribute("memberOf").Values.Select(v => v.Text));
    }

    /// <summary>
    /// The order is the controller's, and it is kept because losing it would silently reorder a
    /// membership list nobody could then check against the directory.
    /// </summary>
    [Fact]
    public void AMultiValuedAttributeCarriesTheOrderTheDirectorySent()
    {
        WriteObject(Alice(Text("memberOf", AdminsDn, "CN=Backup Operators," + DomainDn)));

        Assert.Equal([0, 1], Attribute("memberOf").Values.Select(v => v.Ordinal));
    }

    [Fact]
    public void AMultiValuedAttributeIsDeclaredMultiValued()
    {
        WriteObject(Alice(Text("memberOf", AdminsDn)));

        Assert.Equal(AttributeCardinality.MultiValued, Attribute("memberOf").Cardinality);
    }

    // ---------------------------------------------------------------------------------------
    // Nothing there
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Capture asks every object for every catalogued attribute whatever its class, so an
    /// attribute with no value is present and empty rather than absent. A section that finds
    /// nothing here has been refused or has nothing to find, and hiding it would hide the first.
    /// </summary>
    [Fact]
    public void AnAttributeNoValueArrivedForIsPresentAndEmpty()
    {
        WriteObject(Alice());

        Assert.False(Attribute("sAMAccountName").HasValue);
    }

    [Fact]
    public void AMultiValuedAttributeNoValueArrivedForIsPresentAndEmpty()
    {
        WriteObject(Alice());

        Assert.Empty(Attribute("memberOf").Values);
    }

    [Fact]
    public void EveryCataloguedAttributeIsReadBack()
    {
        WriteObject(Alice());

        var attributes = Read(AliceDn)!;

        Assert.Equal(
            CapturedAttributeCatalog.All.Select(a => a.LdapDisplayName).Order(StringComparer.OrdinalIgnoreCase),
            attributes.Attributes.Select(a => a.LdapDisplayName));
    }

    /// <summary>
    /// Every captured value, not only the attributes used by requester discovery. The expected
    /// bytes and text come from the input, not from a second projection through the reader.
    /// </summary>
    [Fact]
    public void EveryPopulatedCataloguedAttributeSurvivesOneRead()
    {
        var input = CapturedAttributeCatalog.All
            .Where(a => a.LdapDisplayName is not "distinguishedName" and not "objectGUID")
            .Select(a => new EvidenceAttribute(a.LdapDisplayName, StoredAttributeCompleteness.Complete,
                Enumerable.Range(0, a.Cardinality == AttributeCardinality.MultiValued ? 3 : 1)
                    .Select(i => a.Storage == AttributeStorage.Binary
                        ? EvidenceValue.OfBytes(i == 1 ? [] : Sid.ToBytes(AliceSid)!)
                        : EvidenceValue.OfText(i == 1 ? "" : a.LdapDisplayName + "-é-值"))
                    .ToArray()))
            .ToArray();
        var evidence = Alice(input);
        WriteObject(evidence);

        var read = Read(AliceDn.ToUpperInvariant())!;
        Assert.Equal(evidence.ObjectGuid, read.ObjectGuid);
        Assert.Equal(Started, read.CapturedUtc);
        Assert.Equal("contoso.com", read.DomainFqdn);
        Assert.Equal(AliceDn, read.DistinguishedName);
        Assert.Equal(CapturedAttributeCatalog.All.Count, read.Attributes.Count);
        AssertCapturedValues(input, read);

        // A deliberately narrowed result must fail this check, even if both catalogues agree.
        var narrowed = read with
        {
            Attributes = read.Attributes.Where(a => a.LdapDisplayName != "msDS-KeyCredentialLink").ToArray(),
        };
        Assert.ThrowsAny<Xunit.Sdk.XunitException>(() => AssertCapturedValues(input, narrowed));
    }

    /// <summary>
    /// Independent names: the predecessor's version-10 CapturedAttributeCatalog identity, account,
    /// group, GPO and password-settings lists, plus appliesTo from Microsoft's MS-ADA1 schema.
    /// These are literals, not generated from the new reader, rules or catalogue. Losing a table
    /// from all three still fails. Duplicate, empty and non-ASCII values must remain distinct.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void IndependentlyNamedMultiValuedAttributesAreNeverUnfetched(bool populated)
    {
        string[] textNames = ["objectClass", "description", "memberOf", "servicePrincipalName",
            "msDS-AllowedToDelegateTo", "msDS-KeyCredentialLink", "member",
            "gPCMachineExtensionNames", "msDS-PSOAppliesTo", "appliesTo"];
        var expected = textNames.Select(name => Text(name,
            populated ? [name + "-é-值", "", name + "-é-值"] : []))
            .Append(new EvidenceAttribute("sIDHistory", StoredAttributeCompleteness.Complete,
                populated ? [EvidenceValue.OfBytes(Sid.ToBytes(AliceSid)!),
                    EvidenceValue.OfBytes([]), EvidenceValue.OfBytes(Sid.ToBytes(AliceSid)!)] : []))
            .ToArray();
        WriteObject(Alice(expected));

        var read = Read(AliceDn)!;
        AssertCapturedValues(expected, read);
        Assert.Equal(expected.Select(a => a.LdapDisplayName).Order(StringComparer.OrdinalIgnoreCase),
            read.Attributes.Where(a => a.Cardinality == AttributeCardinality.MultiValued)
                .Select(a => a.LdapDisplayName));
        Assert.Null(read.Find("not-a-captured-attribute"));
    }

    [Fact]
    public void AReadCannotMixValuesFromAnotherObjectOrEarlierRead()
    {
        using (var writer = BundleWriter.Create(_directory, Started))
        {
            writer.WriteCoverage(SomeCoverage());
            writer.WriteObject(Alice(Text("member", "alice-member")));
            writer.WriteObject(new EvidenceObject(SomeCoverage(), AdminsDn, null,
                [Text("member", "other-member"), Text("description", "other-description")], Finished));
            writer.Complete(OneDomainRead(), Finished);
        }

        using var reader = BundleReader.Open(_directory).Value;
        var first = reader.ReadObjectAttributes(AliceDn)!;
        var other = reader.ReadObjectAttributes(AdminsDn)!;
        Assert.Equal("other-member", other.Find("member")!.OnlyValue!.Text);
        Assert.Null(other.ObjectGuid);
        Assert.Empty(other.Find("objectGUID")!.Values);
        Assert.Equal(Finished, other.CapturedUtc);
        Assert.Null(reader.ReadObjectAttributes("CN=Absent," + DomainDn));
        Assert.Equal("alice-member", first.Find("member")!.OnlyValue!.Text);
        Assert.Empty(reader.ReadObjectAttributes(AliceDn)!.Find("description")!.Values);
    }

    private static void AssertCapturedValues(IEnumerable<EvidenceAttribute> expected, ObjectAttributes read)
    {
        foreach (var input in expected)
        {
            var actual = read.Find(input.LdapDisplayName);
            Assert.NotNull(actual);
            Assert.Equal(input.Values.Count, actual.Values.Count);
            for (var i = 0; i < input.Values.Count; i++)
            {
                Assert.Equal(i, actual.Values[i].Ordinal);
                Assert.Equal(input.Values[i].Text, actual.Values[i].Text);
                Assert.Equal(input.Values[i].Bytes, actual.Values[i].Bytes);
            }
        }
    }

    /// <summary>
    /// An attribute this build does not capture is a fact about this build, and is told apart from
    /// an attribute that captured nothing.
    /// </summary>
    [Fact]
    public void AnAttributeTheCatalogueDoesNotNameIsNotFound()
    {
        WriteObject(Alice());

        Assert.Null(Read(AliceDn)!.Find("badPasswordTime"));
    }

    /// <summary>
    /// An object read over an encrypted connection could have been served every confidential
    /// attribute it holds, so nothing was withheld on account of how the connection was made.
    /// </summary>
    [Theory]
    [InlineData(ConnectionSecurityLevel.Ldaps)]
    [InlineData(ConnectionSecurityLevel.SignedAndSealed)]
    public void AnObjectReadOverAnEncryptedConnectionReadsBackAsComplete(
        ConnectionSecurityLevel security)
    {
        WriteObject(AliceReadOver(security));

        Assert.Equal(EvidenceCompleteness.Complete, Read(AliceDn)!.Completeness);
    }

    /// <summary>
    /// The other half, and the point of carrying the statement at all: a controller may strip
    /// confidential attributes from an unencrypted search and return no error, so a section
    /// finding nothing has to be able to tell that from an object that holds no value. The bundle
    /// records the rung; this read used to drop it.
    /// </summary>
    [Theory]
    [InlineData(ConnectionSecurityLevel.Signed)]
    [InlineData(ConnectionSecurityLevel.Unprotected)]
    public void AnObjectReadOverAnUnencryptedConnectionReadsBackAsPossiblyMissingValues(
        ConnectionSecurityLevel security)
    {
        WriteObject(AliceReadOver(security));

        Assert.Equal(
            EvidenceCompleteness.MayBeMissingConfidentialValues,
            Read(AliceDn)!.Completeness);
    }

    // ---------------------------------------------------------------------------------------
    // The two the schema stores under a name of its own
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// <c>distinguishedName</c> and <c>objectGUID</c> are columns of the object's identity rather
    /// than derived columns, and a caller asking the catalogue for them should not have to know it.
    /// </summary>
    [Fact]
    public void TheDistinguishedNameIsReadableAsAnAttribute()
    {
        WriteObject(Alice());

        Assert.Equal(AliceDn, Attribute("distinguishedName").OnlyValue!.Text);
    }

    [Fact]
    public void TheObjectGuidIsReadableAsAnAttributeInItsCanonicalForm()
    {
        var guid = Guid.NewGuid();
        WriteObject(new EvidenceObject(SomeCoverage(), AliceDn, guid, [], Started));

        Assert.Equal(guid.ToString("D"), Attribute("objectGUID").OnlyValue!.Text);
    }

    // ---------------------------------------------------------------------------------------
    // Finding one
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The directory treats attribute names case-insensitively, so a section naming one must not
    /// have to spell it the way the catalogue happens to.
    /// </summary>
    [Fact]
    public void AnAttributeIsFoundWhateverTheCaseOfTheNameAskedFor()
    {
        WriteObject(Alice(Text("sAMAccountName", "alice")));

        Assert.Equal("alice", Read(AliceDn)!.Find("samaccountname")!.OnlyValue!.Text);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }

    // ---------------------------------------------------------------------------------------

    private ObjectAttribute Attribute(string ldapDisplayName) =>
        Read(AliceDn)!.Find(ldapDisplayName)!;

    private ObjectAttributes? Read(string distinguishedName)
    {
        var opening = BundleReader.Open(_directory);
        Assert.True(opening.IsSuccess);

        using var reader = opening.Value;
        return reader.ReadObjectAttributes(distinguishedName);
    }

    private void WriteObject(EvidenceObject evidenceObject)
    {
        using var writer = BundleWriter.Create(_directory, Started);
        writer.WriteCoverage(evidenceObject.Coverage);
        writer.WriteObject(evidenceObject);
        writer.Complete(OneDomainRead(), Finished);
    }

    private static EvidenceObject Alice(params EvidenceAttribute[] attributes) =>
        AliceReadOver(ConnectionSecurityLevel.SignedAndSealed, attributes);

    private static EvidenceObject AliceReadOver(
        ConnectionSecurityLevel security, params EvidenceAttribute[] attributes) =>
        new(CoverageOver(security), AliceDn, Guid.NewGuid(), attributes, Started);

    private static EvidenceAttribute Text(string ldapDisplayName, params string[] values) =>
        new(
            ldapDisplayName,
            StoredAttributeCompleteness.Complete,
            [.. values.Select(EvidenceValue.OfText)]);

    private static EvidenceAttribute Bytes(string ldapDisplayName, byte[] value) =>
        new(
            ldapDisplayName,
            StoredAttributeCompleteness.Complete,
            [EvidenceValue.OfBytes(value)]);

    private static RunCoverage OneDomainRead() =>
        RunCoverage.Of(
            CoverageId.ForDomains("contoso.com", ["contoso.com"]),
            [DomainCoverage.Read("contoso.com")],
            [
                ForestPartitionCoverage.Read(
                    "CN=Configuration," + DomainDn, NamingContextKind.Configuration),
                ForestPartitionCoverage.Read(
                    "CN=Schema,CN=Configuration," + DomainDn, NamingContextKind.Schema),
            ],
            SysvolCoverage.Of([]));

    private static PartitionCoverage SomeCoverage() =>
        CoverageOver(ConnectionSecurityLevel.SignedAndSealed);

    private static PartitionCoverage CoverageOver(ConnectionSecurityLevel security) => new(
        DomainDn,
        NamingContextKind.Domain,
        "dc01.contoso.com",
        security,
        12,
        4200,
        3,
        [],
        false);
}
