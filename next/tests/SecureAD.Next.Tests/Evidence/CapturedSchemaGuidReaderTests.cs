using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Schema;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// The captured half of the schema-GUID catalogue, which
/// <c>docs/decisions/0014-capture-reads-the-schema-partition.md</c> specified and nothing read
/// until now.
/// </summary>
/// <remarks>
/// <para>
/// <b>What these are really guarding.</b> A permission naming a GUID the catalogue cannot resolve
/// renders as a GUID, and an operator reading <c>Create 4828cc14-1437-45bc-9b07-ad6f015e5f28
/// objects</c> cannot tell whether that is a stock class, a forest extension, or a mistake. The
/// bundle held the answer the whole time.
/// </para>
/// <para>
/// The subtle failures here are silent ones: a GUID decoded with the wrong byte order is still a
/// well-formed GUID and simply matches nothing, and a control access right filed under the wrong
/// kind understates what a permission naming it hands over.
/// </para>
/// </remarks>
public sealed class CapturedSchemaGuidReaderTests : IDisposable
{
    private const string DomainDn = "DC=contoso,DC=com";
    private const string SchemaDn = "CN=Schema,CN=Configuration," + DomainDn;

    private static readonly DateTimeOffset Started = new(2026, 9, 14, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 9, 14, 10, 0, 0, TimeSpan.Zero);

    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securead-schema-" + Guid.NewGuid().ToString("N"));

    // -------------------------------------------------------------------------------------------
    // Reading what the forest said.
    // -------------------------------------------------------------------------------------------

    [Fact]
    public void AnAttributeDefinitionIsReadUnderTheNameTheForestGaveIt()
    {
        var guid = Guid.Parse("bf967a68-0de6-11d0-a285-00aa003049e2");

        WriteSchema(AttributeDefinition("contoso-PayrollId", guid));

        Assert.Equal("contoso-PayrollId", Catalogue().FindByGuid(guid.ToString("D"))[0].LdapName);
    }

    /// <summary>
    /// The whole point of capturing the schema: a forest's own extension can never be in a table
    /// shipped with the product, and those are the attributes most likely to be delegated
    /// carelessly and least likely to be understood.
    /// </summary>
    [Fact]
    public void AForestExtensionResolvesThoughNoShippedTableCouldKnowIt()
    {
        var guid = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

        WriteSchema(AttributeDefinition("contoso-Payroll-Secret", guid));

        Assert.Empty(SchemaGuidCatalog.Embedded.FindByGuid(guid.ToString("D")));
        Assert.NotEmpty(Catalogue().FindByGuid(guid.ToString("D")));
    }

    [Fact]
    public void ACapturedEntrySaysItCameFromTheForest()
    {
        var guid = Guid.Parse("bf967a68-0de6-11d0-a285-00aa003049e2");

        WriteSchema(AttributeDefinition("contoso-PayrollId", guid));

        Assert.Equal(
            SchemaGuidSource.Captured,
            Catalogue().FindByGuid(guid.ToString("D"))[0].Source);
    }

    /// <summary>
    /// The failure that produced this session. <c>inetOrgPerson</c> is a stock class absent from
    /// the shipped table, so a permission to create one rendered as a raw GUID.
    /// </summary>
    [Fact]
    public void AClassDefinitionIsReadAsAClass()
    {
        var guid = Guid.Parse("4828cc14-1437-45bc-9b07-ad6f015e5f28");

        WriteSchema(ClassDefinition("inetOrgPerson", guid));

        Assert.Equal(
            SchemaGuidKind.ObjectClass, Catalogue().FindByGuid(guid.ToString("D"))[0].Kind);
    }

    /// <summary>
    /// A class and an attribute are told apart by <c>isSingleValued</c>, which the schema makes
    /// mandatory on <c>attributeSchema</c> and which no class carries.
    /// </summary>
    [Fact]
    public void AnAttributeDefinitionIsReadAsAnAttributeRatherThanAClass()
    {
        var guid = Guid.Parse("bf967a68-0de6-11d0-a285-00aa003049e2");

        WriteSchema(AttributeDefinition("contoso-PayrollId", guid));

        Assert.Equal(SchemaGuidKind.Attribute, Catalogue().FindByGuid(guid.ToString("D"))[0].Kind);
    }

    /// <summary>
    /// <c>schemaIDGUID</c> is an octet string in the GUID's native little-endian layout. Read as a
    /// big-endian sequence it yields a well-formed GUID that matches nothing, which on screen is
    /// indistinguishable from a forest that never defined the attribute.
    /// </summary>
    [Fact]
    public void TheGuidIsDecodedInTheByteOrderActiveDirectoryStoresIt()
    {
        var guid = Guid.Parse("12345678-9abc-def0-1234-56789abcdef0");

        WriteSchema(AttributeDefinition("contoso-Ordering", guid));

        Assert.Equal(
            guid.ToString("D"),
            Catalogue().Entries.Single(e => e.LdapName == "contoso-Ordering").Guid);
    }

    // -------------------------------------------------------------------------------------------
    // The three kinds that share the extended-rights container.
    // -------------------------------------------------------------------------------------------

    [Theory]
    [InlineData(256, SchemaGuidKind.ExtendedRight)]
    [InlineData(48, SchemaGuidKind.PropertySet)]
    [InlineData(8, SchemaGuidKind.ValidatedWrite)]
    public void ValidAccessesDecidesWhichKindOfRightItIs(int validAccesses, SchemaGuidKind expected)
    {
        var guid = Guid.Parse("cccccccc-1111-2222-3333-444444444444");

        WriteSchema(ControlAccessRight("Contoso-Right", guid, validAccesses));

        Assert.Equal(expected, Catalogue().FindByGuid(guid.ToString("D"))[0].Kind);
    }

    /// <summary>
    /// There were three ways to guess a kind here and this covers all of them. Until <c>S-58</c>
    /// finding <c>#13</c> each returned <see cref="SchemaGuidKind.ExtendedRight"/> on the reasoning
    /// that it is the reading which grants most - sound for a severity judgement, and wrong for a
    /// factual classification that selects which rule computes the verdict. <c>S-53</c> carries the
    /// amendment.
    /// </summary>
    [Fact]
    public void WhenValidAccessesIsUnrecognised_ThenTheKindIsUnclassified()
    {
        var guid = Guid.Parse("cccccccc-1111-2222-3333-444444444444");

        WriteSchema(ControlAccessRight("Contoso-Odd", guid, validAccesses: 9999));

        Assert.Equal(
            SchemaGuidKind.Unclassified, Catalogue().FindByGuid(guid.ToString("D"))[0].Kind);
    }

    [Fact]
    public void WhenValidAccessesWillNotParse_ThenTheKindIsUnclassified()
    {
        var guid = Guid.Parse("cccccccc-1111-2222-3333-444444444444");

        WriteSchema(ControlAccessRightWithRawValidAccesses("Contoso-Unparseable", guid, "not a number"));

        Assert.Equal(
            SchemaGuidKind.Unclassified, Catalogue().FindByGuid(guid.ToString("D"))[0].Kind);
    }

    /// <summary>
    /// The fallback <c>S-57</c>'s verdict on <c>#13</c> does not mention. It named the unparseable
    /// and unrecognised cases; a <c>controlAccessRight</c> carrying no <c>validAccesses</c> at all
    /// took the same guess and was in no adjudicated verdict.
    /// </summary>
    [Fact]
    public void WhenValidAccessesIsAbsent_ThenTheKindIsUnclassified()
    {
        var guid = Guid.Parse("cccccccc-1111-2222-3333-444444444444");

        WriteSchema(ControlAccessRightWithoutValidAccesses("Contoso-Silent", guid));

        Assert.Equal(
            SchemaGuidKind.Unclassified, Catalogue().FindByGuid(guid.ToString("D"))[0].Kind);
    }

    /// <summary>
    /// An unclassified capture must not silence a shipped classification for the same GUID.
    /// </summary>
    /// <remarks>
    /// The captured layer wins over the shipped one, and
    /// <see cref="SchemaGuidKind.Unclassified"/> is the absence of an answer rather than one that
    /// should beat anybody. Without the guard in <c>SchemaGuidCatalog.CapturedOver</c> a forest row
    /// for a well-known extended right with no readable <c>validAccesses</c> would take the name
    /// and suppress the shipped entry, turning a <c>Dangerous</c> verdict into
    /// <c>CannotClassify</c> - a false negative produced by a fix for a false positive, which is
    /// <c>F-S54-2</c>.
    /// </remarks>
    [Fact]
    public void WhenAnUnclassifiedCaptureCollidesWithAShippedRight_ThenTheShippedKindSurvives()
    {
        var forceChangePassword = Guid.Parse("00299570-246d-11d0-a768-00aa006e0529");

        WriteSchema(ControlAccessRightWithoutValidAccesses(
            "User-Force-Change-Password", forceChangePassword));

        var found = Catalogue().FindByGuid(forceChangePassword.ToString("D"));

        Assert.Contains(found, e => e.Kind == SchemaGuidKind.ExtendedRight);
        Assert.DoesNotContain(found, e => e.Kind == SchemaGuidKind.Unclassified);
    }

    // -------------------------------------------------------------------------------------------
    // Two layers, and which one wins.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// A run that was refused the schema partition still resolves what Microsoft publishes, and
    /// says it captured nothing - which is a smaller answer, not a complete one.
    /// </summary>
    [Fact]
    public void ARunThatReadNoSchemaFallsBackToTheShippedTable()
    {
        WriteSchema();

        Assert.NotEmpty(Catalogue().FindByGuid(
            SchemaGuidCatalog.Embedded.GuidFor("userAccountControl")!));
    }

    [Fact]
    public void ARunThatReadNoSchemaSaysItCapturedNothing()
    {
        WriteSchema();

        Assert.False(Catalogue().HasCapturedEntries);
    }

    [Fact]
    public void ARunThatReadTheSchemaSaysSo()
    {
        WriteSchema(AttributeDefinition("contoso-PayrollId", Guid.NewGuid()));

        Assert.True(Catalogue().HasCapturedEntries);
    }

    /// <summary>
    /// Both layers certainly name <c>userAccountControl</c>. Names index uniquely, so a catalogue
    /// that concatenated rather than merged would throw the moment a real forest was read.
    /// </summary>
    [Fact]
    public void ANameInBothLayersDoesNotBuildTwoEntries()
    {
        var guid = Guid.Parse(SchemaGuidCatalog.Embedded.GuidFor("userAccountControl")!);

        WriteSchema(AttributeDefinition("userAccountControl", guid));

        Assert.Single(Catalogue().Entries.Where(e => e.LdapName == "userAccountControl"));
    }

    /// <summary>
    /// Where the two disagree the forest wins: a shipped name is a general claim about Active
    /// Directory, and a captured one is a fact about the forest being audited.
    /// </summary>
    [Fact]
    public void WhereTheLayersDisagreeTheForestWins()
    {
        var guid = Guid.Parse(SchemaGuidCatalog.Embedded.GuidFor("userAccountControl")!);

        WriteSchema(AttributeDefinition("contoso-RenamedFlags", guid));

        Assert.Equal(
            SchemaGuidSource.Captured, Catalogue().FindByGuid(guid.ToString("D"))[0].Source);
    }

    [Fact]
    public void AnObjectThatIsNeitherASchemaDefinitionNorARightIsIgnored()
    {
        WriteSchema(Object("CN=Alice," + DomainDn, Text("cn", "Alice")));

        Assert.False(Catalogue().HasCapturedEntries);
    }

    // -------------------------------------------------------------------------------------------
    // What a property set contains.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The join runs attribute-to-set, because a property set names none of its members: each
    /// attribute points back at the set through <c>attributeSecurityGUID</c>.
    /// </summary>
    [Fact]
    public void AnAttributeIsFiledUnderThePropertySetItPointsAt()
    {
        var setGuid = Guid.Parse("4c164200-20c0-11d0-a768-00aa006e0529");

        WriteSchema(
            ControlAccessRight("User-Account-Restrictions", setGuid, 48),
            AttributeIn("userAccountControl", Guid.NewGuid(), setGuid));

        Assert.Equal(
            ["userAccountControl"], Catalogue().MembersOfPropertySet(setGuid.ToString("D"))!);
    }

    /// <summary>
    /// The two ends of the join are the same GUID in two representations - an octet string on the
    /// attribute and a 36-character string on the set. Compared as they arrive they never match,
    /// and a join that never matches produces an empty set rather than an error.
    /// </summary>
    [Fact]
    public void TheJoinMatchesAcrossTheTwoRepresentationsOfTheSameGuid()
    {
        var setGuid = Guid.Parse("12345678-9abc-def0-1234-56789abcdef0");

        WriteSchema(
            ControlAccessRight("Contoso-Set", setGuid, 48),
            AttributeIn("contoso-Secret", Guid.NewGuid(), setGuid));

        Assert.NotNull(Catalogue().MembersOfPropertySet(setGuid.ToString("D")));
    }

    /// <summary>
    /// A set nothing points at is unknown rather than empty, so a caller cannot read it as
    /// containing nothing dangerous.
    /// </summary>
    [Fact]
    public void ASetNoAttributePointsAtIsNotKnownRatherThanEmpty()
    {
        var setGuid = Guid.Parse("bbbbbbbb-1111-2222-3333-444444444444");

        WriteSchema(ControlAccessRight("Contoso-Empty", setGuid, 48));

        Assert.Null(Catalogue().MembersOfPropertySet(setGuid.ToString("D")));
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }

    // -------------------------------------------------------------------------------------------

    private SchemaGuidCatalog Catalogue()
    {
        var opening = BundleReader.Open(_directory);
        Assert.True(opening.IsSuccess);

        using var reader = opening.Value;
        return reader.ReadSchemaGuids();
    }

    private void WriteSchema(params EvidenceObject[] objects)
    {
        using var writer = BundleWriter.Create(_directory, Started);
        writer.WriteCoverage(SomeCoverage());

        foreach (var evidenceObject in objects)
            writer.WriteObject(evidenceObject);

        writer.Complete(OneDomainRead(), Finished);
    }

    private static EvidenceObject AttributeDefinition(string ldapDisplayName, Guid guid) =>
        Object(
            "CN=" + ldapDisplayName + "," + SchemaDn,
            Text("lDAPDisplayName", ldapDisplayName),
            Bytes("schemaIDGUID", guid.ToByteArray()),
            Text("isSingleValued", "TRUE"));

    private static EvidenceObject ClassDefinition(string ldapDisplayName, Guid guid) =>
        Object(
            "CN=" + ldapDisplayName + "," + SchemaDn,
            Text("lDAPDisplayName", ldapDisplayName),
            Bytes("schemaIDGUID", guid.ToByteArray()));

    /// <summary>An attribute that names the property set it belongs to.</summary>
    private static EvidenceObject AttributeIn(
        string ldapDisplayName, Guid guid, Guid propertySet) =>
        Object(
            "CN=" + ldapDisplayName + "," + SchemaDn,
            Text("lDAPDisplayName", ldapDisplayName),
            Bytes("schemaIDGUID", guid.ToByteArray()),
            Bytes("attributeSecurityGUID", propertySet.ToByteArray()),
            Text("isSingleValued", "TRUE"));

    private static EvidenceObject ControlAccessRight(string cn, Guid guid, int validAccesses) =>
        ControlAccessRightWithRawValidAccesses(cn, guid, validAccesses.ToString());

    /// <summary>A control access right whose <c>validAccesses</c> is whatever the forest wrote.</summary>
    private static EvidenceObject ControlAccessRightWithRawValidAccesses(
        string cn, Guid guid, string validAccesses) =>
        Object(
            "CN=" + cn + ",CN=Extended-Rights,CN=Configuration," + DomainDn,
            Text("cn", cn),
            Text("rightsGuid", guid.ToString("D")),
            Text("validAccesses", validAccesses));

    /// <summary>A control access right that publishes no <c>validAccesses</c> at all.</summary>
    private static EvidenceObject ControlAccessRightWithoutValidAccesses(string cn, Guid guid) =>
        Object(
            "CN=" + cn + ",CN=Extended-Rights,CN=Configuration," + DomainDn,
            Text("cn", cn),
            Text("rightsGuid", guid.ToString("D")));

    private static EvidenceObject Object(string dn, params EvidenceAttribute[] attributes) =>
        new(SomeCoverage(), dn, Guid.NewGuid(), attributes, Started);

    private static EvidenceAttribute Text(string ldapDisplayName, string value) =>
        new(ldapDisplayName, StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(value)]);

    private static EvidenceAttribute Bytes(string ldapDisplayName, byte[] value) =>
        new(ldapDisplayName, StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(value)]);

    private static PartitionCoverage SomeCoverage() => new(
        DomainDn,
        NamingContextKind.Domain,
        "dc01.contoso.com",
        ConnectionSecurityLevel.SignedAndSealed,
        12,
        4200,
        3,
        [],
        false);

    private static RunCoverage OneDomainRead() =>
        RunCoverage.Of(
            CoverageId.ForDomains("contoso.com", ["contoso.com"]),
            [DomainCoverage.Read("contoso.com")],
            [
                ForestPartitionCoverage.Read(
                    "CN=Configuration," + DomainDn, NamingContextKind.Configuration),
                ForestPartitionCoverage.Read(SchemaDn, NamingContextKind.Schema),
            ],
            SysvolCoverage.Of([]));
}
