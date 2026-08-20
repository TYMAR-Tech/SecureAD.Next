using SecureAD.Kernel.Schema;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Schema;

/// <summary>
/// The schema-GUID catalogue: rows K13 and K14 of the inventory, merged.
///
/// <para>
/// The previous implementation kept two hand-curated tables of the same facts, in two folders,
/// with two entry records and two category enums, mapping in opposite directions. Both carried
/// correction comments about entries that had pointed at the wrong GUID, which is the cost of two
/// places to be wrong. These tests hold the one merged table.
/// </para>
/// <para>
/// <b>Where the expected values come from.</b> Every GUID a rule specification in
/// <c>docs/rules/</c> names is asserted from that specification, not from the old catalogue. The
/// rest are Microsoft adschema values, carried with the correction comments that produced them.
/// </para>
/// </summary>
public sealed class SchemaGuidCatalogTests
{
    private static SchemaGuidCatalog Catalog => SchemaGuidCatalog.Embedded;

    // ---------------------------------------------------------------------
    //  Assertions taken from docs/rules/, which is the source of truth
    // ---------------------------------------------------------------------

    /// <summary>
    /// Each row is a GUID written down in a rule specification. If the catalogue and the
    /// specification disagree, the catalogue is wrong: the specification is what the product
    /// promises a customer, and the rule that reads it is what fires.
    /// </summary>
    [Theory]
    [InlineData("member", "bf9679c0-0de6-11d0-a285-00aa003049e2")]                                  // SEC-006 §"the member attribute schema GUID"
    [InlineData("msDS-AllowedToActOnBehalfOfOtherIdentity", "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79")] // SEC-014
    [InlineData("Certificate-Enrollment", "0e10c968-78fb-11d2-90d4-00c04f79dc55")]                  // SEC-040
    [InlineData("Certificate-AutoEnrollment", "a05b8cc2-17bc-4802-a710-e7c15ab866a2")]              // SEC-041
    [InlineData("ms-Mcs-AdmPwd", "2e0e4a88-f5fa-11df-b3af-001fc000a000")]                           // SEC-090
    [InlineData("msLAPS-Password", "53c5be7e-5403-4013-a04b-b22e05d0e3c1")]                         // SEC-090
    [InlineData("sIDHistory", "17eb4278-d167-11d0-b002-0000f80367c1")]                              // SEC-123
    [InlineData("DS-Replication-Manage-Topology", "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2")]          // SEC-124
    public void WhenARuleSpecificationNamesAGuid_ThenTheCatalogueAgreesWithIt(string ldapName, string guid)
    {
        Assert.Equal(guid, Catalog.GuidFor(ldapName));
    }

    /// <summary>
    /// The two wrong values SEC-123 and SEC-124 record as having been shipped. A catalogue that
    /// resolved either would reinstate a defect whose consequence was a complete miss on the
    /// attack the rule exists to find, plus noise on a benign grant.
    /// </summary>
    [Theory]
    [InlineData("sIDHistory", "bf967a6d-0de6-11d0-a285-00aa003049e2")]                     // SEC-123 §13: userParameters
    [InlineData("sIDHistory", "9a9a0220-4ab5-11d1-afa6-00c04fd7d83a")]                     // SEC-123 §13: userSharedFolderOther
    [InlineData("DS-Replication-Manage-Topology", "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2")] // SEC-124 §: DS-Replication-Synchronize
    // The ten wrong GUIDs S-61 found by pinning every entry to Microsoft. Three are transpositions
    // within a pair, so each half guards the other: reinstating one reinstates both.
    [InlineData("DS-Replication-Monitor-Topology", "ee914b82-0a98-11d1-adbb-00c04fd8d5cd")]        // S-61: Abandon-Replication
    [InlineData("DS-Check-Stale-Phantoms", "bae50096-4752-11d1-9052-00c04fc2d4cf")]                // S-61
    [InlineData("DS-Query-Self-Quota", "014bf69c-7b3b-11d1-85f6-08002be74fab")]                    // S-61
    [InlineData("Recalculate-Hierarchy", "62dd28a8-7f46-11d2-b9ad-00c04f79f805")]                  // S-61: Recalculate-Security-Inheritance
    [InlineData("Recalculate-Security-Inheritance", "0bc1554e-0a99-11d1-adbb-00c04fd8d5cd")]       // S-61: Recalculate-Hierarchy
    [InlineData("Validated-MS-DS-Behavior-Version", "80863791-dbe9-4eb8-837e-7f0ab55d9ac7")]       // S-61: Validated-MS-DS-Additional-DNS-Host-Name
    [InlineData("Validated-MS-DS-Additional-DNS-Host-Name", "d31a8757-2447-4545-8081-3bb610cacbf2")] // S-61: Validated-MS-DS-Behavior-Version
    [InlineData("msDS-ResultantPSO", "3bcd8cb7-4fbb-4a01-a3a1-e6e0bd4c33c5")]                      // S-61
    [InlineData("groupPolicyContainer", "f30e3bc1-9ff0-11d1-b603-0000f80367c1")]                   // S-61: the gPLink attribute, one digit off
    public void WhenAGuidWasShippedWrongOnce_ThenTheCatalogueDoesNotResolveToItAgain(string ldapName, string wrongGuid)
    {
        Assert.NotEqual(wrongGuid, Catalog.GuidFor(ldapName));
    }

    /// <summary>
    /// The two LAPS attributes SEC-090 reads were in the schema index and absent from the danger
    /// catalogue. The merge is what closes that: one table cannot be missing an entry the other
    /// has. See finding F-S3-1.
    /// </summary>
    [Theory]
    [InlineData("ms-Mcs-AdmPwd")]
    [InlineData("msLAPS-Password")]
    public void WhenAnAttributeWasInOnlyOneOfTheTwoTables_ThenTheMergedCatalogueHasIt(string ldapName)
    {
        Assert.NotNull(Catalog.FindByLdapName(ldapName));
    }

    // ---------------------------------------------------------------------
    //  A GUID can mean more than one thing, and the catalogue says so
    // ---------------------------------------------------------------------

    /// <summary>
    /// <c>bf9679c0</c> is both the <c>Self-Membership</c> validated write and the <c>member</c>
    /// attribute; <c>f3a64788</c> is both <c>Validated-SPN</c> and <c>servicePrincipalName</c>.
    /// This is Active Directory, not a mistake in the table.
    ///
    /// <para>
    /// Both previous tables resolved such a GUID to whichever entry was declared first and said
    /// nothing about the other. For an audit tool that is the wrong shape: which meaning applies
    /// is decided by the ACE type at the call site, and a lookup that silently picks one has
    /// answered a question it was not asked.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData("bf9679c0-0de6-11d0-a285-00aa003049e2", "Self-Membership", "member")]
    [InlineData("f3a64788-5306-11d1-a9c5-0000f80367c1", "Validated-SPN", "servicePrincipalName")]
    public void WhenOneGuidHasTwoMeanings_ThenTheLookupReturnsBoth(
        string guid, string validatedWrite, string attribute)
    {
        var found = Catalog.FindByGuid(guid);

        Assert.Contains(found, e => e.LdapName == validatedWrite && e.Kind == SchemaGuidKind.ValidatedWrite);
        Assert.Contains(found, e => e.LdapName == attribute && e.Kind == SchemaGuidKind.Attribute);
    }

    [Fact]
    public void WhenOneGuidHasThreeMeanings_ThenTheLookupReturnsAllThree()
    {
        // 72e39547 is the Validated-DNS-Host-Name validated write, the DNS-Host-Name-Attributes
        // property set, and the dNSHostName attribute.
        var found = Catalog.FindByGuid("72e39547-7b18-11d1-adef-00c04fd8d5cd");

        Assert.Equal(3, found.Count);
    }

    [Fact]
    public void WhenAGuidHasOneMeaning_ThenTheLookupReturnsExactlyOneEntry()
    {
        var found = Catalog.FindByGuid("00299570-246d-11d0-a768-00aa006e0529");

        Assert.Single(found);
        Assert.Equal("User-Force-Change-Password", found[0].LdapName);
    }

    // ---------------------------------------------------------------------
    //  Absence
    // ---------------------------------------------------------------------

    [Fact]
    public void WhenTheGuidIsUnknown_ThenTheLookupIsEmptyRatherThanNull()
    {
        Assert.Empty(Catalog.FindByGuid("ffffffff-ffff-ffff-ffff-ffffffffffff"));
    }

    [Fact]
    public void WhenTheLdapNameIsUnknown_ThenTheEntryIsNull()
    {
        Assert.Null(Catalog.FindByLdapName("NoSuchAttribute"));
    }

    [Fact]
    public void WhenTheLdapNameIsUnknown_ThenNoGuidIsReturned()
    {
        Assert.Null(Catalog.GuidFor("NoSuchAttribute"));
    }

    // ---------------------------------------------------------------------
    //  Case, which Active Directory does not care about and neither does this
    // ---------------------------------------------------------------------

    [Fact]
    public void WhenTheGuidIsUpperCase_ThenItStillResolves()
    {
        Assert.Single(Catalog.FindByGuid("00299570-246D-11D0-A768-00AA006E0529"));
    }

    [Theory]
    [InlineData("sIDHistory")]
    [InlineData("sidhistory")]
    [InlineData("SIDHISTORY")]
    [InlineData("SiDhIsToRy")]
    public void WhenTheLdapNameIsWrittenInAnyCase_ThenItStillResolves(string ldapName)
    {
        Assert.Equal("17eb4278-d167-11d0-b002-0000f80367c1", Catalog.GuidFor(ldapName));
    }

    // ---------------------------------------------------------------------
    //  Kinds
    // ---------------------------------------------------------------------

    [Theory]
    [InlineData("User-Force-Change-Password", SchemaGuidKind.ExtendedRight)]
    [InlineData("DS-Replication-Get-Changes-All", SchemaGuidKind.ExtendedRight)]
    [InlineData("Self-Membership", SchemaGuidKind.ValidatedWrite)]
    [InlineData("Domain-Password", SchemaGuidKind.PropertySet)]
    [InlineData("General-Information", SchemaGuidKind.PropertySet)]
    [InlineData("sAMAccountName", SchemaGuidKind.Attribute)]
    [InlineData("nTSecurityDescriptor", SchemaGuidKind.Attribute)]
    [InlineData("user", SchemaGuidKind.ObjectClass)]
    [InlineData("organizationalUnit", SchemaGuidKind.ObjectClass)]
    public void WhenAnEntryIsLookedUpByName_ThenItCarriesTheKindItIs(string ldapName, SchemaGuidKind kind)
    {
        Assert.Equal(kind, Catalog.FindByLdapName(ldapName)!.Kind);
    }

    /// <summary>
    /// The anti-swap guard the previous tests carried. Three shipped defects had one signature: an
    /// attribute pointing at an object-class or property-set GUID from the same namespace.
    /// </summary>
    [Theory]
    [InlineData("member", "bf967a9c-0de6-11d0-a285-00aa003049e2")]                  // the group object class
    [InlineData("userAccountControl", "bf967a86-0de6-11d0-a285-00aa003049e2")]      // the computer object class
    [InlineData("msDS-AllowedToDelegateTo", "5f202010-79a5-11d0-9020-00c04fc2d3cf")] // the User-Logon property set
    public void WhenAnAttributeIsResolved_ThenItIsNotTheSameNamespaceClassOrPropertySet(
        string ldapName, string wrongGuid)
    {
        Assert.NotEqual(wrongGuid, Catalog.GuidFor(ldapName));
    }

    /// <summary>
    /// Every kind the shipped table can express is in it, and the one it must never express is
    /// not.
    /// </summary>
    /// <remarks>
    /// This was <c>Assert.Equal(Enum.GetValues&lt;SchemaGuidKind&gt;(), kinds)</c> until
    /// <see cref="SchemaGuidKind.Unclassified"/> existed, and loosening it to accommodate the new
    /// member would have thrown away what it was for. The member says <i>this build could not read
    /// what the forest published</i>, and the shipped table is not a forest: every entry in it was
    /// classified by hand, so one appearing here is a table defect rather than a fact about
    /// anybody's directory. Asserting its absence is a stronger claim than the original made.
    /// </remarks>
    [Fact]
    public void WhenTheCatalogueIsRead_ThenEveryKindTheTableCanExpressIsRepresented()
    {
        var kinds = Catalog.Entries.Select(e => e.Kind).Distinct().ToHashSet();

        var expected = Enum.GetValues<SchemaGuidKind>()
            .Where(k => k != SchemaGuidKind.Unclassified)
            .ToHashSet();

        Assert.Equal(expected, kinds);
    }

    [Fact]
    public void WhenTheShippedTableIsRead_ThenNothingInItIsUnclassified()
    {
        Assert.DoesNotContain(Catalog.Entries, e => e.Kind == SchemaGuidKind.Unclassified);
    }

    // ---------------------------------------------------------------------
    //  Table invariants
    // ---------------------------------------------------------------------

    [Fact]
    public void WhenTheCatalogueIsRead_ThenEveryGuidParses()
    {
        foreach (var entry in Catalog.Entries)
            Assert.True(Guid.TryParse(entry.Guid, out _), $"Not a GUID: {entry.Guid} ({entry.LdapName})");
    }

    [Fact]
    public void WhenTheCatalogueIsRead_ThenEveryGuidIsLowercase()
    {
        foreach (var entry in Catalog.Entries)
            Assert.Equal(entry.Guid.ToLowerInvariant(), entry.Guid);
    }

    [Fact]
    public void WhenTheCatalogueIsRead_ThenEveryEntryHasAnLdapName()
    {
        foreach (var entry in Catalog.Entries)
            Assert.False(string.IsNullOrWhiteSpace(entry.LdapName), $"Empty name for {entry.Guid}");
    }

    /// <summary>
    /// The name index can only be unambiguous if names are. A duplicate name would mean one of the
    /// two entries is unreachable by name and nothing says which.
    /// </summary>
    [Fact]
    public void WhenTheCatalogueIsRead_ThenNoLdapNameIsUsedTwice()
    {
        var duplicates = Catalog.Entries
            .GroupBy(e => e.LdapName, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        Assert.Empty(duplicates);
    }

    /// <summary>
    /// One GUID may appear under several names, but not twice under the same kind: that would be
    /// two rows claiming to be the same fact.
    /// </summary>
    [Fact]
    public void WhenTheCatalogueIsRead_ThenNoGuidIsRepeatedWithinOneKind()
    {
        var duplicates = Catalog.Entries
            .GroupBy(e => (e.Guid, e.Kind))
            .Where(g => g.Count() > 1)
            .Select(g => $"{g.Key.Guid} as {g.Key.Kind}")
            .ToList();

        Assert.Empty(duplicates);
    }

    [Fact]
    public void WhenTheCatalogueIsRead_ThenEveryEntryIsReachableByBothIndexes()
    {
        foreach (var entry in Catalog.Entries)
        {
            Assert.Contains(entry, Catalog.FindByGuid(entry.Guid));
            Assert.Equal(entry, Catalog.FindByLdapName(entry.LdapName));
        }
    }

    // ---------------------------------------------------------------------
    //  Provenance
    // ---------------------------------------------------------------------

    /// <summary>
    /// The previous catalogue was a static mutable singleton: a schema capture merged entries into
    /// a process-wide dictionary, so the same GUID could resolve differently depending on whether
    /// a capture had run first, and there was no way to ask for the shipped answer afterwards. For
    /// a tool whose whole value is that two runs can be compared, that is a provenance hazard.
    ///
    /// <para>
    /// It is prevented by construction rather than by discipline: the catalogue is an instance
    /// with no mutating member, so there is nothing to call.
    /// </para>
    /// </summary>
    [Fact]
    public void WhenTheEmbeddedCatalogueIsReadTwice_ThenItIsTheSameCatalogue()
    {
        Assert.Same(SchemaGuidCatalog.Embedded, SchemaGuidCatalog.Embedded);
    }

    [Fact]
    public void WhenTheCatalogueIsInspected_ThenItOffersNoWayToChangeIt()
    {
        var mutators = typeof(SchemaGuidCatalog)
            .GetMethods()
            .Where(m => m.Name is "LoadOverlay" or "Add" or "Merge" or "Clear")
            .Select(m => m.Name)
            .ToList();

        Assert.Empty(mutators);
    }

    [Fact]
    public void WhenTheCatalogueIsRead_ThenItStatesItsVersion()
    {
        Assert.True(SchemaGuidCatalog.Version > 0);
    }

    /// <summary>
    /// Every shipped row says so. A name in a report is a claim, and "Microsoft publishes this"
    /// is a stronger claim than "your forest said this on the day of the capture" - so the two are
    /// distinguishable rather than presented alike. The captured half arrives with inventory row D3.
    /// </summary>
    [Fact]
    public void WhenTheEmbeddedCatalogueIsRead_ThenEveryEntrySaysItWasShipped()
    {
        Assert.All(Catalog.Entries, e => Assert.Equal(SchemaGuidSource.Embedded, e.Source));
    }

    /// <summary>
    /// The provenance field can express something other than "shipped". A source with one possible
    /// value is a constant wearing a field's clothes, and would pass the test above for ever while
    /// recording nothing.
    /// </summary>
    [Fact]
    public void WhenProvenanceIsExpressed_ThenCapturedIsAvailableToSayToo()
    {
        Assert.Contains(SchemaGuidSource.Captured, Enum.GetValues<SchemaGuidSource>());
    }

    // ---------------------------------------------------------------------
    //  The scanner self-test
    // ---------------------------------------------------------------------

    /// <summary>
    /// Without this, the invariant checks above pass by iterating an empty table and finding
    /// nothing wrong with it.
    /// </summary>
    [Fact]
    public void TheCheckFindsTheCatalogue()
    {
        Assert.True(Catalog.Entries.Count > 50, $"Read only {Catalog.Entries.Count} entries.");
        Assert.Contains(Catalog.Entries, e => e.LdapName == "User-Force-Change-Password");
        Assert.Contains(Catalog.Entries, e => e.Kind == SchemaGuidKind.ObjectClass);
    }

    /// <summary>
    /// And the other direction: the lookups report an absent name as absent rather than returning
    /// something for anything asked of them.
    /// </summary>
    [Fact]
    public void TheCheckReportsANameTheCatalogueDoesNotHave()
    {
        Assert.Null(Catalog.GuidFor("msDS-QuantumFlux"));
        Assert.Empty(Catalog.FindByGuid("00000000-0000-0000-0000-000000000000"));
    }
}
