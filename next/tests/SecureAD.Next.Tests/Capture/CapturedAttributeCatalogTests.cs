using SecureAD.Audit.Capture;
using SecureAD.Evidence;
using Xunit;
using SecureAD.Kernel.Capture;

namespace SecureAD.Next.Tests.Capture;

/// <summary>
/// The catalogue's own behaviour, as distinct from whether it agrees with its document.
/// </summary>
public sealed class CapturedAttributeCatalogTests
{
    /// <summary>
    /// What capture actually requests, asserted against the request builder rather than against the
    /// catalogue's own shape.
    ///
    /// <para>
    /// The catalogue is written as a per-class table and it does not scope the request: every object
    /// is asked for <see cref="CapturedAttributeCatalog.All"/> whatever its class. This test exists
    /// because that is invisible from the catalogue and was misread as a per-class request during
    /// S-24, which produced a finding that had to be withdrawn. Anyone switching capture to a
    /// per-class request must delete this test to do it, which makes the change a decision rather
    /// than an edit.
    /// </para>
    /// </summary>
    [Fact]
    public void CaptureAsksEveryObjectForTheWholeCatalogueWhateverItsClass()
    {
        var unit = new CaptureUnit("DC=contoso,DC=com", NamingContextKind.Domain, "dc1.contoso.com");
        var request = CaptureSearchRequestFactory.ForUnit(unit, []);

        var requested = request.Attributes.Cast<string>().ToList();

        Assert.Equal(
            CapturedAttributeCatalog.All.Select(a => a.LdapDisplayName).OrderBy(n => n, StringComparer.OrdinalIgnoreCase),
            requested.OrderBy(n => n, StringComparer.OrdinalIgnoreCase));

        // Named, so a request that had quietly become class-scoped fails here rather than passing by
        // comparing one short list against another. A user is asked for attributes only an extended
        // right or a schema object can hold.
        Assert.Contains("rightsGuid", requested, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("searchFlags", requested, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("gPCFileSysPath", requested, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The point of having one filter rather than two. A vendor object of a class nobody
    /// anticipated is still captured, and still has its permissions read - which is what the
    /// previous product's inclusion list made impossible unless an operator found and ticked a
    /// radio button whose setting the settings panel then destroyed.
    /// </summary>
    [Fact]
    public void AnUnknownClassStillGetsItsSecurityDescriptor()
    {
        var attributes = CapturedAttributeCatalog.AttributesJustifiedBy("enatelSSOProfile");

        Assert.Contains(attributes, a => a.LdapDisplayName == "nTSecurityDescriptor");
    }

    [Fact]
    public void AnUnknownClassGetsExactlyTheUniversalSet()
    {
        Assert.Equal(
            CapturedAttributeCatalog.Universal,
            CapturedAttributeCatalog.AttributesJustifiedBy("enatelSSOProfile"));
    }

    /// <summary>
    /// An LDAP class name is matched without regard to case, and a directory returns the class in
    /// whatever case its schema records. A lookup that cared would silently downgrade every user in
    /// the forest to the universal set.
    /// </summary>
    [Theory]
    [InlineData("user")]
    [InlineData("User")]
    [InlineData("USER")]
    public void AClassIsMatchedWithoutRegardToCase(string objectClass)
    {
        Assert.Contains(
            CapturedAttributeCatalog.AttributesJustifiedBy(objectClass),
            a => a.LdapDisplayName == "userAccountControl");
    }

    [Fact]
    public void AKnownClassGetsTheUniversalSetAsWellAsItsOwn()
    {
        var group = CapturedAttributeCatalog.AttributesJustifiedBy("group");

        Assert.Contains(group, a => a.LdapDisplayName == "member");
        Assert.Contains(group, a => a.LdapDisplayName == "objectSid");
    }

    [Fact]
    public void AGroupManagedServiceAccountGetsThePasswordRetrievalDescriptor()
    {
        Assert.Contains(
            CapturedAttributeCatalog.AttributesJustifiedBy("msDS-GroupManagedServiceAccount"),
            a => a.LdapDisplayName == "msDS-GroupMSAMembership");
    }

    [Fact]
    public void AnOrdinaryUserDoesNotGetThePasswordRetrievalDescriptor()
    {
        Assert.DoesNotContain(
            CapturedAttributeCatalog.AttributesJustifiedBy("user"),
            a => a.LdapDisplayName == "msDS-GroupMSAMembership");
    }

    [Fact]
    public void AskingAboutNoClassAtAllIsAMistakeRatherThanAnEmptyAnswer()
    {
        Assert.Throws<ArgumentNullException>(() => CapturedAttributeCatalog.AttributesJustifiedBy(null!));
    }

    /// <summary>
    /// Range-liability is derived from cardinality rather than listed, so that adding a
    /// multi-valued attribute cannot leave a second hand-maintained list behind. This asserts the
    /// derivation, not the list.
    /// </summary>
    [Fact]
    public void EveryMultiValuedAttributeIsRangeLiable()
    {
        var expected = CapturedAttributeCatalog.All
            .Where(a => a.Cardinality == AttributeCardinality.MultiValued);

        Assert.Equal(expected, CapturedAttributeCatalog.RangeLiable);
    }

    [Fact]
    public void NoSingleValuedAttributeIsRangeLiable()
    {
        Assert.DoesNotContain(
            CapturedAttributeCatalog.RangeLiable,
            a => a.Cardinality == AttributeCardinality.SingleValued);
    }

    /// <summary>
    /// The attributes the previous product knew were range-liable, plus the two it did not name and
    /// that have grown since. A rebuild that lost any of them would report a large group, a
    /// migrated account or a key-credential list as smaller than it is, and report it confidently.
    /// </summary>
    [Theory]
    [InlineData("member")]
    [InlineData("memberOf")]
    [InlineData("sIDHistory")]
    [InlineData("servicePrincipalName")]
    [InlineData("msDS-AllowedToDelegateTo")]
    [InlineData("msDS-KeyCredentialLink")]
    [InlineData("objectClass")]
    public void TheKnownLargeAttributesAreRangeLiable(string attribute)
    {
        Assert.Contains(
            CapturedAttributeCatalog.RangeLiable,
            a => string.Equals(a.LdapDisplayName, attribute, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Several attributes appear in more than one class's set. <c>All</c> collapses them by name,
    /// so a disagreement about cardinality or storage between two declarations would be hidden by
    /// whichever happened to be first.
    /// </summary>
    [Fact]
    public void NoAttributeIsDeclaredTwoDifferentWays()
    {
        var everyDeclaration = CapturedAttributeCatalog.ObjectClasses
            .SelectMany(CapturedAttributeCatalog.AttributesJustifiedBy)
            .Concat(CapturedAttributeCatalog.SchemaPartition)
            .Concat(CapturedAttributeCatalog.ExtendedRights);

        var contradictions = everyDeclaration
            .GroupBy(a => a.LdapDisplayName, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Select(a => (a.Cardinality, a.Storage)).Distinct().Count() > 1)
            .Select(g => g.Key)
            .ToList();

        Assert.True(
            contradictions.Count == 0,
            "Attributes declared with different cardinality or storage in different sets: "
            + string.Join(", ", contradictions));
    }

    /// <summary>
    /// The DNS scope decision of 2026-08-11, expressed where it can be checked. Excluding a class
    /// and enumerating it are contradictory instructions, and the contradiction would resolve
    /// silently in favour of whichever code looked first.
    /// </summary>
    [Fact]
    public void NoExcludedClassIsAlsoEnumerated()
    {
        Assert.Empty(
            CapturedAttributeCatalog.UnreadObjectClasses
                .Intersect(CapturedAttributeCatalog.ObjectClasses, StringComparer.OrdinalIgnoreCase));
    }

    [Fact]
    public void TheDnsClassesAreTheOnlyOnesExcluded()
    {
        Assert.Equal(["dnsNode", "dnsZone"], CapturedAttributeCatalog.UnreadObjectClasses);
    }

    /// <summary>
    /// The schema read exists to answer two questions the catalogue deliberately does not answer
    /// itself: what a property-set permission really grants, and whether an absent value was
    /// withheld rather than unset.
    /// </summary>
    [Theory]
    [InlineData("attributeSecurityGUID")]
    [InlineData("searchFlags")]
    [InlineData("systemFlags")]
    [InlineData("schemaIDGUID")]
    public void TheSchemaReadCarriesWhatItIsFor(string attribute)
    {
        Assert.Contains(
            CapturedAttributeCatalog.SchemaPartition,
            a => a.LdapDisplayName == attribute);
    }

    /// <summary>
    /// A GUID that arrives as bytes on one side of a join and as a 36-character string on the other
    /// never matches if either is read the wrong way.
    /// </summary>
    [Fact]
    public void ThePropertySetJoinIsCarriedInBothRepresentations()
    {
        Assert.Equal(
            AttributeStorage.Binary,
            CapturedAttributeCatalog.SchemaPartition
                .Single(a => a.LdapDisplayName == "attributeSecurityGUID").Storage);

        Assert.Equal(
            AttributeStorage.Text,
            CapturedAttributeCatalog.ExtendedRights
                .Single(a => a.LdapDisplayName == "rightsGuid").Storage);
    }
}
