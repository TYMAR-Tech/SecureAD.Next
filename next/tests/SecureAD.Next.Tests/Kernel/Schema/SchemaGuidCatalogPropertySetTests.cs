using SecureAD.Kernel.Schema;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Schema;

public sealed class SchemaGuidCatalogPropertySetTests
{
    private const string Attribute = "msDS-KeyCredentialLink";
    private const string Set = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    private const string OtherSet = "bbbbbbbb-1111-2222-3333-444444444444";

    [Theory]
    [InlineData(Set, true)]
    [InlineData(OtherSet, false)]
    [InlineData("invalid", null)]
    public void CapturedAssignmentAnswersMembershipWithoutRequiringARightDefinition(string requested, bool? expected)
    {
        var catalogue = new SchemaGuidCatalog([], new Dictionary<string, IReadOnlyList<string>> { [Set] = [Attribute] });
        Assert.Equal(expected, catalogue.AttributeBelongsToPropertySet(Attribute, requested));
    }

    [Fact]
    public void AnotherObservedMemberDoesNotProveExclusion()
    {
        var catalogue = new SchemaGuidCatalog([], new Dictionary<string, IReadOnlyList<string>> { [Set] = ["displayName"] });
        Assert.Null(catalogue.AttributeBelongsToPropertySet(Attribute, Set));
    }

    [Fact]
    public void AnEmptyMemberListDoesNotProveAnUnassignedAttribute()
    {
        var catalogue = new SchemaGuidCatalog([], new Dictionary<string, IReadOnlyList<string>> { [Set] = [] });
        Assert.Null(catalogue.AttributeBelongsToPropertySet(Attribute, Set));
    }

    [Fact]
    public void EmbeddedNamesDoNotInventAnAssignment()
    {
        Assert.Null(SchemaGuidCatalog.Embedded.AttributeBelongsToPropertySet(Attribute, Set));
    }

    [Fact]
    public void ConflictingAssignmentsRemainUnknown()
    {
        var catalogue = new SchemaGuidCatalog([], new Dictionary<string, IReadOnlyList<string>> { [Set] = [Attribute], [OtherSet] = [Attribute] });
        Assert.Null(catalogue.AttributeBelongsToPropertySet(Attribute, Set));
    }

    [Fact]
    public void MalformedAssignmentRemainsUnknown()
    {
        var catalogue = new SchemaGuidCatalog([], new Dictionary<string, IReadOnlyList<string>> { ["invalid"] = [Attribute] });
        Assert.Null(catalogue.AttributeBelongsToPropertySet(Attribute, Set));
    }

    [Fact]
    public void NamesAndGuidsAreCaseInsensitive()
    {
        var catalogue = new SchemaGuidCatalog([], new Dictionary<string, IReadOnlyList<string>> { [Set] = [Attribute] });
        Assert.Equal(true, catalogue.AttributeBelongsToPropertySet(Attribute.ToUpperInvariant(), Set.ToUpperInvariant()));
    }

    [Fact]
    public void NullAttributeIsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => SchemaGuidCatalog.Embedded.AttributeBelongsToPropertySet(null!, Set));
    }

    [Fact]
    public void NullSetIsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => SchemaGuidCatalog.Embedded.AttributeBelongsToPropertySet(Attribute, null!));
    }
}
