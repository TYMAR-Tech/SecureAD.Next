using SecureAD.Evidence;
using SecureAD.Kernel.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// Guards the two derivations the schema now rests on: the rule that turns an
/// <c>lDAPDisplayName</c> into a SQL identifier, and the list of attributes deliberately left out
/// of that derivation because they are already stored as identity columns.
/// </summary>
/// <remarks>
/// Both are the kind of thing that works on the day it is written and stops working silently. A
/// naming rule that collides puts two attributes in one column; an exclusion that outlives its
/// reason drops an attribute out of the schema with nothing to show for it.
/// </remarks>
public sealed class BundleSchemaTests
{
    /// <summary>
    /// The naming rule is injective over the catalogue, so no two attributes share a column.
    /// </summary>
    [Fact]
    public void NoTwoCatalogueAttributesShareAColumnName()
    {
        var collisions = CapturedAttributeCatalog.All
            .GroupBy(a => BundleSchema.ColumnNameFor(a.LdapDisplayName), StringComparer.Ordinal)
            .Where(g => g.Count() > 1)
            .Select(g => $"{g.Key}: {string.Join(", ", g.Select(a => a.LdapDisplayName))}")
            .ToList();

        Assert.True(
            collisions.Count == 0,
            "Two catalogued attributes map to one column, so one would overwrite the other:"
            + Environment.NewLine
            + string.Join(Environment.NewLine, collisions));
    }

    /// <summary>
    /// The reason the rule above cannot collide: lowercasing is only injective while no display
    /// name already contains the character hyphens are folded onto.
    /// </summary>
    [Fact]
    public void NoCatalogueAttributeAlreadyContainsAnUnderscore()
    {
        var underscored = CapturedAttributeCatalog.All
            .Select(a => a.LdapDisplayName)
            .Where(name => name.Contains('_', StringComparison.Ordinal))
            .ToList();

        Assert.True(
            underscored.Count == 0,
            "An attribute already contains an underscore, so a hyphenated name could now collide "
            + "with it: " + string.Join(", ", underscored));
    }

    /// <summary>
    /// Every attribute excluded from the derivation is really in the catalogue. Without this the
    /// list can name something that no longer exists and go on excluding nothing.
    /// </summary>
    [Fact]
    public void EveryStructurallyStoredAttributeIsRealAndExcluded()
    {
        Assert.NotEmpty(BundleSchema.StructurallyStoredAttributes);

        foreach (var name in BundleSchema.StructurallyStoredAttributes)
        {
            Assert.Contains(
                CapturedAttributeCatalog.All,
                a => string.Equals(a.LdapDisplayName, name, StringComparison.OrdinalIgnoreCase));

            Assert.DoesNotContain(
                BundleSchema.SingleValuedColumns,
                a => string.Equals(a.LdapDisplayName, name, StringComparison.OrdinalIgnoreCase));
        }
    }

    /// <summary>
    /// The derivation covers the catalogue: every attribute is a column, a value table, or
    /// deliberately excluded. An attribute in none of the three would be asked for on every object
    /// and have nowhere to go.
    /// </summary>
    [Fact]
    public void EveryCatalogueAttributeIsStoredSomewhere()
    {
        var accounted = BundleSchema.SingleValuedColumns.Select(a => a.LdapDisplayName)
            .Concat(BundleSchema.MultiValuedTables.Select(a => a.LdapDisplayName))
            .Concat(BundleSchema.StructurallyStoredAttributes)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var homeless = CapturedAttributeCatalog.All
            .Select(a => a.LdapDisplayName)
            .Where(name => !accounted.Contains(name))
            .ToList();

        Assert.True(
            homeless.Count == 0,
            "The catalogue asks for attributes the schema has nowhere to put: "
            + string.Join(", ", homeless));
    }

    /// <summary>
    /// The self-test. Without it every check above passes over an empty catalogue by finding
    /// nothing wrong with nothing.
    /// </summary>
    [Fact]
    public void TheDerivationReadsARealCatalogue()
    {
        Assert.True(
            CapturedAttributeCatalog.All.Count >= 30,
            $"Read only {CapturedAttributeCatalog.All.Count} attributes from the catalogue.");

        Assert.NotEmpty(BundleSchema.SingleValuedColumns);
        Assert.NotEmpty(BundleSchema.MultiValuedTables);

        // Named, so a derivation that returned nothing fails here rather than passing by matching
        // nothing against nothing.
        Assert.Equal("ntsecuritydescriptor", BundleSchema.ColumnNameFor("nTSecurityDescriptor"));
        Assert.Equal("msds_keycredentiallink_value", BundleSchema.ValueTableNameFor("msDS-KeyCredentialLink"));
        Assert.Contains("member_value", BundleSchema.TableNames);

        // And the tables that were replaced at S-24, whose absence is a decision rather than an
        // oversight: docs/decisions/0022 stores an object as one row with typed columns.
        Assert.DoesNotContain("captured_attribute", BundleSchema.TableNames);
        Assert.DoesNotContain("attribute_value", BundleSchema.TableNames);
    }
}
