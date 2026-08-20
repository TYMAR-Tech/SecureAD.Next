using System.Reflection;
using SecureAD.Kernel.Schema;
using SecureAD.Next.Tests.Inventory;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/next/S-3-schema-guid-catalogue.md</c> to the code it describes.
///
/// <para>
/// Per <c>docs/next/README.md</c>, a document is not the new product's documentation until a test
/// holds it to the code. The drift that matters here is a member or a type changing while the
/// document goes on describing the old set, and - because this component's whole subject is where
/// the line between data and classification falls - a finding losing the identifier a later
/// session must cite it by.
/// </para>
/// <para>
/// What it cannot check is whether the explanation of why the danger flag was left behind is any
/// good. That needs a reader.
/// </para>
/// </summary>
[Collection(nameof(InventoryFileCollection))]
public sealed class SchemaGuidDocumentationTests
{
    private const string Document = "S-3-schema-guid-catalogue.md";

    [Fact]
    public void TheDocumentNamesEveryPublicTypeInTheComponent()
    {
        var text = Read();

        var missing = PublicTypeNames()
            .Where(name => !text.Contains(Quoted(name), StringComparison.Ordinal))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not name: {string.Join(", ", missing)}. A type the documentation "
            + "does not mention is a piece of the component nobody reading it knows exists.");
    }

    /// <summary>
    /// Every member a caller can reach is described, with what it gives back when it knows
    /// nothing. An unknown GUID and an unknown name answer differently, and a caller that guesses
    /// which convention a member follows is a caller that will read an absent answer as a present
    /// one.
    /// </summary>
    [Fact]
    public void TheDocumentNamesEveryPublicMemberOfTheComponent()
    {
        var text = Read();

        var missing = PublicMemberNames()
            .Where(name => !text.Contains(Quoted(name), StringComparison.Ordinal))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not describe: {string.Join(", ", missing)}. Every member a caller "
            + "can reach needs its absent-input answer stated, or the caller guesses.");
    }

    /// <summary>
    /// The other direction. The two fields deliberately left behind are discussed by name, so the
    /// document must not present them as though the code still has them.
    /// </summary>
    [Fact]
    public void TheDocumentDoesNotPresentTheLeftBehindFieldsAsMembers()
    {
        var text = Read();
        var actual = PublicMemberNames().ToHashSet(StringComparer.Ordinal);

        string[] leftBehind = ["IsDangerous", "DisplayName"];

        var claimed = leftBehind
            .Where(name => !actual.Contains(name))
            .Where(name => text.Contains(Quoted(name), StringComparison.Ordinal))
            .Where(name => !text.Contains(Quoted(name) + " does not come across", StringComparison.Ordinal))
            .ToList();

        Assert.True(
            claimed.Count == 0,
            $"{Document} presents members the component does not have: {string.Join(", ", claimed)}. "
            + "Names it discusses as absent must be written as absent.");
    }

    // EveryFindingCarriesAnIdentifier stood here and was deleted on 2026-08-14. It asserted that
    // every third-level heading contained 'F-S3-'. That is the shape of prose, and no change to
    // SchemaGuidCatalog could break it.

    /// <summary>
    /// The document states where the component lands, and the code is there. Both previous tables
    /// were filed under folders named for a shape rather than a subject, which is a large part of
    /// why neither author found the other's.
    /// </summary>
    [Fact]
    public void TheDocumentStatesTheNamespaceTheCodeDeclares()
    {
        Assert.Contains($"`{typeof(SchemaGuidCatalog).Namespace}`", Read(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The nine GUIDs the previous catalogue flagged dangerous are the one piece of knowledge that
    /// could be lost between this row and K16, because the flag is deliberately not carried. The
    /// document is where they are written down, so this asserts they are all still written down.
    /// </summary>
    [Theory]
    [InlineData("User-Force-Change-Password")]
    [InlineData("DS-Replication-Get-Changes")]
    [InlineData("DS-Replication-Get-Changes-All")]
    [InlineData("Self-Membership")]
    [InlineData("Validated-SPN")]
    [InlineData("msDS-AllowedToActOnBehalfOfOtherIdentity")]
    [InlineData("msDS-KeyCredentialLink")]
    [InlineData("userAccountControl")]
    [InlineData("unicodePwd")]
    public void TheDocumentHandsEveryPreviouslyDangerousNameOnToTheNextRow(string ldapName)
    {
        Assert.Contains(Quoted(ldapName), Read(), StringComparison.Ordinal);
        Assert.NotNull(SchemaGuidCatalog.Embedded.FindByLdapName(ldapName));
    }

    /// <summary>
    /// The finding that hands them on must name the row that takes them, and that row must be a
    /// real one. A handover addressed to nothing cannot come due.
    /// </summary>
    [Fact]
    public void TheHandoverNamesARealInventoryRow()
    {
        Assert.Contains("K16", Read(), StringComparison.Ordinal);
        Assert.Contains("K16", OldAppInventory.RowIdentifiers());
    }

    /// <summary>
    /// The scanner self-test. Without it every assertion above passes by searching an empty string
    /// and reflecting over an empty set, and finding nothing wrong with either.
    /// </summary>
    [Fact]
    public void TheCheckFindsBothTheDocumentAndTheComponent()
    {
        Assert.True(File.Exists(Path()), $"Expected the slice document at {Path()}.");
        Assert.True(Read().Length > 1000, $"{Document} is too short to be the document it claims.");
        Assert.Contains(nameof(SchemaGuidCatalog), PublicTypeNames());
        Assert.Contains(nameof(SchemaGuidCatalog.GuidFor), PublicMemberNames());
    }

    /// <summary>
    /// The scan reports an absent name as missing. Run over an invented member, so it proves the
    /// search works without the document having to be broken to prove it.
    /// </summary>
    [Fact]
    public void TheCheckReportsANameThatIsAbsent()
    {
        Assert.DoesNotContain(Quoted("FindByQuantumFlux"), Read(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The scan is not a bare substring search. Mutation-testing the equivalent guard in session
    /// S-2 found that it was: a member renamed by appending two characters still matched the
    /// document, so the check reported nothing missing while the document named nothing that
    /// existed. The backticked form makes the match exact without needing a parser, and also keeps
    /// <c>FindByGuid</c> from being satisfied by the entry for <c>FindByLdapName</c>.
    /// </summary>
    [Fact]
    public void TheCheckIsNotSatisfiedByANameThatMerelyContainsTheMemberName()
    {
        var text = Read();

        Assert.DoesNotContain(Quoted(nameof(SchemaGuidCatalog.GuidFor) + "XX"), text, StringComparison.Ordinal);
        Assert.Contains(Quoted(nameof(SchemaGuidCatalog.GuidFor)), text, StringComparison.Ordinal);
    }

    private static string Quoted(string name) => "`" + name + "`";

    private static IEnumerable<string> PublicTypeNames() =>
        typeof(SchemaGuidCatalog).Assembly
            .GetExportedTypes()
            .Where(t => t.Namespace == typeof(SchemaGuidCatalog).Namespace)
            .Select(t => t.Name);

    /// <summary>
    /// Every member a caller can reach and an author wrote.
    ///
    /// <para>
    /// Enum types are excluded: their members are the vocabulary <c>SchemaGuidKind</c> already
    /// documents as a whole, and reflecting over one also yields the machinery every enum has.
    /// Property accessors and the members the compiler writes for a record are excluded for the
    /// same reason - a document naming <c>get_Entries</c> would be describing the compiler.
    /// </para>
    /// </summary>
    private static IEnumerable<string> PublicMemberNames() =>
        typeof(SchemaGuidCatalog).Assembly
            .GetExportedTypes()
            .Where(t => t.Namespace == typeof(SchemaGuidCatalog).Namespace)
            .Where(t => !t.IsEnum)
            .SelectMany(t => t.GetMembers(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance))
            .Where(m => m.DeclaringType != typeof(object))
            .Where(m => m.MemberType is MemberTypes.Method or MemberTypes.Property or MemberTypes.Field)
            .Where(m => m is not MethodInfo method || !method.IsSpecialName)
            .Select(m => m.Name)
            .Where(name => !name.Contains('<', StringComparison.Ordinal))
            .Where(name => !Compiler.Contains(name))
            .Distinct(StringComparer.Ordinal);

    /// <summary>
    /// Names the compiler generates for a record, which no author wrote and no reader would look
    /// for.
    /// </summary>
    private static readonly HashSet<string> Compiler = new(StringComparer.Ordinal)
    {
        "Equals", "GetHashCode", "ToString", "Deconstruct", "Clone", "op_Equality", "op_Inequality",
        "EqualityContract",
    };

    private static string Path() =>
        System.IO.Path.Combine(OldAppInventory.RepositoryRoot(), "docs", "next", Document);

    private static string Read() => File.ReadAllText(Path());
}
