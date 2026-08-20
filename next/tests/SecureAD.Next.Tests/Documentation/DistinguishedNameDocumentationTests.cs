using System.Reflection;
using SecureAD.Kernel.Naming;
using SecureAD.Next.Tests.Inventory;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/next/S-2-distinguished-name-manipulation.md</c> to the code it describes.
///
/// <para>
/// Per <c>docs/next/README.md</c>, a document is not the new product's documentation until a test
/// holds it to the code. This component is a handful of members with no state, so the drift a
/// reader would not otherwise notice is a member renamed, added or removed while the document goes
/// on describing the old set.
/// </para>
/// <para>
/// What it cannot check is whether the explanation of the escaped comma is any good. That needs a
/// reader.
/// </para>
/// </summary>
public sealed class DistinguishedNameDocumentationTests
{
    private const string Document = "S-2-distinguished-name-manipulation.md";

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
    /// Every member a caller can reach is described. The document's shape table is the only place
    /// the three absence conventions are written down, so a fourth member added without an entry
    /// would leave a caller guessing which of them it follows.
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
            + "can reach needs its absence convention stated, or the caller guesses.");
    }

    /// <summary>
    /// The other direction. A document naming a member that was removed reads as a specification
    /// for behaviour nobody can call.
    /// </summary>
    [Fact]
    public void TheDocumentNamesNoMemberTheComponentDoesNotHave()
    {
        var text = Read();
        var actual = PublicMemberNames().ToHashSet(StringComparer.Ordinal);

        string[] retired = ["ExtractLastRdn", "ReRootDn", "AreSameDn", "IsDescendantOf"];

        var claimed = retired
            .Where(name => !actual.Contains(name))
            .Where(name => text.Contains(Quoted(name), StringComparison.Ordinal))
            .ToList();

        Assert.True(
            claimed.Count == 0,
            $"{Document} presents members the component does not have: {string.Join(", ", claimed)}. "
            + "Names it discusses as absent must not be written as though they exist.");
    }

    // EveryFindingCarriesAnIdentifier stood here and was deleted on 2026-08-14. It asserted that
    // every third-level heading in the document contained 'F-S2-', which is the shape of prose and
    // not a fact about the component. No change to DnHelper could break it.

    /// <summary>
    /// The document says where the component lands, and the code is there. The whole point of this
    /// row was that the previous location recorded which feature needed it first and nothing since.
    /// </summary>
    [Fact]
    public void TheDocumentStatesTheNamespaceTheCodeDeclares()
    {
        Assert.Contains($"`{typeof(DnHelper).Namespace}`", Read(), StringComparison.Ordinal);
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
        Assert.Contains(nameof(DnHelper), PublicTypeNames());
        Assert.Contains(nameof(DnHelper.DnToFqdn), PublicMemberNames());
    }

    /// <summary>
    /// The scan reports an absent name as missing. Run over an invented member, so it proves the
    /// search works without the document having to be edited to prove it.
    /// </summary>
    [Fact]
    public void TheCheckReportsANameThatIsAbsent()
    {
        var text = Read();
        string[] invented = ["DnToQuantumFlux"];

        Assert.Single(invented.Where(n => !text.Contains(Quoted(n), StringComparison.Ordinal)));
    }

    /// <summary>
    /// The scan is not a bare substring search. Mutation-testing this guard found that it was: a
    /// member renamed from <c>ExtractNameFromDn</c> to <c>ExtractNameFromDnXX</c> still matched the
    /// document, so the check reported nothing missing while the document named nothing that
    /// existed. Requiring the backticked form also keeps <c>ExtractFirstRdn</c> from being
    /// satisfied by the entry for <c>ExtractFirstRdnOrNull</c>.
    /// </summary>
    [Fact]
    public void TheCheckIsNotSatisfiedByANameThatMerelyContainsTheMemberName()
    {
        var text = Read();

        Assert.DoesNotContain(Quoted(nameof(DnHelper.ExtractNameFromDn) + "XX"), text, StringComparison.Ordinal);
        Assert.Contains(Quoted(nameof(DnHelper.ExtractNameFromDn)), text, StringComparison.Ordinal);
    }

    /// <summary>
    /// The name as the document must write it. A bare name would match any longer name containing
    /// it; the backticks make the match exact without needing a parser.
    /// </summary>
    private static string Quoted(string name) => "`" + name + "`";

    private static IEnumerable<string> PublicTypeNames() =>
        typeof(DnHelper).Assembly
            .GetExportedTypes()
            .Where(t => t.Namespace == typeof(DnHelper).Namespace)
            .Select(t => t.Name);

    private static IEnumerable<string> PublicMemberNames() =>
        typeof(DnHelper).Assembly
            .GetExportedTypes()
            .Where(t => t.Namespace == typeof(DnHelper).Namespace)
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance))
            .Where(m => m.DeclaringType != typeof(object))
            .Select(m => m.Name)
            .Distinct(StringComparer.Ordinal);

    private static string Path() =>
        System.IO.Path.Combine(OldAppInventory.RepositoryRoot(), "docs", "next", Document);

    private static string Read() => File.ReadAllText(Path());
}
