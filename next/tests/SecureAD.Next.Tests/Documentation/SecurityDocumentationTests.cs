using System.Text.RegularExpressions;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds the Kernel security documentation to the code it describes.
///
/// <para>
/// A document is not the product's documentation until a test holds it to the code. These
/// assertions catch drift and omission in both directions — a type renamed, a DACL state added, the
/// canonicalisation version bumped — so the documentation cannot quietly describe a component that
/// has moved on, and cannot omit a piece of it either.
/// </para>
/// <para>
/// <b>There is no list of types in this file.</b> The previous version carried two hand-maintained
/// lists — the types the document must name, and the types covered elsewhere — so a type could not
/// be added to the code without also editing them. The names are now read out of the documents' own
/// type tables and compared against the namespace, so the check has no list to fall behind.
/// </para>
/// <para>
/// What it cannot check is whether the explanation is any good. That needs a reader.
/// </para>
/// </summary>
public sealed class SecurityDocumentationTests
{
    /// <summary>
    /// The documents that between them describe <c>SecureAD.Kernel.Security</c>. Split by the job
    /// each does rather than by namespace, because one document naming thirty-four types is an
    /// index rather than an explanation.
    /// </summary>
    private static readonly string[] Documents =
    [
        "security-descriptors.md",
        "permission-classification.md",
        "naming.md",
    ];

    /// <summary>
    /// The block a document's type table lives in. Only rows inside these delimiters are read, so
    /// the other tables in a document — enum members, attribute names, capabilities — are not
    /// mistaken for type names. The delimiters also let a generator fill the block later without
    /// this check changing.
    /// </summary>
    private static readonly Regex TypeBlock =
        new(@"<!--\s*TYPES:BEGIN\s*-->(?<body>.*?)<!--\s*TYPES:END\s*-->",
            RegexOptions.Singleline | RegexOptions.Compiled);

    /// <summary>
    /// A row of a type table: <c>| `TypeName` | what it is |</c>.
    /// </summary>
    private static readonly Regex TypeRow =
        new(@"^\|\s*`(?<name>[A-Za-z][A-Za-z0-9_]*)`\s*\|", RegexOptions.Multiline | RegexOptions.Compiled);

    [Fact]
    public void TheDocumentationNamesEveryPublicTypeInTheNamespace()
    {
        var documented = NamedInDocumentation();

        var missing = PublicTypes()
            .Where(t => !documented.Contains(t))
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "The Kernel security documentation does not name: " + string.Join(", ", missing)
            + ". A type the documentation does not mention is a piece of the component nobody "
            + "reading it knows exists.");
    }

    [Fact]
    public void TheDocumentationNamesNoTypeTheNamespaceDoesNotHave()
    {
        var actual = PublicTypes();

        var phantom = NamedInDocumentation()
            .Where(name => !actual.Contains(name))
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            phantom.Count == 0,
            "The Kernel security documentation names types that are not in "
            + typeof(AceNormalizer).Namespace + ": " + string.Join(", ", phantom)
            + ". An entry for a type that does not exist makes the documentation look more "
            + "complete than it is.");
    }

    /// <summary>
    /// Every DACL state is described, because the whole point of the enum is that a reader must be
    /// able to tell them apart — and two of them mean opposite things.
    /// </summary>
    [Fact]
    public void TheDocumentationNamesEveryDaclState()
    {
        var text = ReadAll();

        var missing = Enum.GetNames<DaclState>()
            .Where(name => !text.Contains(name, StringComparison.Ordinal))
            .ToList();

        Assert.True(
            missing.Count == 0,
            "The Kernel security documentation does not describe DACL states: "
            + string.Join(", ", missing));
    }

    /// <summary>
    /// The documentation states the canonicalisation version, which is the number that invalidates
    /// every stored hash if it moves. Naming a stale one would be worse than naming none.
    /// </summary>
    [Fact]
    public void TheDocumentationStatesTheCanonicalizationVersionTheCodeDeclares()
    {
        Assert.Contains(
            $"**{AceCanonicalization.Version}**",
            ReadAll(),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The reader found the documents. Without this every assertion above passes by searching an
    /// empty string and finding nothing missing.
    /// </summary>
    [Fact]
    public void TheReaderFindsEveryDocument()
    {
        foreach (var document in Documents)
        {
            var path = PathTo(document);
            Assert.True(File.Exists(path), $"Expected the document at {path}.");
            Assert.True(
                File.ReadAllText(path).Length > 1000,
                $"{document} is too short to be the document it claims.");
        }
    }

    /// <summary>
    /// The scanner self-test. It proves the type tables were actually read, and that an absent name
    /// is reported as absent, without needing a document edited to prove it.
    /// </summary>
    [Fact]
    public void TheCheckReadsTheTypeTablesAndReportsAnAbsentName()
    {
        var documented = NamedInDocumentation();

        Assert.True(
            documented.Count > 25,
            $"Read only {documented.Count} type names out of the documentation, which is too few "
            + "to be the whole namespace.");

        Assert.DoesNotContain("AceQuantumFluxNormalizer", documented);
    }

    private static HashSet<string> PublicTypes() =>
        typeof(AceNormalizer).Assembly
            .GetExportedTypes()
            .Where(t => t.Namespace == typeof(AceNormalizer).Namespace)
            .Select(t => t.Name)
            .ToHashSet(StringComparer.Ordinal);

    private static HashSet<string> NamedInDocumentation()
    {
        var names = new HashSet<string>(StringComparer.Ordinal);

        foreach (var document in Documents)
        {
            var blocks = TypeBlock.Matches(File.ReadAllText(PathTo(document)));

            Assert.True(
                blocks.Count == 1,
                $"{document} should carry exactly one TYPES block; found {blocks.Count}.");

            foreach (Match row in TypeRow.Matches(blocks[0].Groups["body"].Value))
            {
                names.Add(row.Groups["name"].Value);
            }
        }

        return names;
    }

    private static string ReadAll() =>
        string.Join("\n", Documents.Select(d => File.ReadAllText(PathTo(d))));

    private static string PathTo(string document) =>
        Path.Combine(RepositoryLocation.Root(), "docs", "layers", "kernel", document);
}
