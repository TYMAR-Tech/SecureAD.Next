using System.Reflection;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/evidence/how-a-bundle-is-read.md</c> to <see cref="RunLibrary"/>,
/// <see cref="RunListing"/> and the refusals the library actually constructs.
/// </summary>
/// <remarks>
/// <para>
/// Every table is checked in both directions. A member in the code and not in the document is a
/// capability nobody wrote down; a member in the document and not in the code is a claim about a
/// product that does not exist. The second direction is the one that rots, because nothing about
/// deleting a method makes a paragraph describing it go red.
/// </para>
/// <para>
/// <b>This document deliberately carries no <c>STATES</c> table.</b> Run states are observed from
/// files on disk and belong beside the file names, so they live on
/// <c>the-bundle-on-disk.md</c>. <see cref="TheStateVocabularyIsNotRestatedHere"/> holds that split
/// open, because a second copy of a table is how two descriptions of one thing start to disagree.
/// </para>
/// </remarks>
public sealed class RunLibraryDocumentationTests
{
    private const string Document = "docs/evidence/how-a-bundle-is-read.md";

    /// <summary>
    /// The refusals the library builds. Read off the source rather than reflected, because an
    /// <c>AuditError</c> code is a string literal at a call site and there is no type to enumerate.
    /// </summary>
    private static readonly string[] Refusals =
    [
        "RunIdentifierIsEmpty",
        "RunIdentifierIsNotAName",
        "RunIsOutsideTheLibrary",
        "RunDirectoryAlreadyExists",
        "RunIsNotThere",
        "RunCouldNotBeDeleted",
        "RunLibraryCannotBeRead",
    ];

    [Fact]
    public void EveryPublicMemberOfTheLibraryIsInTheDocument()
    {
        var documented = FirstColumn("LIBRARY").ToHashSet(StringComparer.Ordinal);

        var missing = LibraryMembers()
            .Where(m => !documented.Contains(m))
            .Select(m => $"  {m} is public on RunLibrary and the document does not name it")
            .ToList();

        Assert.True(missing.Count == 0, Explain(missing));
    }

    [Fact]
    public void TheDocumentNamesNoLibraryMemberThatIsNotThere()
    {
        var actual = LibraryMembers().ToHashSet(StringComparer.Ordinal);

        var invented = FirstColumn("LIBRARY")
            .Where(m => !actual.Contains(m))
            .Select(m => $"  the document names `{m}`, which RunLibrary does not declare")
            .ToList();

        Assert.True(invented.Count == 0, Explain(invented));
    }

    [Fact]
    public void EveryMemberOfAListingIsInTheDocument()
    {
        var documented = FirstColumn("LISTING").ToHashSet(StringComparer.Ordinal);

        var missing = ListingMembers()
            .Where(m => !documented.Contains(m))
            .Select(m => $"  {m} is carried by RunListing and the document does not name it")
            .ToList();

        Assert.True(missing.Count == 0, Explain(missing));
    }

    [Fact]
    public void TheDocumentNamesNoListingMemberThatIsNotThere()
    {
        var actual = ListingMembers().ToHashSet(StringComparer.Ordinal);

        var invented = FirstColumn("LISTING")
            .Where(m => !actual.Contains(m))
            .Select(m => $"  the document names `{m}`, which RunListing does not carry")
            .ToList();

        Assert.True(invented.Count == 0, Explain(invented));
    }

    [Fact]
    public void EveryRefusalTheLibraryBuildsIsInTheDocument()
    {
        var documented = FirstColumn("REFUSALS").ToHashSet(StringComparer.Ordinal);

        var missing = Refusals
            .Where(r => !documented.Contains(r))
            .Select(r => $"  the library can refuse with '{r}' and the document does not say so")
            .ToList();

        Assert.True(missing.Count == 0, Explain(missing));
    }

    [Fact]
    public void TheDocumentNamesNoRefusalTheLibraryCannotProduce()
    {
        var invented = FirstColumn("REFUSALS")
            .Where(r => !Refusals.Contains(r, StringComparer.Ordinal))
            .Select(r => $"  the document names refusal `{r}`, which is not in the library")
            .ToList();

        Assert.True(invented.Count == 0, Explain(invented));
    }

    /// <summary>
    /// The refusal list above is hand-written, so it is itself checked against the source. Without
    /// this the gate would compare the document to a list that had quietly gone stale, which is a
    /// sound check pointed at a dead reference.
    /// </summary>
    [Fact]
    public void TheRefusalListMatchesWhatTheSourceActuallyConstructs()
    {
        var source = File.ReadAllText(
            Path.Combine(RepositoryLocation.Root(), "next", "src", "SecureAD.Evidence", "Run", "RunLibrary.cs"));

        var missing = Refusals
            .Where(r => !source.Contains($"\"{r}\"", StringComparison.Ordinal))
            .Select(r => $"  '{r}' is in this test's list and not in RunLibrary.cs")
            .ToList();

        Assert.True(missing.Count == 0, Explain(missing));
    }

    /// <summary>
    /// Run states are described on the on-disk page. A second copy here would be two descriptions of
    /// one vocabulary, free to drift apart.
    /// </summary>
    [Fact]
    public void TheStateVocabularyIsNotRestatedHere()
    {
        Assert.DoesNotContain("<!-- STATES:BEGIN", Read(), StringComparison.Ordinal);
    }

    /// <summary>
    /// A marker block that is not there is a failure and never an empty result. A gate left pointing
    /// at a document whose table has moved elsewhere must say so. Two gates in this repository have
    /// already passed for months while measuring nothing.
    /// </summary>
    [Fact]
    public void AMissingTableIsAFailureRatherThanAnEmptyScan()
    {
        var thrown = Record.Exception(() => TableRows("STATES"));

        Assert.NotNull(thrown);
    }

    /// <summary>
    /// The scanner self-test: the three tables are found and are not empty.
    /// </summary>
    [Fact]
    public void TheCheckReadsAllThreeTables()
    {
        Assert.NotEmpty(FirstColumn("LIBRARY"));
        Assert.NotEmpty(FirstColumn("LISTING"));
        Assert.NotEmpty(FirstColumn("REFUSALS"));

        Assert.Contains(nameof(RunLibrary.Resolve), FirstColumn("LIBRARY"));
        Assert.Contains(nameof(RunListing.Scope), FirstColumn("LISTING"));
    }

    // --- helpers -----------------------------------------------------------------------------------

    private static string Explain(List<string> problems) =>
        $"{Document} and the code disagree:" + Environment.NewLine
        + string.Join(Environment.NewLine, problems);

    private static List<string> LibraryMembers() =>
        [.. typeof(RunLibrary)
            .GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(m => m.MemberType is MemberTypes.Method or MemberTypes.Property)
            .Where(m => m is not MethodInfo { IsSpecialName: true })
            .Where(m => m.DeclaringType == typeof(RunLibrary))
            .Select(m => m.Name)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(n => n, StringComparer.Ordinal)];

    private static List<string> ListingMembers() =>
        [.. typeof(RunListing)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(p => p.Name != "EqualityContract")
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)];

    private static List<string> FirstColumn(string marker) =>
        [.. TableRows(marker).Select(r => Cells(r)[0].Trim('`'))];

    /// <summary>
    /// The rows between a pair of markers, excluding the header and the separator, so the test
    /// parses the table rather than the prose around it.
    /// </summary>
    private static List<string> TableRows(string marker)
    {
        var text = Read();
        var begin = text.IndexOf($"<!-- {marker}:BEGIN -->", StringComparison.Ordinal);
        var end = text.IndexOf($"<!-- {marker}:END -->", StringComparison.Ordinal);

        Assert.True(begin >= 0 && end > begin, $"{Document} has no {marker} table.");

        return
        [
            .. text[begin..end]
                .Split('\n')
                .Select(l => l.Trim())
                .Where(l => l.StartsWith('|') && !l.Contains("---", StringComparison.Ordinal))
                .Skip(1)
        ];
    }

    private static string[] Cells(string row) =>
        [.. row.Trim('|').Split('|').Select(c => c.Trim())];

    private static string Read() =>
        File.ReadAllText(Path.Combine(RepositoryLocation.Root(), Document.Replace('/', Path.DirectorySeparatorChar)));
}
