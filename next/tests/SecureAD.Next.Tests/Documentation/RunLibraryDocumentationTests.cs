using System.Reflection;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/layers/evidence/how-a-bundle-is-read.md</c> to <see cref="RunLibrary"/>,
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
/// This page owns <see cref="RunState"/> all the same: the enum is declared here because the
/// listing carries it, while what each member means is explained there. Owning a type and
/// explaining it are different things, and the register tracks the first.
/// </para>
/// <para>
/// <b>Mutation-tested 2026-08-24 by <c>next/tools/mutate-run-library-doc-gates.ps1</c>, eleven
/// mutations, all killed; six touched files verified byte-identical by hash.</b> Three were aimed
/// here. Dropping the <c>RunScope</c> row is killed by
/// <see cref="TheTypesTableAndTheComponentAgree"/> and by
/// <c>TypesTableOwnershipTests.EveryClaimedTypeIsRegisteredToThePageThatClaimsIt</c>. Removing
/// <c>RunScope.cs</c> from the page's own header is killed by
/// <see cref="TheDocumentNamesTheSourceFilesItClaimsFrom"/>, which is what stops the stated
/// component and the checked component being two different things. Adding an eighth public type
/// to one of the named files is killed by three checks at once, including
/// <c>SurfaceRegisterTests.EveryPublicTypeIsInTheRegister</c>.
/// </para>
/// <para>
/// <b><see cref="EveryTypeTheScanFindsIsOneTheCompilerExports"/> fired on none of the eleven</b>,
/// and that is what it is for rather than a hole: the mutation adds a type to the source and the
/// assembly is rebuilt, so the compiler does export it. It guards the scan drifting away from the
/// compiler, which no edit to these files can simulate.
/// </para>
/// </remarks>
public sealed class RunLibraryDocumentationTests
{
    private const string Document = "docs/layers/evidence/how-a-bundle-is-read.md";

    /// <summary>
    /// The files this page's <c>Code:</c> header names, and the only files it may claim a type
    /// from. <c>RunCompletionReader.cs</c> is one of them and declares nothing public, which is the
    /// case worth keeping in the list rather than out of it: dropping it would let a public type
    /// appear there unnoticed.
    /// </summary>
    private static readonly string[] SourceFiles =
    [
        "RunLibrary.cs",
        "RunStateNames.cs",
        "RunCompletionReader.cs",
        "RunListing.cs",
        "RunState.cs",
        "RunMoment.cs",
        "RunScope.cs",
    ];

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

    /// <summary>
    /// The <c>TYPES</c> table and the component agree, in both directions.
    /// </summary>
    /// <remarks>
    /// <b>The component is scoped from the files the page's own header names, not from a
    /// namespace.</b> <c>SecureAD.Evidence.Run</c> also holds the coverage records and the
    /// comparability verdict, which other pages own, so a namespace filter would have this page
    /// claim them. A hardcoded list of six would be worse: it would be the table restated, so a
    /// seventh public type added beside <see cref="RunScope"/> would be invisible to the check
    /// meant to notice it.
    /// </remarks>
    [Fact]
    public void TheTypesTableAndTheComponentAgree()
    {
        var documented = FirstColumn("TYPES").ToHashSet(StringComparer.Ordinal);
        var actual = DeclaredPublicTypeNames().ToHashSet(StringComparer.Ordinal);

        var unclaimed = actual.Except(documented).OrderBy(n => n, StringComparer.Ordinal).ToList();
        var invented = documented.Except(actual).OrderBy(n => n, StringComparer.Ordinal).ToList();

        Assert.True(
            unclaimed.Count == 0 && invented.Count == 0,
            $"The TYPES table in {Document} disagrees with the files its header names. Declared "
            + $"but not claimed: {Describe(unclaimed)}. Claimed but not declared: "
            + $"{Describe(invented)}. A type owned by no page is how the area files came to be the "
            + "only record of anything.");
    }

    /// <summary>
    /// The page names every file it claims a type from, and every one of them is there. Without
    /// this the list above could name a file the document never mentions, and the page's stated
    /// component and its checked component would be two different things.
    /// </summary>
    [Fact]
    public void TheDocumentNamesTheSourceFilesItClaimsFrom()
    {
        var text = Read();

        Assert.Contains(
            "next/src/SecureAD.Evidence/Run/RunLibrary.cs", text, StringComparison.Ordinal);

        foreach (var file in SourceFiles)
        {
            Assert.Contains(file, text, StringComparison.Ordinal);
            Assert.True(File.Exists(SourcePath(file)), $"Expected the component at {SourcePath(file)}.");
        }
    }

    /// <summary>
    /// The source scan agrees with the compiler. A regex that has drifted from what the compiler
    /// sees would quietly narrow the set the check above compares, and narrowing it is how a check
    /// comes to pass while measuring less than its name.
    /// </summary>
    [Fact]
    public void EveryTypeTheScanFindsIsOneTheCompilerExports()
    {
        var exported = typeof(RunLibrary).Assembly
            .GetExportedTypes()
            .Select(t => t.Name)
            .ToHashSet(StringComparer.Ordinal);

        var unknown = DeclaredPublicTypeNames()
            .Where(name => !exported.Contains(name))
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            unknown.Count == 0,
            $"The source scan found types SecureAD.Evidence does not export: {Describe(unknown)}. "
            + "The scan has drifted from the compiler.");
    }

    /// <summary>
    /// The scanner self-test for the two checks above. Without it both pass by scanning no files,
    /// comparing two empty sets, and finding nothing wrong with either.
    /// </summary>
    /// <remarks>
    /// It asserts no floor on the number of pages or rows anywhere else in the tree, only that
    /// this component is the size the page says and that one file in the list genuinely declares
    /// nothing - which is the case a looser scan would silently absorb.
    /// </remarks>
    [Fact]
    public void TheCheckFindsTheDocumentAndEveryFileOfTheComponent()
    {
        Assert.True(Read().Length > 1000, $"{Document} is too short to be the document it claims.");
        Assert.NotEmpty(FirstColumn("TYPES"));

        var declared = DeclaredPublicTypeNames().ToList();

        Assert.Equal(6, declared.Count);
        Assert.Contains(nameof(RunListing), declared);
        Assert.Contains(nameof(RunScope), declared);

        Assert.Empty(DeclaredPublicTypeNamesIn("RunCompletionReader.cs"));
    }

    // --- helpers -----------------------------------------------------------------------------------

    private static string Explain(List<string> problems) =>
        $"{Document} and the code disagree:" + Environment.NewLine
        + string.Join(Environment.NewLine, problems);

    private static string Describe(List<string> names) =>
        names.Count == 0 ? "none" : string.Join(", ", names);

    /// <summary>
    /// The public types declared in the component's own files, read from those files.
    /// </summary>
    private static IEnumerable<string> DeclaredPublicTypeNames() =>
        SourceFiles.SelectMany(DeclaredPublicTypeNamesIn);

    private static IEnumerable<string> DeclaredPublicTypeNamesIn(string file)
    {
        foreach (var line in File.ReadAllLines(SourcePath(file)))
        {
            if (!line.StartsWith("public ", StringComparison.Ordinal))
                continue;

            var words = line.Split(
                [' ', '(', '<', '{'], StringSplitOptions.RemoveEmptyEntries);

            var keyword = Array.FindIndex(
                words, w => w is "record" or "class" or "enum" or "struct" or "interface");

            if (keyword >= 0 && keyword + 1 < words.Length)
                yield return words[keyword + 1];
        }
    }

    private static string SourcePath(string file) =>
        Path.Combine(
            RepositoryLocation.Root(), "next", "src", "SecureAD.Evidence", "Run", file);

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
