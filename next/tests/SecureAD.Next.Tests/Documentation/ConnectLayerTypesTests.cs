using SecureAD.Audit.Connect;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds the two Connect layer documents to the source files each one names, so their
/// <c>TYPES</c> tables are held to the code rather than only to the surface register.
/// </summary>
/// <remarks>
/// <para>
/// Written when the area file the-new-audit-wizard.md was reduced to its shell content. Giving
/// these two pages a <c>TYPES</c> table moved 30 register rows: 3 wizard types and 16 others to
/// <c>how-the-forest-is-found.md</c>, and 2 wizard types with 7 others to
/// <c>what-preflight-proves.md</c>. Twenty-three of those thirty came out of the area file
/// <c>which-controller-we-read</c>, which fell from 34 governed types to 11.
/// </para>
/// <para>
/// <b>Each component is scoped from the files its own page names, not from a namespace.</b>
/// <c>SecureAD.Audit.Connect</c> holds both components and more besides, so a namespace filter
/// would have each page claim the other's types. A hardcoded list would be the page's table
/// restated, so a new public type would be invisible to the check meant to notice it.
/// </para>
/// <para>
/// <b>Two files named by these pages declare nothing public and are kept in the lists anyway:</b>
/// <c>ForestPartitions.cs</c> and <c>PreflightDispatch.cs</c>. Dropping them would let a public
/// type appear there unnoticed, which is the case worth guarding rather than tidying away.
/// <see cref="TheFilesThatDeclareNothingStillDeclareNothing"/> holds that.
/// </para>
/// <para>
/// <b>Mutation-tested 2026-08-24 by <c>next/tools/mutate-wizard-doc-gates.ps1</c>, six directions,
/// all killed; five touched files verified byte-identical by hash.</b> Dropping the
/// <c>DomainSelection</c> row and dropping the <c>NamedControllerAnswer</c> row are each killed by
/// this class and by <c>TypesTableOwnershipTests</c>. Adding a public type to
/// <c>ForestPartitions.cs</c> - a file both this class and the page say declares nothing - is
/// killed by four checks at once, including
/// <c>SurfaceRegisterTests.EveryPublicTypeIsInTheRegister</c>.
/// </para>
/// <para>
/// <b><see cref="EveryTypeTheScanFindsIsOneTheCompilerExports"/> and
/// <see cref="EachPageNamesEveryFileItsComponentIsScopedFrom"/> fired on none of the six.</b> The
/// first cannot be reached by editing these files, because the assembly is rebuilt and the compiler
/// does then export whatever was added; it guards the scan drifting from the compiler. The second
/// was not exercised by this harness and is stated here rather than claimed as observed.
/// </para>
/// </remarks>
public sealed class ConnectLayerTypesTests
{
    private static readonly string[] ForestFiles =
    [
        "ForestBootstrap.cs", "MachineDomain.cs", "MachineAddresses.cs", "ForestDiscovery.cs",
        "ForestPartitions.cs", "ForestTopology.cs", "ForestRoles.cs", "OperatorSite.cs",
        "ControllerSelection.cs", "ForestPlan.cs", "PlanPreview.cs",
    ];

    private static readonly string[] PreflightFiles =
    [
        "Preflight.cs", "PreflightDispatch.cs", "DomainPreflightRead.cs", "PreflightReport.cs",
        "PreflightFile.cs", "NamedControllerCheck.cs", "CaptureSession.cs",
    ];

    [Fact]
    public void TheForestPageTypesTableAndItsComponentAgree()
    {
        AssertTableMatchesFiles("how-the-forest-is-found.md", ForestFiles);
    }

    [Fact]
    public void ThePreflightPageTypesTableAndItsComponentAgree()
    {
        AssertTableMatchesFiles("what-preflight-proves.md", PreflightFiles);
    }

    /// <summary>
    /// Each page names every file its component is scoped from. Without this the lists above could
    /// name a file the document never mentions, and the page's stated component and its checked
    /// component would be two different things.
    /// </summary>
    [Fact]
    public void EachPageNamesEveryFileItsComponentIsScopedFrom()
    {
        var wrong = new List<string>();

        foreach (var (document, files) in Pages())
        {
            var text = Read(document);

            foreach (var file in files)
            {
                if (!text.Contains(file, StringComparison.Ordinal))
                    wrong.Add($"  {document} is scoped from {file} and does not name it");

                if (!File.Exists(SourcePath(file)))
                    wrong.Add($"  {document} names {file}, which is not at {SourcePath(file)}");
            }
        }

        Assert.True(wrong.Count == 0, string.Join(Environment.NewLine, wrong));
    }

    /// <summary>
    /// The two files that contribute no row still contribute none. Each page says so in writing, so
    /// a public type appearing in either would make the page wrong as well as the table.
    /// </summary>
    [Fact]
    public void TheFilesThatDeclareNothingStillDeclareNothing()
    {
        Assert.Empty(DeclaredPublicTypeNames("ForestPartitions.cs"));
        Assert.Empty(DeclaredPublicTypeNames("PreflightDispatch.cs"));
    }

    /// <summary>
    /// The source scan agrees with the compiler, so a regex that has drifted from what the compiler
    /// sees fails rather than quietly narrowing the sets compared above.
    /// </summary>
    [Fact]
    public void EveryTypeTheScanFindsIsOneTheCompilerExports()
    {
        var exported = typeof(ForestPlan).Assembly
            .GetExportedTypes()
            .Select(t => t.Name)
            .ToHashSet(StringComparer.Ordinal);

        var unknown = ForestFiles.Concat(PreflightFiles)
            .SelectMany(DeclaredPublicTypeNames)
            .Where(name => !exported.Contains(name))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            unknown.Count == 0,
            $"The source scan found types SecureAD.Audit does not export: {Describe(unknown)}.");
    }

    /// <summary>
    /// The scanner self-test. Without it every check above passes by reading no files, comparing
    /// empty sets, and finding nothing wrong with either page.
    /// </summary>
    /// <remarks>
    /// It asserts the size of each component because those are the two figures this pass turned on
    /// and getting either wrong is how the table comes to describe a component nobody scoped. They
    /// are not thresholds to be raised when a gate goes red: a change to either means a type was
    /// added or removed, and the table must change with it.
    /// </remarks>
    [Fact]
    public void TheCheckReadsBothDocumentsAndBothComponents()
    {
        Assert.Equal(19, ForestFiles.SelectMany(DeclaredPublicTypeNames).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(10, PreflightFiles.SelectMany(DeclaredPublicTypeNames).Distinct(StringComparer.Ordinal).Count());

        Assert.NotEmpty(FirstColumn("how-the-forest-is-found.md", "TYPES"));
        Assert.NotEmpty(FirstColumn("what-preflight-proves.md", "TYPES"));

        Assert.Contains(nameof(DomainSelection), FirstColumn("how-the-forest-is-found.md", "TYPES"));
        Assert.Contains(nameof(NamedControllerAnswer), FirstColumn("what-preflight-proves.md", "TYPES"));
    }

    // --- helpers -----------------------------------------------------------------------------------

    private static List<(string Document, string[] Files)> Pages() =>
    [
        ("how-the-forest-is-found.md", ForestFiles),
        ("what-preflight-proves.md", PreflightFiles),
    ];

    private static void AssertTableMatchesFiles(string document, string[] files)
    {
        var documented = FirstColumn(document, "TYPES").ToHashSet(StringComparer.Ordinal);
        var actual = files.SelectMany(DeclaredPublicTypeNames).ToHashSet(StringComparer.Ordinal);

        var unclaimed = actual.Except(documented).OrderBy(n => n, StringComparer.Ordinal).ToList();
        var invented = documented.Except(actual).OrderBy(n => n, StringComparer.Ordinal).ToList();

        Assert.True(
            unclaimed.Count == 0 && invented.Count == 0,
            $"The TYPES table in {document} disagrees with the files its header names. Declared but "
            + $"not claimed: {Describe(unclaimed)}. Claimed but not declared: {Describe(invented)}. "
            + "A type owned by no page is how the area files came to be the only record of anything.");
    }

    private static string Describe(List<string> names) =>
        names.Count == 0 ? "none" : string.Join(", ", names);

    private static IEnumerable<string> DeclaredPublicTypeNames(string file)
    {
        foreach (var line in File.ReadAllLines(SourcePath(file)))
        {
            if (!line.StartsWith("public ", StringComparison.Ordinal))
                continue;

            var words = line.Split([' ', '(', '<', '{'], StringSplitOptions.RemoveEmptyEntries);

            var keyword = Array.FindIndex(
                words, w => w is "record" or "class" or "enum" or "struct" or "interface");

            if (keyword >= 0 && keyword + 1 < words.Length)
                yield return words[keyword + 1];
        }
    }

    private static List<string> FirstColumn(string document, string marker) =>
        [.. TableRows(document, marker).Select(r => r.Trim('|').Split('|')[0].Trim().Trim('`'))];

    private static List<string> TableRows(string document, string marker)
    {
        var text = Read(document);
        var begin = text.IndexOf($"<!-- {marker}:BEGIN -->", StringComparison.Ordinal);
        var end = text.IndexOf($"<!-- {marker}:END -->", StringComparison.Ordinal);

        Assert.True(begin >= 0 && end > begin, $"{document} has no {marker} table.");

        return
        [
            .. text[begin..end]
                .Split('\n')
                .Select(l => l.Trim())
                .Where(l => l.StartsWith('|') && !l.Contains("---", StringComparison.Ordinal))
                .Skip(1)
        ];
    }

    private static string SourcePath(string file) =>
        Path.Combine(RepositoryLocation.Root(), "next", "src", "SecureAD.Audit", "Connect", file);

    private static string Read(string document) =>
        File.ReadAllText(
            Path.Combine(RepositoryLocation.Root(), "docs", "layers", "connect", document));
}
