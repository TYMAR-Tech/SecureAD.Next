using SecureAD.Audit.Connect;
using SecureAD.Evidence;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds each Connect layer document to the source files it names, so their <c>TYPES</c> tables are
/// held to the code rather than only to the surface register.
/// </summary>
/// <remarks>
/// <para>
/// Written when the area file the-new-audit-wizard.md was reduced to its shell content. Giving
/// <c>how-the-forest-is-found.md</c> and <c>what-preflight-proves.md</c> a <c>TYPES</c> table moved
/// 30 register rows, 23 of them out of the area file <c>which-controller-we-read</c>, which fell
/// from 34 governed types to 11.
/// </para>
/// <para>
/// <b>Extended to the remaining two Connect pages when that area file was deleted.</b>
/// <c>the-connection-ladder.md</c> took 7 types and <c>how-a-connection-is-opened.md</c> took 4,
/// which was the last 11 and the reason the file could go. All four pages are checked here rather
/// than in a second class, because a second parser written beside this one drifts from it.
/// </para>
/// <para>
/// <b>Each component is scoped from the files its own page names, not from a namespace.</b>
/// <c>SecureAD.Audit.Connect</c> holds all four components and more besides, so a namespace filter
/// would have each page claim the others' types. A hardcoded list would be the page's table
/// restated, so a new public type would be invisible to the check meant to notice it.
/// </para>
/// <para>
/// <b>Files are written project-first because one page names a file from another library.</b>
/// <c>ConnectionSecurityLevel.cs</c> compiles into <c>SecureAD.Evidence</c> and is described on the
/// ladder page, since the four names it declares are the four rows of that page's ladder table.
/// </para>
/// <para>
/// <b>Three files named by these pages declare nothing public and are kept in the lists anyway:</b>
/// <c>ForestPartitions.cs</c>, <c>PreflightDispatch.cs</c> and <c>ConnectionFailureReason.cs</c>.
/// Dropping them would let a public type appear there unnoticed, which is the case worth guarding
/// rather than tidying away. <see cref="TheFilesThatDeclareNothingStillDeclareNothing"/> holds that.
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
/// <b>Mutation-tested again 2026-08-24 by <c>next/tools/mutate-connection-doc-gates.ps1</c> when
/// the ladder and channel pages were added, five directions, all killed; four touched files
/// verified byte-identical.</b> Dropping the <c>ConnectionSecurityLevel</c> row and dropping the
/// <c>LdapDirectoryChannel</c> row are each killed by this class and by
/// <c>TypesTableOwnershipTests.EveryClaimedTypeIsRegisteredToThePageThatClaimsIt</c>. Moving
/// <c>ConnectionSecurityLog</c>'s register row to the other connect page is killed by that
/// ownership check alone, which is the point of it: neither page's own table changed, so nothing
/// scoped from files could notice. Adding a public type to <c>ConnectionFailureReason.cs</c> is
/// killed by four checks including <see cref="TheFilesThatDeclareNothingStillDeclareNothing"/>.
/// Removing <c>ConnectionSecurityLevel.cs</c> from the ladder page's header is killed by
/// <see cref="EachPageNamesEveryFileItsComponentIsScopedFrom"/> alone, which is why that check is
/// separate from the table comparison.
/// </para>
/// <para>
/// <b><see cref="EveryTypeTheScanFindsIsOneTheCompilerExports"/> fired on none of the eleven.</b>
/// It cannot be reached by editing these files, because the assembly is rebuilt and the compiler
/// does then export whatever was added; it guards the scan drifting from the compiler. Nothing in
/// <c>AreaFileCitationSurvivalTests</c> fired either, and could not have: it reads deleted area
/// files out of git history, so it first sees a deletion once that deletion is committed.
/// </para>
/// </remarks>
public sealed class ConnectLayerTypesTests
{
    private static readonly string[] ForestFiles =
    [
        "SecureAD.Audit/Connect/ForestBootstrap.cs", "SecureAD.Audit/Connect/MachineDomain.cs",
        "SecureAD.Audit/Connect/MachineAddresses.cs", "SecureAD.Audit/Connect/ForestDiscovery.cs",
        "SecureAD.Audit/Connect/ForestPartitions.cs", "SecureAD.Audit/Connect/ForestTopology.cs",
        "SecureAD.Audit/Connect/ForestRoles.cs", "SecureAD.Audit/Connect/OperatorSite.cs",
        "SecureAD.Audit/Connect/ControllerSelection.cs", "SecureAD.Audit/Connect/ForestPlan.cs",
        "SecureAD.Audit/Connect/PlanPreview.cs",
    ];

    private static readonly string[] PreflightFiles =
    [
        "SecureAD.Audit/Connect/Preflight.cs", "SecureAD.Audit/Connect/PreflightDispatch.cs",
        "SecureAD.Audit/Connect/DomainPreflightRead.cs", "SecureAD.Audit/Connect/PreflightReport.cs",
        "SecureAD.Audit/Connect/PreflightFile.cs", "SecureAD.Audit/Connect/NamedControllerCheck.cs",
        "SecureAD.Audit/Connect/CaptureSession.cs",
    ];

    /// <summary>
    /// The ladder page's component. <c>ConnectionSecurityLevel.cs</c> compiles into
    /// <c>SecureAD.Evidence</c> rather than <c>SecureAD.Audit</c>, which is why every file here is
    /// written project-first: the page that describes a type is not always in the library that
    /// declares it.
    /// </summary>
    private static readonly string[] LadderFiles =
    [
        "SecureAD.Audit/Connect/ConnectionSecurityLadder.cs",
        "SecureAD.Audit/Connect/ConnectionLadderWalk.cs",
        "SecureAD.Audit/Connect/ConnectionSecurityLog.cs",
        "SecureAD.Audit/Connect/ConnectionFailureReason.cs",
        "SecureAD.Audit/Connect/UnprotectedConnectionAllowance.cs",
        "SecureAD.Evidence/ConnectionSecurityLevel.cs",
    ];

    private static readonly string[] ChannelFiles =
    [
        "SecureAD.Audit/Connect/LdapDirectoryChannelFactory.cs",
        "SecureAD.Audit/Connect/LdapDirectoryChannel.cs",
        "SecureAD.Audit/Connect/DirectoryConnectionSettings.cs",
        "SecureAD.Audit/Connect/DirectoryCredential.cs",
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

    [Fact]
    public void TheLadderPageTypesTableAndItsComponentAgree()
    {
        AssertTableMatchesFiles("the-connection-ladder.md", LadderFiles);
    }

    [Fact]
    public void TheChannelPageTypesTableAndItsComponentAgree()
    {
        AssertTableMatchesFiles("how-a-connection-is-opened.md", ChannelFiles);
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
    /// The three files that contribute no row still contribute none. Each page says so in writing,
    /// so a public type appearing in any of them would make the page wrong as well as the table.
    /// </summary>
    [Fact]
    public void TheFilesThatDeclareNothingStillDeclareNothing()
    {
        Assert.Empty(DeclaredPublicTypeNames("SecureAD.Audit/Connect/ForestPartitions.cs"));
        Assert.Empty(DeclaredPublicTypeNames("SecureAD.Audit/Connect/PreflightDispatch.cs"));
        Assert.Empty(DeclaredPublicTypeNames("SecureAD.Audit/Connect/ConnectionFailureReason.cs"));
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
            .Concat(typeof(ConnectionSecurityLevel).Assembly.GetExportedTypes())
            .Select(t => t.Name)
            .ToHashSet(StringComparer.Ordinal);

        var unknown = Pages()
            .SelectMany(p => p.Files)
            .SelectMany(DeclaredPublicTypeNames)
            .Where(name => !exported.Contains(name))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            unknown.Count == 0,
            "The source scan found types neither SecureAD.Audit nor SecureAD.Evidence exports: "
            + $"{Describe(unknown)}.");
    }

    /// <summary>
    /// The scanner self-test. Without it every check above passes by reading no files, comparing
    /// empty sets, and finding nothing wrong with either page.
    /// </summary>
    /// <remarks>
    /// It asserts the size of each of the four components, because those are the figures this work
    /// turned on and getting one wrong is how a table comes to describe a component nobody scoped.
    /// They are not thresholds to be raised when a gate goes red: a change to any of them means a
    /// type was added or removed, and the table must change with it.
    /// </remarks>
    [Fact]
    public void TheCheckReadsEveryDocumentAndEveryComponent()
    {
        Assert.Equal(19, ForestFiles.SelectMany(DeclaredPublicTypeNames).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(10, PreflightFiles.SelectMany(DeclaredPublicTypeNames).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(7, LadderFiles.SelectMany(DeclaredPublicTypeNames).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(4, ChannelFiles.SelectMany(DeclaredPublicTypeNames).Distinct(StringComparer.Ordinal).Count());

        foreach (var (document, _) in Pages())
            Assert.NotEmpty(FirstColumn(document, "TYPES"));

        Assert.Contains(nameof(DomainSelection), FirstColumn("how-the-forest-is-found.md", "TYPES"));
        Assert.Contains(nameof(NamedControllerAnswer), FirstColumn("what-preflight-proves.md", "TYPES"));
        Assert.Contains(nameof(ConnectionSecurityLevel), FirstColumn("the-connection-ladder.md", "TYPES"));
        Assert.Contains(nameof(LdapDirectoryChannel), FirstColumn("how-a-connection-is-opened.md", "TYPES"));
    }

    // --- helpers -----------------------------------------------------------------------------------

    private static List<(string Document, string[] Files)> Pages() =>
    [
        ("how-the-forest-is-found.md", ForestFiles),
        ("what-preflight-proves.md", PreflightFiles),
        ("the-connection-ladder.md", LadderFiles),
        ("how-a-connection-is-opened.md", ChannelFiles),
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
        Path.Combine(
            RepositoryLocation.Root(), "next", "src",
            file.Replace('/', Path.DirectorySeparatorChar));

    private static string Read(string document) =>
        File.ReadAllText(
            Path.Combine(RepositoryLocation.Root(), "docs", "layers", "connect", document));
}
