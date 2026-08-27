using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds each shell layer document to the source files it names, so their <c>TYPES</c> tables are
/// held to the code.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the device <c>P-56</c> asked for.</b> Every other layer document is held to
/// <c>SURFACE-REGISTER.md</c> by <see cref="Architecture.TypesTableOwnershipTests"/>, and that
/// register is keyed to the <i>exported</i> types of the production assemblies. The shell exports
/// nothing by design - <see cref="Architecture.ShellSurfaceGateTests"/> fails the build the day it
/// does - so a register-based check can never say anything about a shell page, and the area file
/// <c>the-new-audit-wizard.md</c> could not be deleted for as long as that was the only device.
/// </para>
/// <para>
/// <b>So the anchor is visibility read from the source, not membership of the register.</b> The
/// scan reads <c>internal</c> declarations, which is the departure from
/// <see cref="ConnectLayerTypesTests"/>; everything else about the technique is the same, because a
/// second technique invented beside a working one drifts from it.
/// </para>
/// <para>
/// <b>The scan being wrong in the quiet direction is the risk worth guarding.</b> A scanner that
/// filtered on the wrong keyword would find no types at all, compare an empty set against a table
/// nobody checked, and report that nothing is wrong - which is the failure this repository has
/// committed three times. <see cref="TheScanReadsInternalDeclarationsAndNotPublicOnes"/> is the
/// discriminator: it proves the scan finds a type the compiler does <i>not</i> export.
/// </para>
/// <para>
/// <b>Which screens exist is <see cref="ShellSection"/>,</b> and a member is added there only when
/// the screen behind it can answer for itself. This class grows a page at a time as that enum does,
/// rather than assuming the shell is finished at two screens.
/// </para>
/// <para>
/// <b>Mutation-tested 2026-08-24 by <c>next/tools/mutate-shell-doc-gates.ps1</c>, five directions,
/// all killed; three touched files verified byte-identical by hash.</b> Dropping a row from either
/// page's table is killed by that page's check and by
/// <see cref="TheCheckReadsBothDocumentsAndBothComponents"/>. Removing a file from a page's header
/// is killed by <see cref="EachPageNamesEveryFileItsComponentIsScopedFrom"/> alone. A shell page
/// claiming a type the register already holds is killed by
/// <c>TypesTableOwnershipTests.TheShellExemptionCoversOnlyTypesTheRegisterCannotHold</c>, which is
/// the one that matters: it is what stops the shell exemption hiding a real disagreement.
/// </para>
/// <para>
/// <b>The fifth mutation was killed by the compiler rather than by any gate, and that is worth
/// saying plainly.</b> Making <c>NewAuditViewModel</c> public fails the build with an accessibility
/// error before a test runs, because a public type cannot expose internal ones. So neither
/// <see cref="TheScanReadsInternalDeclarationsAndNotPublicOnes"/> nor
/// <see cref="Architecture.ShellSurfaceGateTests"/> was exercised by it. Both are stated here as
/// reasoning rather than claimed as observed, and the honest position is that the shell growing a
/// surface is guarded first by the compiler and only then by those two.
/// <see cref="AMissingTableIsAFailureRatherThanAnEmptyScan"/> fired on none of the five; it guards
/// the parser, which no edit to these files reaches.
/// </para>
/// <para>
/// <b>The assets page was mutation-tested on the day it was added, three directions, all killed.</b>
/// Dropping the <c>ObjectPaging</c> row from its table failed
/// <see cref="TheAssetsPageTypesTableAndItsComponentAgree"/>, naming the type. Removing
/// <c>FactState.cs</c> from the page's header failed
/// <see cref="EachPageNamesEveryFileItsComponentIsScopedFrom"/>, naming the file. Removing
/// <c>BundleAssetSource.cs</c> from <see cref="AssetsFiles"/> failed two tests including
/// <see cref="TheCheckReadsBothDocumentsAndBothComponents"/>, which is the one worth having: it
/// proves the component count is measuring the component rather than agreeing with whatever the
/// scan happened to find.
/// </para>
/// </remarks>
public sealed class ShellLayerTypesTests
{
    private static readonly string[] NewAuditFiles =
    [
        "ViewModels/NewAuditViewModel.cs",
        "ViewModels/AuditRowViewModel.cs",
        "ViewModels/ExcludedDomainViewModel.cs",
        "ViewModels/ExclusionAttestationViewModel.cs",
        "ViewModels/DomainDetailsViewModel.cs",
        "Services/AuditPlan.cs",
        "Services/AuditReview.cs",
        "Services/ExclusionAttestation.cs",
        "Services/INewAuditDialog.cs",
        "Services/NewAuditDialog.cs",
        "Services/IJudgingLauncher.cs",
        "Services/JudgingLauncher.cs",
        "Services/IDerivationLauncher.cs",
        "Services/DerivationLauncher.cs",
    ];

    /// <summary>
    /// The assets screen's component, which is the largest in the shell.
    /// </summary>
    /// <remarks>
    /// <b>One page, because <see cref="ShellSection"/> has one member for it.</b> The objects, the
    /// findings and an opened object are all <c>Assets</c>: an object is opened from the grid rather
    /// than navigated to. Splitting them across pages would invent a second rule for what a shell
    /// page is, beside the one this class already states.
    /// <para>
    /// <b>Added 2026-08-26, closing <c>P-100</c>.</b> Until then this screen had no layer document,
    /// so this gate bound none of its types - and the findings grid, the navigation to an object and
    /// the filters over it were all built with nothing holding them.
    /// </para>
    /// </remarks>
    private static readonly string[] AssetsFiles =
    [
        "ViewModels/AssetsViewModel.cs",
        "ViewModels/AssetRowViewModels.cs",
        "ViewModels/ObjectViewModel.cs",
        "ViewModels/ObjectSections.cs",
        "ViewModels/ObjectSectionCatalog.cs",
        "ViewModels/FactState.cs",
        "Services/IAssetSource.cs",
        "Services/BundleAssetSource.cs",
    ];

    private static readonly string[] HomeFiles =
    [
        "ViewModels/HomeViewModel.cs",
        "ViewModels/RunLibraryViewModel.cs",
        "ViewModels/RunSummaryViewModel.cs",
        "Settings/IShellSettingsStore.cs",
        "Settings/JsonShellSettingsStore.cs",
        "Settings/RunLibraryLocation.cs",
        "Settings/ShellSettings.cs",
        "Services/IRunCatalog.cs",
        "Services/RunCatalog.cs",
    ];

    [Fact]
    public void TheNewAuditPageTypesTableAndItsComponentAgree()
    {
        AssertTableMatchesFiles("the-new-audit-screen.md", NewAuditFiles);
    }

    [Fact]
    public void TheHomePageTypesTableAndItsComponentAgree()
    {
        AssertTableMatchesFiles("the-home-screen.md", HomeFiles);
    }

    [Fact]
    public void TheAssetsPageTypesTableAndItsComponentAgree()
    {
        AssertTableMatchesFiles("the-assets-screen.md", AssetsFiles);
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
                var name = file.Split('/')[^1];

                if (!text.Contains(name, StringComparison.Ordinal))
                    wrong.Add($"  {document} is scoped from {file} and does not name it");

                if (!File.Exists(SourcePath(file)))
                    wrong.Add($"  {document} names {file}, which is not at {SourcePath(file)}");
            }
        }

        Assert.True(wrong.Count == 0, string.Join(Environment.NewLine, wrong));
    }

    /// <summary>
    /// The discriminator. The scan must read <c>internal</c> declarations, and the proof is that it
    /// finds types the compiler does not export: the shell exports nothing, so every type it finds
    /// is one an exported-types check would have missed.
    /// </summary>
    [Fact]
    public void TheScanReadsInternalDeclarationsAndNotPublicOnes()
    {
        var found = Pages().SelectMany(p => p.Files).SelectMany(DeclaredTypeNames).ToList();

        Assert.NotEmpty(found);

        var exported = typeof(ShellViewModel).Assembly
            .GetExportedTypes()
            .Select(t => t.Name)
            .ToHashSet(StringComparer.Ordinal);

        var alsoExported = found.Where(exported.Contains).ToList();

        Assert.True(
            alsoExported.Count == 0,
            "The shell exports nothing, so no type this scan finds should appear in the assembly's "
            + $"exported set. These did, which means either the shell has grown a public surface or "
            + $"the scan is reading the wrong thing: {string.Join(", ", alsoExported)}.");

        // And every name really is a type the compiler emitted, so the scan has not drifted into
        // matching prose.
        var emitted = typeof(ShellViewModel).Assembly
            .GetTypes()
            .Select(t => t.Name)
            .ToHashSet(StringComparer.Ordinal);

        var phantom = found.Where(n => !emitted.Contains(n)).Distinct(StringComparer.Ordinal).ToList();

        Assert.True(
            phantom.Count == 0,
            $"The scan found names the compiler did not emit: {string.Join(", ", phantom)}.");
    }

    /// <summary>
    /// The scanner self-test. Without it every check above passes by reading no files, comparing
    /// empty sets, and finding nothing wrong with either page.
    /// </summary>
    /// <remarks>
    /// It asserts the size of each component, because those are the figures this pass turned on and
    /// getting one wrong is how a table comes to describe a component nobody scoped. They are not
    /// thresholds to be raised when a gate goes red: a change to either means a type was added or
    /// removed, and the table must change with it.
    /// </remarks>
    [Fact]
    public void TheCheckReadsBothDocumentsAndBothComponents()
    {
        Assert.Equal(30, NewAuditFiles.SelectMany(DeclaredTypeNames).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(9, HomeFiles.SelectMany(DeclaredTypeNames).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(29, AssetsFiles.SelectMany(DeclaredTypeNames).Distinct(StringComparer.Ordinal).Count());

        foreach (var (document, _) in Pages())
        {
            Assert.True(File.Exists(PathTo(document)), $"Expected the layer document at {PathTo(document)}.");
            Assert.NotEmpty(FirstColumn(document, "TYPES"));
        }

        Assert.Contains(nameof(NewAuditViewModel), FirstColumn("the-new-audit-screen.md", "TYPES"));
        Assert.Contains(nameof(HomeViewModel), FirstColumn("the-home-screen.md", "TYPES"));
        Assert.Contains(nameof(AssetsViewModel), FirstColumn("the-assets-screen.md", "TYPES"));
    }

    /// <summary>
    /// A marker block that is not there is a failure and never an empty result.
    /// </summary>
    [Fact]
    public void AMissingTableIsAFailureRatherThanAnEmptyScan()
    {
        var thrown = Record.Exception(() => TableRows("the-home-screen.md", "SHAPE"));

        Assert.NotNull(thrown);
    }

    // --- helpers -----------------------------------------------------------------------------------

    private static List<(string Document, string[] Files)> Pages() =>
    [
        ("the-new-audit-screen.md", NewAuditFiles),
        ("the-home-screen.md", HomeFiles),
        ("the-assets-screen.md", AssetsFiles),
    ];

    private static void AssertTableMatchesFiles(string document, string[] files)
    {
        var documented = FirstColumn(document, "TYPES").ToHashSet(StringComparer.Ordinal);
        var actual = files.SelectMany(DeclaredTypeNames).ToHashSet(StringComparer.Ordinal);

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

    /// <summary>
    /// The types declared in one shell file. Both <c>internal</c> and <c>public</c> are read, so a
    /// type that gained a public modifier would still be compared rather than silently dropped out
    /// of the set; <see cref="TheScanReadsInternalDeclarationsAndNotPublicOnes"/> is what notices
    /// that it happened.
    /// </summary>
    private static IEnumerable<string> DeclaredTypeNames(string file)
    {
        foreach (var line in File.ReadAllLines(SourcePath(file)))
        {
            if (!line.StartsWith("internal ", StringComparison.Ordinal)
                && !line.StartsWith("public ", StringComparison.Ordinal))
                continue;

            var words = line.Split([' ', '(', '<', '{', ':'], StringSplitOptions.RemoveEmptyEntries);

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
            RepositoryLocation.Root(), "next", "src", "SecureAD.Shell",
            file.Replace('/', Path.DirectorySeparatorChar));

    private static string PathTo(string document) =>
        Path.Combine(RepositoryLocation.Root(), "docs", "layers", "shell", document);

    private static string Read(string document) => File.ReadAllText(PathTo(document));
}
