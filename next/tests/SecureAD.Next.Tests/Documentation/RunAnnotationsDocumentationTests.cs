using System.Reflection;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/layers/evidence/what-an-operator-writes-on-a-run.md</c> to
/// <see cref="RunAnnotations"/> and <see cref="RunAnnotation"/>.
/// </summary>
/// <remarks>
/// <para>
/// Written when the area file docs/areas/the-run-library.md was deleted on 2026-08-24. That file
/// owned nine register rows and no layer document claimed any of them; six went to
/// <c>docs/layers/evidence/how-a-bundle-is-read.md</c>, one to
/// <c>docs/layers/evidence/whether-two-runs-compare.md</c>, and these two here.
/// </para>
/// <para>
/// <b>Why these two are not on the page describing the listing that carries them.</b>
/// <see cref="RunListing"/> has an <c>Annotation</c> column, so the obvious home was
/// <c>how-a-bundle-is-read.md</c> beside the record. Everything else on that page is
/// <i>observed</i> - read off a directory, or out of a sealed database - and these two are
/// <i>written</i>, by a person, after the run finished, into a file deliberately outside the seal.
/// Putting a writer on a page called <i>how a bundle is read</i> would blur the one line this
/// component exists to hold. The cost is one more page than the rewrite would otherwise have, and
/// it is paid for by the area file going.
/// </para>
/// <para>
/// <b>The component is scoped from its one source file, not from a namespace.</b>
/// <c>SecureAD.Evidence.Run</c> also holds the library, the listing, the coverage records and the
/// comparability verdict, all owned elsewhere, so a namespace filter would have this page claim
/// them. A hardcoded pair would be worse: it would be the page's table restated, so a third public
/// type added to <c>RunAnnotations.cs</c> would be invisible to the check meant to notice it.
/// </para>
/// <para>
/// <b>Mutation-tested 2026-08-24 by <c>next/tools/mutate-run-library-doc-gates.ps1</c>, eleven
/// mutations across this class, <see cref="RunLibraryDocumentationTests"/> and
/// <see cref="RunComparabilityDocumentationTests"/>. Baseline 2311 passed, 0 failed; all six
/// touched files verified byte-identical by hash afterwards.</b> Four were aimed here and all four
/// were killed: dropping the <c>RunAnnotations</c> row, dropping the <c>Save</c> door, removing
/// the sentence that an annotation is not evidence, and emptying the <c>TYPES</c> table outright.
/// Only the last is killed by <c>TypesTableOwnershipTests.APageThatOpensATypesTableFillsIt</c>,
/// which is why that check is separate from the ownership one.
/// </para>
/// <para>
/// <b>Three checks here fired on nothing, and that is stated rather than hidden.</b>
/// <see cref="EveryTypeTheScanFindsIsOneTheCompilerExports"/> cannot be reached by editing these
/// files, because the assembly is rebuilt and the compiler does then export whatever was added; it
/// guards the scan drifting from the compiler, which no source edit simulates.
/// <see cref="AMissingTableIsAFailureRatherThanAnEmptyScan"/> guards the parser rather than the
/// document, and <see cref="ThePageNamesTheRefusalTheSavePathConstructs"/> was not exercised by
/// the harness - it is stated here rather than claimed as observed.
/// </para>
/// </remarks>
public sealed class RunAnnotationsDocumentationTests
{
    private const string Document = "what-an-operator-writes-on-a-run.md";

    /// <summary>The file this page claims from, and the only one it may claim from.</summary>
    private const string SourceFile = "RunAnnotations.cs";

    /// <summary>
    /// The <c>TYPES</c> table and the component agree, in both directions.
    /// </summary>
    [Fact]
    public void TheTypesTableAndTheComponentAgree()
    {
        var documented = FirstColumn("TYPES").ToHashSet(StringComparer.Ordinal);
        var actual = DeclaredPublicTypeNames().ToHashSet(StringComparer.Ordinal);

        var unclaimed = actual.Except(documented).OrderBy(n => n, StringComparer.Ordinal).ToList();
        var invented = documented.Except(actual).OrderBy(n => n, StringComparer.Ordinal).ToList();

        Assert.True(
            unclaimed.Count == 0 && invented.Count == 0,
            $"The TYPES table in {Document} disagrees with {SourceFile}. Declared but not claimed: "
            + $"{Describe(unclaimed)}. Claimed but not declared: {Describe(invented)}. A type owned "
            + "by no page is how the area files came to be the only record of anything.");
    }

    /// <summary>
    /// Every way a caller can reach this component has a row, and the table invents none. Both
    /// doors carry a rule that only this page states - that reading never writes, and that a save
    /// replaces rather than appends - so a third door arriving undocumented would arrive with no
    /// rule attached.
    /// </summary>
    [Fact]
    public void TheDoorsTableAndTheClassAgree()
    {
        var documented = FirstColumn("DOORS").ToHashSet(StringComparer.Ordinal);
        var actual = PublicDoors().ToHashSet(StringComparer.Ordinal);

        var missing = actual.Except(documented).OrderBy(n => n, StringComparer.Ordinal).ToList();
        var invented = documented.Except(actual).OrderBy(n => n, StringComparer.Ordinal).ToList();

        Assert.True(
            missing.Count == 0 && invented.Count == 0,
            $"The DOORS table in {Document} disagrees with {nameof(RunAnnotations)}. Public and "
            + $"undocumented: {Describe(missing)}. Documented and not public: {Describe(invented)}.");
    }

    /// <summary>
    /// The refusal the save path reports is the one the page would send an operator looking for.
    /// It is the only literal error code on the page.
    /// </summary>
    [Fact]
    public void ThePageNamesTheRefusalTheSavePathConstructs()
    {
        var source = File.ReadAllText(SourcePath());

        Assert.Contains("\"RunAnnotationNotSaved\"", source, StringComparison.Ordinal);
    }

    /// <summary>
    /// The page states where the component lands, and it is there.
    /// </summary>
    [Fact]
    public void TheDocumentNamesTheSourceFileItDescribes()
    {
        var text = Read();

        Assert.Contains(
            "next/src/SecureAD.Evidence/Run/RunAnnotations.cs", text, StringComparison.Ordinal);

        Assert.True(File.Exists(SourcePath()), $"Expected the component at {SourcePath()}.");
    }

    /// <summary>
    /// The annotation is described as something a person wrote and not as something the run
    /// observed. This is the one claim on the page a customer's security decision could rest on
    /// being wrong about, so it is held rather than left to prose review.
    /// </summary>
    /// <remarks>
    /// It asks whether the sentence is there, which is weaker than asking whether the product
    /// behaves that way. What makes the behaviour true is that the sidecar is a separate file
    /// outside the seal, and <c>RunAnnotationsTests.AnnotatingLeavesTheSealedEvidenceUntouched</c>
    /// is what proves it.
    /// </remarks>
    [Fact]
    public void ThePageSaysAnAnnotationIsNotEvidence()
    {
        Assert.Contains("is not evidence", Read(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The source scan agrees with the compiler, so a regex that has drifted from what the
    /// compiler sees fails rather than quietly narrowing the set it compares.
    /// </summary>
    [Fact]
    public void EveryTypeTheScanFindsIsOneTheCompilerExports()
    {
        var exported = typeof(RunAnnotations).Assembly
            .GetExportedTypes()
            .Select(t => t.Name)
            .ToHashSet(StringComparer.Ordinal);

        var unknown = DeclaredPublicTypeNames()
            .Where(name => !exported.Contains(name))
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            unknown.Count == 0,
            $"The source scan found types SecureAD.Evidence does not export: {Describe(unknown)}.");
    }

    /// <summary>
    /// A marker block that is not there is a failure and never an empty result. A gate left
    /// pointing at a table that has moved must say so; two gates in this repository have already
    /// passed for months while measuring nothing.
    /// </summary>
    [Fact]
    public void AMissingTableIsAFailureRatherThanAnEmptyScan()
    {
        Assert.NotNull(Record.Exception(() => TableRows("STATES")));
    }

    /// <summary>
    /// The scanner self-test. Without it every check above passes by reading an empty string and
    /// comparing two empty sets, and finding nothing wrong with either.
    /// </summary>
    [Fact]
    public void TheCheckFindsTheDocumentAndTheComponent()
    {
        Assert.True(File.Exists(Path()), $"Expected the layer document at {Path()}.");
        Assert.True(Read().Length > 1000, $"{Document} is too short to be the document it claims.");

        Assert.NotEmpty(FirstColumn("TYPES"));
        Assert.NotEmpty(FirstColumn("DOORS"));

        var declared = DeclaredPublicTypeNames().ToList();

        Assert.Equal(2, declared.Count);
        Assert.Contains(nameof(RunAnnotation), declared);
        Assert.Contains(nameof(RunAnnotations), declared);
    }

    /// <summary>
    /// The type check is not satisfied by a name that merely contains the type's name, which is
    /// the failure mutation-testing found in the equivalent guard in session S-2.
    /// </summary>
    [Fact]
    public void TheCheckIsNotSatisfiedByANameThatMerelyContainsTheTypeName()
    {
        Assert.DoesNotContain(nameof(RunAnnotation) + "XX", FirstColumn("TYPES"));
        Assert.Contains(nameof(RunAnnotation), FirstColumn("TYPES"));
    }

    // --- helpers -----------------------------------------------------------------------------------

    private static string Describe(List<string> names) =>
        names.Count == 0 ? "none" : string.Join(", ", names);

    private static List<string> PublicDoors() =>
        [.. typeof(RunAnnotations)
            .GetMembers(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)
            .Where(m => m.MemberType is MemberTypes.Method or MemberTypes.Property)
            .Where(m => m is not MethodInfo { IsSpecialName: true })
            .Select(m => m.Name)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(n => n, StringComparer.Ordinal)];

    private static IEnumerable<string> DeclaredPublicTypeNames()
    {
        foreach (var line in File.ReadAllLines(SourcePath()))
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

    private static string Path() =>
        System.IO.Path.Combine(RepositoryLocation.Root(), "docs", "layers", "evidence", Document);

    private static string SourcePath() =>
        System.IO.Path.Combine(
            RepositoryLocation.Root(), "next", "src", "SecureAD.Evidence", "Run", SourceFile);

    private static string Read() => File.ReadAllText(Path());
}
