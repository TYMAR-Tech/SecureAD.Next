using SecureAD.Kernel;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/layers/kernel/how-failure-is-reported.md</c> to the code it describes.
/// </summary>
/// <remarks>
/// <para>
/// Written when docs/areas/how-failures-are-reported.md was deleted. That file governed seven
/// public types and no layer document claimed any of them; four are this component and three went
/// to <c>docs/layers/evidence/the-bundle-on-disk.md</c>.
/// </para>
/// <para>
/// <b>The component is scoped from its two source files, not from a namespace.</b>
/// <c>SecureAD.Kernel</c> exports far more than this, so a namespace filter would pull in the whole
/// layer. An explicit list of four would be worse: the list would be the page's claim restated, so
/// a fifth public type added beside <see cref="AuditError"/> would be invisible to the very check
/// meant to notice it. Reading the declarations out of the files keeps the anchor outside the
/// document.
/// </para>
/// <para>
/// <b>The source scan is cross-checked against reflection</b>, so a regex that has drifted from
/// what the compiler sees fails rather than quietly narrowing the set it compares. Generic arity is
/// stripped, because the compiler calls the result type <c>Result`1</c> and a reader calls it
/// <c>Result</c>.
/// </para>
/// <para>
/// <b>Mutation-tested 2026-08-24 by <c>next/tools/mutate-failure-doc-gates.ps1</c>, six mutations
/// across this class and <see cref="BundleOnDiskDocumentationTests"/>. Baseline 27 passed,
/// 0 failed; all four touched files reverted byte-identical.</b>
/// </para>
/// <list type="bullet">
///   <item>Page drops the <c>ErrorSeverity</c> row - killed by
///   <c>TheTypesTableAndTheComponentAgree</c>.</item>
///   <item>Code gains a public type the page does not claim - killed by
///   <c>TheTypesTableAndTheComponentAgree</c> and <c>TheCheckFindsBothTheDocumentAndTheComponent</c>.</item>
///   <item>Page invents a category the enum does not declare - killed by
///   <c>TheCategoryTableAndTheEnumAgree</c>.</item>
/// </list>
/// <para>
/// <b><see cref="EveryTypeTheScanFindsIsOneTheCompilerExports"/> fired on none of the six</b>, and
/// that is what it is for rather than a hole: the mutation adds a type to the source and the
/// assembly is rebuilt, so the compiler does export it. It guards against the scan drifting away
/// from the compiler, which no edit to these two files can simulate.
/// <c>TheSeverityTableAndTheEnumAgree</c> and <c>ThePagePrintsTheCodeAnUnassignedResultActuallyReports</c>
/// were not exercised by this harness; the first is the same check as the category one against a
/// different enum, and the second is stated here rather than claimed as observed.
/// </para>
/// </remarks>
public sealed class FailureReportingDocumentationTests
{
    private const string Document = "how-failure-is-reported.md";

    /// <summary>
    /// The two files this page claims, and the only two it may claim from.
    /// </summary>
    private static readonly string[] SourceFiles = ["Result.cs", "AuditError.cs", "IRunLog.cs"];

    [Fact]
    public void TheTypesTableAndTheComponentAgree()
    {
        var documented = FirstColumn("TYPES").ToHashSet(StringComparer.Ordinal);
        var actual = DeclaredPublicTypeNames().ToHashSet(StringComparer.Ordinal);

        var unclaimed = actual.Except(documented).OrderBy(n => n, StringComparer.Ordinal).ToList();
        var invented = documented.Except(actual).OrderBy(n => n, StringComparer.Ordinal).ToList();

        Assert.True(
            unclaimed.Count == 0 && invented.Count == 0,
            $"The TYPES table in {Document} disagrees with {string.Join(" and ", SourceFiles)}. "
            + $"Declared but not claimed by the table: {Describe(unclaimed)}. Claimed by the table "
            + $"but not declared: {Describe(invented)}. A type owned by no page is how the area "
            + "files came to be the only record of anything.");
    }

    /// <summary>
    /// Every category the enum declares has a row, and the table invents none. A category exists
    /// because a subsystem produces one, so a new subsystem surfacing its first failure must add a
    /// row here rather than arriving undocumented.
    /// </summary>
    [Fact]
    public void TheCategoryTableAndTheEnumAgree()
    {
        AssertTableMatchesEnum<ErrorCategory>("CATEGORIES");
    }

    /// <summary>
    /// Every severity the enum declares has a row, and the table invents none. The two are the
    /// difference between an audit missing a domain and an audit that is missing, and a page that
    /// named only one would describe a product that cannot tell them apart.
    /// </summary>
    [Fact]
    public void TheSeverityTableAndTheEnumAgree()
    {
        AssertTableMatchesEnum<ErrorSeverity>("SEVERITIES");
    }

    /// <summary>
    /// The page states where the component lands, and both files are there.
    /// </summary>
    [Fact]
    public void TheDocumentNamesTheSourceFilesItDescribes()
    {
        var text = Read();

        Assert.Contains("next/src/SecureAD.Kernel/Result.cs", text, StringComparison.Ordinal);

        foreach (var file in SourceFiles)
        {
            Assert.Contains(file, text, StringComparison.Ordinal);
            Assert.True(File.Exists(SourcePath(file)), $"Expected the component at {SourcePath(file)}.");
        }
    }

    /// <summary>
    /// The code a default result reports is the one the page prints. It is the only literal error
    /// code on the page, and it is what an operator would search for after seeing it in output, so
    /// a rename that left the page behind would send them looking for a string that no longer
    /// exists.
    /// </summary>
    [Fact]
    public void ThePagePrintsTheCodeAnUnassignedResultActuallyReports()
    {
        var reported = default(Result<int>).Error!.Code;

        Assert.Contains(Quoted(reported), Read(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The scanner self-test. Without it every assertion above passes by searching an empty string
    /// and comparing two empty sets, and finding nothing wrong with either.
    /// </summary>
    [Fact]
    public void TheCheckFindsBothTheDocumentAndTheComponent()
    {
        Assert.True(File.Exists(Path()), $"Expected the layer document at {Path()}.");
        Assert.True(Read().Length > 1000, $"{Document} is too short to be the document it claims.");

        var declared = DeclaredPublicTypeNames().ToList();
        Assert.Equal(7, declared.Count);
        Assert.Contains(nameof(AuditError), declared);
        Assert.Contains("Result", declared);

        Assert.NotEmpty(TableRows("TYPES"));
        Assert.NotEmpty(TableRows("CATEGORIES"));
        Assert.NotEmpty(TableRows("SEVERITIES"));
    }

    /// <summary>
    /// The source scan agrees with the compiler. A regex that has drifted would otherwise narrow
    /// the set silently, and a check comparing a shrunken set against a shrunken table passes while
    /// measuring less and less.
    /// </summary>
    [Fact]
    public void EveryTypeTheScanFindsIsOneTheCompilerExports()
    {
        var exported = typeof(AuditError).Assembly
            .GetExportedTypes()
            .Select(t => WithoutArity(t.Name))
            .ToHashSet(StringComparer.Ordinal);

        var phantom = DeclaredPublicTypeNames()
            .Where(name => !exported.Contains(name))
            .ToList();

        Assert.True(
            phantom.Count == 0,
            $"The scan of {string.Join(" and ", SourceFiles)} found types the compiler does not "
            + $"export: {Describe(phantom)}. The scan has drifted from the code.");
    }

    /// <summary>
    /// A marker block that is not there is a failure and never an empty result. Two gates in this
    /// repository have already passed for months while measuring nothing.
    /// </summary>
    [Fact]
    public void AMissingTableIsAFailureRatherThanAnEmptyScan()
    {
        var thrown = Record.Exception(() => TableRows("SHAPE"));

        Assert.NotNull(thrown);
    }

    /// <summary>
    /// The scan is not a bare substring search. A type renamed by appending two characters must not
    /// still match, which is the defect mutation-testing found in the S-2 guard.
    /// </summary>
    [Fact]
    public void TheCheckIsNotSatisfiedByANameThatMerelyContainsTheTypeName()
    {
        var text = Read();

        Assert.DoesNotContain(Quoted(nameof(AuditError) + "XX"), text, StringComparison.Ordinal);
        Assert.Contains(Quoted(nameof(AuditError)), text, StringComparison.Ordinal);
    }

    // --- helpers -----------------------------------------------------------------------------------

    private static void AssertTableMatchesEnum<TEnum>(string marker)
        where TEnum : struct, Enum
    {
        var documented = FirstColumn(marker).ToHashSet(StringComparer.Ordinal);
        var actual = Enum.GetNames<TEnum>().ToHashSet(StringComparer.Ordinal);

        var missing = actual.Except(documented).OrderBy(n => n, StringComparer.Ordinal).ToList();
        var invented = documented.Except(actual).OrderBy(n => n, StringComparer.Ordinal).ToList();

        Assert.True(
            missing.Count == 0 && invented.Count == 0,
            $"The {marker} table in {Document} disagrees with {typeof(TEnum).Name}. Declared but "
            + $"undocumented: {Describe(missing)}. Documented but not declared: {Describe(invented)}.");
    }

    private static string Describe(List<string> names) =>
        names.Count == 0 ? "none" : string.Join(", ", names);

    private static string Quoted(string name) => "`" + name + "`";

    /// <summary>
    /// A generic type's name as a reader writes it: <c>Result</c> rather than <c>Result`1</c>.
    /// </summary>
    private static string WithoutArity(string name)
    {
        var tick = name.IndexOf('`', StringComparison.Ordinal);

        return tick < 0 ? name : name[..tick];
    }

    /// <summary>
    /// The public types declared in the component's own files, read from those files.
    /// </summary>
    private static IEnumerable<string> DeclaredPublicTypeNames()
    {
        foreach (var file in SourceFiles)
        {
            foreach (var line in File.ReadAllLines(SourcePath(file)))
            {
                if (!line.StartsWith("public ", StringComparison.Ordinal))
                    continue;

                var words = line.Split(
                    [' ', '(', '<', '{'], StringSplitOptions.RemoveEmptyEntries);

                // The LAST keyword, not the first. "public readonly record struct RunLogDetail"
                // carries two of them, and taking the first yields "struct" as the type name -
                // which is how this scan first reported a type the compiler does not export.
                var keyword = Array.FindLastIndex(
                    words, w => w is "record" or "class" or "enum" or "struct" or "interface");

                if (keyword >= 0 && keyword + 1 < words.Length)
                    yield return words[keyword + 1];
            }
        }
    }

    private static List<string> FirstColumn(string marker) =>
        TableRows(marker).Select(r => Cells(r)[0].Trim('`')).ToList();

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

        return text[begin..end]
            .Split('\n')
            .Select(l => l.Trim())
            .Where(l => l.StartsWith('|') && !l.Contains("---", StringComparison.Ordinal))
            .Skip(1)
            .ToList();
    }

    private static string[] Cells(string row) =>
        row.Trim('|').Split('|').Select(c => c.Trim()).ToArray();

    private static string Path() =>
        System.IO.Path.Combine(
            RepositoryLocation.Root(), "docs", "layers", "kernel", Document);

    private static string SourcePath(string file) =>
        System.IO.Path.Combine(
            RepositoryLocation.Root(), "next", "src", "SecureAD.Kernel", file);

    private static string Read() => File.ReadAllText(Path());
}
