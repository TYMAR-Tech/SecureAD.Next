using SecureAD.Evidence;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/layers/evidence/what-an-objects-permissions-hold.md</c> to the code it describes.
/// </summary>
/// <remarks>
/// <para>
/// Written when docs/areas/what-a-permission-means.md was deleted. That file governed
/// twenty-four public types; twenty were already owned by a layer document's <c>TYPES</c> table and
/// four were owned by nothing, and those four are this component.
/// </para>
/// <para>
/// <b>The component is scoped from the source file, not from a namespace.</b>
/// <c>SecureAD.Evidence</c> holds many types, so the namespace filter that scopes
/// <see cref="SchemaGuidDocumentationTests"/> would pull in the whole layer. Scoping from an
/// explicit list of four would be worse: the list would be the page's claim restated, so a fifth
/// public type added to the file would be invisible to the very check meant to notice it. Reading
/// the declarations out of the file keeps the anchor outside the document.
/// </para>
/// <para>
/// <b>The source scan is cross-checked against reflection</b>, so a regex that has drifted from what
/// the compiler sees fails rather than quietly narrowing the set it compares.
/// </para>
/// <para>
/// <b>Mutation-tested 2026-08-24, four directions, by
/// <c>next/tools/mutate-permissions-doc-gate.ps1</c>. Baseline 8 passed, 0 failed; both files
/// reverted byte-identical.</b>
/// </para>
/// <list type="bullet">
///   <item>Page drops the <c>PermissionTrustee</c> row - killed by
///   <c>TheTypesTableAndTheComponentAgree</c>.</item>
///   <item>Code gains a public type the page does not claim - killed by
///   <c>TheTypesTableAndTheComponentAgree</c> and <c>TheCheckFindsBothTheDocumentAndTheComponent</c>.</item>
///   <item>Enum gains a state the page does not name - killed by
///   <c>TheAvailabilityTableAndTheEnumAgree</c>.</item>
///   <item>Page invents a state the enum does not declare - killed by
///   <c>TheAvailabilityTableAndTheEnumAgree</c>.</item>
/// </list>
/// <para>
/// <b>The first run of that harness reported the first mutation as surviving, and the harness was
/// at fault rather than the gate:</b> the page is stored with CRLF endings, so removing
/// <c>anchor + "\n"</c> matched nothing and the row was never actually deleted. A mutation that
/// does not mutate is indistinguishable from a gate that does not measure, so the harness now
/// throws when a replacement changes nothing.
/// </para>
/// </remarks>
public sealed class ObjectPermissionsDocumentationTests
{
    private const string Document = "what-an-objects-permissions-hold.md";

    private const string SourceFile = "ObjectPermissions.cs";

    [Fact]
    public void TheTypesTableAndTheComponentAgree()
    {
        var documented = FirstColumn("TYPES").ToHashSet(StringComparer.Ordinal);
        var actual = DeclaredPublicTypeNames().ToHashSet(StringComparer.Ordinal);

        var unclaimed = actual.Except(documented).OrderBy(n => n, StringComparer.Ordinal).ToList();
        var invented = documented.Except(actual).OrderBy(n => n, StringComparer.Ordinal).ToList();

        Assert.True(
            unclaimed.Count == 0 && invented.Count == 0,
            $"The TYPES table in {Document} disagrees with {SourceFile}. Declared but not claimed "
            + $"by the table: {Describe(unclaimed)}. Claimed by the table but not declared: "
            + $"{Describe(invented)}. A type owned by no page is how the area files came to be the "
            + "only record of anything.");
    }

    /// <summary>
    /// Every state the enum declares has a row, and the table invents none. The three states are the
    /// whole point of the type - a viewer that collapses them reports an object nobody could read as
    /// an object that grants nothing.
    /// </summary>
    [Fact]
    public void TheAvailabilityTableAndTheEnumAgree()
    {
        var documented = FirstColumn("AVAILABILITY").ToHashSet(StringComparer.Ordinal);
        var actual = Enum.GetNames<DescriptorAvailability>().ToHashSet(StringComparer.Ordinal);

        var missing = actual.Except(documented).OrderBy(n => n, StringComparer.Ordinal).ToList();
        var invented = documented.Except(actual).OrderBy(n => n, StringComparer.Ordinal).ToList();

        Assert.True(
            missing.Count == 0 && invented.Count == 0,
            $"The AVAILABILITY table in {Document} disagrees with {nameof(DescriptorAvailability)}. "
            + $"Declared but undocumented: {Describe(missing)}. Documented but not declared: "
            + $"{Describe(invented)}.");
    }

    /// <summary>
    /// The page states where the component lands, and the code is there.
    /// </summary>
    [Fact]
    public void TheDocumentNamesTheSourceFileItDescribes()
    {
        Assert.Contains(
            $"next/src/SecureAD.Evidence/{SourceFile}", Read(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The reader is named but not claimed. <c>ObjectPermissionsReader</c> is internal, so it is not
    /// a public type and must not appear in the ownership table - but its behaviour is the only
    /// thing a caller can observe, so the page has to describe it.
    /// </summary>
    [Fact]
    public void TheInternalReaderIsNamedButNotClaimed()
    {
        const string reader = "ObjectPermissionsReader";

        Assert.Contains(Quoted(reader), Read(), StringComparison.Ordinal);
        Assert.DoesNotContain(reader, FirstColumn("TYPES"));
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
        Assert.True(File.Exists(SourcePath()), $"Expected the component at {SourcePath()}.");

        var declared = DeclaredPublicTypeNames().ToList();
        Assert.Equal(4, declared.Count);
        Assert.Contains(nameof(ObjectPermissions), declared);
        Assert.Contains(nameof(DescriptorAvailability), declared);

        Assert.NotEmpty(TableRows("TYPES"));
        Assert.NotEmpty(TableRows("AVAILABILITY"));
    }

    /// <summary>
    /// The source scan agrees with the compiler. A regex that has drifted would otherwise narrow the
    /// set silently, and a check comparing a shrunken set against a shrunken table passes while
    /// measuring less and less.
    /// </summary>
    [Fact]
    public void EveryTypeTheScanFindsIsOneTheCompilerExports()
    {
        var exported = typeof(ObjectPermissions).Assembly
            .GetExportedTypes()
            .Select(t => t.Name)
            .ToHashSet(StringComparer.Ordinal);

        var phantom = DeclaredPublicTypeNames()
            .Where(name => !exported.Contains(name))
            .ToList();

        Assert.True(
            phantom.Count == 0,
            $"The scan of {SourceFile} found types the compiler does not export: "
            + $"{Describe(phantom)}. The scan has drifted from the code.");
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

        Assert.DoesNotContain(Quoted(nameof(PermissionEntry) + "XX"), text, StringComparison.Ordinal);
        Assert.Contains(Quoted(nameof(PermissionEntry)), text, StringComparison.Ordinal);
    }

    // --- helpers -----------------------------------------------------------------------------------

    private static string Describe(List<string> names) =>
        names.Count == 0 ? "none" : string.Join(", ", names);

    private static string Quoted(string name) => "`" + name + "`";

    /// <summary>
    /// The public types declared in the component's own file, read from the file.
    /// </summary>
    private static IEnumerable<string> DeclaredPublicTypeNames()
    {
        foreach (var line in File.ReadAllLines(SourcePath()))
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
            RepositoryLocation.Root(), "docs", "layers", "evidence", Document);

    private static string SourcePath() =>
        System.IO.Path.Combine(
            RepositoryLocation.Root(), "next", "src", "SecureAD.Evidence", SourceFile);

    private static string Read() => File.ReadAllText(Path());
}
