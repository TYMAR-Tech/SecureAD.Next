using SecureAD.Evidence;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/layers/evidence/a-domain-left-out-on-purpose.md</c> to
/// <see cref="AttestedExclusion"/> and <see cref="ExclusionKind"/>.
/// </summary>
/// <remarks>
/// <para>
/// Written when the area file the-new-audit-wizard.md was reduced to its shell content. That file
/// owned these two and five others, and no layer document claimed any of them.
/// </para>
/// <para>
/// <b>The component is scoped from its one source file, not from a namespace.</b>
/// <c>SecureAD.Evidence</c> exports the whole evidence layer, so a namespace filter would have this
/// page claim it. A hardcoded pair would be worse: it would be the page's table restated, so a
/// third public type added to <c>AttestedExclusion.cs</c> would be invisible to the check meant to
/// notice it.
/// </para>
/// <para>
/// <b>The two kinds are bound in both directions</b> because
/// <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c> turns on them being told
/// apart. A page that named only one would describe a product that cannot distinguish a domain an
/// operator removed from a domain the forest could not offer a controller for - which is the
/// distinction this evidence exists to preserve for a reader months later.
/// </para>
/// <para>
/// <b>Mutation-tested 2026-08-24 by <c>next/tools/mutate-wizard-doc-gates.ps1</c>, two of six
/// directions aimed here, both killed.</b> Dropping <c>ForWantOfCandidates</c> from the kinds table
/// is killed by <see cref="TheKindsTableAndTheEnumAgree"/>; changing the page to say the
/// authorising name is checked against the directory is killed by
/// <see cref="ThePageSaysTheAuthorisingNameIsNotValidated"/>.
/// </para>
/// <para>
/// <b><see cref="EveryMemberOfAnExclusionIsDescribed"/> found a real gap on its first run:</b> the
/// page carried the kinds table and never named <c>AttestedExclusion.Kind</c>, the member that
/// carries it. A reader could have seen the two values and not known what held them. The page was
/// fixed rather than the check relaxed.
/// </para>
/// </remarks>
public sealed class AttestedExclusionDocumentationTests
{
    private const string Document = "a-domain-left-out-on-purpose.md";

    private const string SourceFile = "AttestedExclusion.cs";

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
            + $"{Describe(unclaimed)}. Claimed but not declared: {Describe(invented)}.");
    }

    /// <summary>
    /// Every kind the enum declares has a row and the table invents none.
    /// </summary>
    [Fact]
    public void TheKindsTableAndTheEnumAgree()
    {
        var documented = FirstColumn("KINDS").ToHashSet(StringComparer.Ordinal);
        var actual = Enum.GetNames<ExclusionKind>().ToHashSet(StringComparer.Ordinal);

        var missing = actual.Except(documented).OrderBy(n => n, StringComparer.Ordinal).ToList();
        var invented = documented.Except(actual).OrderBy(n => n, StringComparer.Ordinal).ToList();

        Assert.True(
            missing.Count == 0 && invented.Count == 0,
            $"The KINDS table in {Document} disagrees with {nameof(ExclusionKind)}. Declared but "
            + $"undocumented: {Describe(missing)}. Documented but not declared: {Describe(invented)}. "
            + "Decision 0063 turns on these two being told apart.");
    }

    /// <summary>
    /// Every member a caller can read off an exclusion is described. This record is written into
    /// evidence and read back by somebody with no screen and no operator to ask, so a field nobody
    /// documented is a field nobody can interpret.
    /// </summary>
    [Fact]
    public void EveryMemberOfAnExclusionIsDescribed()
    {
        var text = Read();

        var missing = typeof(AttestedExclusion)
            .GetProperties()
            .Select(p => p.Name)
            .Where(n => n != "EqualityContract")
            .Where(n => !text.Contains("`AttestedExclusion." + n + "`", StringComparison.Ordinal)
                     && !text.Contains("`" + n + "`", StringComparison.Ordinal))
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not describe: {Describe(missing)}.");
    }

    /// <summary>
    /// The page says the authorising name is not validated. This is the one claim on the page a
    /// reader could act wrongly on: presenting a typed string as a checked identity would tell a
    /// customer the product verified something it never looked at.
    /// </summary>
    [Fact]
    public void ThePageSaysTheAuthorisingNameIsNotValidated()
    {
        Assert.Contains("not validated", Read(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The source scan agrees with the compiler, so a regex that has drifted fails rather than
    /// quietly narrowing the set the first check compares.
    /// </summary>
    [Fact]
    public void EveryTypeTheScanFindsIsOneTheCompilerExports()
    {
        var exported = typeof(AttestedExclusion).Assembly
            .GetExportedTypes()
            .Select(t => t.Name)
            .ToHashSet(StringComparer.Ordinal);

        var unknown = DeclaredPublicTypeNames()
            .Where(name => !exported.Contains(name))
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.True(unknown.Count == 0, $"The scan found unexported types: {Describe(unknown)}.");
    }

    /// <summary>
    /// A marker block that is not there is a failure and never an empty result.
    /// </summary>
    [Fact]
    public void AMissingTableIsAFailureRatherThanAnEmptyScan()
    {
        Assert.NotNull(Record.Exception(() => TableRows("STATES")));
    }

    /// <summary>
    /// The scanner self-test. Without it every check above passes by reading an empty string and
    /// comparing two empty sets.
    /// </summary>
    [Fact]
    public void TheCheckFindsTheDocumentAndTheComponent()
    {
        Assert.True(File.Exists(Path()), $"Expected the layer document at {Path()}.");
        Assert.True(Read().Length > 1000, $"{Document} is too short to be the document it claims.");

        Assert.NotEmpty(FirstColumn("TYPES"));
        Assert.NotEmpty(FirstColumn("KINDS"));

        var declared = DeclaredPublicTypeNames().ToList();

        Assert.Equal(2, declared.Count);
        Assert.Contains(nameof(AttestedExclusion), declared);
        Assert.Contains(nameof(ExclusionKind), declared);
    }

    // --- helpers -----------------------------------------------------------------------------------

    private static string Describe(List<string> names) =>
        names.Count == 0 ? "none" : string.Join(", ", names);

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
            RepositoryLocation.Root(), "next", "src", "SecureAD.Evidence", SourceFile);

    private static string Read() => File.ReadAllText(Path());
}
