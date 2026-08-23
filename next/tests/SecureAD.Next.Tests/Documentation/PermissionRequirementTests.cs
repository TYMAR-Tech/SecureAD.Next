using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// The twenty requirements of <c>S-56</c>, each held to a type that exists or an admission that
/// it is not built.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this document is different.</b> It is a specification of how Active Directory
/// permissions work, arrived at over a long session with several assistants checking each other.
/// It was archived with the session narrative on 2026-09-XX, which was wrong: narrative describes
/// what somebody did, and this states what the product must do.
/// </para>
/// <para>
/// <b>Why it needs a test.</b> When it was restored, only three of its twenty requirements - R1,
/// R2 and R13 - were cited anywhere in the code. Seventeen had no link to an implementation, so
/// nothing could tell whether they were built, and nothing would fail if one were dropped. That
/// is the same shape as a document naming an enforcing test that does not exist.
/// </para>
/// <para>
/// <b>What this does not check.</b> That a named type satisfies the requirement well, or at all.
/// It checks that the type exists. A requirement can still be met badly - what it can no longer be
/// is met by a name nobody wrote.
/// </para>
/// </remarks>
public sealed class PermissionRequirementTests
{
    private const string Document = "permission-requirements.md";
    private const string NotBuilt = "not built";

    private static string Path() =>
        System.IO.Path.Combine(RepositoryLocation.Root(), "docs", "layers", "kernel", Document);

    /// <summary>
    /// Every requirement names a type that is in the product, or says it is not built. A third
    /// answer - a blank cell, or a name nobody wrote - is what this exists to stop.
    /// </summary>
    [Fact]
    public void EveryRequirementNamesSomethingRealOrAdmitsItIsNotBuilt()
    {
        var productTypes = ProductTypeNames();
        var wrong = new List<string>();

        foreach (var (id, built) in Requirements())
        {
            if (built.Contains(NotBuilt, StringComparison.OrdinalIgnoreCase)) continue;

            var names = System.Text.RegularExpressions.Regex
                .Matches(built, "`([A-Za-z_][A-Za-z0-9_]*)`")
                .Select(m => m.Groups[1].Value)
                .ToArray();

            if (names.Length == 0)
            {
                wrong.Add($"  {id} names nothing and does not say '{NotBuilt}'");
                continue;
            }

            foreach (var name in names.Where(n => !productTypes.Contains(n)))
                wrong.Add($"  {id} names `{name}`, which is not a type in the product");
        }

        Assert.True(
            wrong.Count == 0,
            $"{Document} section 10 must name a real type for each requirement or say "
            + $"'{NotBuilt}'. A requirement pointing at nothing cannot come due:"
            + Environment.NewLine + string.Join(Environment.NewLine, wrong));
    }

    /// <summary>
    /// The scanner self-test. Without it the check above passes by reading no requirements and
    /// reporting that none of them is wrong - which is how a gate comes to measure nothing.
    /// </summary>
    [Fact]
    public void TheCheckReadsAllTwentyRequirements()
    {
        var requirements = Requirements();

        Assert.Equal(20, requirements.Count);
        Assert.Contains(requirements, r => r.Id == "R1");
        Assert.Contains(requirements, r => r.Id == "R20");
    }

    /// <summary>
    /// The two findings recorded against the table stay visible. Deleting a finding is a decision,
    /// not an edit, and an over-reported owner is something a customer would act on.
    /// </summary>
    [Theory]
    [InlineData("F-1")]
    [InlineData("F-2")]
    [InlineData("S-1-3-4")]
    [InlineData("S-1-5-10")]
    public void TheFindingsAgainstTheTableAreStillRecorded(string marker)
    {
        Assert.Contains(marker, File.ReadAllText(Path()), StringComparison.Ordinal);
    }

    private static List<(string Id, string Built)> Requirements()
    {
        var rows = new List<(string, string)>();

        foreach (var line in File.ReadAllLines(Path()))
        {
            var match = System.Text.RegularExpressions.Regex
                .Match(line, @"^\|\s*(R\d+)\s*\|.*\|.*\|(.*)\|\s*$");

            if (match.Success) rows.Add((match.Groups[1].Value, match.Groups[2].Value));
        }

        return rows;
    }

    private static HashSet<string> ProductTypeNames()
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        var source = System.IO.Path.Combine(RepositoryLocation.Root(), "next", "src");

        foreach (var file in Directory.EnumerateFiles(source, "*.cs", SearchOption.AllDirectories))
        {
            foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex
                .Matches(File.ReadAllText(file), @"\b(?:class|record|enum|struct|interface)\s+([A-Za-z_][A-Za-z0-9_]*)"))
            {
                names.Add(m.Groups[1].Value);
            }
        }

        return names;
    }
}
