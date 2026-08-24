using System.Reflection;
using System.Text.RegularExpressions;
using SecureAD.Next.Tests.Architecture;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Holds <c>docs/PUNCH-LIST.md</c> to the tree it describes.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> `P-19` recorded a defect against a test called
/// <c>EveryPublicTypeInTheCaptureProjectIsNamedByACaptureSliceDocument</c>. Searching for that name
/// returns nothing, because the Audit/Capture pass renamed it when slice documents became layer
/// documents. For some minutes the honest reading was that a fixed gate had regressed.
/// </para>
/// <para>
/// Every identifier in that file is prose, checked by nothing, in a repository whose whole method is
/// binding documents to code with gates. A renamed test orphans its record silently, and the failure
/// runs the expensive way: a closed item reads as a live defect, so somebody re-investigates
/// finished work or re-fixes something sound.
/// </para>
/// <para>
/// <b>What this checks and what it deliberately does not.</b> It resolves any backticked token long
/// enough and PascalCase enough to be a code identifier, against every type and member in the
/// production assemblies and this test assembly. It does not demand that <i>every</i> backticked
/// token resolve: the punch list also names SQL columns, decision records, predecessor types
/// deleted on purpose, and types from the old <c>src/</c> tree - and a check demanding those resolve
/// would fail on entries that are correct precisely because the thing is gone.
/// </para>
/// <para>
/// A name quoted as history - something that <i>used</i> to be called this - is written without
/// backticks, which is the convention the layer documents already use for the same reason.
/// </para>
/// </remarks>
public sealed class PunchListIdentifierTests
{
    private const string Document = "PUNCH-LIST.md";

    /// <summary>
    /// A backticked token that looks like a code identifier: PascalCase, no dots, and long enough
    /// that it cannot be a column name or a word this list uses in passing.
    /// </summary>
    private static readonly Regex Identifier =
        new(@"^[A-Z][A-Za-z0-9]{24,}$", RegexOptions.Compiled);

    /// <summary>
    /// The dashed line under a table's header, which is what marks the start of its rows.
    /// </summary>
    private static readonly Regex Separator =
        new(@"^\|[-\s|:]+\|$", RegexOptions.Compiled);

    /// <summary>
    /// Every name the tree actually defines - types, methods, properties and fields across the
    /// production assemblies, plus every test method.
    /// </summary>
    /// <remarks>
    /// Deliberately a flat set of bare names rather than qualified ones. This check answers
    /// <i>does the tree still contain something by this name</i>, which is the question a stale
    /// record fails; whether it is in the right place is the layer documents' business and they are
    /// bound to it far more strictly.
    /// </remarks>
    private static readonly HashSet<string> RealNames = BuildRealNames();

    private static HashSet<string> BuildRealNames()
    {
        var names = new HashSet<string>(StringComparer.Ordinal);

        var assemblies = RebuildAssemblies.All
            .Append(typeof(PunchListIdentifierTests).Assembly);

        foreach (var assembly in assemblies)
        {
            foreach (var type in assembly.GetTypes())
            {
                names.Add(type.Name);

                foreach (var member in type.GetMembers(
                    BindingFlags.Public | BindingFlags.NonPublic
                    | BindingFlags.Instance | BindingFlags.Static))
                {
                    names.Add(member.Name);
                }
            }
        }

        return names;
    }

    /// <summary>
    /// An identifier named here must exist somewhere in the tree. This is the check that would have
    /// caught `P-19`.
    /// </summary>
    [Fact]
    public void EveryIdentifierThePunchListNamesExists()
    {
        var missing = Mentioned()
            .Where(token => Identifier.IsMatch(token))
            .Where(token => !RealNames.Contains(token))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} names identifiers that do not exist: {string.Join(", ", missing)}. Either "
            + "the name was changed and this record was left behind, or the thing was deleted and "
            + "the record is stale. A record naming code by a name the tree does not have reads as "
            + "a live defect, which is the expensive direction to be wrong in. If the name is "
            + "quoted deliberately as history - something that used to be called this - write it "
            + "without backticks, as the layer documents do.");
    }

    /// <summary>
    /// A repository path named here must exist. The punch list cites source files as the evidence
    /// for its items, and a moved file turns the citation into something nobody can follow.
    /// </summary>
    [Fact]
    public void EveryRepositoryPathThePunchListNamesExists()
    {
        var root = RepositoryLocation.Root();

        var missing = Mentioned()
            .Where(token => token.StartsWith("next/", StringComparison.Ordinal)
                || token.StartsWith("docs/", StringComparison.Ordinal))
            .Where(token => !token.Contains(' ', StringComparison.Ordinal))
            .Select(token => token.Split(':')[0])
            .Where(path => !File.Exists(Absolute(root, path)) && !Directory.Exists(Absolute(root, path)))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} names paths that do not exist: {string.Join(", ", missing)}.");
    }

    /// <summary>
    /// Every line inside a table opens a row.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>An item with no identifier cannot be cited, closed or counted</b>, and no search for its
    /// number will find it. Two rows were written without one and neither check above noticed,
    /// because both read the rows that <i>have</i> an identifier - so they passed over exactly the
    /// rows that were broken. One of the two was this session's own subject, described by its brief
    /// as recorded when it was not. That is <c>P-64</c>, and this is the check it asked for.
    /// </para>
    /// <para>
    /// The rule is that a line between a table's separator and the blank line ending it must begin
    /// with a pipe. That is stricter than markdown requires, deliberately: nothing in this document
    /// needs a continuation line, and allowing one is what let a headless row look ordinary.
    /// </para>
    /// </remarks>
    [Fact]
    public void EveryLineInsideATableOpensARow()
    {
        var headless = HeadlessRowsIn(File.ReadAllLines(Path()));

        Assert.True(
            headless.Count == 0,
            $"{Document} has table lines that open no row: {string.Join("; ", headless)}. A row "
            + "begins with its identifier in the first cell. A line that does not is an item "
            + "nobody can cite, close or count, and it is invisible to anyone searching for its "
            + "number.");
    }

    // --- scanner self-tests --------------------------------------------------------------------

    /// <summary>
    /// The table scan really does walk this document's tables, and really does reject a line that
    /// opens no row. Without this it could pass by never entering a table at all - which is the
    /// failure mode of the two checks it was added to cover for.
    /// </summary>
    [Fact]
    public void TheTableScanFindsTablesAndRejectsAHeadlessRow()
    {
        string[] wellFormed =
        [
            "| ID | Item | Status | Blocked on |",
            "|---|---|---|---|",
            "| P-1 | Something | open | - |",
            string.Empty,
            "Prose below the table opens no row, and is not inside one.",
        ];

        Assert.Empty(HeadlessRowsIn(wellFormed));

        string[] headless =
        [
            "| ID | Item | Status | Blocked on |",
            "|---|---|---|---|",
            "| P-1 | Something | open | - |",
            "and the remainder of it, carrying no identifier | open | - |",
        ];

        Assert.Single(HeadlessRowsIn(headless));

        var identified = File.ReadAllLines(Path())
            .Count(line => line.StartsWith("| P-", StringComparison.Ordinal));

        Assert.True(
            identified > 40,
            $"Found only {identified} identified rows in {Document}, which is too few to be this "
            + "document - the scan is looking in the wrong place.");
    }

    /// <summary>
    /// Lines that sit inside a table but begin no row, each with the line number that locates it.
    /// </summary>
    /// <param name="lines">The document, in order.</param>
    private static List<string> HeadlessRowsIn(IReadOnlyList<string> lines)
    {
        var headless = new List<string>();
        var inTable = false;

        for (var i = 0; i < lines.Count; i++)
        {
            var line = lines[i].Trim();

            if (Separator.IsMatch(line))
            {
                inTable = true;
                continue;
            }

            if (!inTable)
                continue;

            if (line.Length == 0)
            {
                inTable = false;
                continue;
            }

            if (!line.StartsWith('|'))
                headless.Add($"line {i + 1}: {line[..Math.Min(60, line.Length)]}");
        }

        return headless;
    }

    // --- scanner self-tests --------------------------------------------------------------------

    /// <summary>
    /// Without this both checks above could pass by scanning an empty document or reflecting over
    /// an empty assembly, and find nothing wrong with either. Two gates in this repository have
    /// already passed for months while measuring nothing.
    /// </summary>
    [Fact]
    public void TheCheckFindsBothTheDocumentAndTheTree()
    {
        Assert.True(File.Exists(Path()), $"Expected the punch list at {Path()}.");
        Assert.True(Read().Length > 5000, $"{Document} is too short to be the document it claims.");
        Assert.True(
            RealNames.Count > 2000,
            $"Found only {RealNames.Count} names by reflection, which is too few to be this tree - "
            + "the scan is looking in the wrong place.");
        Assert.NotEmpty(Mentioned());
    }

    /// <summary>
    /// The pattern really does select code identifiers, and really does reject the other things
    /// this document puts in backticks. Without this the check above could pass by matching
    /// nothing.
    /// </summary>
    [Fact]
    public void ThePatternSelectsIdentifiersAndNothingElse()
    {
        Assert.Matches(Identifier, "EveryPublicTypeInTheCaptureProjectIsNamedByACaptureDocument");
        Assert.Matches(Identifier, "ABundleCanonicalisedByAnEarlierVersionIsRefusedUnderItsOwnCode");

        Assert.DoesNotMatch(Identifier, "canonicalization_version");
        Assert.DoesNotMatch(Identifier, "AclSize");
        Assert.DoesNotMatch(Identifier, "BundleReader.Open");
        Assert.DoesNotMatch(Identifier, "0021");
    }

    /// <summary>
    /// At least one real identifier is actually named by the document, so the check is exercising
    /// the path rather than finding nothing to look at.
    /// </summary>
    [Fact]
    public void ThePunchListNamesAtLeastOneRealIdentifier()
    {
        var named = Mentioned()
            .Where(token => Identifier.IsMatch(token))
            .Where(RealNames.Contains)
            .ToList();

        Assert.NotEmpty(named);
    }

    // --- helpers -------------------------------------------------------------------------------

    private static IEnumerable<string> Mentioned()
    {
        var parts = Read().Split('`');
        for (var i = 1; i < parts.Length; i += 2)
            yield return parts[i];
    }

    private static string Absolute(string root, string repositoryPath) =>
        System.IO.Path.Combine(
            root,
            repositoryPath.Replace('/', System.IO.Path.DirectorySeparatorChar));

    private static string Path() =>
        System.IO.Path.Combine(RepositoryLocation.Root(), "docs", Document);

    private static string Read() => File.ReadAllText(Path());
}
