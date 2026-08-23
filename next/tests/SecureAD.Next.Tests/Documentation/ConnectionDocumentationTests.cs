using SecureAD.Audit.Connect;
using SecureAD.Evidence;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/layers/connect/the-connection-ladder.md</c> to the ladder the code actually climbs, per
/// <c>docs/next/README.md</c> §When a document counts as documentation.
///
/// <para>
/// The document's table is the only readable statement of how well protected a customer's evidence
/// was. If it and the code disagree, the product climbs one ladder and a reader is told about
/// another - and a reader in this case is somebody deciding whether to trust a security report.
/// That is the failure <c>docs/decisions/0016</c> records, one document keeping something the other
/// dropped, arriving at the worst possible subject.
/// </para>
/// </summary>
public sealed class ConnectionDocumentationTests
{
    private const string Document = "the-connection-ladder.md";
    private const string TableBegin = "<!-- LADDER:BEGIN -->";
    private const string TableEnd = "<!-- LADDER:END -->";

    /// <summary>
    /// One row of the document's ladder table, read as the values the code would have to hold for
    /// the row to be true.
    /// </summary>
    private sealed record DocumentedRung(
        string Level, int Port, bool UseTls, bool Sign, bool Seal, bool NeedsDeclaration);

    /// <summary>
    /// Every rung the code names has a row, every row names a rung, and the two are in the same
    /// order - which matters as much as the membership, because the order is the order the ladder
    /// is descended.
    /// </summary>
    [Fact]
    public void TheDocumentedLadderIsTheLadderTheCodeClimbs()
    {
        var documented = DocumentedLadder();

        var actual = ConnectionSecurityLadder.Rungs
            .Select(r => new DocumentedRung(
                r.Level.ToString(), r.Port, r.UseTls, r.Sign, r.Seal, r.RequiresDeclaredAllowance))
            .ToList();

        Assert.Equal(actual, documented);
    }

    /// <summary>
    /// The claim the whole design rests on, checked against the document rather than assumed: the
    /// bottom rung, and only the bottom rung, is the one a run cannot reach without saying so.
    /// </summary>
    [Fact]
    public void TheDocumentAgreesThatOnlyTheBottomRungNeedsADeclaration()
    {
        var documented = DocumentedLadder();

        var needing = documented.Where(r => r.NeedsDeclaration).ToList();

        Assert.Single(needing);
        Assert.Equal(documented[^1], needing[0]);
        Assert.Equal(nameof(ConnectionSecurityLevel.Unprotected), needing[0].Level);
    }

    /// <summary>
    /// The scanner self-test. Without it the two checks above pass by comparing an empty table
    /// against an empty ladder and finding nothing wrong with either - the failure this repository
    /// has committed three times.
    ///
    /// <para>
    /// It asserts a floor on what was read rather than that something was read, which is the lesson
    /// F-S7-43 records. The negative control is that the parser must not be matching every line in
    /// the document: a table that swallowed the prose would have far more than four rows.
    /// </para>
    /// </summary>
    [Fact]
    public void TheCheckReadsBothTheTableAndTheLadderAndDoesNotMatchEverything()
    {
        var documented = DocumentedLadder();

        Assert.Equal(4, documented.Count);
        Assert.Equal(4, ConnectionSecurityLadder.Rungs.Count);
        Assert.Contains(documented, r => r.UseTls);
        Assert.Contains(documented, r => !r.UseTls);
        Assert.Contains(documented, r => r.Sign);
        Assert.Contains(documented, r => !r.Sign);
        Assert.DoesNotContain(documented, r => r.Level.Contains(' ', StringComparison.Ordinal));

        // The document must also still be the one that explains the ladder, rather than a stub
        // carrying a correct table and nothing else.
        var text = DocumentText();
        Assert.True(text.Length > 6000, $"Read only {text.Length} characters of {Document}.");
        Assert.Contains("how-a-connection-is-opened.md", text, StringComparison.Ordinal);
        Assert.Contains("0018-connection-security", DecisionReference(text), StringComparison.Ordinal);
    }

    /// <summary>
    /// The document must cite the decision it implements. A slice that quietly diverged from the
    /// record would leave the record looking followed.
    /// </summary>
    private static string DecisionReference(string text)
    {
        var decisions = Directory
            .EnumerateFiles(Path.Combine(RepositoryLocation.Root(), "docs", "decisions"), "*.md")
            .Select(Path.GetFileNameWithoutExtension)
            .Where(name => name is not null && text.Contains(name, StringComparison.Ordinal))
            .ToList();

        Assert.NotEmpty(decisions);
        return string.Join(";", decisions);
    }

    private static string DocumentText()
    {
        var path = Path.Combine(RepositoryLocation.Root(), "docs", "layers", "connect", Document);
        if (!File.Exists(path))
            throw new FileNotFoundException("Expected the layer document at " + path + ".", path);

        return File.ReadAllText(path);
    }

    /// <summary>
    /// The ladder table, read only between its markers so that a rung named in the prose does not
    /// count as a row.
    /// </summary>
    private static List<DocumentedRung> DocumentedLadder()
    {
        var lines = DocumentText().Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

        var begin = Array.FindIndex(lines, l => l.Trim() == TableBegin);
        var end = Array.FindIndex(lines, l => l.Trim() == TableEnd);

        if (begin < 0 || end < 0 || end < begin)
        {
            throw new InvalidOperationException(
                "Could not find the " + TableBegin + " / " + TableEnd + " markers in " + Document
                + ". A missing marker must fail rather than silently empty the scan.");
        }

        var rungs = new List<DocumentedRung>();

        for (var i = begin + 1; i < end; i++)
        {
            var trimmed = lines[i].Trim();
            if (!trimmed.StartsWith('|') || !trimmed.EndsWith('|'))
                continue;

            var cells = trimmed.Trim('|').Split('|').Select(c => c.Trim()).ToArray();
            if (cells.Length != 6 || cells[0] == "Rung" || cells[0].All(c => c is '-' or ':'))
                continue;

            rungs.Add(new DocumentedRung(
                cells[0],
                int.Parse(cells[1], System.Globalization.CultureInfo.InvariantCulture),
                YesNo(cells[2]),
                YesNo(cells[3]),
                YesNo(cells[4]),
                YesNo(cells[5])));
        }

        return rungs;
    }

    /// <summary>
    /// A cell of the table. Anything that is neither yes nor no is refused rather than read as no,
    /// because a typo that silently became "not protected" is the one direction this check must
    /// never fail in.
    /// </summary>
    private static bool YesNo(string cell) => cell switch
    {
        "yes" => true,
        "no" => false,
        _ => throw new InvalidOperationException(
            $"'{cell}' is neither yes nor no in {Document}'s ladder table."),
    };
}
