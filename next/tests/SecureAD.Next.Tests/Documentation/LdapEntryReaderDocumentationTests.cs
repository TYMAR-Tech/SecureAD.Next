using System.Reflection;
using SecureAD.Audit.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/next/S-11-reading-what-a-controller-returns.md</c> to
/// <see cref="LdapEntryReader"/>, <see cref="AttributeValues"/> and <see cref="AttributeRange"/>.
///
/// <para>
/// This is inventory row B8's deliverable. The row owes the range-retrieval rule, and what makes a
/// document of it rather than an essay is that the states it describes are the states the code has,
/// and the conversions it lists are the conversions the code offers - in both directions, so a
/// state added to the code without a word written about it fails, and a state described here that
/// the code does not have fails too.
/// </para>
/// <para>
/// <b>Names are compared whole, never as substrings.</b> A guard that matched a table cell against
/// a member name by containment let a renamed member through in this repository once already: the
/// document was deliberately broken and the check stayed green. Each cell here is matched exactly.
/// </para>
/// <para>
/// <b>What it cannot check.</b> That the limits quoted are the limits Microsoft documents - a
/// reader has to compare them against the linked articles - or that a real domain controller
/// formats a ranged name the way the tests model. The second is recorded as a finding rather than
/// implied.
/// </para>
/// </summary>
public sealed class LdapEntryReaderDocumentationTests
{
    private const string Document = "S-11-reading-what-a-controller-returns.md";

    [Fact]
    public void TheDocumentDescribesEveryCompletenessStateTheCodeHas()
    {
        var documented = DocumentedCompleteness().Keys;

        var missing = Enum.GetNames<AttributeCompleteness>()
            .Where(state => !documented.Contains(state, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            missing.Count == 0,
            "Completeness states the code has that " + Document + " does not describe. A state a "
            + "caller can be handed and nobody has written down is a state nobody has decided how "
            + "to read: " + string.Join(", ", missing));
    }

    [Fact]
    public void TheDocumentDescribesNoCompletenessStateTheCodeDoesNotHave()
    {
        var known = Enum.GetNames<AttributeCompleteness>();

        var phantom = DocumentedCompleteness().Keys
            .Where(state => !known.Contains(state, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            phantom.Count == 0,
            Document + " describes completeness states the code does not have: "
            + string.Join(", ", phantom));
    }

    /// <summary>
    /// Every state says what a caller may conclude from it, and never nothing. That column is the
    /// whole reason there are three states rather than two.
    /// </summary>
    [Fact]
    public void EveryStateSaysWhatACallerMayConcludeFromIt()
    {
        var silent = DocumentedCompleteness()
            .Where(state => state.Value.Third.Length < 20)
            .Select(state => state.Key)
            .ToList();

        Assert.True(
            silent.Count == 0,
            "States in " + Document + " with nothing said about what may be concluded from them: "
            + string.Join(", ", silent));
    }

    [Fact]
    public void TheDocumentListsEveryConversionTheReaderOffers()
    {
        var documented = DocumentedConversions();

        var missing = CodeConversions()
            .Where(name => !documented.Contains(name))
            .ToList();

        Assert.True(
            missing.Count == 0,
            "Conversions the reader offers that " + Document + " does not list: "
            + string.Join(", ", missing));
    }

    [Fact]
    public void TheDocumentListsNoConversionTheReaderDoesNotOffer()
    {
        var offered = CodeConversions();

        var phantom = DocumentedConversions()
            .Where(name => !offered.Contains(name))
            .ToList();

        Assert.True(
            phantom.Count == 0,
            Document + " lists conversions the reader does not offer. A document promising a way "
            + "to read a value that does not exist is worse than one that omits it: "
            + string.Join(", ", phantom));
    }

    /// <summary>
    /// The numbers the document rests on are the numbers the code uses. A block size stated in the
    /// prose and contradicted by the request is how a client ends up asking for more values than
    /// every server will serve.
    /// </summary>
    [Fact]
    public void TheBlockSizeAndTheLimitsAreTheSameInBothPlaces()
    {
        // Line breaks are collapsed so that a sentence wrapped differently is still the same
        // sentence. The check is about the numbers, not about where the paragraph was rewrapped.
        var text = string.Join(' ', DocumentText().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

        Assert.Equal(1_000, AttributeRange.ValuesPerRound);
        Assert.Contains("a maximum number of 1000 should be used", text, StringComparison.Ordinal);
        Assert.Contains("**1,500 by default**", text, StringComparison.Ordinal);
        Assert.Contains("the ceiling is **5,000 values**", text, StringComparison.Ordinal);
        Assert.Equal("member;range=0-999", AttributeRange.FirstRound.SpecifierFor("member"));
        Assert.Contains("member;range=0-999", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// The document states that a retrieval has no cap and no partial answer, and the code has to
    /// agree: a partial read is refused rather than returned, and the refusal has a name.
    /// </summary>
    [Fact]
    public void TheNoPartialAnswerRuleIsStatedAndHeld()
    {
        Assert.Contains(
            "There is no limit on the number of blocks, and there is no partial answer",
            DocumentText(),
            StringComparison.Ordinal);

        var soFar = new AttributeValues(
            "member", new object[] { "CN=a" }, AttributeCompleteness.MoreToFetch, new(1, 1_000));

        var stalled = LdapEntryReader.Continue(
            soFar, new AttributeValues("member", [], AttributeCompleteness.MoreToFetch, new(1, 1_000)));

        Assert.False(stalled.IsSuccess);
    }

    /// <summary>
    /// The scanner self-test. Without it the checks above pass by comparing an empty table with an
    /// empty reflection and report a document in perfect order.
    /// </summary>
    [Fact]
    public void TheCheckReadsBothTablesAndTheCode()
    {
        var states = DocumentedCompleteness();
        var conversions = DocumentedConversions();

        Assert.Equal(3, states.Count);
        Assert.Equal(3, Enum.GetNames<AttributeCompleteness>().Length);
        Assert.Contains(nameof(AttributeCompleteness.NotReturned), states.Keys);

        Assert.True(conversions.Count >= 5, $"Read {conversions.Count} conversions from the table.");
        Assert.Contains(nameof(LdapEntryReader.AsSid), conversions);
        Assert.Contains(nameof(LdapEntryReader.AsSid), CodeConversions());

        // The negative control: a name that is not a conversion must not be read as one.
        Assert.DoesNotContain(nameof(LdapEntryReader.Continue), CodeConversions());
    }

    /// <summary>Every public way the reader turns one value into a typed one.</summary>
    private static HashSet<string> CodeConversions() =>
        typeof(LdapEntryReader)
            .GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)
            .Where(m => m.Name.StartsWith("As", StringComparison.Ordinal))
            .Select(m => m.Name)
            .ToHashSet(StringComparer.Ordinal);

    private static HashSet<string> DocumentedConversions() =>
        Table("<!-- CONVERSIONS:BEGIN -->", "<!-- CONVERSIONS:END -->", "Reads a value as")
            .Values
            .Select(row => row.Second)
            .ToHashSet(StringComparer.Ordinal);

    private static Dictionary<string, (string Second, string Third)> DocumentedCompleteness() =>
        Table("<!-- COMPLETENESS:BEGIN -->", "<!-- COMPLETENESS:END -->", "State");

    private static string DocumentText() =>
        File.ReadAllText(Path.Combine(RepositoryLocation.Root(), "docs", "next", Document));

    /// <summary>
    /// A three-column table between two markers, keyed by its first column. Only what lies between
    /// the markers is read, so a name appearing in the prose does not count as a documented one,
    /// and a missing marker fails rather than silently emptying the scan.
    /// </summary>
    private static Dictionary<string, (string Second, string Third)> Table(
        string begin, string end, string headerCell)
    {
        var path = Path.Combine(RepositoryLocation.Root(), "docs", "next", Document);
        Assert.True(File.Exists(path), $"Expected the document at {path}.");

        var lines = File.ReadAllLines(path);
        var first = Array.FindIndex(lines, l => l.Trim() == begin);
        var last = Array.FindIndex(lines, l => l.Trim() == end);

        if (first < 0 || last < 0 || last < first)
        {
            throw new InvalidOperationException(
                $"Could not find the {begin} / {end} markers in {Document}. The tests parse only "
                + "what lies between them, so a missing marker must fail rather than silently "
                + "widen or empty the scan.");
        }

        var rows = new Dictionary<string, (string, string)>(StringComparer.Ordinal);

        for (var i = first + 1; i < last; i++)
        {
            var line = lines[i].Trim();
            if (!line.StartsWith('|') || !line.EndsWith('|'))
                continue;

            var cells = line.Trim('|').Split('|').Select(c => c.Trim()).ToArray();
            if (cells.Length < 3 || cells[0] == headerCell || cells[0].All(c => c is '-' or ':'))
                continue;

            rows[cells[0]] = (cells[1], cells[2]);
        }

        return rows;
    }
}
