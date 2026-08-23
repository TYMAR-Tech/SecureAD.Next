using System.Text.RegularExpressions;
using SecureAD.Audit.Capture;
using Xunit;
using SecureAD.Kernel.Capture;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/layers/audit/the-attribute-catalogue.md</c> to <see cref="CapturedAttributeCatalog"/>.
///
/// <para>
/// S-23 is the derivation of the catalogue from the sixty-two rule cards, and its central table
/// makes a claim of a kind no other document here makes: for each attribute, whether capture
/// requests it, and which rules consume it. The first half is checkable against the code and is
/// checked here in both directions. The second half is not - no rule is ported - so what is checked
/// of it is that every rule named is a card that exists, which is what catches the typo that would
/// otherwise read as a satisfied dependency.
/// </para>
/// <para>
/// <b>Why the <c>In catalogue</c> column is worth a gate.</b> It is the column a later session will
/// trust when it asks whether a rule can be ported yet. A row saying <c>absent</c> for an attribute
/// that is in fact captured sends somebody to add it twice; a row saying <c>yes</c> for one that is
/// not sends somebody to write a rule against a column that will be empty. Both are quiet, and both
/// are why F-S23-1 went unnoticed for as long as it did.
/// </para>
/// </summary>
public sealed class CapturedAttributeDerivationDocumentationTests
{
    private const string Document = "the-attribute-catalogue.md";
    private const string TableBegin = "<!-- DERIVATION:BEGIN -->";
    private const string TableEnd = "<!-- DERIVATION:END -->";

    /// <summary>One row of the derivation table.</summary>
    private sealed record DerivedAttribute(string Name, string InCatalogue, string Rules, int Line);

    /// <summary>
    /// Every attribute S-23 says is captured, is. This is the direction that would otherwise send a
    /// later session to build a rule on a column capture never fills.
    /// </summary>
    [Fact]
    public void EveryAttributeTheDerivationCallsCapturedIsInTheCatalogue()
    {
        var catalogue = CatalogueNames();

        var wrong = DerivedAttributes()
            .Where(d => IsCaptured(d) && !catalogue.Contains(d.Name))
            .Select(d => $"  {d.Name} (line {d.Line})")
            .ToList();

        Assert.True(
            wrong.Count == 0,
            Document + " says these attributes are captured and the catalogue does not request "
            + "them. A derivation that overstates what a bundle holds is worse than none, because "
            + "the next session ports a rule against a column that will be empty and finds out "
            + "from a customer:"
            + Environment.NewLine + string.Join(Environment.NewLine, wrong));
    }

    /// <summary>
    /// Every attribute S-23 says is absent, is. The other direction, and the one that would send
    /// somebody to add an attribute the catalogue already has.
    /// </summary>
    [Fact]
    public void EveryAttributeTheDerivationCallsAbsentIsAbsentFromTheCatalogue()
    {
        var catalogue = CatalogueNames();

        var wrong = DerivedAttributes()
            .Where(d => !IsCaptured(d) && catalogue.Contains(d.Name))
            .Select(d => $"  {d.Name} (line {d.Line})")
            .ToList();

        Assert.True(
            wrong.Count == 0,
            Document + " says these attributes are absent and the catalogue requests them:"
            + Environment.NewLine + string.Join(Environment.NewLine, wrong));
    }

    /// <summary>
    /// The derivation accounts for the whole catalogue. An attribute the catalogue requests and the
    /// derivation does not mention is one nobody asked the question of - which is exactly the state
    /// this session existed to end.
    /// </summary>
    [Fact]
    public void TheDerivationAccountsForEveryAttributeTheCatalogueRequests()
    {
        var derived = DerivedAttributes()
            .Select(d => d.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var missing = CapturedAttributeCatalog.All
            .Where(a => !derived.Contains(a.LdapDisplayName))
            .Select(a => "  " + a.LdapDisplayName)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "Attributes the catalogue requests that " + Document + " does not account for. The "
            + "derivation's whole value is that it is exhaustive against the product; one it "
            + "skipped is one whose consumer nobody has checked:"
            + Environment.NewLine + string.Join(Environment.NewLine, missing));
    }

    /// <summary>
    /// Every rule the derivation names is a card that exists. The same rule the catalogue gate
    /// applies to its own consumer column, for the same reason: a mistyped identifier is
    /// indistinguishable from a satisfied dependency.
    /// </summary>
    [Fact]
    public void EveryRuleTheDerivationNamesIsARealCard()
    {
        var cards = RuleCardIds();

        var unknown = DerivedAttributes()
            .SelectMany(d => NamedRules(d).Select(r => (d, r)))
            .Where(x => !cards.Contains(x.r))
            .Select(x => $"  {x.d.Name} names '{x.r}' (line {x.d.Line})")
            .ToList();

        Assert.True(
            unknown.Count == 0,
            Document + " names rules that have no card in docs/rules/:"
            + Environment.NewLine + string.Join(Environment.NewLine, unknown));
    }

    /// <summary>
    /// The three attributes F-S23-1 turned on are pinned, in the document and in the code together.
    /// Without this the finding is a paragraph, and a later session tidying the catalogue removes
    /// the attributes and leaves the paragraph describing a product that no longer exists.
    /// </summary>
    [Theory]
    [InlineData("operatingSystem", "SEC-091")]
    [InlineData("ms-Mcs-AdmPwdExpirationTime", "SEC-092")]
    [InlineData("msLAPS-PasswordExpirationTime", "SEC-092")]
    public void TheAttributesThatUnblockTheLapsRulesAreCapturedAndAttributed(
        string attribute, string rule)
    {
        Assert.Contains(
            CapturedAttributeCatalog.AttributesJustifiedBy("computer"),
            a => string.Equals(a.LdapDisplayName, attribute, StringComparison.OrdinalIgnoreCase));

        var row = DerivedAttributes()
            .SingleOrDefault(d => string.Equals(d.Name, attribute, StringComparison.OrdinalIgnoreCase));

        Assert.True(row is not null, $"{Document} has no derivation row for {attribute}.");
        Assert.Contains(rule, NamedRules(row!));
    }

    /// <summary>
    /// The scanner self-test. Without it every check above passes by parsing an empty table against
    /// a catalogue, or a catalogue against an empty table, and reporting a clean result either way -
    /// the failure this repository has committed three times, and the reason the markers exist.
    /// </summary>
    [Fact]
    public void TheCheckReadsBothTheDerivationAndTheCatalogue()
    {
        var derived = DerivedAttributes();

        Assert.True(derived.Count > 0, $"Read no derivation rows from {Document}.");
        Assert.True(CapturedAttributeCatalog.All.Count > 0, "The catalogue requests nothing.");

        // The column is genuinely read, and reading it is not trivially true. Requiring a row of
        // each kind would be the wrong self-test: a complete catalogue has no absent row, so that
        // form would oblige the product to stay incomplete in order to prove the check works.
        Assert.All(derived, d => Assert.False(string.IsNullOrWhiteSpace(d.InCatalogue)));
        Assert.Contains(derived, d => IsCaptured(d));
        Assert.False(IsCaptured(new DerivedAttribute("x", "absent", "-", 0)));
        Assert.True(IsCaptured(new DerivedAttribute("x", "yes (added here)", "-", 0)));

        // Rules are genuinely parsed out of the cell, and the em-dash that means "no rule" is
        // genuinely distinguished from a rule.
        Assert.Contains(derived, d => NamedRules(d).Count > 0);
        Assert.Contains(derived, d => NamedRules(d).Count == 0);

        Assert.True(RuleCardIds().Count > 0, "Read no rule cards from docs/rules/.");
    }

    private static bool IsCaptured(DerivedAttribute row) =>
        row.InCatalogue.Contains("yes", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The rule identifiers named in a row's prose. Extracted by pattern rather than by splitting,
    /// because the cell is a sentence as often as it is a list.
    /// </summary>
    private static List<string> NamedRules(DerivedAttribute row) =>
        RuleId().Matches(row.Rules).Select(m => m.Value).Distinct(StringComparer.Ordinal).ToList();

    private static Regex RuleId() => new(@"SEC-[0-9]{3}", RegexOptions.Compiled);

    private static HashSet<string> CatalogueNames() =>
        CapturedAttributeCatalog.All
            .Select(a => a.LdapDisplayName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Every rule the product has a card for, read from <c>docs/rules/</c> rather than listed.
    /// </summary>
    private static HashSet<string> RuleCardIds()
    {
        var directory = Path.Combine(RepositoryLocation.Root(), "docs", "rules");

        if (!Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException(
                "Expected the rule cards at " + directory + ". An absent folder must fail rather "
                + "than let every rule identifier through unchecked.");
        }

        return Directory
            .GetFiles(directory, "SEC-*.md")
            .Select(Path.GetFileNameWithoutExtension)
            .Where(id => id is not null && Regex.IsMatch(id, @"^SEC-[0-9]{3}$"))
            .ToHashSet(StringComparer.Ordinal)!;
    }

    /// <summary>
    /// The rows of the derivation table. Delimited by markers so that the other tables in the
    /// document - the rule shapes, the findings - are not read as though they were part of it.
    /// </summary>
    private static List<DerivedAttribute> DerivedAttributes()
    {
        var lines = File.ReadAllLines(DocumentPath());

        var begin = Array.FindIndex(lines, l => l.Trim() == TableBegin);
        var end = Array.FindIndex(lines, l => l.Trim() == TableEnd);

        if (begin < 0 || end < 0 || end < begin)
        {
            throw new InvalidOperationException(
                "Could not find the " + TableBegin + " / " + TableEnd + " markers in "
                + DocumentPath() + ". The checks parse only what lies between them, so a missing "
                + "marker must fail rather than silently widen or empty the scan.");
        }

        var rows = new List<DerivedAttribute>();

        for (var i = begin + 1; i < end; i++)
        {
            var cells = SplitRow(lines[i]);
            if (cells is null || cells.Length < 4)
                continue;

            if (cells[0] is "Attribute" || cells[0].All(c => c is '-' or ':'))
                continue;

            rows.Add(new DerivedAttribute(cells[0], cells[1], cells[2], i + 1));
        }

        return rows;
    }

    private static string[]? SplitRow(string line)
    {
        var trimmed = line.Trim();
        if (!trimmed.StartsWith('|') || !trimmed.EndsWith('|'))
            return null;

        return trimmed[1..^1].Split('|').Select(c => c.Trim().Trim('`')).ToArray();
    }

    private static string DocumentPath()
    {
        var path = Path.Combine(RepositoryLocation.Root(), "docs", "layers", "audit", Document);

        Assert.True(
            File.Exists(path),
            $"Expected the derivation document at {path}. Per docs/next/README.md a document is "
            + "not the new product's documentation until a test binds it to the code, so an absent "
            + "document fails rather than being skipped.");

        return path;
    }
}
