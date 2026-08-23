using System.Text.RegularExpressions;
using SecureAD.Audit.Capture;
using Xunit;
using SecureAD.Kernel.Capture;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/layers/audit/the-attribute-catalogue.md</c> to
/// <see cref="CapturedAttributeCatalog"/>.
///
/// <para>
/// This is inventory row B2's deliverable. The list of attributes is only data; the test is the thing
/// that makes the rule real, because the rule is <i>every attribute names something that reads
/// it</i>, and a catalogue without a check for that is a list somebody will add to.
/// </para>
/// <para>
/// <b>Only one of the two directions B2 owes is here.</b> The other - a rule that needs an
/// attribute the catalogue does not request fails the build - cannot be written yet, because the
/// rebuild has no rules. Walking an empty set of rules and reporting that none of them wants a
/// missing attribute would pass forever while measuring nothing, which is exactly how gate 5's
/// original wording came to pass against a tree in which nothing was used at all. So the split
/// follows gate 5's: B2a is here, B2b is owed by inventory row E16 and recorded as F-S7-24.
/// </para>
/// <para>
/// <b>What counts as a consumer changed on 2026-08-13, at S-23.</b> It was an inventory row and
/// nothing else, which bounded the catalogue by the port's progress rather than by the product:
/// almost no row is built, so almost nothing could be named, and
/// <c>F-S20-13</c> explained the resulting gaps as <i>"an attribute with no rule yet written was
/// correctly left out"</i>. The rules are written - sixty-two cards in <c>docs/rules/</c>, each
/// with the data it depends on. They are unported, not unwritten. So a <c>Read by</c> cell may
/// now name a <b>rule</b> - <c>SEC-091</c> - as well as an inventory row, and a named rule has to be
/// a card that exists, on the same terms as a named row having to be a real inventory row.
/// </para>
/// <para>
/// This does not weaken the rule the gate exists for. An attribute naming nothing is still dead
/// capture and still fails the build. What changes is that the answer to <i>what reads this?</i>
/// can now be the product rather than the plan.
/// </para>
/// <para>
/// <b>What it cannot check.</b> Whether the reason given for an attribute is a good reason, whether
/// the row named as its reader genuinely needs it, and whether one of the twelve attributes the
/// document records as deliberately dropped was dropped in error. Those need a reader.
/// </para>
/// <para>
/// <b>The decay guard was removed on 2026-08-16.</b> It read the inventory's <c>Status</c> column
/// and failed when a forecast row reached <c>Done</c>, on the reasoning that a promise must come
/// due. That column was dropped when the inventory became an inventory of the predecessor, and the
/// guard could not simply be re-anchored: it was measuring a scheduled finish date, and the work is
/// no longer scheduled. A subject is now chosen, the old application's documentation and this
/// catalogue are read as research, and what the attribute is for is settled then. Under that
/// process <i>an attribute nothing reads yet is the expected state</i>, not a defect, so a check
/// firing on it would report a fault that is not one.
/// </para>
/// <para>
/// <b>What that costs, recorded plainly.</b> Thirty-four entries forecast a reader and nothing now
/// makes anybody revisit them - see <c>F-S45-1</c>, raised in the session document
/// docs/next/sessions/S-45-demoting-the-ledger.md, since deleted, which listed them. The larger gap is not
/// this one: it is that nothing checks the opposite direction, whether something that needs an
/// attribute finds it captured. That is the direction with the one-way door in it, owed by row
/// <c>E16</c> and recorded as <c>F-S7-24</c> and <c>F-S44-2</c>.
/// </para>
/// </summary>
public sealed class CapturedAttributeCatalogDocumentationTests
{
    private const string Document = "the-attribute-catalogue.md";
    private const string TableBegin = "<!-- CATALOGUE:BEGIN -->";
    private const string TableEnd = "<!-- CATALOGUE:END -->";

    /// <summary>One row of the document's catalogue table.</summary>
    private sealed record DocumentedAttribute(
        string Name, string Cardinality, string Storage, string ReadBy, int Line);

    [Fact]
    public void TheDocumentDescribesEveryAttributeTheCatalogueRequests()
    {
        var documented = DocumentedNames();

        var missing = CapturedAttributeCatalog.All
            .Where(a => !documented.Contains(a.LdapDisplayName))
            .Select(a => "  " + a.LdapDisplayName)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "Attributes the product asks a domain controller for that " + Document + " does not "
            + "describe. Every attribute is bytes multiplied by object count in every bundle "
            + "forever, so one nobody can name a reader for is dead weight nobody will ever dare "
            + "remove:" + Environment.NewLine + string.Join(Environment.NewLine, missing));
    }

    [Fact]
    public void TheDocumentDescribesNoAttributeTheCatalogueDoesNotRequest()
    {
        var actual = CapturedAttributeCatalog.All
            .Select(a => a.LdapDisplayName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var phantom = DocumentedAttributes()
            .Where(d => !actual.Contains(d.Name))
            .Select(d => $"  {d.Name} (line {d.Line})")
            .Distinct(StringComparer.Ordinal)
            .ToList();

        Assert.True(
            phantom.Count == 0,
            Document + " describes attributes capture does not request. A document promising more "
            + "than the code collects is worse than no document, because a later session builds a "
            + "rule on one of them and finds the column empty:"
            + Environment.NewLine + string.Join(Environment.NewLine, phantom));
    }

    /// <summary>
    /// The rule this row exists for. <c>Read by</c> may not be blank, and it may not be a dash.
    /// </summary>
    [Fact]
    public void EveryAttributeNamesSomethingThatReadsIt()
    {
        var unread = DocumentedAttributes()
            .Where(d => Readers(d).Count == 0)
            .Select(d => $"  {d.Name} (line {d.Line})")
            .ToList();

        Assert.True(
            unread.Count == 0,
            "Attributes in " + Document + " with nothing named as reading them. \"The previous "
            + "product had it\" is not a consumer. An attribute that cannot name one does not go "
            + "in, because a bundle captured without an attribute cannot gain it and a bundle "
            + "captured with a useless one carries it forever:"
            + Environment.NewLine + string.Join(Environment.NewLine, unread));
    }

    /// <summary>
    /// Every reader a documented attribute names has to be a real rule card, or one of the
    /// eighteen old-application components listed below. A promise pointing at nothing can never
    /// come due, which is how an exemption becomes permanent.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This check is weaker than it looks, and the weakness is deliberate and temporary.</b>
    /// A reader used to be validated against the old application's inventory, which was archived
    /// along with the component map behind it. Eighteen of the catalogue's readers are not rule
    /// cards at all: they are components of the predecessor - <c>J34</c> was its object inspector,
    /// <c>E19</c> its object-attribute rules. So a large part of what this product captures is
    /// justified by what the old product did with the value, not by any rule this one has.
    /// </para>
    /// <para>
    /// Listing them here keeps the guard doing its real job - a mistyped rule identifier still
    /// fails - without pretending the eighteen are justified. <c>docs/decisions/0064</c> says an
    /// attribute is justified by a rule or by the object view, and re-justifying these against
    /// that record is work this session did not do.
    /// </para>
    /// </remarks>
    [Fact]
    public void EveryReaderNamedIsARealRuleCardOrANamedLegacyComponent()
    {
        var known = new HashSet<string>(RuleCardIds(), StringComparer.Ordinal);
        foreach (var legacy in LegacyComponentReaders) known.Add(legacy);

        var unknown = DocumentedAttributes()
            .SelectMany(d => Readers(d).Select(r => (d, r)))
            .Where(x => !known.Contains(x.r))
            .Select(x => $"  {x.d.Name} names '{x.r}' (line {x.d.Line})")
            .ToList();

        Assert.True(
            unknown.Count == 0,
            Document + " names readers that are neither rule cards in docs/rules/ nor one of the "
            + "listed old-application components. A consumer that does not exist is "
            + "indistinguishable from no consumer at all, and a typo in a rule identifier would "
            + "otherwise read as a satisfied promise:"
            + Environment.NewLine + string.Join(Environment.NewLine, unknown));
    }

    /// <summary>
    /// The old application's components the catalogue still cites as readers, with what each one
    /// was. Closed and explicit so that adding a nineteenth is a deliberate act.
    /// </summary>
    private static readonly string[] LegacyComponentReaders =
    [
        "B2", "B4", "B6", "B8",
        "B11",  // Group membership writer and unresolved-member classification
        "B12",  // Principal resolution writer
        "B13",
        "B20",  // Capture run bookkeeping and guards
        "D3",
        "E16", "E18",
        "E19",  // Object-attribute rules
        "E20", "E21", "E22",
        "J33",  // ACE decoding and trustee aggregation
        "J34",  // Object inspector
        "K16",
    ];

    /// <summary>
    /// Cardinality decides whether a value is range-retrieved and storage decides whether it is
    /// read as bytes. Both are load-bearing, so the document may not describe one thing and the
    /// code do another.
    /// </summary>
    [Fact]
    public void TheDocumentAgreesWithTheCodeOnCardinalityAndStorage()
    {
        var actual = CapturedAttributeCatalog.All
            .ToDictionary(a => a.LdapDisplayName, a => a, StringComparer.OrdinalIgnoreCase);

        var wrong = DocumentedAttributes()
            .Where(d => actual.ContainsKey(d.Name))
            .Where(d => actual[d.Name].Cardinality.ToString() != d.Cardinality
                        || actual[d.Name].Storage.ToString() != d.Storage)
            .Select(d => $"  {d.Name}: document says {d.Cardinality}/{d.Storage}, code says "
                         + $"{actual[d.Name].Cardinality}/{actual[d.Name].Storage} (line {d.Line})")
            .ToList();

        Assert.True(
            wrong.Count == 0,
            Document + " disagrees with the catalogue. A multi-valued attribute described as "
            + "single-valued is one nobody range-retrieves, which silently truncates it, and a "
            + "binary attribute described as text is one somebody reads as a mangled string:"
            + Environment.NewLine + string.Join(Environment.NewLine, wrong));
    }

    /// <summary>
    /// Every public type in the capture subsystem is named by one of the capture documents.
    ///
    /// <para>
    /// Widened on 2026-08-11, from "named by S-8" to "named by S-8, S-9 or S-10", and again the
    /// same day for S-11. The rule being enforced never changed - every public type in the
    /// component has to be described somewhere a reader will find it - only the set of places that
    /// count grew with the component.
    /// </para>
    /// <para>
    /// <b>Corrected during the documentation rewrite, and the correction is the point.</b> This
    /// scanned <c>typeof(CapturedAttributeCatalog).Assembly</c> filtered to
    /// <see cref="CatalogueNamespace"/>, which is <c>SecureAD.Kernel</c> and four types. Its name
    /// and its failure message both said <i>the capture project</i>. The fifteen public types in
    /// <c>SecureAD.Audit.Capture</c> - the capture project - were never looked at, so the check was
    /// green while covering four types out of nineteen.
    /// </para>
    /// <para>
    /// The fault arrived by repair. S-24 moved the catalogue into the kernel, this check failed
    /// loudly, and the fix pointed the scan at the catalogue's <i>new neighbours</i> rather than at
    /// the component the test is named for - a different set, checked against the same document,
    /// passing. That is the shape <c>.github/copilot-instructions.md</c> names first: a check that
    /// passes while measuring nothing. Both namespaces are now scanned, and
    /// <see cref="TheScanReadsBothNamespacesAndNotOnlyTheCatalogue"/> is the self-test that would
    /// notice either half going quiet.
    /// </para>
    /// </summary>
    [Fact]
    public void EveryPublicTypeInTheCaptureProjectIsNamedByACaptureDocument()
    {
        var text = string.Join(Environment.NewLine, CaptureDocuments.Select(ReadSlice));

        var missing = PublicTypeNames()
            .Where(name => !text.Contains($"`{name}`", StringComparison.Ordinal))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"No capture document names: {string.Join(", ", missing)}. A type the "
            + "documentation does not mention is a piece of the component nobody reading it knows "
            + $"exists. The documents are {string.Join(", ", CaptureDocuments)}.");
    }

    /// <summary>
    /// The self-test for the check above. Without it, a scan that had quietly stopped seeing one of
    /// the two namespaces would report every type accounted for - which is exactly what happened
    /// between S-24 and the documentation rewrite.
    /// </summary>
    [Fact]
    public void TheScanReadsBothNamespacesAndNotOnlyTheCatalogue()
    {
        var names = PublicTypeNames().ToList();

        Assert.True(
            names.Count >= 15,
            $"Reflected over {names.Count} public types across {CatalogueNamespace} and "
            + $"{CaptureNamespace}, expected at least fifteen. A shrinking scan is how this check "
            + "came to cover four types while claiming the capture project.");

        Assert.Contains("CapturedAttributeCatalog", names);
        Assert.Contains("PartitionCapture", names);
        Assert.Contains("CaptureSearchRequestFactory", names);
        Assert.Contains("RetryPolicy", names);
    }

    /// <summary>
    /// The classes are half the catalogue. The exclusions are the more important half: an inclusion
    /// list that happens not to mention DNS is a silence, and a named exclusion is something a
    /// report can print.
    /// </summary>
    [Fact]
    public void TheDocumentNamesTheObjectClassesAndTheExclusions()
    {
        var text = Read();

        var missing = CapturedAttributeCatalog.ObjectClasses
            .Concat(CapturedAttributeCatalog.UnreadObjectClasses)
            .Where(name => !text.Contains($"`{name}`", StringComparison.Ordinal))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not name these object classes: {string.Join(", ", missing)}. What "
            + "capture reads and what it deliberately does not are both statements the product "
            + "makes to a customer.");
    }

    /// <summary>
    /// A bundle records the catalogue version so it can say, years later, what it was allowed to
    /// see. A document describing a different version describes a different bundle.
    /// </summary>
    [Fact]
    public void TheDocumentStatesTheCatalogueVersion()
    {
        Assert.Contains(
            $"version {CapturedAttributeCatalog.Version}",
            Read(),
            StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The scanner self-test. Without it every check above passes by comparing an empty catalogue
    /// against an empty table and finding nothing wrong with either - which is the worst thing a
    /// check can do, and which this repository has done three times.
    /// </summary>
    [Fact]
    public void TheCheckReadsBothTheCatalogueAndTheDocument()
    {
        var documented = DocumentedAttributes();

        Assert.True(
            CapturedAttributeCatalog.All.Count > 0,
            "The catalogue requests no attributes at all.");
        Assert.True(documented.Count > 0, $"Read no attribute rows from {Document}.");

        Assert.Contains(CapturedAttributeCatalog.All, a => a.LdapDisplayName == "member");
        Assert.Contains(documented, d => d.Name == "member");
        Assert.Contains(documented, d => Readers(d).Count > 0);
        Assert.Contains(documented, d => d.Storage == nameof(AttributeStorage.Binary));
        Assert.Contains(documented, d => d.Cardinality == nameof(AttributeCardinality.MultiValued));

        // Both kinds of consumer are genuinely parsed. Without these two, the widening of
        // 2026-08-13 could be undone by a document that names only inventory rows, or by a
        // regular expression that matched no rule identifier, and every check above would go on
        // passing while the thing they were widened for measured nothing.
        Assert.Contains(documented, d => InventoryReaders(d).Count > 0);
        Assert.Contains(documented, d => Readers(d).Any(r => RuleId().IsMatch(r)));

        var rules = RuleCardIds();
        Assert.True(rules.Count > 0, "Read no rule cards from docs/rules/.");
        Assert.Contains("SEC-091", rules);
    }

    /// <summary>
    /// The readers named on one row. A dash or an empty cell is no reader, deliberately, so the
    /// usual markdown way of writing "none" cannot slip past the rule.
    /// </summary>
    private static List<string> Readers(DocumentedAttribute row) =>
        row.ReadBy
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(r => r != "-" && r.Length > 0)
            .ToList();

    /// <summary>
    /// The readers on one row that name an inventory row rather than a rule card. Kept so the
    /// scanner self-test can prove both kinds of consumer are genuinely parsed.
    /// </summary>
    private static List<string> InventoryReaders(DocumentedAttribute row) =>
        Readers(row).Where(r => !RuleId().IsMatch(r)).ToList();

    /// <summary>A rule identifier as the cards spell it: <c>SEC-091</c>.</summary>
    private static Regex RuleId() => new(@"^SEC-[0-9]{3}$", RegexOptions.Compiled);

    /// <summary>
    /// Every rule the product has a card for, read from <c>docs/rules/</c> rather than listed, so
    /// that a card added or renamed moves this set without anybody editing the test.
    /// </summary>
    private static HashSet<string> RuleCardIds()
    {
        var directory = Path.Combine(RepositoryLocation.Root(), "docs", "rules");

        if (!Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException(
                "Expected the rule cards at " + directory + ". A consumer named as a rule is "
                + "checked against the cards on disk, so an absent folder must fail rather than "
                + "let every rule identifier through unchecked.");
        }

        return Directory
            .GetFiles(directory, "SEC-*.md")
            .Select(f => Path.GetFileNameWithoutExtension(f))
            .Where(id => RuleId().IsMatch(id))
            .ToHashSet(StringComparer.Ordinal);
    }

    private static HashSet<string> DocumentedNames() =>
        DocumentedAttributes().Select(d => d.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The rows of the document's catalogue tables. The section is delimited by markers so that a
    /// table elsewhere in the document - the twelve attributes deliberately not carried, in
    /// particular - is not read as though it were part of the catalogue.
    /// </summary>
    private static List<DocumentedAttribute> DocumentedAttributes()
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

        var rows = new List<DocumentedAttribute>();

        for (var i = begin + 1; i < end; i++)
        {
            var cells = SplitRow(lines[i]);
            if (cells is null || cells.Length < 5)
                continue;

            if (cells[0] is "Attribute" || cells[0].All(c => c is '-' or ':'))
                continue;

            rows.Add(new DocumentedAttribute(cells[0], cells[1], cells[2], cells[3], i + 1));
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

    /// <summary>
    /// The public types the capture slice documents must account for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The scope is named, not derived from a type.</b> This read
    /// <c>typeof(CapturedAttributeCatalog).Assembly</c> and <c>.Namespace</c> until 2026-08-13, so
    /// the gate followed the catalogue wherever it went. When S-24 moved the catalogue into the
    /// kernel, the scan became <i>every public type beside it in its new home</i> - a different set,
    /// checked against the same document.
    /// </para>
    /// <para>
    /// That failed loudly and immediately, which is the point worth recording: the move broke this
    /// check and two in <c>SchemaGuidDocumentationTests</c> on the first run, because a binding that
    /// runs in both directions cannot quietly change its subject. Naming the namespace as a string
    /// is still better - it costs a compile-time reference and buys a failure that says what
    /// happened rather than one that has to be worked out.
    /// </para>
    /// </remarks>
    private const string CatalogueNamespace = "SecureAD.Kernel.Capture";

    /// <summary>
    /// The other half of the capture subsystem, and the half this scan used to miss entirely. It is
    /// a different assembly from <see cref="CatalogueNamespace"/>, which is why omitting it was
    /// invisible: a single-assembly scan cannot report that it looked in one place.
    /// </summary>
    private const string CaptureNamespace = "SecureAD.Audit.Capture";

    private static IEnumerable<string> PublicTypeNames() =>
        typeof(CapturedAttributeCatalog).Assembly
            .GetExportedTypes()
            .Where(t => t.Namespace == CatalogueNamespace)
            .Concat(typeof(PartitionCapture).Assembly
                .GetExportedTypes()
                .Where(t => t.Namespace == CaptureNamespace))
            .Where(t => !t.IsNested)
            .Select(t => t.Name);

    private static string DocumentPath() =>
        Path.Combine(RepositoryLocation.Root(), "docs", "layers", "audit", Document);

    /// <summary>
    /// The documents describing the capture subsystem. Named explicitly rather than discovered by
    /// pattern, so that a new one is added here deliberately and a deleted one fails.
    /// </summary>
    private static readonly string[] CaptureDocuments =
    [
        Document,
        "the-search-capture-issues.md",
        "limits-and-failures.md",
        "how-a-controller-is-read.md",
    ];

    private static string ReadSlice(string slice)
    {
        var path = Path.Combine(RepositoryLocation.Root(), "docs", "layers", "audit", slice);

        Assert.True(
            File.Exists(path),
            $"Expected the capture slice document at {path}. Per docs/next/README.md a document is "
            + "not the new product's documentation until a test binds it to the code, so an absent "
            + "document fails rather than being skipped.");

        return File.ReadAllText(path);
    }

    private static string Read()
    {
        var path = DocumentPath();

        Assert.True(
            File.Exists(path),
            $"Expected the catalogue document at {path}. Per docs/next/README.md a document is not "
            + "the new product's documentation until a test binds it to the code, so an absent "
            + "document fails rather than being skipped.");

        return File.ReadAllText(path);
    }
}
