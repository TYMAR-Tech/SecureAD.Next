using System.Reflection;
using SecureAD.Kernel.Schema;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/layers/schema/what-a-schema-guid-means.md</c> to the code it describes.
/// </summary>
/// <remarks>
/// <para>
/// Retargeted from <c>docs/next/S-3-schema-guid-catalogue.md</c>, which this document consumed and
/// which is deleted. The retarget was proven rather than assumed: the gate was pointed at the
/// document the tables had left and produced failures naming the tables it could not find, rather
/// than passing against an empty scan.
/// </para>
/// <para>
/// <b>Two checks from the slice document were dropped, and the reason matters more than the
/// deletion.</b> <c>TheDocumentHandsEveryPreviouslyDangerousNameOnToTheNextRow</c> and
/// <c>TheHandoverNamesARealInventoryRow</c> existed because the danger flag was deliberately left
/// behind and no component had yet taken it, so the document was the only place the nine names were
/// written down. That row has since shipped as <c>DangerousPermissionClassifier</c>, documented at
/// <c>docs/layers/kernel/permission-classification.md</c> and bound by its own gate. Keeping a check whose
/// stated purpose has been served elsewhere is how a suite comes to measure something other than
/// its name.
/// </para>
/// <para>
/// <b>What replaced them is stronger.</b> The kind table's counts are compared against the shipped
/// catalogue rather than read as prose, so a row added to the code without the document being
/// updated fails here — which is the drift a hand-counted table cannot catch.
/// </para>
/// <para>
/// What it cannot check is whether the explanation of where the line between data and
/// classification falls is any good. That needs a reader.
/// </para>
/// </remarks>
public sealed class SchemaGuidDocumentationTests
{
    private const string Document = "what-a-schema-guid-means.md";

    [Fact]
    public void TheDocumentNamesEveryPublicTypeInTheComponent()
    {
        var text = Read();

        var missing = PublicTypeNames()
            .Where(name => !text.Contains(Quoted(name), StringComparison.Ordinal))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not name: {string.Join(", ", missing)}. A type the documentation "
            + "does not mention is a piece of the component nobody reading it knows exists.");
    }

    /// <summary>
    /// Every member a caller can reach is described, with what it gives back when it knows
    /// nothing. An unknown GUID and an unknown name answer differently, and a caller that guesses
    /// which convention a member follows is a caller that will read an absent answer as a present
    /// one.
    /// </summary>
    [Fact]
    public void TheDocumentNamesEveryPublicMemberOfTheComponent()
    {
        var text = Read();

        var missing = PublicMemberNames()
            .Where(name => !text.Contains(Quoted(name), StringComparison.Ordinal))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not describe: {string.Join(", ", missing)}. Every member a caller "
            + "can reach needs its absent-input answer stated, or the caller guesses.");
    }

    /// <summary>
    /// The types table lists the component and nothing else, in both directions.
    /// </summary>
    [Fact]
    public void TheTypesTableAndTheComponentAgree()
    {
        var documented = FirstColumn("TYPES").ToHashSet(StringComparer.Ordinal);
        var actual = PublicTypeNames().ToHashSet(StringComparer.Ordinal);

        Assert.Equal(
            actual.OrderBy(n => n, StringComparer.Ordinal),
            documented.OrderBy(n => n, StringComparer.Ordinal));
    }

    /// <summary>
    /// The member table lists every reachable member and invents none, in both directions. The
    /// slice document's guard asked only whether a name appeared <i>anywhere</i> on the page, and
    /// its own mutation record noted that a member could therefore be dropped from the shape table
    /// and stay "described" by a passing mention elsewhere. Reading the marked table closes that.
    /// </summary>
    [Fact]
    public void TheMemberTableAndTheComponentAgree()
    {
        var documented = FirstColumn("MEMBERS").ToHashSet(StringComparer.Ordinal);
        var actual = PublicMemberNames().ToHashSet(StringComparer.Ordinal);

        var undocumented = actual.Except(documented).OrderBy(n => n, StringComparer.Ordinal).ToList();
        var invented = documented.Except(actual).OrderBy(n => n, StringComparer.Ordinal).ToList();

        Assert.True(
            undocumented.Count == 0 && invented.Count == 0,
            $"The MEMBERS table in {Document} disagrees with the component. Missing from the "
            + $"table: {Describe(undocumented)}. Named by the table but not on the type: "
            + $"{Describe(invented)}.");
    }

    /// <summary>
    /// Every kind the enum declares has a row, and the row's count is the number of shipped
    /// entries of that kind.
    /// </summary>
    /// <remarks>
    /// The counts are the part worth checking. A document that states how many extended rights the
    /// product ships is making a claim nobody re-reads, and the shipped table is edited by hand -
    /// which is exactly how eleven of its entries came to be wrong while every test passed.
    /// </remarks>
    [Fact]
    public void TheKindTableCountsWhatTheCatalogueActuallyShips()
    {
        var documented = TableRows("KINDS")
            .Select(Cells)
            .ToDictionary(c => c[0].Trim('`'), c => int.Parse(c[1]), StringComparer.Ordinal);

        var actual = Enum.GetValues<SchemaGuidKind>()
            .ToDictionary(
                k => k.ToString(),
                k => SchemaGuidCatalog.Embedded.Entries.Count(e => e.Kind == k),
                StringComparer.Ordinal);

        var wrong = actual
            .Where(a => !documented.TryGetValue(a.Key, out var claimed) || claimed != a.Value)
            .Select(a => $"{a.Key}: document says "
                + (documented.TryGetValue(a.Key, out var c) ? c.ToString() : "nothing")
                + $", the catalogue ships {a.Value}")
            .ToList();

        Assert.True(
            wrong.Count == 0,
            $"The KINDS table in {Document} does not match the shipped catalogue:"
            + Environment.NewLine + string.Join(Environment.NewLine, wrong));

        Assert.Equal(
            actual.Keys.OrderBy(k => k, StringComparer.Ordinal),
            documented.Keys.OrderBy(k => k, StringComparer.Ordinal));
    }

    /// <summary>
    /// The total the prose states is the total the catalogue holds. Written out because a reader
    /// takes a headline number on trust in a way they do not take a table.
    /// </summary>
    [Fact]
    public void TheDocumentStatesTheRowCountTheCatalogueActuallyHas()
    {
        var rows = SchemaGuidCatalog.Embedded.Entries.Count;
        var distinct = SchemaGuidCatalog.Embedded.Entries
            .Select(e => e.Guid)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        Assert.Contains($"**{rows} rows over {distinct} distinct GUIDs.**", Read(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The other direction. The two fields deliberately left behind are discussed by name, so the
    /// document must name them as absent rather than list them among the members.
    /// </summary>
    [Fact]
    public void TheDocumentDoesNotPresentTheLeftBehindFieldsAsMembers()
    {
        var text = Read();
        var actual = PublicMemberNames().ToHashSet(StringComparer.Ordinal);
        var documented = FirstColumn("MEMBERS").ToHashSet(StringComparer.Ordinal);

        string[] leftBehind = ["IsDangerous", "DisplayName"];

        foreach (var name in leftBehind)
        {
            Assert.False(actual.Contains(name), $"{name} is on the type; this check is stale.");

            Assert.True(
                text.Contains(Quoted(name), StringComparison.Ordinal),
                $"{Document} does not mention {name}. Both fields were dropped on purpose, and a "
                + "reader who does not find out why will put one back.");

            Assert.False(
                documented.Contains(name),
                $"{Document} lists {name} in the MEMBERS table, which the component does not have.");
        }
    }

    /// <summary>
    /// The boundary ruling, held open. <c>CapturedSchemaGuidReader</c> is the only producer of
    /// captured entries and this document names it, but it lives in <c>SecureAD.Evidence</c> and
    /// belongs to that layer's documents. It must stay out of the component tables here: a type
    /// bound by two layer documents is the failure that split <c>S-18</c>, and once a name is in a
    /// component table a later Evidence pass has no way to see that it was already taken.
    /// </summary>
    [Fact]
    public void TheEvidenceReaderIsNamedButNotClaimedByThisLayer()
    {
        const string reader = "CapturedSchemaGuidReader";

        Assert.Contains(Quoted(reader), Read(), StringComparison.Ordinal);
        Assert.DoesNotContain(reader, FirstColumn("TYPES"));
        Assert.DoesNotContain(reader, FirstColumn("MEMBERS"));
    }

    /// <summary>
    /// The document states where the component lands, and the code is there. Both tables this
    /// folder replaced were filed under folders named for a shape rather than a subject, which is a
    /// large part of why neither author found the other's.
    /// </summary>
    [Fact]
    public void TheDocumentStatesTheNamespaceTheCodeDeclares()
    {
        Assert.Contains($"`{typeof(SchemaGuidCatalog).Namespace}`", Read(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The scanner self-test. Without it every assertion above passes by searching an empty string
    /// and reflecting over an empty set, and finding nothing wrong with either.
    /// </summary>
    [Fact]
    public void TheCheckFindsBothTheDocumentAndTheComponent()
    {
        Assert.True(File.Exists(Path()), $"Expected the layer document at {Path()}.");
        Assert.True(Read().Length > 1000, $"{Document} is too short to be the document it claims.");
        Assert.Contains(nameof(SchemaGuidCatalog), PublicTypeNames());
        Assert.Contains(nameof(SchemaGuidCatalog.GuidFor), PublicMemberNames());
        Assert.NotEmpty(TableRows("TYPES"));
        Assert.NotEmpty(TableRows("MEMBERS"));
        Assert.NotEmpty(TableRows("KINDS"));
    }

    /// <summary>
    /// A marker block that is not there is a failure and never an empty result. A gate left
    /// pointing at a document whose table has moved elsewhere must say so. Two gates in this
    /// repository have already passed for months while measuring nothing.
    /// </summary>
    [Fact]
    public void AMissingTableIsAFailureRatherThanAnEmptyScan()
    {
        var thrown = Record.Exception(() => TableRows("SHAPE"));

        Assert.NotNull(thrown);
    }

    /// <summary>
    /// The scan reports an absent name as missing. Run over an invented member, so it proves the
    /// search works without the document having to be broken to prove it.
    /// </summary>
    [Fact]
    public void TheCheckReportsANameThatIsAbsent()
    {
        Assert.DoesNotContain(Quoted("FindByQuantumFlux"), Read(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The scan is not a bare substring search. Mutation-testing the equivalent guard in session
    /// S-2 found that it was: a member renamed by appending two characters still matched the
    /// document, so the check reported nothing missing while the document named nothing that
    /// existed. The backticked form makes the match exact without needing a parser, and also keeps
    /// <c>FindByGuid</c> from being satisfied by the entry for <c>FindByLdapName</c>.
    /// </summary>
    [Fact]
    public void TheCheckIsNotSatisfiedByANameThatMerelyContainsTheMemberName()
    {
        var text = Read();

        Assert.DoesNotContain(Quoted(nameof(SchemaGuidCatalog.GuidFor) + "XX"), text, StringComparison.Ordinal);
        Assert.Contains(Quoted(nameof(SchemaGuidCatalog.GuidFor)), text, StringComparison.Ordinal);
    }

    // --- helpers -----------------------------------------------------------------------------------

    private static string Describe(List<string> names) =>
        names.Count == 0 ? "none" : string.Join(", ", names);

    private static string Quoted(string name) => "`" + name + "`";

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

    private static IEnumerable<string> PublicTypeNames() =>
        typeof(SchemaGuidCatalog).Assembly
            .GetExportedTypes()
            .Where(t => t.Namespace == typeof(SchemaGuidCatalog).Namespace)
            .Select(t => t.Name);

    /// <summary>
    /// Every member a caller can reach and an author wrote.
    ///
    /// <para>
    /// Enum types are excluded: their members are the vocabulary <c>SchemaGuidKind</c> already
    /// documents as a whole, and reflecting over one also yields the machinery every enum has.
    /// Property accessors and the members the compiler writes for a record are excluded for the
    /// same reason - a document naming <c>get_Entries</c> would be describing the compiler.
    /// </para>
    /// </summary>
    private static IEnumerable<string> PublicMemberNames() =>
        typeof(SchemaGuidCatalog).Assembly
            .GetExportedTypes()
            .Where(t => t.Namespace == typeof(SchemaGuidCatalog).Namespace)
            .Where(t => !t.IsEnum)
            .SelectMany(t => t.GetMembers(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance))
            .Where(m => m.DeclaringType != typeof(object))
            .Where(m => m.MemberType is MemberTypes.Method or MemberTypes.Property or MemberTypes.Field)
            .Where(m => m is not MethodInfo method || !method.IsSpecialName)
            .Select(m => m.Name)
            .Where(name => !name.Contains('<', StringComparison.Ordinal))
            .Where(name => !Compiler.Contains(name))
            .Distinct(StringComparer.Ordinal);

    /// <summary>
    /// Names the compiler generates for a record, which no author wrote and no reader would look
    /// for.
    /// </summary>
    private static readonly HashSet<string> Compiler = new(StringComparer.Ordinal)
    {
        "Equals", "GetHashCode", "ToString", "Deconstruct", "Clone", "op_Equality", "op_Inequality",
        "EqualityContract",
    };

    private static string Path() =>
        System.IO.Path.Combine(RepositoryLocation.Root(), "docs", "layers", "schema", Document);

    private static string Read() => File.ReadAllText(Path());
}
