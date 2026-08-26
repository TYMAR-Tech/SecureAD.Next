using System.Reflection;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/layers/evidence/what-an-object-holds.md</c> to the code it describes.
///
/// <para>
/// The storage table is bound <b>in both directions</b>, and against values produced by writing a
/// real bundle and reading it back rather than against the reader's source. A storage kind the
/// code handles and the page does not name fails the build, and so does a row on the page
/// describing a shape the reader never produces.
/// </para>
/// <para>
/// The page exists because <c>ObjectAttributes</c>, <c>ObjectAttribute</c> and
/// <c>AttributeValue</c> were named by no layer document at all, which left their rows in
/// <c>docs/next/SURFACE-REGISTER.md</c> with nowhere to point. It was the last thing blocking
/// the deletion of docs/areas/what-we-capture.md, which went on 2026-08-22.
/// </para>
/// </summary>
public sealed class ObjectAttributesDocumentationTests : IDisposable
{
    private const string Document = "what-an-object-holds.md";

    /// <summary>
    /// The types this page is the description of. The catalogue's own vocabulary -
    /// <c>AttributeCardinality</c>, <c>AttributeStorage</c>, <c>CapturedAttribute</c> - is
    /// deliberately absent: what this build asks for belongs to
    /// <c>the-attribute-catalogue.md</c>, and a component listed in two documents is one question
    /// answered twice.
    /// </summary>
    private static readonly Type[] TheComponent =
    [
        typeof(ObjectAttributes),
        typeof(ObjectAttribute),
        typeof(AttributeValue),
        typeof(BundleObjects),
    ];

    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securead-attribute-doc-" + Guid.NewGuid().ToString("N"));

    private static readonly DateTimeOffset Started = new(2026, 9, 13, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 9, 13, 11, 30, 0, TimeSpan.Zero);

    private const string DomainDn = "DC=contoso,DC=com";
    private const string AliceDn = "CN=Alice," + DomainDn;

    // --- the component, both directions --------------------------------------------------------

    [Fact]
    public void TheDocumentNamesEveryPublicTypeInTheComponent()
    {
        var mentioned = Mentioned();

        var missing = TheComponent
            .Select(t => t.Name)
            .Where(name => !mentioned.Contains(name))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not name: {string.Join(", ", missing)}. A type the documentation "
            + "does not mention is a piece of the component nobody reading it knows exists.");
    }

    [Fact]
    public void TheDocumentNamesEveryPublicMemberOfTheComponent()
    {
        var standalone = MentionedStandalone();
        var qualified = MentionedQualified();

        var missing = PublicMemberNames()
            .Where(pair => !standalone.Contains(pair.Member))
            .Where(pair => !qualified.Contains(pair.Type + "." + pair.Member))
            .Select(pair => $"{pair.Type}.{pair.Member}")
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not describe: {string.Join(", ", missing)}. Every member a caller "
            + "can reach is a way to ask one of this component's questions, and one that is not "
            + "written down is one a caller has to guess the meaning of.");
    }

    /// <summary>
    /// The direction a one-way gate never has. Every <c>Type.Member</c> the page writes in
    /// backticks must resolve, so a member that was renamed or never existed fails here rather
    /// than sitting in a bound document reading like fact.
    /// </summary>
    [Fact]
    public void EveryQualifiedMentionResolvesToARealMember()
    {
        var byName = TheComponent.ToDictionary(t => t.Name, StringComparer.Ordinal);

        var real = PublicMemberNames()
            .Select(pair => pair.Type + "." + pair.Member)
            .ToHashSet(StringComparer.Ordinal);

        var invented = Mentioned()
            .Where(token => token.Contains('.', StringComparison.Ordinal))
            .Where(token => !token.EndsWith(".cs", StringComparison.Ordinal))
            .Where(token => byName.ContainsKey(token.Split('.')[0]))
            .Where(token => !real.Contains(token))
            .ToList();

        Assert.True(
            invented.Count == 0,
            $"{Document} names members that do not exist: {string.Join(", ", invented)}.");
    }

    // --- the ownership claim, both directions --------------------------------------------------

    /// <summary>
    /// The page's <c>TYPES</c> table is what makes it the owner of these three rather than merely
    /// a page that names them, and <c>docs/next/SURFACE-REGISTER.md</c> points its rows at the
    /// owner. Measured 2026-08-22: anchored to mentions, seven of the 31 types the register then
    /// keyed to docs/areas/what-we-capture.md had two to four claimants; anchored to this table,
    /// none had two.
    /// </summary>
    [Fact]
    public void ThePageClaimsEveryPublicTypeInTheComponent()
    {
        var claimed = DeclaredTypes();

        var missing = TheComponent
            .Select(t => t.Name)
            .Where(name => !claimed.Contains(name))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not claim: {string.Join(", ", missing)}. A type no page claims is "
            + "surface nobody owns, which is what the register exists to prevent.");
    }

    [Fact]
    public void ThePageClaimsNothingThatIsNotPartOfTheComponent()
    {
        var real = TheComponent.Select(t => t.Name).ToHashSet(StringComparer.Ordinal);

        var invented = DeclaredTypes()
            .Where(name => !real.Contains(name))
            .ToList();

        Assert.True(
            invented.Count == 0,
            $"{Document} claims types it does not describe: {string.Join(", ", invented)}. Two "
            + "pages claiming one type leaves a reader unable to tell which owns it.");
    }

    // --- the storage table, both directions ----------------------------------------------------

    [Fact]
    public void EveryStorageKindTheCodeHandlesIsInTheDocument()
    {
        var documented = StorageTable().Keys;

        var missing = Enum.GetNames<AttributeStorage>()
            .Where(name => !documented.Contains(name, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not list: {string.Join(", ", missing)}. A way a value can be stored "
            + "that nobody wrote down is one nobody chose the handling of.");
    }

    [Fact]
    public void EveryStorageKindInTheDocumentIsOneTheCodeHandles()
    {
        var real = Enum.GetNames<AttributeStorage>();

        var invented = StorageTable().Keys
            .Where(name => !real.Contains(name, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            invented.Count == 0,
            $"{Document} describes storage that cannot arise: {string.Join(", ", invented)}.");
    }

    /// <summary>
    /// The part a reader acts on: which of the two halves of a value is empty. Text read back as
    /// bytes, or bytes read back as text, is the confusion this component exists to prevent, so
    /// the page's claim is compared against a value the reader actually produced.
    /// </summary>
    [Fact]
    public void TheDocumentedEmptyHalfIsTheHalfTheCodeLeavesEmpty()
    {
        var documented = StorageTable();

        foreach (var (storage, value) in ValuesTheCodeProduces())
        {
            Assert.True(
                documented.TryGetValue(storage.ToString(), out var claimed),
                $"{Document} does not list {storage}.");

            Assert.Equal(
                value.Text is null,
                string.Equals(claimed.Text, "null", StringComparison.Ordinal));

            Assert.Equal(
                value.Bytes is null,
                string.Equals(claimed.Bytes, "null", StringComparison.Ordinal));
        }
    }

    /// <summary>
    /// The fourth column is prose and is not parsed. What it claims is held instead by this
    /// assertion, which is about the product rather than about the page: bytes become characters
    /// in exactly one place, and say so by being uppercase hexadecimal.
    /// </summary>
    [Fact]
    public void ByteValuesAreStoredAsUppercaseHexadecimal()
    {
        WriteObject(Alice(Bytes("objectSid", [0x01, 0x02, 0xAB])));

        Assert.Equal("0102AB", Read()!.Find("objectSid")!.OnlyValue!.Stored);
    }

    // --- the vocabulary that lives elsewhere, and must not come back here -----------------------

    /// <summary>
    /// Which attributes this build asks for is <c>the-attribute-catalogue.md</c>'s, and the bundle
    /// tables are <c>what-a-bundle-holds.md</c>'s. Either table reappearing here would be a second
    /// description of one vocabulary.
    /// </summary>
    [Theory]
    [InlineData("CATALOGUE")]
    [InlineData("TABLES")]
    public void TheTablesThatBelongElsewhereAreNotDescribedHereAsWell(string marker)
    {
        Assert.DoesNotContain($"<!-- {marker}:BEGIN -->", ReadDocument(), StringComparison.Ordinal);
    }

    // --- scanner self-tests --------------------------------------------------------------------

    /// <summary>
    /// Without this the checks above could all pass by parsing an empty table and reflecting over
    /// an empty component, and find nothing wrong with either.
    /// </summary>
    [Fact]
    public void TheCheckFindsBothTheDocumentAndTheComponent()
    {
        Assert.True(File.Exists(DocumentPath()), $"Expected the document at {DocumentPath()}.");
        Assert.True(
            ReadDocument().Length > 1000,
            $"{Document} is too short to be the document it claims.");
        Assert.Equal(4, TheComponent.Length);
        Assert.True(
            PublicMemberNames().Count >= 14,
            "The reflection scan found fewer members than the component declares.");
        Assert.Contains(nameof(ObjectAttribute.OnlyValue), Mentioned());
        Assert.True(Mentioned().Count > 20, "The mention scan found almost nothing to check against.");
        Assert.Equal(Enum.GetValues<AttributeStorage>().Length, StorageTable().Count);
        Assert.Equal(TheComponent.Length, DeclaredTypes().Count);
    }

    /// <summary>
    /// A marker block that is not there is a failure and never an empty result. Without this the
    /// storage checks could all pass against a table that had been moved to another document,
    /// finding nothing wrong because they found nothing at all.
    /// </summary>
    [Fact]
    public void AMissingTableIsAFailureRatherThanAnEmptyScan()
    {
        Assert.NotNull(Record.Exception(() => TableRows("CATALOGUE")));
    }

    [Fact]
    public void TheCheckReportsANameThatIsAbsent()
    {
        Assert.DoesNotContain("StoredByQuantumFlux", Mentioned());
    }

    /// <summary>
    /// The scan is not a bare substring search. A member renamed by appending two characters must
    /// not still match, which is the failure mutation-testing found in the equivalent guard in
    /// session S-2.
    /// </summary>
    [Fact]
    public void TheCheckIsNotSatisfiedByANameThatMerelyContainsTheMemberName()
    {
        var mentioned = Mentioned();

        Assert.DoesNotContain(nameof(ObjectAttribute.OnlyValue) + "XX", mentioned);
        Assert.Contains(nameof(ObjectAttribute.OnlyValue), mentioned);
    }

    /// <summary>
    /// The masking case, held open by a live example. <c>EvidenceObject.Completeness</c> is named
    /// on this page to say where the statement comes from, and its bare tail must not be able to
    /// stand in for <c>ObjectAttributes.Completeness</c>. If someone writes <c>Completeness</c> on
    /// its own here, this fails and the member check quietly weakens — which is the point of
    /// failing rather than of passing.
    /// </summary>
    [Fact]
    public void TheTailOfAnotherTypesMemberDoesNotCountAsAMentionOfThisOne()
    {
        Assert.Contains("EvidenceObject.Completeness", MentionedQualified());
        Assert.DoesNotContain("Completeness", MentionedStandalone());
        Assert.Contains(
            $"{nameof(ObjectAttributes)}.{nameof(ObjectAttributes.Completeness)}",
            MentionedQualified());
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }

    // --- helpers -------------------------------------------------------------------------------

    /// <summary>
    /// One value of each storage kind, produced by writing a bundle and reading it back. This is
    /// what makes the table an assertion about behaviour rather than about prose.
    /// </summary>
    private IEnumerable<(AttributeStorage Storage, AttributeValue Value)> ValuesTheCodeProduces()
    {
        WriteObject(Alice(
            Text("sAMAccountName", "alice"),
            Bytes("objectSid", [0x01, 0x02, 0xAB])));

        var attributes = Read()!;

        yield return (
            AttributeStorage.Text, attributes.Find("sAMAccountName")!.OnlyValue!);

        yield return (
            AttributeStorage.Binary, attributes.Find("objectSid")!.OnlyValue!);
    }

    private ObjectAttributes? Read()
    {
        var opening = BundleReader.Open(_directory);
        Assert.True(opening.IsSuccess);

        using var reader = opening.Value;
        return reader.ReadObjectAttributes(AliceDn);
    }

    private void WriteObject(EvidenceObject evidenceObject)
    {
        using var writer = BundleWriter.Create(_directory, Started);
        writer.WriteCoverage(evidenceObject.Coverage);
        writer.WriteObject(evidenceObject);
        writer.Complete(OneDomainRead(), Finished);
    }

    private static EvidenceObject Alice(params EvidenceAttribute[] attributes) =>
        new(SomeCoverage(), AliceDn, Guid.NewGuid(), attributes, Started);

    private static EvidenceAttribute Text(string ldapDisplayName, params string[] values) =>
        new(
            ldapDisplayName,
            StoredAttributeCompleteness.Complete,
            [.. values.Select(EvidenceValue.OfText)]);

    private static EvidenceAttribute Bytes(string ldapDisplayName, byte[] value) =>
        new(
            ldapDisplayName,
            StoredAttributeCompleteness.Complete,
            [EvidenceValue.OfBytes(value)]);

    private static RunCoverage OneDomainRead() =>
        RunCoverage.Of(
            CoverageId.ForDomains("contoso.com", ["contoso.com"]),
            [DomainCoverage.Read("contoso.com")],
            [
                ForestPartitionCoverage.Read(
                    "CN=Configuration," + DomainDn, NamingContextKind.Configuration),
                ForestPartitionCoverage.Read(
                    "CN=Schema,CN=Configuration," + DomainDn, NamingContextKind.Schema),
            ],
            SysvolCoverage.Of([]));

    private static PartitionCoverage SomeCoverage() => new(
        DomainDn,
        NamingContextKind.Domain,
        "dc01.contoso.com",
        ConnectionSecurityLevel.SignedAndSealed,
        12,
        4200,
        3,
        [],
        false);

    /// <summary>The types the page claims, as rows of its <c>TYPES</c> table.</summary>
    private static List<string> DeclaredTypes() =>
        TableRows("TYPES").Select(r => Cells(r)[0]).ToList();

    /// <summary>Storage kind to the two halves the page claims for it.</summary>
    private static Dictionary<string, (string Text, string Bytes)> StorageTable() =>
        TableRows("STORED")
            .Select(Cells)
            .Where(c => c.Length >= 4)
            .ToDictionary(c => c[0], c => (c[1], c[2]), StringComparer.Ordinal);

    /// <summary>
    /// The rows between a pair of markers, excluding the header and the separator, so the test
    /// parses the table rather than the prose around it.
    /// </summary>
    private static List<string> TableRows(string marker)
    {
        var text = ReadDocument();
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
        row.Trim('|').Split('|').Select(c => c.Trim().Trim('`')).ToArray();

    /// <summary>
    /// Every identifier the page mentions inside backticks, with a qualified name counting as a
    /// mention of both halves. Used for the type checks, where a bare name is unambiguous.
    /// </summary>
    private static HashSet<string> Mentioned()
    {
        var mentioned = new HashSet<string>(StringComparer.Ordinal);
        var parts = ReadDocument().Split('`');

        for (var i = 1; i < parts.Length; i += 2)
        {
            mentioned.Add(parts[i]);

            foreach (var half in parts[i].Split('.'))
            {
                mentioned.Add(half);
            }
        }

        return mentioned;
    }

    /// <summary>
    /// The identifiers written on their own, with no type in front of them.
    /// </summary>
    /// <remarks>
    /// <b>The tail of a qualified name does not count.</b> Attributing it to this component's type
    /// is how a member check passes while measuring nothing: measured 2026-08-22, removing
    /// <c>ObjectAttributes.Completeness</c> from the page left every check green, because
    /// <c>EvidenceObject.Completeness</c> — a different type's member, named here only to say
    /// where the statement comes from — supplied the bare word. Qualified names are still accepted
    /// through <see cref="MentionedQualified"/>, so the page is not pushed towards worse
    /// documentation to suit the check.
    /// </remarks>
    private static HashSet<string> MentionedStandalone() =>
        BacktickedTokens()
            .Where(token => !token.Contains('.', StringComparison.Ordinal))
            .ToHashSet(StringComparer.Ordinal);

    /// <summary>The identifiers written as <c>Type.Member</c>.</summary>
    private static HashSet<string> MentionedQualified() =>
        BacktickedTokens()
            .Where(token => token.Contains('.', StringComparison.Ordinal))
            .ToHashSet(StringComparer.Ordinal);

    private static List<string> BacktickedTokens()
    {
        var tokens = new List<string>();
        var parts = ReadDocument().Split('`');

        for (var i = 1; i < parts.Length; i += 2)
        {
            tokens.Add(parts[i]);
        }

        return tokens;
    }

    private static List<(string Type, string Member)> PublicMemberNames() =>
        TheComponent
            .Where(t => !t.IsEnum)
            .SelectMany(t => t
                .GetMembers(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance)
                .Where(m => m.DeclaringType != typeof(object))
                .Where(m => m.MemberType is MemberTypes.Method or MemberTypes.Property
                    or MemberTypes.Field)
                .Where(m => m is not MethodInfo method || !method.IsSpecialName)
                .Select(m => (t.Name, m.Name)))
            .Where(pair => !pair.Item2.Contains('<', StringComparison.Ordinal))
            .Where(pair => !Compiler.Contains(pair.Item2))
            .Distinct()
            .ToList();

    private static readonly HashSet<string> Compiler = new(StringComparer.Ordinal)
    {
        "Equals", "GetHashCode", "ToString", "Deconstruct", "Clone", "op_Equality", "op_Inequality",
        "EqualityContract",
    };

    private static string DocumentPath() =>
        Path.Combine(RepositoryLocation.Root(), "docs", "layers", "evidence", Document);

    private static string ReadDocument() => File.ReadAllText(DocumentPath());
}
