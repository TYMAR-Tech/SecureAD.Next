using System.Reflection;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/layers/evidence/run-identity-and-coverage.md</c> to the two identities a run carries and
/// to what it recorded about how much of the forest it read.
/// </summary>
/// <remarks>
/// <para>
/// Four outcome tables, each bound <b>in both directions</b>. A member in the code and not in the
/// document is a situation nobody reading it knows the product can reach; a member in the document
/// and not in the code is a promise the product cannot keep, and it reads exactly like one it can.
/// </para>
/// <para>
/// Three of the four are new binding rather than moved binding. <c>S-18</c> described
/// <c>ForestPartitionCoverage</c>, <c>SysvolCoverage</c> and <c>GpoCoverage</c> in prose while its
/// gate listed eleven types and reached none of them, so those three enums were named in a bound
/// document and checked by nothing. That is <c>P-19</c>'s shape: a check narrower than the document
/// it is named for.
/// </para>
/// </remarks>
public sealed class RunIdentityDocumentationTests
{
    private const string Document = "run-identity-and-coverage.md";

    /// <summary>
    /// The types this page is the description of. <c>RunSummary</c>, <c>RunComparability</c> and
    /// the verdict types are deliberately absent: whether a run may be <i>used</i> belongs to
    /// <c>whether-two-runs-compare.md</c>, and a component listed in two documents is one question
    /// answered twice.
    /// </summary>
    private static readonly Type[] TheComponent =
    [
        typeof(ProfileId),
        typeof(CoverageId),
        typeof(DomainReadOutcome),
        typeof(DomainCoverage),
        typeof(ForestPartitionReadOutcome),
        typeof(ForestPartitionCoverage),
        typeof(NamingContextKind),
        typeof(SysvolReadOutcome),
        typeof(SysvolCoverage),
        typeof(GpoReadOutcome),
        typeof(GpoCoverage),
        typeof(RunCoverage),
    ];

    // --- the four outcome tables, both directions ------------------------------------------------

    [Theory]
    [InlineData("DOMAIN-OUTCOMES", typeof(DomainReadOutcome))]
    [InlineData("PARTITION-OUTCOMES", typeof(ForestPartitionReadOutcome))]
    [InlineData("SYSVOL-OUTCOMES", typeof(SysvolReadOutcome))]
    [InlineData("GPO-OUTCOMES", typeof(GpoReadOutcome))]
    public void EveryOutcomeInTheCodeIsInTheDocument(string marker, Type outcome)
    {
        var documented = FirstColumn(marker);

        var missing = Enum.GetNames(outcome)
            .Where(name => !documented.Contains(name, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not list {outcome.Name}: {string.Join(", ", missing)}. Every "
            + "situation the product can record is a different thing to tell an operator, and one "
            + "nobody wrote down is one nobody chose the wording of.");
    }

    /// <summary>
    /// The direction that catches a document describing a state capture cannot reach. Four states
    /// of decision <c>0026</c> were exactly this, and they survived a review.
    /// </summary>
    [Theory]
    [InlineData("DOMAIN-OUTCOMES", typeof(DomainReadOutcome))]
    [InlineData("PARTITION-OUTCOMES", typeof(ForestPartitionReadOutcome))]
    [InlineData("SYSVOL-OUTCOMES", typeof(SysvolReadOutcome))]
    [InlineData("GPO-OUTCOMES", typeof(GpoReadOutcome))]
    public void EveryOutcomeInTheDocumentIsInTheCode(string marker, Type outcome)
    {
        var real = Enum.GetNames(outcome);

        var invented = FirstColumn(marker)
            .Where(name => !real.Contains(name, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            invented.Count == 0,
            $"{Document} describes {outcome.Name} situations that cannot arise: "
            + $"{string.Join(", ", invented)}.");
    }

    /// <summary>
    /// The distinction <c>docs/decisions/0063</c> holds: an exclusion must never read as a domain
    /// that could not be reached. Asserted against the document, because the document is where a
    /// reader learns the difference.
    /// </summary>
    [Fact]
    public void TheDocumentKeepsAnExclusionApartFromAnUnreachableDomain()
    {
        var rows = TableRows("DOMAIN-OUTCOMES")
            .Select(Cells)
            .Where(c => c.Length >= 2)
            .ToDictionary(c => c[0], c => c[1], StringComparer.Ordinal);

        Assert.NotEqual(
            rows[nameof(DomainReadOutcome.ExcludedByChoice)],
            rows[nameof(DomainReadOutcome.NotRead)]);

        Assert.NotEqual(
            rows[nameof(DomainReadOutcome.ExcludedByChoice)],
            rows[nameof(DomainReadOutcome.ExcludedForWantOfCandidates)]);
    }

    /// <summary>
    /// Only <c>Read</c> counts as read, and the document's third column has to say so. A reader who
    /// takes <c>PartiallyRead</c> for a smaller success is the mistake <c>DomainCoverage</c> exists
    /// to refuse.
    /// </summary>
    [Fact]
    public void OnlyAFullyReadDomainCountsAsRead()
    {
        foreach (var row in TableRows("DOMAIN-OUTCOMES"))
        {
            var cells = Cells(row);

            Assert.True(cells.Length >= 3, $"{cells[0]} does not say whether it counts as read.");

            var expected = string.Equals(
                cells[0], nameof(DomainReadOutcome.Read), StringComparison.Ordinal) ? "yes" : "no";

            Assert.Equal(expected, cells[2]);
        }
    }

    // --- the component ---------------------------------------------------------------------------

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
        var mentioned = Mentioned();

        var missing = PublicMemberNames()
            .Where(pair => !mentioned.Contains(pair.Member))
            .Select(pair => $"{pair.Type}.{pair.Member}")
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not describe: {string.Join(", ", missing)}. Every member a caller "
            + "can reach is a way to ask one of this component's questions, and one that is not "
            + "written down is one a caller has to guess the meaning of.");
    }

    /// <summary>
    /// The direction the gate on <c>S-18</c> never had. Every <c>Type.Member</c> the document
    /// writes in backticks must resolve, so a member that was renamed or never existed fails here
    /// rather than sitting in a bound document reading like fact.
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
            $"{Document} names members that do not exist: {string.Join(", ", invented)}. S-18 "
            + "carried two invented members of RunOutcomeFile for a month under a gate that only "
            + "looked the other way.");
    }

    // --- the tables that live elsewhere, and must not come back here ------------------------------

    /// <summary>
    /// The comparability verdict is <c>whether-two-runs-compare.md</c>'s and the run states are
    /// <c>the-bundle-on-disk.md</c>'s. Either table reappearing here would be a second description
    /// of one vocabulary, which is the state the repository was left in when a document was drafted
    /// and the old one was not cut in the same turn.
    ///
    /// <para>
    /// The marker is matched with its comment opener, not as a bare substring. Without that,
    /// <c>DOMAIN-OUTCOMES:BEGIN</c> contains <c>OUTCOMES:BEGIN</c> and this page failed its own
    /// check for carrying a table it does not have.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData("OUTCOMES")]
    [InlineData("STATES")]
    public void TheTablesThatBelongElsewhereAreNotDescribedHereAsWell(string marker)
    {
        Assert.DoesNotContain($"<!-- {marker}:BEGIN -->", Read(), StringComparison.Ordinal);
    }

    // --- scanner self-tests ------------------------------------------------------------------------

    /// <summary>
    /// Without this every check above could pass by parsing four empty tables and reflecting over
    /// an empty component, and find nothing wrong with either.
    /// </summary>
    [Fact]
    public void TheCheckFindsBothTheDocumentAndTheComponent()
    {
        Assert.True(File.Exists(Path()), $"Expected the document at {Path()}.");
        Assert.True(Read().Length > 1000, $"{Document} is too short to be the document it claims.");
        Assert.NotEmpty(TheComponent);
        Assert.NotEmpty(PublicMemberNames());
        Assert.Contains(nameof(RunCoverage.Of), Mentioned());
        Assert.True(Mentioned().Count > 40, "The mention scan found almost nothing to check against.");
        Assert.Equal(Enum.GetValues<DomainReadOutcome>().Length, FirstColumn("DOMAIN-OUTCOMES").Count);
        Assert.Equal(
            Enum.GetValues<ForestPartitionReadOutcome>().Length,
            FirstColumn("PARTITION-OUTCOMES").Count);
        Assert.Equal(Enum.GetValues<SysvolReadOutcome>().Length, FirstColumn("SYSVOL-OUTCOMES").Count);
        Assert.Equal(Enum.GetValues<GpoReadOutcome>().Length, FirstColumn("GPO-OUTCOMES").Count);
    }

    /// <summary>
    /// A marker block that is not there is a failure and never an empty result. A gate left
    /// pointing at a document whose table has moved elsewhere must say so. Two gates in this
    /// repository have already passed for months while measuring nothing.
    /// </summary>
    [Fact]
    public void AMissingTableIsAFailureRatherThanAnEmptyScan()
    {
        var thrown = Record.Exception(() => TableRows("OUTCOMES"));

        Assert.NotNull(thrown);
    }

    [Fact]
    public void TheCheckIsNotSatisfiedByANameThatMerelyContainsTheMemberName()
    {
        var mentioned = Mentioned();

        Assert.DoesNotContain(nameof(CoverageId.ForDomains) + "XX", mentioned);
        Assert.Contains(nameof(CoverageId.ForDomains), mentioned);
    }

    // --- helpers -----------------------------------------------------------------------------------

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

    /// <summary>
    /// Every identifier the document mentions inside backticks, with a qualified name counting as
    /// a mention of both halves and of the whole. Qualified names are better documentation than
    /// bare ones, and a check that forced bare ones would be making the document worse to suit
    /// itself.
    /// </summary>
    private static HashSet<string> Mentioned()
    {
        var mentioned = new HashSet<string>(StringComparer.Ordinal);

        var parts = Read().Split('`');
        for (var i = 1; i < parts.Length; i += 2)
        {
            var token = parts[i];
            mentioned.Add(token);

            foreach (var half in token.Split('.'))
            {
                mentioned.Add(half);
            }
        }

        return mentioned;
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

    private static string Path() =>
        System.IO.Path.Combine(RepositoryLocation.Root(), "docs", "layers", "evidence", Document);

    private static string Read() => File.ReadAllText(Path());
}
