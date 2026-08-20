using System.Reflection;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Next.Tests.Inventory;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/next/S-18-run-identity-and-comparability.md</c> to the code it describes.
///
/// <para>
/// Two of the tables are bound <b>in both directions</b>, which decision <c>0026</c> asked for by
/// name: a situation in the code and not in the document fails the build, and so does a situation
/// in the document and not in the code. The second direction is the one that matters here. This
/// session began by finding four states in a decision record that nothing could produce, and the
/// document that named them would have passed a one-directional check while describing situations
/// that cannot arise.
/// </para>
/// <para>
/// The outcome table also binds the <i>shape</i> of each situation against the shape the code
/// actually produces, so the document cannot go on claiming a refusal is qualified after someone
/// has changed it.
/// </para>
/// </summary>
public sealed class RunComparabilityDocumentationTests
{
    private const string Document = "S-18-run-identity-and-comparability.md";

    private static readonly Type[] TheComponent =
    [
        typeof(ProfileId),
        typeof(CoverageId),
        typeof(RunState),
        typeof(RunStateNames),
        typeof(RunStateObservation),
        typeof(RunStateReader),
        typeof(RunOutcome),
        typeof(RunOutcomeContents),
        typeof(RunOutcomeFile),
        typeof(DomainReadOutcome),
        typeof(DomainCoverage),
        typeof(RunCoverage),
        typeof(RunSummary),
        typeof(ComparabilityOutcome),
        typeof(DriftCardShape),
        typeof(ComparabilityVerdict),
        typeof(BaselineVerdict),
        typeof(RunComparability),
    ];

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
            .Where(name => !mentioned.Contains(name))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not describe: {string.Join(", ", missing)}. Every member a caller "
            + "can reach is a way to ask one of this component's questions, and one that is not "
            + "written down is one a caller has to guess the meaning of.");
    }

    // --- the outcome table, both directions ----------------------------------------------------

    [Fact]
    public void EveryOutcomeInTheCodeIsInTheDocument()
    {
        var documented = OutcomeTable().Keys;

        var missing = Enum.GetNames<ComparabilityOutcome>()
            .Where(name => !documented.Contains(name, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not list: {string.Join(", ", missing)}. Every situation the product "
            + "can reach is a different thing to tell an operator, and one nobody wrote down is "
            + "one nobody chose the wording of.");
    }

    /// <summary>
    /// The direction this session exists to enforce. A situation described in the document and
    /// absent from the code is a promise the product cannot keep, and it reads exactly like one it
    /// can.
    /// </summary>
    [Fact]
    public void EveryOutcomeInTheDocumentIsInTheCode()
    {
        var real = Enum.GetNames<ComparabilityOutcome>();

        var invented = OutcomeTable().Keys
            .Where(name => !real.Contains(name, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            invented.Count == 0,
            $"{Document} describes situations that cannot arise: {string.Join(", ", invented)}. "
            + "Four states of decision 0026 were exactly this, and they survived a review.");
    }

    /// <summary>
    /// The shape is the part a reader acts on: whether the card may say nothing changed. Comparing
    /// the document against the shape the code produces makes the table an assertion about
    /// behaviour rather than about prose.
    /// </summary>
    [Fact]
    public void TheDocumentedShapeIsTheShapeTheCodeProduces()
    {
        var documented = OutcomeTable();

        foreach (var (outcome, shape) in ShapesTheCodeProduces())
        {
            Assert.True(
                documented.TryGetValue(outcome.ToString(), out var claimed),
                $"{Document} does not list {outcome}.");

            Assert.True(
                string.Equals(claimed, shape.ToString(), StringComparison.Ordinal),
                $"{Document} says {outcome} renders as {claimed}; the code produces {shape}.");
        }
    }

    // --- the state table, both directions ------------------------------------------------------

    [Fact]
    public void EveryRunStateInTheCodeIsInTheDocument()
    {
        var documented = StateTable();

        var missing = Enum.GetNames<RunState>()
            .Where(name => !documented.Contains(name, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not explain: {string.Join(", ", missing)}.");
    }

    /// <summary>
    /// A state in the document and not in the code would be a word an operator is told to expect
    /// and never sees - which is how this session's second finding nearly reached the tree.
    /// </summary>
    [Fact]
    public void EveryRunStateInTheDocumentIsInTheCode()
    {
        var real = Enum.GetNames<RunState>();

        var invented = StateTable()
            .Where(name => !real.Contains(name, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            invented.Count == 0,
            $"{Document} names states that do not exist: {string.Join(", ", invented)}.");
    }

    /// <summary>
    /// Every state must say how it is told apart from the others. A state with no observation
    /// behind it is one the product cannot actually reach, and the document is where that becomes
    /// visible.
    /// </summary>
    [Fact]
    public void EveryRunStateSaysHowItIsObserved()
    {
        foreach (var row in TableRows("STATES"))
        {
            var cells = Cells(row);

            Assert.True(
                cells.Length >= 3 && !string.IsNullOrWhiteSpace(cells[2]),
                $"{cells[0]} does not say how it is observed.");
        }
    }

    // --- scanner self-tests --------------------------------------------------------------------

    /// <summary>
    /// Without this the checks above could all pass by parsing an empty table and reflecting over
    /// an empty component, and find nothing wrong with either.
    /// </summary>
    [Fact]
    public void TheCheckFindsBothTheDocumentAndTheComponent()
    {
        Assert.True(File.Exists(Path()), $"Expected the slice document at {Path()}.");
        Assert.True(Read().Length > 1000, $"{Document} is too short to be the document it claims.");
        Assert.NotEmpty(TheComponent);
        Assert.Contains(nameof(RunComparability.Evaluate), Mentioned());
        Assert.True(Mentioned().Count > 40, "The mention scan found almost nothing to check against.");
        Assert.Equal(Enum.GetValues<ComparabilityOutcome>().Length, OutcomeTable().Count);
        Assert.Equal(Enum.GetValues<RunState>().Length, StateTable().Count);
        Assert.Equal(5, FindingHeadings().Count);
    }

    [Fact]
    public void TheCheckReportsANameThatIsAbsent()
    {
        Assert.DoesNotContain("EvaluateByQuantumFlux", Mentioned());
    }

    /// <summary>
    /// The scan is not a bare substring search. Mutation-testing the equivalent guard in session
    /// S-2 found that it was: a member renamed by appending two characters still matched the
    /// document, so the check reported nothing missing while the document named nothing that
    /// existed.
    /// </summary>
    [Fact]
    public void TheCheckIsNotSatisfiedByANameThatMerelyContainsTheMemberName()
    {
        var mentioned = Mentioned();

        Assert.DoesNotContain(nameof(RunComparability.Evaluate) + "XX", mentioned);
        Assert.Contains(nameof(RunComparability.Evaluate), mentioned);
    }

    // --- helpers -------------------------------------------------------------------------------

    /// <summary>
    /// The shape the code produces for each outcome, by producing one of every verdict. This is
    /// what makes the document's third column an assertion rather than a claim.
    /// </summary>
    private static IEnumerable<(ComparabilityOutcome Outcome, DriftCardShape Shape)> ShapesTheCodeProduces()
    {
        string[] two = ["contoso.com", "eu.contoso.com"];
        string[] three = ["contoso.com", "eu.contoso.com", "us.contoso.com"];

        var verdicts = new[]
        {
            RunComparability.NoEarlierRun(),
            RunComparability.EarlierRunDeleted(),
            RunComparability.Evaluate(Run(two), Unfinished()),
            RunComparability.Evaluate(Run(two, complete: false), Run(two)),
            RunComparability.Evaluate(Run(two), Run(two, complete: false)),
            RunComparability.Evaluate(Run(three), Run(two)),
            RunComparability.Evaluate(Run(two, withheld: true), Run(two)),
            RunComparability.Evaluate(Run(two, majorVersion: 5), Run(two)),
            RunComparability.Evaluate(Run(two), Run(two)),
        };

        return verdicts.Select(v => (v.Outcome, v.Shape));
    }

    private static RunSummary Run(
        string[] domains,
        bool complete = true,
        bool withheld = false,
        int majorVersion = 4)
    {
        var declared = CoverageId.ForDomains("contoso.com", domains);

        var outcomes = domains
            .Select(d => d.ToLowerInvariant())
            .Distinct(StringComparer.Ordinal)
            .OrderBy(d => d, StringComparer.Ordinal)
            .Select((d, i) => complete || i > 0
                ? DomainCoverage.Read(d)
                : DomainCoverage.NotRead(d, "No controller answered."));

        return RunSummary.OfCompletedRun(
            ProfileId.ForForest("contoso.com"),
            RunCoverage.Of(
                declared,
                outcomes,
                [
                    ForestPartitionCoverage.Read(
                        "CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
                    ForestPartitionCoverage.Read(
                        "CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema),
                ],
                SysvolCoverage.Of([])),
            majorVersion,
            withheld);
    }

    private static RunSummary Unfinished() =>
        RunSummary.OfUnfinishedRun(ProfileId.ForForest("contoso.com"), RunState.Failed);

    /// <summary>Outcome name to documented shape.</summary>
    private static Dictionary<string, string> OutcomeTable() =>
        TableRows("OUTCOMES")
            .Select(Cells)
            .Where(c => c.Length >= 3)
            .ToDictionary(c => c[1], c => c[2], StringComparer.Ordinal);

    /// <summary>The state names the document lists.</summary>
    private static List<string> StateTable() =>
        TableRows("STATES").Select(r => Cells(r)[0]).ToList();

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

    private static List<string> FindingHeadings() =>
        Read()
            .Split('\n')
            .Select(l => l.Trim())
            .Where(l => l.StartsWith("### F-S18-", StringComparison.Ordinal))
            .ToList();

    private static string Quoted(string name) => "`" + name + "`";

    /// <summary>
    /// Every identifier the document mentions inside backticks, with a qualified name counting as
    /// a mention of both halves - so <c>`RunComparability.Evaluate`</c> names the type and the
    /// member. Qualified names are better documentation than bare ones, and a check that forced
    /// bare ones would be making the document worse to suit itself.
    ///
    /// <para>
    /// The match is still exact within the backticks. A member renamed by appending two characters
    /// does not match, which is the failure mutation-testing found in the equivalent guard in
    /// session S-2, where a bare substring search reported nothing missing while the document
    /// named nothing that existed.
    /// </para>
    /// </summary>
    private static HashSet<string> Mentioned()
    {
        var mentioned = new HashSet<string>(StringComparer.Ordinal);
        var text = Read();

        var parts = text.Split('`');
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

    private static IEnumerable<string> PublicMemberNames() =>
        TheComponent
            .Where(t => !t.IsEnum)
            .SelectMany(t => t.GetMembers(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance))
            .Where(m => m.DeclaringType != typeof(object))
            .Where(m => m.MemberType is MemberTypes.Method or MemberTypes.Property or MemberTypes.Field)
            .Where(m => m is not MethodInfo method || !method.IsSpecialName)
            .Select(m => m.Name)
            .Where(name => !name.Contains('<', StringComparison.Ordinal))
            .Where(name => !Compiler.Contains(name))
            .Distinct(StringComparer.Ordinal);

    private static readonly HashSet<string> Compiler = new(StringComparer.Ordinal)
    {
        "Equals", "GetHashCode", "ToString", "Deconstruct", "Clone", "op_Equality", "op_Inequality",
        "EqualityContract",
    };

    private static string Path() =>
        System.IO.Path.Combine(OldAppInventory.RepositoryRoot(), "docs", "next", Document);

    private static string Read() => File.ReadAllText(Path());
}
