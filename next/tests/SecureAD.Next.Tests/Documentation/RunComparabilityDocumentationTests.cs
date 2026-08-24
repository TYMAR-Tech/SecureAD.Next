using System.Reflection;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/layers/evidence/whether-two-runs-compare.md</c> to the code it describes.
///
/// <para>
/// Both tables are bound <b>in both directions</b>, which decision <c>0026</c> asked for by
/// name: a situation in the code and not in the document fails the build, and so does a situation
/// in the document and not in the code. The second direction is the one that matters here. The
/// session that wrote the outcome table began by finding four states in a decision record that
/// nothing could produce, and the document that named them would have passed a one-directional
/// check while describing situations that cannot arise.
/// </para>
/// <para>
/// The outcome table also binds the <i>shape</i> of each situation against the shape the code
/// actually produces, so the document cannot go on claiming a refusal is qualified after someone
/// has changed it.
/// </para>
/// <para>
/// Retargeted from docs/next/S-18-run-identity-and-comparability.md, which was deleted when
/// the last of its content moved. Identity and coverage went to
/// <c>run-identity-and-coverage.md</c> and are bound by <c>RunIdentityDocumentationTests</c>; the
/// run states had already gone to <c>the-bundle-on-disk.md</c>.
/// </para>
/// <para>
/// <b><c>RunSummary</c> was added to this page's ownership on 2026-08-24</b>, when the area file
/// the-run-library.md was deleted. It is the only one of the six that moved; the register already
/// assigned the other five here.
/// </para>
/// <para>
/// <b>Mutation-tested 2026-08-24 by <c>next/tools/mutate-run-library-doc-gates.ps1</c>, eleven
/// mutations, all killed; six touched files verified byte-identical by hash.</b> Two were aimed
/// here. Dropping the <c>RunSummary</c> row is killed by
/// <see cref="TheTypesTableAndTheComponentAgree"/> and by
/// <c>TypesTableOwnershipTests.EveryClaimedTypeIsRegisteredToThePageThatClaimsIt</c>. Deleting
/// <c>typeof(RunSummary)</c> from <see cref="TheComponent"/> is killed only by
/// <see cref="TheHandWrittenComponentListMatchesWhatTheSourceFilesDeclare"/> - which is the point
/// of that check, because before it existed every assertion keyed on that array was comparing the
/// document against a second copy of the document's own claim.
/// </para>
/// </summary>
public sealed class RunComparabilityDocumentationTests
{
    private const string Document = "whether-two-runs-compare.md";

    /// <summary>
    /// The types this page is the description of. <c>ProfileId</c>, <c>CoverageId</c> and the
    /// coverage records are deliberately absent: what a run <i>is</i> and what it <i>read</i>
    /// belong to <c>run-identity-and-coverage.md</c>, and a component listed in two documents is
    /// one question answered twice.
    /// </summary>
    private static readonly Type[] TheComponent =
    [
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

    /// <summary>
    /// The <c>TYPES</c> table and the component agree, in both directions. Mentioning a type is
    /// not the same as owning it, and this page's table is what the surface register is held to.
    /// </summary>
    [Fact]
    public void TheTypesTableAndTheComponentAgree()
    {
        var documented = TableRows("TYPES")
            .Select(r => Cells(r)[0].Trim('`'))
            .ToHashSet(StringComparer.Ordinal);

        var actual = DeclaredPublicTypeNames().ToHashSet(StringComparer.Ordinal);

        var unclaimed = actual.Except(documented).OrderBy(n => n, StringComparer.Ordinal).ToList();
        var invented = documented.Except(actual).OrderBy(n => n, StringComparer.Ordinal).ToList();

        Assert.True(
            unclaimed.Count == 0 && invented.Count == 0,
            $"The TYPES table in {Document} disagrees with the files its header names. Declared "
            + $"but not claimed: {Describe(unclaimed)}. Claimed but not declared: "
            + $"{Describe(invented)}.");
    }

    /// <summary>
    /// <see cref="TheComponent"/> is the set the source files declare. It is hand-written, so
    /// without this every check keyed on it is pointed at a list that may have gone stale, which
    /// is a sound check aimed at a dead reference.
    /// </summary>
    [Fact]
    public void TheHandWrittenComponentListMatchesWhatTheSourceFilesDeclare()
    {
        var listed = TheComponent.Select(t => t.Name).ToHashSet(StringComparer.Ordinal);
        var declared = DeclaredPublicTypeNames().ToHashSet(StringComparer.Ordinal);

        Assert.Equal(declared.OrderBy(n => n, StringComparer.Ordinal), listed.OrderBy(n => n, StringComparer.Ordinal));
    }

    /// <summary>
    /// The source scan agrees with the compiler, so a regex that has drifted fails rather than
    /// quietly narrowing the set the two checks above compare.
    /// </summary>
    [Fact]
    public void EveryTypeTheScanFindsIsOneTheCompilerExports()
    {
        var exported = typeof(RunComparability).Assembly
            .GetExportedTypes()
            .Select(t => t.Name)
            .ToHashSet(StringComparer.Ordinal);

        var unknown = DeclaredPublicTypeNames()
            .Where(name => !exported.Contains(name))
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.True(unknown.Count == 0, $"The scan found unexported types: {Describe(unknown)}.");
    }

    /// <summary>
    /// The scanner self-test for the three checks above: without it each passes by scanning no
    /// files and comparing two empty sets.
    /// </summary>
    [Fact]
    public void TheCheckFindsTheDocumentAndTheComponent()
    {
        Assert.True(File.Exists(Path()), $"Expected the layer document at {Path()}.");
        Assert.NotEmpty(TableRows("TYPES"));

        var declared = DeclaredPublicTypeNames().ToList();

        Assert.Equal(6, declared.Count);
        Assert.Contains(nameof(RunSummary), declared);
        Assert.Contains(nameof(BaselineVerdict), declared);
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
    /// rather than sitting in a bound document reading like fact. <c>S-18</c> carried two invented
    /// members of <c>RunOutcomeFile</c> for a month under a gate that only looked the other way.
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

    // --- the shape table, both directions -------------------------------------------------------

    [Fact]
    public void EveryCardShapeInTheCodeIsInTheDocument()
    {
        var documented = ShapeTable();

        var missing = Enum.GetNames<DriftCardShape>()
            .Where(name => !documented.Contains(name, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not list: {string.Join(", ", missing)}. The shape is what decides "
            + "whether a card may say nothing changed.");
    }

    [Fact]
    public void EveryCardShapeInTheDocumentIsInTheCode()
    {
        var real = Enum.GetNames<DriftCardShape>();

        var invented = ShapeTable()
            .Where(name => !real.Contains(name, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            invented.Count == 0,
            $"{Document} describes card shapes that cannot arise: {string.Join(", ", invented)}.");
    }

    // --- the tables that live elsewhere, and must not come back here -----------------------------

    /// <summary>
    /// The run states are observed from files in the bundle directory, so they are described by
    /// <c>docs/layers/evidence/the-bundle-on-disk.md</c> and bound by <c>BundleOnDiskDocumentationTests</c>.
    /// What a run read is <c>run-identity-and-coverage.md</c>'s. Either table reappearing here
    /// would be a second description of one vocabulary, which is the state the repository was left
    /// in when a document was drafted and the old one was not cut in the same turn.
    /// </summary>
    [Theory]
    [InlineData("STATES")]
    [InlineData("DOMAIN-OUTCOMES")]
    public void TheTablesThatBelongElsewhereAreNotDescribedHereAsWell(string marker)
    {
        Assert.DoesNotContain($"<!-- {marker}:BEGIN -->", Read(), StringComparison.Ordinal);
    }

    // --- scanner self-tests --------------------------------------------------------------------

    /// <summary>
    /// Without this the checks above could all pass by parsing an empty table and reflecting over
    /// an empty component, and find nothing wrong with either.
    /// </summary>
    [Fact]
    public void TheCheckFindsBothTheDocumentAndTheComponent()
    {
        Assert.True(File.Exists(Path()), $"Expected the document at {Path()}.");
        Assert.True(Read().Length > 1000, $"{Document} is too short to be the document it claims.");
        Assert.NotEmpty(TheComponent);
        Assert.Contains(nameof(RunComparability.Evaluate), Mentioned());
        Assert.True(Mentioned().Count > 40, "The mention scan found almost nothing to check against.");
        Assert.Equal(Enum.GetValues<ComparabilityOutcome>().Length, OutcomeTable().Count);
        Assert.Equal(Enum.GetValues<DriftCardShape>().Length, ShapeTable().Count);
    }

    /// <summary>
    /// A marker block that is not there is a failure and never an empty result. Without this the
    /// outcome checks could all pass against a table that had been moved to another document,
    /// finding nothing wrong because they found nothing at all.
    /// </summary>
    [Fact]
    public void AMissingTableIsAFailureRatherThanAnEmptyScan()
    {
        var thrown = Record.Exception(() => TableRows("STATES"));

        Assert.NotNull(thrown);
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

    private static List<string> ShapeTable() =>
        TableRows("SHAPES").Select(r => Cells(r)[0].Trim('`')).ToList();

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

    /// <summary>
    /// The files this page's <c>Code:</c> header names, and the only files it may claim from.
    /// </summary>
    private static readonly string[] SourceFiles =
        ["RunComparability.cs", "ComparabilityOutcome.cs", "RunSummary.cs"];

    /// <summary>
    /// The public types declared in the component's own files, read from those files rather than
    /// from <see cref="TheComponent"/>.
    /// </summary>
    /// <remarks>
    /// <b>This is the anchor <see cref="TheComponent"/> did not have.</b> That array is a hand
    /// written list of six, so every check keyed on it compares the document against a second copy
    /// of the document's own claim: a seventh public type added to one of these files would be
    /// absent from both, and nothing would report a disagreement. Reading the declarations out of
    /// the files puts the anchor outside anything a documentation edit can reach.
    /// </remarks>
    private static IEnumerable<string> DeclaredPublicTypeNames()
    {
        foreach (var file in SourceFiles)
        {
            var path = System.IO.Path.Combine(
                RepositoryLocation.Root(), "next", "src", "SecureAD.Evidence", "Run", file);

            foreach (var line in File.ReadAllLines(path))
            {
                if (!line.StartsWith("public ", StringComparison.Ordinal))
                    continue;

                var words = line.Split(
                    [' ', '(', '<', '{'], StringSplitOptions.RemoveEmptyEntries);

                var keyword = Array.FindIndex(
                    words, w => w is "record" or "class" or "enum" or "struct" or "interface");

                if (keyword >= 0 && keyword + 1 < words.Length)
                    yield return words[keyword + 1];
            }
        }
    }

    private static string Describe(List<string> names) =>
        names.Count == 0 ? "none" : string.Join(", ", names);
}
