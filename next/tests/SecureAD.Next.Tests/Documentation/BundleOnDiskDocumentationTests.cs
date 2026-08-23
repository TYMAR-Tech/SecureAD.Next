using System.Reflection;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/evidence/the-bundle-on-disk.md</c> to the files a bundle is made of, the seal
/// that covers one of them, and the states a run is read back in.
/// </summary>
/// <remarks>
/// <para>
/// Three tables, each bound <b>in both directions</b>. A name in the code and not in the document
/// is a piece of a bundle nobody reading it knows exists; a name in the document and not in the
/// code is a promise the product cannot keep, and it reads exactly like one it can.
/// </para>
/// <para>
/// The member check is also two-directional, which the gate this page inherits from was not.
/// <c>S-18</c> named two members of <c>RunOutcomeFile</c> that do not exist for a month, because
/// the only check ran from the code to the document. Every qualified mention here is resolved
/// against the type it names.
/// </para>
/// </remarks>
public sealed class BundleOnDiskDocumentationTests
{
    private const string Document = "the-bundle-on-disk.md";

    /// <summary>
    /// The types this page is the description of. <c>BundleSchema</c> and <c>BundleWriter</c> are
    /// deliberately absent: what is inside the database belongs to
    /// <c>what-a-bundle-holds.md</c>, and a component listed in two documents is a schema
    /// described twice.
    /// </summary>
    private static readonly Type[] TheComponent =
    [
        typeof(BundleLayout),
        typeof(BundleSealing),
        typeof(BundleSealContents),
        typeof(SealState),
        typeof(SealVerdict),
        typeof(RunState),
        typeof(RunStateNames),
        typeof(RunStateObservation),
        typeof(RunStateReader),
        typeof(RunOutcome),
        typeof(RunOutcomeContents),
        typeof(RunOutcomeFile),
    ];

    // --- the file table, both directions ------------------------------------------------------

    [Fact]
    public void EveryFileNameInTheLayoutIsInTheDocument()
    {
        var documented = FileTable();

        var missing = LayoutFileNames()
            .Where(f => !documented.TryGetValue(f.Constant, out var name)
                || !string.Equals(name, f.Value, StringComparison.Ordinal))
            .Select(f => $"{f.Constant} ({f.Value})")
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not name, or names wrongly: {string.Join(", ", missing)}. A file a "
            + "bundle can hold and the document does not list is one nobody knows to look for.");
    }

    /// <summary>
    /// The direction that catches a document describing a bundle the product stopped writing.
    /// <c>S-16</c> said a bundle was four files where <c>BundleLayout</c> declares six, and the
    /// count survived because nothing counted it.
    /// </summary>
    [Fact]
    public void EveryFileNameInTheDocumentIsInTheLayout()
    {
        var real = LayoutFileNames().Select(f => f.Constant).ToList();

        var invented = FileTable().Keys
            .Where(name => !real.Contains(name, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            invented.Count == 0,
            $"{Document} lists files a bundle cannot hold: {string.Join(", ", invented)}.");
    }

    [Fact]
    public void EveryFileHasAPathHelperAndTheDocumentSaysSo()
    {
        var text = Read();

        foreach (var (constant, _) in LayoutFileNames())
        {
            var helper = constant.Replace("FileName", "Path", StringComparison.Ordinal);

            Assert.True(
                typeof(BundleLayout).GetMethod(helper, BindingFlags.Public | BindingFlags.Static)
                    is not null,
                $"BundleLayout has no {helper} beside {constant}. A caller with no helper composes "
                + "a bundle path by concatenation, which gives the file names a second owner.");

            Assert.True(
                text.Contains(helper, StringComparison.Ordinal),
                $"{Document} does not name {helper}.");
        }
    }

    // --- the seal table, both directions ------------------------------------------------------

    [Fact]
    public void EverySealStateInTheCodeIsInTheDocument()
    {
        var documented = SealTable();

        var missing = Enum.GetNames<SealState>()
            .Where(name => !documented.Contains(name, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not explain: {string.Join(", ", missing)}. Each seal state is a "
            + "different thing to tell an operator, and one nobody wrote down is one nobody chose "
            + "the wording of.");
    }

    [Fact]
    public void EverySealStateInTheDocumentIsInTheCode()
    {
        var real = Enum.GetNames<SealState>();

        var invented = SealTable()
            .Where(name => !real.Contains(name, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            invented.Count == 0,
            $"{Document} names seal states that do not exist: {string.Join(", ", invented)}.");
    }

    /// <summary>
    /// Only <c>Intact</c> opens a bundle, asserted against <c>SealVerdict.MayBeOpened</c> rather
    /// than against the prose. Folding a failure into a benign absence is the one shape of defect
    /// an audit tool cannot have, and the document is where that becomes visible.
    /// </summary>
    [Fact]
    public void OnlyTheFirstSealStateOpensABundle()
    {
        foreach (var state in Enum.GetValues<SealState>())
        {
            var mayBeOpened = new SealVerdict(state, "detail").MayBeOpened;

            Assert.True(
                mayBeOpened == (state == SealState.Intact),
                $"{state} disagrees with the document, which says only Intact opens a bundle.");
        }
    }

    // --- the state table, both directions -----------------------------------------------------

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
    /// behind it is one the product cannot actually reach, and a state observed from something
    /// other than the bundle directory does not belong on this page at all.
    /// </summary>
    [Fact]
    public void EveryRunStateIsObservedFromTheBundleDirectory()
    {
        string[] observable =
        [
            BundleLayout.EvidenceFileName,
            BundleLayout.PartialFileName,
            BundleLayout.SealFileName,
            BundleLayout.OutcomeFileName,
        ];

        string[] words = ["evidence file", "seal", "outcome file", "partial file"];

        foreach (var row in TableRows("STATES"))
        {
            var cells = Cells(row);

            Assert.True(
                cells.Length >= 3 && !string.IsNullOrWhiteSpace(cells[2]),
                $"{cells[0]} does not say how it is observed.");

            var how = cells[2];

            Assert.True(
                words.Any(w => how.Contains(w, StringComparison.OrdinalIgnoreCase))
                || observable.Any(f => how.Contains(f, StringComparison.OrdinalIgnoreCase)),
                $"{cells[0]} is observed from something that is not a file in the bundle "
                + $"directory: \"{how}\". This page is the on-disk description; a state decided "
                + "anywhere else belongs in the document that owns what decided it.");
        }
    }

    // --- the component -------------------------------------------------------------------------

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
            $"{Document} does not name: {string.Join(", ", missing)}.");
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
            $"{Document} does not describe: {string.Join(", ", missing)}.");
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

    // --- scanner self-tests ---------------------------------------------------------------------

    /// <summary>
    /// Without this every check above could pass by parsing three empty tables and reflecting over
    /// an empty component, and find nothing wrong with either. This is what makes a retarget onto
    /// a document whose markers have moved fail loudly instead of quietly measuring nothing.
    /// </summary>
    [Fact]
    public void TheCheckFindsBothTheDocumentAndTheComponent()
    {
        Assert.True(File.Exists(Path()), $"Expected the document at {Path()}.");
        Assert.True(Read().Length > 1000, $"{Document} is too short to be the document it claims.");
        Assert.NotEmpty(TheComponent);
        Assert.Equal(LayoutFileNames().Count, FileTable().Count);
        Assert.Equal(Enum.GetValues<SealState>().Length, SealTable().Count);
        Assert.Equal(Enum.GetValues<RunState>().Length, StateTable().Count);
        Assert.NotEmpty(PublicMemberNames());
        Assert.Contains(nameof(BundleSealing.Verify), Mentioned());
    }

    /// <summary>
    /// A marker block that is not there is a failure and never an empty result. A gate left
    /// pointing at a document whose table has moved elsewhere must say so.
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

        Assert.DoesNotContain(nameof(BundleSealing.Verify) + "XX", mentioned);
        Assert.Contains(nameof(BundleSealing.Verify), mentioned);
    }

    // --- helpers ---------------------------------------------------------------------------------

    /// <summary>Every <c>*FileName</c> constant on <c>BundleLayout</c>, by reflection.</summary>
    private static List<(string Constant, string Value)> LayoutFileNames() =>
        typeof(BundleLayout)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.IsLiteral && f.Name.EndsWith("FileName", StringComparison.Ordinal))
            .Select(f => (f.Name, (string)f.GetRawConstantValue()!))
            .OrderBy(f => f.Name, StringComparer.Ordinal)
            .ToList();

    /// <summary>Constant name to documented file name.</summary>
    private static Dictionary<string, string> FileTable() =>
        TableRows("FILES")
            .Select(Cells)
            .Where(c => c.Length >= 3)
            .ToDictionary(c => c[0].Trim('`'), c => c[1].Trim('`'), StringComparer.Ordinal);

    private static List<string> SealTable() =>
        TableRows("SEAL").Select(r => Cells(r)[0].Trim('`')).ToList();

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

    /// <summary>
    /// Every identifier the document mentions inside backticks, with a qualified name counting as
    /// a mention of both halves and of the whole.
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
        System.IO.Path.Combine(RepositoryLocation.Root(), "docs", "evidence", Document);

    private static string Read() => File.ReadAllText(Path());
}
