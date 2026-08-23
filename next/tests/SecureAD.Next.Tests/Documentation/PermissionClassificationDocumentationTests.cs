using System.Reflection;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/kernel/permission-classification.md</c> to the code it describes.
///
/// <para>
/// Per <c>docs/next/README.md</c>, a document is not the new product's documentation until a test
/// holds it to the code. Two kinds of drift matter here. A member changing while the document goes
/// on describing the old shape, as everywhere. And - because this component's whole subject is a
/// claim a customer acts on - a right that quietly stops being written down, or a verdict the
/// document does not explain, which is how six disagreeing definitions of "dangerous" accumulated
/// in the first place.
/// </para>
/// <para>
/// What it cannot check is whether the recommendation on <c>gPLink</c> is any good. That needs the
/// owner.
/// </para>
/// </summary>
public sealed class PermissionClassificationDocumentationTests
{
    private const string Document = "permission-classification.md";

    /// <summary>
    /// The component's types, named rather than discovered by namespace: <c>SecureAD.Kernel.Security</c>
    /// also holds K15's parser, which <c>S-1</c> documents and this document must not be asked to.
    /// </summary>
    private static readonly Type[] TheComponent =
    [
        typeof(DangerousPermissionClassifier),
        typeof(PermissionAssessment),
        typeof(PermissionVerdict),
        typeof(EntryReach),
        typeof(EntryReachReader),
    ];

    [Fact]
    public void TheDocumentNamesEveryPublicTypeInTheComponent()
    {
        var text = Read();

        var missing = TheComponent
            .Select(t => t.Name)
            .Where(name => !text.Contains(Quoted(name), StringComparison.Ordinal))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not name: {string.Join(", ", missing)}. A type the documentation "
            + "does not mention is a piece of the component nobody reading it knows exists.");
    }

    /// <summary>
    /// Every member a caller can reach, with what it gives back when it cannot answer. A caller
    /// that has to guess whether an unrecognised GUID comes back as safe or as unassessed is the
    /// exact reader this component exists to stop existing.
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
            + "can reach needs its cannot-answer case stated, or the caller guesses.");
    }

    /// <summary>
    /// Each verdict is a different thing to tell a customer, so each must be explained. A document
    /// that names three of four leaves the fourth to be inferred from its name, and the fourth is
    /// the one that means "nobody has looked at this permission".
    /// </summary>
    [Fact]
    public void TheDocumentExplainsEveryVerdict()
    {
        var text = Read();

        var missing = Enum.GetNames<PermissionVerdict>()
            .Where(name => !text.Contains(Quoted(name), StringComparison.Ordinal))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not explain: {string.Join(", ", missing)}. Each verdict is a "
            + "different statement to a customer and must be written down as one.");
    }

    /// <summary>
    /// The nine names F-S3-2 handed to this row. They were carried across a component boundary in
    /// prose because the catalogue deliberately dropped the flag that held them, and prose is
    /// exactly what gets lost. Each must be written down here <b>and</b> reach a verdict that is
    /// not <see cref="PermissionVerdict.CannotClassify"/> - so a name cannot be honoured by being
    /// mentioned and then quietly not classified.
    /// </summary>
    [Theory]
    [InlineData("User-Force-Change-Password")]
    [InlineData("DS-Replication-Get-Changes")]
    [InlineData("DS-Replication-Get-Changes-All")]
    [InlineData("Self-Membership")]
    [InlineData("Validated-SPN")]
    [InlineData("msDS-AllowedToActOnBehalfOfOtherIdentity")]
    [InlineData("msDS-KeyCredentialLink")]
    [InlineData("userAccountControl")]
    [InlineData("unicodePwd")]
    public void EveryNameHandedOverByTheCatalogueIsWrittenDownAndReachesAVerdict(string ldapName)
    {
        Assert.Contains(Quoted(ldapName), Read(), StringComparison.Ordinal);

        var entry = SchemaGuidCatalog.Embedded.FindByLdapName(ldapName);
        Assert.NotNull(entry);

        var verdict = VerdictFor(entry!);

        Assert.NotEqual(PermissionVerdict.CannotClassify, verdict);
        Assert.NotEqual(PermissionVerdict.NotDangerous, verdict);
    }

    /// <summary>
    /// The two the live and stored effective-access panels disagreed about. The owner settled them,
    /// and the document must name them and the classifier must reach the settled verdict.
    /// </summary>
    /// <remarks>
    /// This formerly also asserted a <c>### Settled 2026-08-10</c> heading. That tested the shape of
    /// one document rather than the behaviour of the classifier, and it was the sort of check a
    /// rewrite has to delete or obey for no reason. The verdict assertion below is the substance.
    /// </remarks>
    [Theory]
    [InlineData("gPLink")]
    [InlineData("scriptPath")]
    public void TheNamesTheOldPanelsDisagreedAboutAreRecordedAsSettled(string ldapName)
    {
        Assert.Contains(Quoted(ldapName), Read(), StringComparison.Ordinal);

        var result = new DangerousPermissionClassifier(SchemaGuidCatalog.Embedded).Classify(
            AceType.AccessAllowedObject,
            0x00000020,
            SchemaGuidCatalog.Embedded.GuidFor(ldapName)!);

        Assert.Equal(PermissionVerdict.Dangerous, result.Verdict);
    }

    // EveryFindingCarriesAnIdentifier stood here and was deleted on 2026-08-14. It asserted that
    // every heading in the findings section contained 'F-S4-'. Its own remarks concede the shape of
    // the failure - that the check could be answered by renaming prose - which is the sign that it
    // was testing the document rather than the classifier.

    /// <summary>
    /// The findings section, and only it.
    /// </summary>
    private static List<string> FindingHeadings()
    {
        var lines = Read().Split('\n');

        var begin = Array.FindIndex(lines, l => l.TrimEnd().Equals("## Findings", StringComparison.Ordinal));

        Assert.True(begin >= 0, $"{Document} has no '## Findings' section to read.");

        var end = Array.FindIndex(lines, begin + 1, l => l.StartsWith("## ", StringComparison.Ordinal));
        if (end < 0)
            end = lines.Length;

        return lines[(begin + 1)..end]
            .Where(line => line.StartsWith("### ", StringComparison.Ordinal))
            .ToList();
    }

    /// <summary>
    /// The document says what was wrong with the old design, not only what the new one is. A
    /// document that describes the new design in isolation leaves the next reader free to reinvent
    /// one of the implementations this component replaced.
    /// </summary>
    /// <remarks>
    /// This formerly asserted the string <c>K16</c> and one sentence from the reference inventory.
    /// That inventory described the old application and has been archived, so the check was anchored
    /// to something no longer in the repository — and its sentence said five implementations while
    /// the classifier's own account says six.
    /// </remarks>
    [Fact]
    public void TheDocumentSaysWhatTheOldDesignGotWrong()
    {
        var text = Read();

        Assert.Contains("disagreed", text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("effective-access", text, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The decisions this component is built on, so a later session changing one can find what
    /// stands on it. <c>0016</c> especially: it is the record that removed a question from this
    /// row, and a document that does not cite it looks like a row that forgot the question.
    /// </summary>
    [Theory]
    [InlineData("0002")]
    [InlineData("0004")]
    [InlineData("0016")]
    public void TheDocumentCitesTheDecisionsItStandsOn(string record)
    {
        Assert.Contains(record, Read(), StringComparison.Ordinal);
    }

    [Fact]
    public void TheDocumentStatesTheNamespaceTheCodeDeclares()
    {
        Assert.Contains(
            $"`{typeof(DangerousPermissionClassifier).Namespace}`",
            Read(),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The DCSync question is not this row's to answer, so the document must say so rather than
    /// leave a silent gap.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The prerequisite this used to point at, written down here because its old home is
    /// gone.</b> This test formerly asserted that inventory row <c>E18</c> existed and carried a
    /// prerequisite. That inventory described the old application and was archived, and the
    /// caveat would have gone with it. Verbatim:
    /// </para>
    /// <para>
    /// <i>Prerequisite before this row starts: the DCSync lab check. <c>SEC-002</c> and
    /// <c>SEC-076</c> contradict each other on what DCSync is and both are source of truth for
    /// their own rule. Do not rebuild the DCSync rule on an assumption; grant a test principal
    /// exactly <c>Get-Changes</c> + <c>Get-Changes-In-Filtered-Set</c> in a lab forest and
    /// attempt the read.</i>
    /// </para>
    /// <para>
    /// That is a contradiction between two rule cards that still ship, so it outlives the
    /// inventory it was recorded in. It belongs against the rules themselves; it is parked here
    /// because <c>docs/rules/</c> is the owner's to change, not this session's.
    /// </para>
    /// </remarks>
    [Fact]
    public void TheDcSyncQuestionIsHandedOnRatherThanAnsweredHere()
    {
        Assert.Contains("DangerousInCombination", Read(), StringComparison.Ordinal);

        var result = new DangerousPermissionClassifier(SchemaGuidCatalog.Embedded).Classify(
            AceType.AccessAllowedObject,
            0x00000100,
            SchemaGuidCatalog.Embedded.GuidFor("DS-Replication-Get-Changes")!);

        Assert.Equal(PermissionVerdict.DangerousInCombination, result.Verdict);
    }

    /// <summary>
    /// The scanner self-test. Without it every assertion above passes by searching an empty string
    /// and reflecting over an empty set, and finds nothing wrong with either.
    /// </summary>
    [Fact]
    public void TheCheckFindsBothTheDocumentAndTheComponent()
    {
        Assert.True(File.Exists(Path()), $"Expected the document at {Path()}.");
        Assert.True(Read().Length > 1000, $"{Document} is too short to be the document it claims.");
        Assert.NotEmpty(TheComponent);
        Assert.Contains(nameof(DangerousPermissionClassifier.Classify), PublicMemberNames());
        Assert.Contains("`SecureAD.Kernel.Security`", Read(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The scan reports an absent name as missing. Run over an invented member, so it proves the
    /// search works without the document having to be broken to prove it.
    /// </summary>
    [Fact]
    public void TheCheckReportsANameThatIsAbsent()
    {
        Assert.DoesNotContain(Quoted("ClassifyByQuantumFlux"), Read(), StringComparison.Ordinal);
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
        var text = Read();

        Assert.DoesNotContain(Quoted(nameof(DangerousPermissionClassifier.Classify) + "XX"), text, StringComparison.Ordinal);
        Assert.Contains(Quoted(nameof(DangerousPermissionClassifier.Classify)), text, StringComparison.Ordinal);
    }

    /// <summary>
    /// Runs the classifier over a catalogue entry the way an ACE naming it would, choosing the
    /// mask bit that matches the kind. This is what makes the handover check an assertion about
    /// behaviour rather than about prose.
    /// </summary>
    private static PermissionVerdict VerdictFor(SchemaGuidEntry entry)
    {
        const int Self = 0x00000008;
        const int WriteProperty = 0x00000020;
        const int ControlAccess = 0x00000100;

        var mask = entry.Kind switch
        {
            SchemaGuidKind.ExtendedRight => ControlAccess,
            SchemaGuidKind.ValidatedWrite => Self,
            _ => WriteProperty,
        };

        return new DangerousPermissionClassifier(SchemaGuidCatalog.Embedded)
            .Classify(AceType.AccessAllowedObject, mask, entry.Guid)
            .Verdict;
    }

    private static string Quoted(string name) => "`" + name + "`";

    /// <summary>
    /// Every member of this component a caller can reach and an author wrote. Enum types are
    /// excluded because their members are the vocabulary the verdict test already checks whole,
    /// and the members the compiler writes for a record are excluded because a document naming
    /// <c>get_Verdict</c> would be describing the compiler.
    /// </summary>
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
        System.IO.Path.Combine(RepositoryLocation.Root(), "docs", "kernel", Document);

    private static string Read() => File.ReadAllText(Path());
}
