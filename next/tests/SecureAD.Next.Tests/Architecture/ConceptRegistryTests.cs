using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Gate 2: a named concept has exactly one owning type, and no second type declares a member that
/// answers the same question.
///
/// <para>
/// <b>What went wrong before.</b> The map found the same question answered three to six times,
/// differently, across branches that could not see each other's work. Two of the five completed
/// rebuild rows were instances of it. K13 and K14 were two hand-maintained tables of the same
/// Active Directory facts in different folders, neither referencing the other, both carrying
/// correction comments about entries that had previously been wrong; exactly one file in the
/// product touched both. K16 was six separate answers to "is this permission dangerous", two of
/// which powered the live and stored effective-access panels - the two screens a customer opens in
/// order to compare them against each other.
/// </para>
/// <para>
/// Both were found by a human reading the map. There are 251 rows left, so the seventh duplicate
/// has to fail the build instead.
/// </para>
/// <para>
/// <b>Reflection, not a text scan.</b> The question this gate asks is <i>which type declares this
/// member</i>, and a declaration is a fact the compiler holds. A text scan cannot tell a
/// declaration from a call site, and would count a member named in a comment - which is exactly how
/// gate 5's original wording came to pass against a tree in which nothing was used. The comparable
/// choice is made the other way in <see cref="NullDefaultGateTests"/>, deliberately, because there
/// the subject is code that must not exist and reflection can only inspect what compiled.
/// </para>
/// <para>
/// <b>What it does not do.</b> It sees .NET members in the rebuild's production assemblies, so a
/// duplicate written somewhere the compiler never looks - the rule SQL that held K16's sixth answer
/// to the danger question, a report template, a stored procedure - is out of its reach. It also
/// cannot judge whether two differently named members answer the same question; that is what the
/// registry's own member shapes are for, and keeping them honest is a reader's job.
/// </para>
/// </summary>
public sealed class ConceptRegistryTests
{
    private const string RegistryFile = "CONCEPT-REGISTRY.md";
    private const string TableBegin = "<!-- CONCEPTS:BEGIN -->";
    private const string TableEnd = "<!-- CONCEPTS:END -->";

    /// <summary>
    /// Assemblies making up the rebuild's production surface. Held once in
    /// <see cref="RebuildAssemblies"/>, which carries the self-test naming the three assemblies a
    /// type move must not change - see <c>F-S24-4</c>.
    /// </summary>
    private static IEnumerable<Assembly> ProductionAssemblies() => RebuildAssemblies.All;

    /// <summary>
    /// The gate. A member whose name matches a concept's shape, declared by a type that does not
    /// own that concept, is a second answer to a question that already has one.
    /// </summary>
    [Fact]
    public void NoTypeOtherThanTheOwnerDeclaresAMemberOfAnOwnedConcept()
    {
        var concepts = RegistryEntries();

        var trespassers =
            (from concept in concepts
             from declaration in Declarations()
             where !IsOwnedBy(declaration.Type, concept.Owner)
             where concept.Shapes.Any(shape => Matches(shape, declaration.Member))
             select $"  {ReadableName(declaration.Type)}.{declaration.Member} answers "
                    + $"'{concept.Name}', which is owned by {concept.Owner} "
                    + $"({RegistryFile} line {concept.Line})")
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            trespassers.Count == 0,
            "A second type answers a question that already has an owner. This is the defect that "
            + "produced two GUID tables neither of which knew about the other, and six answers to "
            + "'is this permission dangerous' - two of them driving the pair of screens a customer "
            + "opens to compare against each other. Call the owning type, or move the concept's "
            + "ownership in " + RegistryFile + " and say why:"
            + Environment.NewLine + string.Join(Environment.NewLine, trespassers));
    }

    /// <summary>
    /// The registry names a type that exists. An owner that is a typo owns nothing, so every
    /// member matching its shapes belongs to somebody else and the gate above fires on all of them
    /// - or, worse, the shapes match nothing and it fires on none.
    /// </summary>
    [Fact]
    public void EveryOwningTypeExists()
    {
        var actual = Types().Select(ReadableName).ToHashSet(StringComparer.Ordinal);

        var phantom = RegistryEntries()
            .Where(c => !actual.Contains(c.Owner))
            .Select(c => $"  '{c.Name}' is owned by {c.Owner}, which does not exist (line {c.Line})")
            .ToList();

        Assert.True(
            phantom.Count == 0,
            RegistryFile + " names owning types that are not in the rebuild:"
            + Environment.NewLine + string.Join(Environment.NewLine, phantom));
    }

    /// <summary>
    /// The decay check, in the form this registry needs. An exemption list is not what goes stale
    /// here - a concept is. A concept whose shapes match nothing its owner actually declares is
    /// guarding a question nobody asks, and it will pass forever while measuring nothing, which is
    /// the worst thing a gate can do.
    /// </summary>
    [Fact]
    public void EveryConceptIsAnsweredByTheTypeThatOwnsIt()
    {
        var declarations = Declarations().ToList();

        var empty = RegistryEntries()
            .Where(c => !declarations.Any(d =>
                IsOwnedBy(d.Type, c.Owner) && c.Shapes.Any(shape => Matches(shape, d.Member))))
            .Select(c => $"  '{c.Name}': {c.Owner} declares no member matching "
                         + $"{string.Join(", ", c.Shapes)} (line {c.Line})")
            .ToList();

        Assert.True(
            empty.Count == 0,
            "Concepts whose owner answers nothing. Either the member was renamed and the shapes "
            + "must follow it, or the concept is gone and its row should go with it. A shape that "
            + "matches nothing cannot fail, and a check that cannot fail is not protection:"
            + Environment.NewLine + string.Join(Environment.NewLine, empty));
    }

    /// <summary>A concept is named once, so there is one place to look and one owner to find.</summary>
    [Fact]
    public void NoConceptIsListedTwice()
    {
        var duplicates = RegistryEntries()
            .GroupBy(c => c.Name, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => $"  '{g.Key}' appears {g.Count()} times")
            .ToList();

        Assert.True(
            duplicates.Count == 0,
            "A concept named twice can have two owners, which is the thing this file exists to "
            + "prevent, recorded in the file that prevents it:"
            + Environment.NewLine + string.Join(Environment.NewLine, duplicates));
    }

    /// <summary>
    /// The scanner self-test. Without it every assertion above passes by reflecting over an empty
    /// set of types and parsing an empty registry, and reporting a tree in perfect order.
    /// </summary>
    [Fact]
    public void TheCheckFindsBothTheCodeAndTheRegistry()
    {
        var declarations = Declarations().ToList();
        var concepts = RegistryEntries();

        Assert.True(declarations.Count > 0, "Reflected over no members in the production assemblies.");
        Assert.True(concepts.Count > 0, $"Read no concepts from {RegistryFile}.");

        Assert.Contains(
            declarations,
            d => ReadableName(d.Type) == nameof(SecureAD.Kernel.Schema.SchemaGuidCatalog)
                 && d.Member == nameof(SecureAD.Kernel.Schema.SchemaGuidCatalog.GuidFor));

        Assert.Contains(
            concepts,
            c => c.Owner == nameof(SecureAD.Kernel.Security.DangerousPermissionClassifier));
    }

    /// <summary>
    /// The shapes are anchored, not a substring scan. This is the failure mode this repository has
    /// already committed twice: gate 5's first wording, and the S-2 document guard that matched a
    /// renamed member because it looked for the name anywhere in the text.
    ///
    /// <para>
    /// The concrete consequence of getting it wrong in the loose direction is that
    /// <c>PermissionAssessment.CannotClassify</c> - which constructs the answer rather than
    /// deciding it - would be reported as a rival to the classifier, the gate would fire on the
    /// rebuild's own correct code on its first run, and the next person would switch it off.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData("Classify", "Classify", true)]
    [InlineData("Classify", "CannotClassify", false)]
    [InlineData("Classify", "ClassifyAce", false)]
    [InlineData("Classify*", "ClassifyAce", true)]
    [InlineData("GuidFor*", "GuidFor", true)]
    [InlineData("GuidFor*", "SchemaGuidFor", false)]
    [InlineData("ByGuid", "ObjectTypeGuid", false)]
    [InlineData("IsDangerous*", "IsDangerous", true)]
    [InlineData("IsDangerous*", "NotDangerous", false)]
    public void TheShapeMatchesTheWholeNameAndNotAPartOfIt(string shape, string member, bool expected)
    {
        Assert.Equal(expected, Matches(shape, member));
    }

    /// <summary>
    /// The gate is shown against the two duplicates that motivated it, using the member names the
    /// old code actually declared rather than invented ones. A gate that would not have caught the
    /// defects it exists for has not been shown to work.
    ///
    /// <para>
    /// K14's <c>WellKnownGuids</c> declared <c>GetGuid</c>, <c>TryGetGuid</c>, <c>ByGuid</c> and
    /// <c>ByLdapName</c> beside K13's catalogue
    /// (<c>git grep -n "^\s*public" -- src/SecureAD.Core/Schema/WellKnownGuids.cs</c>), and K13's
    /// <c>GuidCatalog</c> declared <c>IsDangerous</c>, which is one of the six answers K16 replaced.
    /// Each is checked against the concept that owns the question today, so a shape narrowed until
    /// it no longer covers the historical case fails here.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData("GetGuid", "SchemaGuidCatalog")]
    [InlineData("TryGetGuid", "SchemaGuidCatalog")]
    [InlineData("ByGuid", "SchemaGuidCatalog")]
    [InlineData("ByLdapName", "SchemaGuidCatalog")]
    [InlineData("IsDangerous", "DangerousPermissionClassifier")]
    public void TheGateWouldHaveCaughtTheDuplicatesThatMotivatedIt(string member, string expectedOwner)
    {
        var claiming = RegistryEntries()
            .Where(c => c.Shapes.Any(shape => Matches(shape, member)))
            .Select(c => c.Owner)
            .ToList();

        Assert.Equal([expectedOwner], claiming);
    }

    /// <summary>
    /// Turns a registry shape into an anchored pattern. <c>*</c> is the only wildcard, and it
    /// stands for the rest of a name. Globs rather than regular expressions because a regular
    /// expression's alternation character is the character a markdown table uses to separate cells,
    /// and because the owner has to be able to read this file.
    /// </summary>
    private static bool Matches(string shape, string memberName) =>
        Regex.IsMatch(
            memberName,
            "^" + string.Join("[A-Za-z0-9_]*", shape.Split('*').Select(Regex.Escape)) + "$",
            RegexOptions.CultureInvariant);

    /// <summary>
    /// A type owns a concept if it is the named type, or is nested inside it - a helper written
    /// inside the owner is part of the owner's answer, not a rival to it.
    /// </summary>
    private static bool IsOwnedBy(Type type, string owner)
    {
        for (var t = type; t is not null; t = t.DeclaringType)
        {
            if (string.Equals(ReadableName(t), owner, StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Every member an author wrote, and the type that declares it.
    ///
    /// <para>
    /// Internal and private members are included on purpose. The duplicates this gate exists for
    /// were not all public - K16's six answers included one inside a UI aggregation service - and a
    /// second answer hidden behind <c>private</c> is still a second answer that has to be kept in
    /// step with the first.
    /// </para>
    /// <para>
    /// Enum types are excluded: their members are a vocabulary rather than an answer, and
    /// <c>PermissionVerdict.Dangerous</c> naming the verdict is not a rival to the classifier that
    /// returns it. Compiler-written members are excluded for the reason
    /// <c>SchemaGuidDocumentationTests</c> gives - a gate firing on <c>get_Entries</c> would be
    /// policing the compiler.
    /// </para>
    /// </summary>
    private static IEnumerable<(Type Type, string Member)> Declarations() =>
        Types()
            .Where(t => !t.IsEnum)
            .SelectMany(t => t
                .GetMembers(BindingFlags.Public | BindingFlags.NonPublic
                            | BindingFlags.Static | BindingFlags.Instance
                            | BindingFlags.DeclaredOnly)
                .Where(m => m.MemberType is MemberTypes.Method or MemberTypes.Property or MemberTypes.Field)
                .Where(m => m is not MethodInfo method || !method.IsSpecialName)
                .Where(m => !m.Name.Contains('<', StringComparison.Ordinal))
                .Where(m => !CompilerWritten.Contains(m.Name))
                .Select(m => (t, m.Name)))
            .Distinct();

    /// <summary>Names the compiler generates for a record, which no author wrote.</summary>
    private static readonly HashSet<string> CompilerWritten = new(StringComparer.Ordinal)
    {
        "Equals", "GetHashCode", "ToString", "Deconstruct", "Clone", "PrintMembers",
        "op_Equality", "op_Inequality", "EqualityContract",
    };

    private static IEnumerable<Type> Types() =>
        ProductionAssemblies()
            .SelectMany(a => a.GetTypes())
            .Where(t => t.GetCustomAttribute<CompilerGeneratedAttribute>() is null)
            .Where(t => !t.Name.Contains('<', StringComparison.Ordinal));

    /// <summary>
    /// The name as a person would write it: the runtime reports <c>Result</c> as <c>Result`1</c>.
    /// </summary>
    private static string ReadableName(Type type)
    {
        var name = type.Name;
        var tick = name.IndexOf('`', StringComparison.Ordinal);
        return tick < 0 ? name : name[..tick];
    }

    private static string RegistryPath() =>
        Path.Combine(RepositoryLocation.Root(), "docs", "next", RegistryFile);

    /// <summary>
    /// The registry's rows. Only what lies between the markers is parsed, so the prose around the
    /// table does not have to pretend to be data.
    /// </summary>
    private static List<(string Name, string Owner, string[] Shapes, int Line)> RegistryEntries()
    {
        var path = RegistryPath();
        Assert.True(File.Exists(path), $"Expected the concept registry at {path}.");

        var lines = File.ReadAllLines(path);
        var begin = Array.FindIndex(lines, l => l.Trim() == TableBegin);
        var end = Array.FindIndex(lines, l => l.Trim() == TableEnd);

        Assert.True(
            begin >= 0 && end > begin,
            $"Could not find the {TableBegin} / {TableEnd} markers around the table in {path}. "
            + "The test parses only what lies between them, so a missing marker must fail rather "
            + "than silently empty the scan.");

        var entries = new List<(string, string, string[], int)>();

        for (var i = begin + 1; i < end; i++)
        {
            var cells = lines[i].Split('|', StringSplitOptions.TrimEntries);

            if (!lines[i].TrimStart().StartsWith('|'))
            {
                Assert.True(
                    lines[i].Trim().Length == 0,
                    $"{RegistryFile} line {i + 1} lies between the table markers and is not a "
                    + "table row. Only rows belong there, so prose here is a row that has lost "
                    + "its shape and would be skipped in silence.");
                continue;
            }

            Assert.True(
                cells.Length >= 6,
                $"{RegistryFile} line {i + 1} is a malformed table row with {cells.Length - 2} "
                + "cells rather than four. A row that cannot be parsed must fail rather than be "
                + "skipped: an editing accident during mutation testing truncated exactly this "
                + "row, and every check went on reporting the registry in perfect order because "
                + "the concept it held had quietly stopped existing."
                + Environment.NewLine + "  " + lines[i]);

            var name = cells[1];
            if (name is "Concept" || name.Length == 0 || name.All(c => c is '-' or ':'))
                continue;

            var shapes = cells[3]
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(s => s.Trim('`'))
                .Where(s => s.Length > 0)
                .ToArray();

            Assert.True(
                shapes.Length > 0,
                $"{RegistryFile} line {i + 1}: '{name}' lists no member shapes, so it owns "
                + "nothing and can never fail.");

            entries.Add((name, cells[2], shapes, i + 1));
        }

        return entries;
    }
}
