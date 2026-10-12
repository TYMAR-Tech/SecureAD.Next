using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Gate 2, first instance: an Active Directory GUID is written down in exactly one place.
///
/// <para>
/// <b>What went wrong before.</b> The old product wrote GUID literals in five production files.
/// Two were catalogues that did not reference each other; a third hid inside
/// <c>BuiltInBundles.cs</c>, which nobody grepping for a GUID table would find; and
/// <c>ControlEdgeService</c> - the component that builds the entire control graph - declared nine
/// GUIDs of its own <i>while a ninety-three entry catalogue already existed</i> and never called
/// it once.
/// </para>
/// <para>
/// The lesson is not that people were careless. It is that a correct catalogue nothing is obliged
/// to use does not become the source of truth by being correct. So this is a build failure rather
/// than a convention.
/// </para>
/// <para>
/// <b>Scope, and the one exemption.</b> Only production source under <c>next/src/</c> is scanned.
/// Test source may write literals, and must be able to: a test that asks the catalogue what it
/// thinks is checking the table against itself. The rule-derived assertions in
/// <c>SchemaGuidCatalogTests</c> take their expected values from <c>docs/rules/</c> for exactly
/// that reason.
/// </para>
/// <para>
/// <b>What it does not do.</b> Comment lines are skipped, so a GUID quoted in an explanation does
/// not fail the build - the same allowance every other guard here makes, because a guard's own
/// prose names the thing it forbids. The skip is a text heuristic on the leading characters of a
/// line, not a parser, so a GUID in a trailing comment after code would still be caught. Quoted
/// HTTP documentation URLs are references, not directory identifiers; a separate literal on the
/// same line remains in scope.
/// </para>
/// </summary>
public sealed class SchemaGuidSingleSourceGateTests
{
    /// <summary>
    /// A bare GUID in quotes. Deliberately not anchored to a variable name or an attribute, because
    /// the failure being prevented is a literal appearing anywhere at all.
    /// </summary>
    private static readonly Regex GuidLiteral = new(
        @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        RegexOptions.Compiled);
    private static readonly Regex QuotedWebReference = new(
        "\"https?://[^\"\\r\\n]+\"", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static bool ContainsIdentifierLiteral(string source) => GuidLiteral.IsMatch(QuotedWebReference.Replace(source, ""));

    /// <summary>
    /// The files allowed to contain GUID literals, one per kind of GUID, with the reason each
    /// owns its kind. Held as file names rather than types so the scan needs no reflection and
    /// catches a literal in a file that does not compile.
    /// </summary>
    /// <remarks>
    /// <b>This was a single file until the Group Policy parsers landed, and widening it was the
    /// alternative to filing a GUID under the wrong heading.</b> The gate reads every GUID literal
    /// as an Active Directory schema GUID and tells the author to "ask the catalogue for the GUID
    /// by LDAP name". A Group Policy client-side extension has no LDAP name and is not a schema
    /// object: it identifies an extension that applies part of a GPO, per [MS-GPOL]. Putting one in
    /// <c>SchemaGuidCatalog</c> would have made that table answer two unrelated questions, which is
    /// the defect gate 2 exists to prevent, arrived at by obeying gate 2.
    /// <para>
    /// <b>The invariant is unchanged and is not softened by this.</b> It was never "one file"; it
    /// was <i>one home per kind of identifier</i>, and one file was enough while one kind existed.
    /// Every entry here is still held to <see cref="EveryDeclaredOwnerIsStillEarningItsPlace"/>,
    /// so an owner that stops holding literals fails the build rather than becoming a permanent
    /// hole. Adding an entry means claiming a new kind of GUID exists and naming it here.
    /// </para>
    /// </remarks>
    private static readonly Dictionary<string, string> GuidOwners =
        new(StringComparer.Ordinal)
        {
            ["SchemaGuidCatalog.cs"] = "Active Directory schema GUIDs - attributes, classes, "
                + "control access rights - asked for by LDAP name",
            ["GpoClientSideExtensionCatalog.cs"] = "Group Policy client-side extension GUIDs "
                + "([MS-GPOL]), which name a policy extension rather than a directory object and "
                + "have no LDAP name",
        };

    [Fact]
    public void NoProductionFileOutsideTheCatalogueWritesAGuidLiteral()
    {
        var offenders = RebuildTree
            .ScanPattern(RebuildTree.ProductionFiles(), GuidLiteral)
            .Where(s => ContainsIdentifierLiteral(s.Text))
            .Where(s => !GuidOwners.ContainsKey(Path.GetFileName(s.File)))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "GUID literals outside the file that owns their kind. The old product wrote them in "
            + "five places, and the same attribute ended up recorded under three different GUIDs, "
            + "two of them wrong. Ask the owning catalogue instead, or - if this is a kind of GUID "
            + "none of them owns - say so in GuidOwners and give it a home:"
            + Environment.NewLine + RebuildTree.Describe(offenders)
            + Environment.NewLine + "Declared owners: "
            + string.Join(", ", GuidOwners.Keys));
    }

    /// <summary>
    /// The scanner self-test. Without it this gate passes by finding no files, or by carrying a
    /// pattern that matches nothing, and reports a tree in perfect order either way.
    /// </summary>
    [Fact]
    public void TheCheckReadsTheProductionTreeAndItsPatternMatches()
    {
        var files = RebuildTree.ProductionFiles().ToList();

        Assert.True(files.Count > 0, "Found no production source under next/src/ to scan.");
        Assert.Contains(files, f => Path.GetFileName(f) == "SchemaGuidCatalog.cs");
        Assert.Matches(GuidLiteral, "bf967a68-0de6-11d0-a285-00aa003049e2");
        Assert.DoesNotMatch(GuidLiteral, "userAccountControl");
    }

    [Theory]
    [InlineData("const string Attribute = \"bf967a68-0de6-11d0-a285-00aa003049e2\";", true)]
    [InlineData("Reference: \"https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/f70afbcc-780e-4d91-850c-cfadce5bb15c\"", false)]
    [InlineData("Reference: \"https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/f70afbcc-780e-4d91-850c-cfadce5bb15c\", Attribute: \"bf967a68-0de6-11d0-a285-00aa003049e2\"", true)]
    public void DocumentationUrlsDoNotHideSeparateIdentifierLiterals(string source, bool containsIdentifier) =>
        Assert.Equal(containsIdentifier, ContainsIdentifierLiteral(source));

    /// <summary>
    /// The allowlist-decay test. An exemption that is no longer needed must fail rather than
    /// quietly become permanent - so if a declared owner ever stops holding literals, whether
    /// because the table moved or because it was emptied, the exemption goes with it.
    /// </summary>
    [Fact]
    public void EveryDeclaredOwnerIsStillEarningItsPlace()
    {
        var literalsByFile = RebuildTree
            .ScanPattern(RebuildTree.ProductionFiles(), GuidLiteral)
            .Where(s => ContainsIdentifierLiteral(s.Text))
            .GroupBy(s => Path.GetFileName(s.File), StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);

        var dead = GuidOwners.Keys
            .Where(owner => !literalsByFile.ContainsKey(owner))
            .ToList();

        Assert.True(
            dead.Count == 0,
            "These files are exempt from the GUID-literal gate and contain no literal. Either the "
            + "table moved, in which case the exemption follows it, or the exemption is dead and "
            + "should go: "
            + string.Join(", ", dead));
    }

    /// <summary>
    /// Scope is deliberate, not accidental. Tests carry literals on purpose, and this records that
    /// they do - so a later widening of the scan to the whole tree fails here first, with the
    /// reason attached, rather than being switched off in a hurry when it turns red.
    /// </summary>
    [Fact]
    public void TestSourceIsOutOfScopeAndActuallyUsesThatFreedom()
    {
        var productionPaths = RebuildTree.ProductionFiles().ToHashSet(StringComparer.Ordinal);

        var inTests = RebuildTree
            .ScanPattern(RebuildTree.AllFiles(), GuidLiteral)
            .Where(s => ContainsIdentifierLiteral(s.Text))
            .Where(s => !productionPaths.Contains(s.File))
            .ToList();

        Assert.True(
            inTests.Count > 0,
            "No test writes a GUID literal. The exemption for test source exists because a test "
            + "that asks the catalogue what it thinks proves nothing; if nothing relies on it, the "
            + "scan should widen to the whole tree.");
    }
}
