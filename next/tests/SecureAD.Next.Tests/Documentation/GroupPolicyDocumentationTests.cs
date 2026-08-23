using SecureAD.Kernel.GroupPolicy;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/layers/kernel/what-a-policy-declares.md</c> and
/// <c>docs/layers/kernel/what-a-policy-file-contains.md</c> to the code they describe.
/// </summary>
/// <remarks>
/// <para>
/// <b>This gate is new rather than retargeted, which is unusual here.</b> The five test files under
/// <c>Kernel/GroupPolicy</c> are behaviour tests and not one of them bound a document, so there was
/// nothing to point somewhere else. Before this existed the folder stood at <b>zero of sixteen</b>
/// against the layer documents: six of its types were named only by
/// <c>docs/MICROSOFT-VERIFICATION.md</c> and <c>docs/rules/FIRST-PARTY-VERIFICATION.md</c>, which are
/// verification registers rather than layer documents.
/// </para>
/// <para>
/// <b>It scans the folder, not the document's claim.</b> The usual per-document gate here is
/// <c>TheDocumentNamesEveryPublicTypeInTheComponent</c>, scoped to the component a document already
/// claims, so it can only ever check types somebody already decided to describe. That is the shape
/// recorded as <c>P-38</c>, and it is how <c>Evidence/Findings</c> reached zero of seventeen with the
/// suite green. This check starts from the exported types in the namespace and asks which document
/// names each one, so a type added to the folder tomorrow and described nowhere fails.
/// </para>
/// <para>
/// <b>Two documents, so the union is checked and then the split.</b> Checking only the union would
/// let both pages drift into describing everything vaguely; checking only the split would not notice
/// a type that fell out of both. Both are asserted.
/// </para>
/// <para>
/// <b>The capability-table check was deleted on 2026-08-21 (<c>P-51</c>).</b> It asserted that each
/// page carried a <c>## What an operator can do</c> heading, which is the shape of the prose and not
/// the state of the product: no change to <c>Kernel/GroupPolicy</c> could make it fail.
/// </para>
/// <para>
/// What it cannot check is whether the account of order-versus-precedence is any good, or whether
/// the cpassword page describes the refusal the parser actually implements. That needs a reader.
/// </para>
/// </remarks>
public sealed class GroupPolicyDocumentationTests
{
    private const string Declares = "what-a-policy-declares.md";
    private const string Contains = "what-a-policy-file-contains.md";

    /// <summary>
    /// The types that read a directory attribute, which <see cref="Declares"/> owns.
    /// </summary>
    private static readonly string[] DeclaredInTheDirectory =
    [
        nameof(GpoClientSideExtensionCatalog),
        nameof(GpoClientSideExtensions),
        nameof(ParsedCseList),
        nameof(PolicyLink),
        nameof(PolicyLinkList),
    ];

    /// <summary>
    /// The types that parse a file off SYSVOL, which <see cref="Contains"/> owns.
    /// </summary>
    private static readonly string[] ReadFromAFile =
    [
        nameof(RegistryPolicyParser),
        nameof(ParsedRegistryPolicy),
        nameof(RegistryPolicyEntry),
        nameof(RegistryValueType),
        nameof(SecurityTemplateParser),
        nameof(ParsedSecurityTemplate),
        nameof(SecurityTemplateSetting),
        nameof(RestrictedGroup),
        nameof(GroupPolicyPreferenceParser),
        nameof(ParsedGppFile),
        nameof(GppPasswordFinding),
    ];

    /// <summary>
    /// Every public type in the folder is named by one of the two documents. This is the check the
    /// folder did not have, and the one that would have made its zero of sixteen visible without
    /// anyone counting by hand.
    /// </summary>
    [Fact]
    public void EveryPublicTypeInTheGroupPolicyFolderIsNamedByADocument()
    {
        var both = Read(Declares) + Read(Contains);

        var missing = PublicTypeNames()
            .Where(name => !both.Contains(Quoted(name), StringComparison.Ordinal))
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "These public types in Kernel/GroupPolicy are named by neither layer document: "
            + string.Join(", ", missing)
            + ". A type the documentation does not mention is a piece of the component nobody "
            + "reading it knows exists, and a verification register naming it is not a layer "
            + "document describing it.");
    }

    /// <summary>
    /// Each document names the types it owns. The folder is split across two pages on the axis the
    /// area file opens with — what the directory stores, and what the files behind it contain — and
    /// a type described on the wrong page is a reader sent to the wrong place.
    /// </summary>
    [Fact]
    public void EachDocumentNamesTheTypesItOwns()
    {
        var wrong = new List<string>();

        foreach (var name in DeclaredInTheDirectory)
        {
            if (!Read(Declares).Contains(Quoted(name), StringComparison.Ordinal))
                wrong.Add($"  {Declares} does not name `{name}`");
        }

        foreach (var name in ReadFromAFile)
        {
            if (!Read(Contains).Contains(Quoted(name), StringComparison.Ordinal))
                wrong.Add($"  {Contains} does not name `{name}`");
        }

        Assert.True(
            wrong.Count == 0,
            "A type is described on neither its own page:" + Environment.NewLine
            + string.Join(Environment.NewLine, wrong));
    }

    /// <summary>
    /// The scanner self-test.
    /// assembly it failed to reach, and reports that nothing is wrong with any of them. The two
    /// owned sets are also asserted to account for the whole folder, so a type added to the
    /// namespace without being assigned to a page fails here rather than being quietly unowned.
    /// </summary>
    [Fact]
    public void TheCheckReadsTheFolderAndDiscriminates()
    {
        var found = PublicTypeNames().ToList();

        Assert.True(found.Count > 0, "Read no public types from the GroupPolicy namespace.");

        var owned = DeclaredInTheDirectory.Concat(ReadFromAFile).ToHashSet(StringComparer.Ordinal);
        var unowned = found.Where(n => !owned.Contains(n)).OrderBy(n => n, StringComparer.Ordinal).ToList();

        Assert.True(
            unowned.Count == 0,
            "These types are in the folder but assigned to neither document: "
            + string.Join(", ", unowned) + ". Assign each to the page that describes it.");

        // The scan is not a bare substring search: a rename would otherwise still match.
        var text = Read(Contains);
        Assert.Contains(Quoted(nameof(RegistryPolicyParser)), text, StringComparison.Ordinal);
        Assert.DoesNotContain(Quoted(nameof(RegistryPolicyParser) + "XX"), text, StringComparison.Ordinal);
    }

    /// <summary>
    /// The name as a document must write it. A bare name would match any longer name containing it;
    /// the backticks make the match exact without needing a parser. Without this
    /// <c>ParsedGppFile</c> would be satisfied by prose about <c>ParsedGppFileReader</c>.
    /// </summary>
    private static string Quoted(string name) => "`" + name + "`";

    private static IEnumerable<string> PublicTypeNames() =>
        typeof(RegistryPolicyParser).Assembly
            .GetExportedTypes()
            .Where(t => t.Namespace == typeof(RegistryPolicyParser).Namespace)
            .Select(t => t.Name);

    private static string Read(string document) =>
        File.ReadAllText(Path.Combine(RepositoryLocation.Root(), "docs", "layers", "kernel", document));
}
