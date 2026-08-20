using SecureAD.Kernel.Security;
using SecureAD.Next.Tests.Inventory;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/next/S-1-security-descriptor-parsing.md</c> to the code it describes.
///
/// <para>
/// Per <c>docs/next/README.md</c>, a document is not the new product's documentation until a test
/// holds it to the code. These assertions catch drift and omission — a type renamed, a DACL state
/// added, the canonicalisation version bumped — in both directions, so the document cannot quietly
/// describe a component that has moved on and cannot omit a piece of it either.
/// </para>
/// <para>
/// What they cannot check is whether the explanation is any good. That needs a reader.
/// </para>
/// </summary>
public sealed class SecurityDocumentationTests
{
    private const string Document = "S-1-security-descriptor-parsing.md";

    /// <summary>
    /// The public types this component consists of. The document is a description of the component,
    /// so a type present in one and absent from the other is a gap either way.
    /// </summary>
    private static readonly string[] PublicTypes =
    [
        nameof(SecurityDescriptorParser),
        nameof(ParsedSecurityDescriptor),
        nameof(ParsedAce),
        nameof(DaclState),
        nameof(DaclCompleteness),
        nameof(AceType),
        nameof(GenericRightsExpander),
        nameof(AceNormalizer),
        nameof(CanonicalAce),
        nameof(AceNormalizationResult),
        nameof(AceCanonicalization),
        nameof(PermissionWordingWriter),
        nameof(PermissionWording),
        nameof(PermissionRight),
        nameof(PermissionScopeWriter),
        nameof(PermissionScope),
        nameof(Sid),
    ];

    /// <summary>
    /// Types that share this namespace and belong to a different component and a different
    /// document. K16's classifier sits beside K15's parser because both are about access control
    /// entries, and <c>S-4</c> describes it.
    ///
    /// <para>
    /// Listed rather than ignored, so the surface check below still proves that <b>every</b> public
    /// type in the namespace is covered by some document. A check that simply skipped what it did
    /// not recognise would stop being the thing it exists to be.
    /// </para>
    /// <para>
    /// <c>AceSetHash</c> is the second such case, added 2026-08-12 with inventory row B10. It sits in
    /// this namespace because the determinism rules it depends on are canonicalisation's, and it
    /// belongs to a different document because the reason it exists is
    /// <c>docs/decisions/0015</c> and the bundle - <c>S-16</c> describes it.
    /// </para>
    /// <para>
    /// <c>UserAccountControlWording</c> and <c>UserAccountControlFlag</c> are the third case, added
    /// 2026-08-18 with <c>S-51</c>. They sit in this namespace because a flag deciding whether an
    /// account can log on, or whether a service running as it can impersonate its callers, is a
    /// security fact and belongs beside the other security wording. They are described by
    /// <c>docs/areas/what-we-capture.md</c> rather than here, because the document this test guards
    /// is about parsing a security descriptor and this attribute is not one.
    /// </para>
    /// <para>
    /// <c>EntryReach</c> and <c>EntryReachReader</c> are the fourth case, added 2026-08-19 with
    /// <c>F-S58-6</c>. They sit in this namespace because <c>INHERIT_ONLY_ACE</c> is a fact about
    /// an access control entry, and they belong to <c>S-4</c> because the only thing that consults
    /// them is the classifier - an entry's reach changes what a verdict may claim, not how a
    /// descriptor is parsed.
    /// </para>
    /// </summary>
    private static readonly string[] CoveredByAnotherDocument =
    [
        nameof(DangerousPermissionClassifier),
        nameof(PermissionAssessment),
        nameof(PermissionVerdict),
        nameof(EntryReach),
        nameof(EntryReachReader),
        nameof(AceSetHash),
        nameof(UserAccountControlWording),
        nameof(UserAccountControlFlag),
        nameof(DirectoryTime),
        nameof(DirectoryTimeWording),
        nameof(DirectoryTimeFormat),
        nameof(GroupTypeWording),
    ];

    [Fact]
    public void TheDocumentNamesEveryPublicTypeInTheComponent()
    {
        var text = Read();

        var missing = PublicTypes.Where(t => !text.Contains(t, StringComparison.Ordinal)).ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not name: {string.Join(", ", missing)}. A type the documentation "
            + "does not mention is a piece of the component nobody reading it knows exists.");
    }

    [Fact]
    public void TheDocumentNamesNoTypeTheComponentDoesNotHave()
    {
        var text = Read();
        var actual = typeof(AceNormalizer).Assembly
            .GetExportedTypes()
            .Where(t => t.Namespace == typeof(AceNormalizer).Namespace)
            .Select(t => t.Name)
            .ToHashSet(StringComparer.Ordinal);

        var claimed = PublicTypes.Where(t => !actual.Contains(t)).ToList();

        Assert.True(
            claimed.Count == 0,
            $"{Document} names types that no longer exist in {typeof(AceNormalizer).Namespace}: "
            + string.Join(", ", claimed));
    }

    /// <summary>
    /// The lists above are between them the whole public surface of the namespace, not a subset
    /// someone stopped adding to. A type in neither is a type no document describes.
    /// </summary>
    [Fact]
    public void TheCheckedListIsTheWholePublicSurface()
    {
        var actual = typeof(AceNormalizer).Assembly
            .GetExportedTypes()
            .Where(t => t.Namespace == typeof(AceNormalizer).Namespace)
            .Select(t => t.Name)
            .OrderBy(n => n, StringComparer.Ordinal);

        Assert.Equal(
            PublicTypes.Concat(CoveredByAnotherDocument).OrderBy(n => n, StringComparer.Ordinal),
            actual);
    }

    /// <summary>
    /// Every DACL state is described, because the whole point of the enum is that a reader must be
    /// able to tell them apart.
    /// </summary>
    [Fact]
    public void TheDocumentNamesEveryDaclState()
    {
        var text = Read();

        var missing = Enum.GetNames<DaclState>()
            .Where(name => !text.Contains(name, StringComparison.Ordinal))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{Document} does not describe DACL states: {string.Join(", ", missing)}.");
    }

    /// <summary>
    /// The document states the canonicalisation version, which is the number that invalidates every
    /// stored hash if it moves. A document naming a stale one would be worse than naming none.
    /// </summary>
    [Fact]
    public void TheDocumentStatesTheCanonicalizationVersionTheCodeDeclares()
    {
        var text = Read();

        Assert.Contains(
            $"`{AceCanonicalization.Version}`",
            text,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The reader found the document. Without this every assertion above passes by searching an
    /// empty string and finding nothing missing.
    /// </summary>
    [Fact]
    public void TheReaderFindsTheDocument()
    {
        Assert.True(File.Exists(Path()), $"Expected the slice document at {Path()}.");
        Assert.True(Read().Length > 1000, $"{Document} is too short to be the document it claims.");
    }

    /// <summary>
    /// The check reports an absent name as missing. Run over an invented type name, so it proves
    /// the scan works without needing the document edited to prove it.
    /// </summary>
    [Fact]
    public void TheCheckReportsANameThatIsAbsent()
    {
        var text = Read();
        string[] invented = ["AceQuantumFluxNormalizer"];

        var missing = invented.Where(t => !text.Contains(t, StringComparison.Ordinal)).ToList();

        Assert.Single(missing);
    }

    private static string Path() =>
        System.IO.Path.Combine(OldAppInventory.RepositoryRoot(), "docs", "next", Document);

    private static string Read() => File.ReadAllText(Path());
}
