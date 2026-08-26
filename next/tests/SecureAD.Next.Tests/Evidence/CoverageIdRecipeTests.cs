using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// Ties the recipe behind <see cref="CoverageId"/> to <see cref="BundleSchema.Version"/>, so that
/// changing what goes into the hash cannot be done quietly.
/// </summary>
/// <remarks>
/// <para>
/// <b>The rule is
/// <c>docs/decisions/0084-a-stored-fingerprints-recipe-is-pinned-to-the-schema-version.md</c></b>,
/// which is where the reasoning lives. This is the guard.
/// </para>
/// <para>
/// <b>F-0079-6.</b> <c>coverage_id</c> is stored in every bundle and read back as
/// <c>RunScope.Identity</c>, which is what the run library groups on -
/// <c>RunLibraryViewModel</c> groups a <c>PropertyGroupDescription</c> over it, and baseline
/// selection walks the runs sharing it. Change what goes into the hash and every value computed
/// afterwards differs from every value computed before, while a sixteen-character hex string looks
/// identical either way.
/// </para>
/// <para>
/// <b>It has happened.</b> Commit <c>9a69305</c> on 2026-08-21 added the excluded-domain set to the
/// string - a correct fix for a real defect - and touched <c>CoverageId.cs</c> and its tests and
/// nothing else. The result was two groups in the library under one identical heading, because
/// <c>RunSummaryViewModel.GroupKey</c> comes from the hash while <c>GroupHeading</c> is built from
/// the domain rows. Two sources for one visual group, and the label hides the disagreement.
/// </para>
/// <para>
/// <b>The remedy is a rule rather than a format.</b> <c>coverage_id</c> is a stored column whose
/// meaning depends on the recipe that produced it, which is what <see cref="BundleSchema.Version"/>
/// already exists for - it was raised to 6 when <c>finding</c> was added, because a build reading a
/// version 5 bundle would report no findings and be telling the truth about the table while lying
/// about the forest. A stale <c>coverage_id</c> is the same shape: true about the string, false
/// about what the run covered. So the recipe and the schema version move together, and a bundle
/// from a different recipe is refused at open under <c>SchemaVersionUnsupported</c> rather than
/// reaching the library and forming a second group.
/// </para>
/// <para>
/// <b>What this test can and cannot do.</b> It cannot force anybody to raise a constant. What it
/// does is make the recipe change impossible to make silently, and shape the obvious repair so that
/// it requires the bump: the expected value is keyed on the schema version, so the natural fix for
/// a failure here is to add a row for the next version, and adding a row for the next version
/// requires that version to exist. Editing the current row in place still passes - that is a
/// deliberate act against a message saying not to, which is the same standing every gate in this
/// repository has.
/// </para>
/// </remarks>
public sealed class CoverageIdRecipeTests
{
    /// <summary>
    /// A fixed input, chosen to exercise every part of the recipe: a forest, more than one declared
    /// domain, and an exclusion. Never change these values - changing them changes the expected
    /// hash without changing the recipe, which is the one thing this test exists to detect.
    /// </summary>
    private const string Forest = "contoso.com";

    private static readonly string[] Declared =
        ["eu.contoso.com", "contoso.com", "us.contoso.com"];

    private static readonly string[] Excluded = ["us.contoso.com"];

    /// <summary>
    /// The value the recipe produces, per schema version. Append-only: a row here is a statement
    /// about bundles that exist, and rewriting one says something false about what an older build
    /// wrote.
    /// </summary>
    private static readonly Dictionary<int, string> ExpectedBySchemaVersion = new()
    {
        [6] = "57cf8ba5a9e7fb10",

        // Same value as 6, and that is the correct outcome rather than a missed change. Version 7
        // widened the captured attribute catalogue, which changes the schema but not this recipe -
        // coverage_id is built from the forest, the declared domains and the exclusions, none of
        // which the password policy attributes touch. A differing value here would have meant the
        // recipe moved without anyone saying so.
        [7] = "57cf8ba5a9e7fb10",

        // Same value again, and again the correct outcome. Version 8 removed the finding,
        // finding_unconstrained_delegation and evaluated_rule tables under docs/decisions/0085.
        // coverage_id is built from the forest, the declared domains and the exclusions, and a
        // rule's verdict was never one of its inputs - so a differing value here would have meant
        // the recipe moved while nobody was looking at it.
        [8] = "57cf8ba5a9e7fb10",
    };

    /// <summary>
    /// The recipe still produces what this build's schema version says it produces.
    /// </summary>
    [Fact]
    public void TheRecipeProducesTheValuePinnedForThisSchemaVersion()
    {
        Assert.True(
            ExpectedBySchemaVersion.TryGetValue(BundleSchema.Version, out var expected),
            $"No coverage identity is pinned for schema version {BundleSchema.Version}. If the "
            + "schema version was raised, add a row recording what the recipe produces under it.");

        var actual = CoverageId.ForDomainsExcluding(Forest, Declared, Excluded).Value;

        Assert.True(
            string.Equals(expected, actual, StringComparison.Ordinal),
            $"The coverage identity recipe has changed: schema version {BundleSchema.Version} is "
            + $"pinned to '{expected}' and now produces '{actual}'.\n\n"
            + "coverage_id is stored in every bundle and is what the run library groups on. Every "
            + "bundle written before this change still holds the old value, so old and new runs "
            + "will draw as two groups under one identical heading - which is exactly what "
            + "happened on 2026-08-21.\n\n"
            + "Raise BundleSchema.Version and add a row here for the new version. That makes a "
            + "bundle from the old recipe refuse to open under SchemaVersionUnsupported, which is "
            + "loud, instead of regrouping silently, which is not. Do not edit the existing row: "
            + "it is a statement about bundles that already exist.");
    }

    /// <summary>
    /// The pinned value is a real coverage identity and not a copied literal that happens to sit
    /// in the table. Without this the check above could be satisfied by a value the recipe cannot
    /// produce at all.
    /// </summary>
    [Fact]
    public void ThePinnedValueHasTheShapeOfACoverageIdentity()
    {
        var pinned = ExpectedBySchemaVersion[BundleSchema.Version];

        Assert.Equal(16, pinned.Length);
        Assert.All(pinned, c => Assert.True(
            char.IsAsciiDigit(c) || (c >= 'a' && c <= 'f'),
            $"'{c}' is not lowercase hexadecimal."));
    }

    /// <summary>
    /// The input really does exercise the exclusion half of the recipe. If it did not, a change to
    /// how exclusions are hashed would leave this pin untouched and the check above would pass
    /// through the defect it exists to catch.
    /// </summary>
    [Fact]
    public void TheFixedInputExercisesTheExclusionHalfOfTheRecipe()
    {
        var withExclusion = CoverageId.ForDomainsExcluding(Forest, Declared, Excluded).Value;
        var withoutExclusion = CoverageId.ForDomains(Forest, Declared).Value;

        Assert.NotEqual(withoutExclusion, withExclusion);
    }

    /// <summary>
    /// Every pinned version is one this repository has actually shipped a schema for. A row for a
    /// version that never existed would be a pin nobody can check.
    /// </summary>
    [Fact]
    public void NoValueIsPinnedForASchemaVersionAheadOfThisBuild()
    {
        var ahead = ExpectedBySchemaVersion.Keys
            .Where(version => version > BundleSchema.Version)
            .ToList();

        Assert.True(
            ahead.Count == 0,
            $"Pinned coverage identities name schema versions this build does not have: "
            + $"{string.Join(", ", ahead)}.");
    }
}
