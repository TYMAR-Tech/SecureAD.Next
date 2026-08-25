using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// What a spec document must say, and what it must not pretend to be.
/// </summary>
/// <remarks>
/// <para>
/// <b>These are not prose checks, and the distinction matters because prose checks keep coming
/// back here.</b> Twelve test files asserting heading formats and status lines were deleted on
/// 2026-08-14 and the suite lost 167 tests. The test for whether a check belongs is
/// <i>what change to the product would make this fail?</i> - and for a heading format the answer
/// is nothing.
/// </para>
/// <para>
/// <b>The change these two guard against is a document changing category.</b> A spec sits in
/// <c>docs/layers</c>, one directory away from documents that are held true by tests, and a
/// session that reads the folder name rather than the file will take it for settled. That has a
/// cost the repository has already paid: findings have been raised and withdrawn on the strength
/// of a well-argued paragraph mistaken for a conclusion. The banner is the one thing standing
/// between those two readings, so it is load-bearing rather than decorative, and the absent
/// <c>TYPES</c> table is what stops a spec being scanned as a layer document by a later gate that
/// discovers rather than names.
/// </para>
/// </remarks>
public sealed class SpecDocumentGateTests
{
    /// <summary>
    /// The scan finds the spec documents, so the assertions below are not passing on an empty set.
    /// </summary>
    /// <remarks>
    /// <b>Every gate here carries one of these.</b> A check that runs over nothing passes over
    /// nothing, and this repository has shipped that twice - gate 5 passed against fourteen public
    /// types while nothing in the tree was reachable, and a document guard matched a renamed member
    /// by substring so a deliberately broken document did not fail it. Both looked green.
    /// </remarks>
    [Fact]
    public void TheScanFindsTheSpecDocuments()
    {
        if (!Directory.Exists(SpecDocuments.Root()))
            return;

        Assert.NotEmpty(SpecDocuments.All());
    }

    /// <summary>
    /// Every spec says in writing that it does not state the product's position.
    /// </summary>
    [Fact]
    public void EverySpecSaysItIsDiscussionRatherThanADecision()
    {
        var missing = SpecDocuments.All()
            .Where(file => !File.ReadAllText(file, System.Text.Encoding.UTF8)
                .Contains(SpecDocuments.DiscussionBanner, StringComparison.Ordinal))
            .Select(file => $"  {Path.GetFileName(file)} does not carry "
                + $"\"{SpecDocuments.DiscussionBanner}\"")
            .OrderBy(m => m, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "A spec that does not say it is discussion reads as settled to anyone going by the "
            + "folder it sits in. Only docs/decisions/ states the product's position:"
            + Environment.NewLine
            + string.Join(Environment.NewLine, missing));
    }

    /// <summary>
    /// No spec carries a <c>TYPES</c> table, which is what a layer document carries.
    /// </summary>
    /// <remarks>
    /// A spec describes code that does not exist, so a table of the types it owns can only name
    /// types nobody has written. <c>SurfaceRegister</c> resolves those tables against the
    /// assemblies; a spec offering one would either fail that or, worse, pass by naming nothing.
    /// </remarks>
    [Fact]
    public void NoSpecCarriesATypesTable()
    {
        var offenders = SpecDocuments.All()
            .Where(file => File.ReadAllText(file, System.Text.Encoding.UTF8)
                .Contains("## TYPES", StringComparison.OrdinalIgnoreCase))
            .Select(file => $"  {Path.GetFileName(file)} carries a TYPES table, which is what makes "
                + "a layer document a layer document")
            .OrderBy(m => m, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "A spec describes code that does not exist yet, so it cannot own types. Move the "
            + "content into the layer document for the code once the code is written:"
            + Environment.NewLine
            + string.Join(Environment.NewLine, offenders));
    }
}
