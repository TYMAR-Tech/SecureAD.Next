using SecureAD.Derivation;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

/// <summary>
/// What a forest's own <c>dSHeuristics</c> does to the set AdminSDHolder protects.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the only place the product reports less protection than Microsoft publishes.</b> That
/// direction is the dangerous one: over-reporting protection is a false alarm an operator can check
/// against the directory, but under-reporting it hides a group nobody is watching. So the cases
/// here are as much about when the catalogue must <i>not</i> narrow as about when it must.
/// </para>
/// <para>
/// <b>The mask itself is pinned elsewhere.</b> <c>DirectoryHeuristicsMicrosoftAnchorTests</c> holds
/// which bit means which group, against Microsoft's own worked examples. These are about what the
/// catalogue does with that answer.
/// </para>
/// </remarks>
public sealed class ProtectedCatalogueExclusionTests
{
    private const string AccountOperators = "S-1-5-32-548";
    private const string ServerOperators = "S-1-5-32-549";
    private const string PrintOperators = "S-1-5-32-550";
    private const string BackupOperators = "S-1-5-32-551";
    private const string Administrators = "S-1-5-32-544";

    /// <summary>Character 16 set, with the tenth character a domain controller requires.</summary>
    private static string WithMask(char mask) => "000000000" + "1" + "00000" + mask;

    /// <summary>
    /// A forest that excluded a group no longer protects it.
    /// </summary>
    [Fact]
    public void Stage2a_AnExcludedGroupIsNotProtected()
    {
        var catalogue = ProtectedGroupCatalogue.NarrowedBy(WithMask('1'));

        Assert.False(catalogue.IsProtected(AccountOperators));
    }

    /// <summary>
    /// Excluding one group leaves the others alone.
    /// </summary>
    /// <remarks>
    /// A mask that removed more than it names would understate protection across the forest, which
    /// is the direction that hides things.
    /// </remarks>
    [Fact]
    public void Stage2a_ExcludingOneGroupLeavesTheOthersProtected()
    {
        var catalogue = ProtectedGroupCatalogue.NarrowedBy(WithMask('1'));

        Assert.True(catalogue.IsProtected(ServerOperators));
    }

    /// <summary>
    /// A group the mask cannot name stays protected however the mask is set.
    /// </summary>
    /// <remarks>
    /// <b>The mask is four bits and names four operator groups.</b> Administrators is not one of
    /// them, so no value of this character can remove it - and a catalogue that let one would report
    /// the forest's most privileged group as unprotected.
    /// </remarks>
    [Fact]
    public void Stage2a_AGroupTheMaskCannotNameStaysProtected()
    {
        var catalogue = ProtectedGroupCatalogue.NarrowedBy(WithMask('f'));

        Assert.True(catalogue.IsProtected(Administrators));
    }

    /// <summary>
    /// A forest excluding all four still protects everything else.
    /// </summary>
    [Fact]
    public void Stage2a_AForestExcludingAllFourStillProtectsTheRest()
    {
        var catalogue = ProtectedGroupCatalogue.NarrowedBy("000000000100000f");

        Assert.True(catalogue.IsProtected("S-1-5-21-1-2-3-512"));
    }

    /// <summary>
    /// What Microsoft publishes stays answerable after a forest has narrowed it.
    /// </summary>
    /// <remarks>
    /// An operator asking why a group is unprotected needs to know whether it was never in the
    /// catalogue or was taken out by this forest. Those are different remedies, and a catalogue that
    /// forgot the published set could not tell them apart.
    /// </remarks>
    [Fact]
    public void Stage2a_ThePublishedSetIsStillAnswerableAfterNarrowing()
    {
        var catalogue = ProtectedGroupCatalogue.NarrowedBy("000000000100000f");

        Assert.False(catalogue.IsProtected(PrintOperators));
        Assert.True(ProtectedGroupCatalogue.IsInThePublishedCatalogue(PrintOperators));
    }

    /// <summary>
    /// A forest that set no value protects everything Microsoft publishes.
    /// </summary>
    /// <remarks>
    /// An absent attribute is a documented answer - every character defaults to zero - and not a
    /// gap. Treating it as one would state doubt about a forest that gave a clear answer.
    /// </remarks>
    [Fact]
    public void Stage2a_AForestThatSetNoValueProtectsEverythingPublished()
    {
        var catalogue = ProtectedGroupCatalogue.NarrowedBy(string.Empty);

        Assert.True(catalogue.IsProtected(BackupOperators));
    }

    /// <summary>
    /// A forest that was asked and excluded nothing says the answer was reached.
    /// </summary>
    [Fact]
    public void Stage2a_AForestThatExcludedNothingSaysItWasAsked()
    {
        var catalogue = ProtectedGroupCatalogue.NarrowedBy(string.Empty);

        Assert.True(catalogue.Exclusions.IsComplete);
    }

    /// <summary>
    /// A bundle that does not carry the value protects everything, and says nobody looked.
    /// </summary>
    /// <remarks>
    /// <b>The two halves matter together.</b> Every bundle captured before catalogue version 5 is
    /// this case. It must keep the published set - narrowing on evidence nobody has would hide
    /// groups - and it must not claim the forest confirmed it.
    /// </remarks>
    [Fact]
    public void Stage2a_ABundleWithoutTheValueKeepsThePublishedSet()
    {
        var catalogue = ProtectedGroupCatalogue.NarrowedBy(dsHeuristics: null);

        Assert.True(catalogue.IsProtected(AccountOperators));
    }

    /// <summary>
    /// And it does not pretend the forest was asked.
    /// </summary>
    [Fact]
    public void Stage2a_ABundleWithoutTheValueDoesNotClaimTheForestWasAsked()
    {
        var catalogue = ProtectedGroupCatalogue.NarrowedBy(dsHeuristics: null);

        Assert.False(catalogue.Exclusions.IsComplete);
    }

    /// <summary>
    /// The default catalogue is the published one, unasked.
    /// </summary>
    /// <remarks>
    /// It is what a derivation uses when no bundle has been consulted, so it must not imply that a
    /// forest confirmed anything.
    /// </remarks>
    [Fact]
    public void Stage2a_TheDefaultCatalogueDoesNotClaimAForestWasAsked()
    {
        Assert.False(ProtectedGroupCatalogue.Default.Exclusions.IsComplete);
    }

    /// <summary>
    /// A mask character Microsoft documents no meaning for removes nothing.
    /// </summary>
    /// <remarks>
    /// The specification defines no behaviour for one, and the larger protected set is the direction
    /// that cannot hide a group.
    /// </remarks>
    [Fact]
    public void Stage2a_AnUndocumentedMaskCharacterRemovesNothing()
    {
        var catalogue = ProtectedGroupCatalogue.NarrowedBy(WithMask('z'));

        Assert.True(catalogue.IsProtected(AccountOperators));
    }

    /// <summary>
    /// A short string does not reach character 16, so nothing is excluded.
    /// </summary>
    /// <remarks>
    /// Most forests are this case: a value set for some other heuristic, ending long before this
    /// one. Every character past the end defaults to zero.
    /// </remarks>
    [Fact]
    public void Stage2a_AStringTooShortToReachTheMaskExcludesNothing()
    {
        var catalogue = ProtectedGroupCatalogue.NarrowedBy("0000002");

        Assert.True(catalogue.IsProtected(AccountOperators));
    }
}
