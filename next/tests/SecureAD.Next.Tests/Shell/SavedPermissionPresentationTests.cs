using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.ControlEdgeDeriverTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class SavedPermissionPresentationTests
{
    [Fact]
    public void P248ClassificationUnknownNoticeUpdatesWithHighlighting()
    {
        var section = Section(Permissions(Ace(0, Holder, 0x200)));
        var changes = new List<string?>();
        section.PropertyChanged += (_, change) => changes.Add(change.PropertyName);

        section.HighlightRiskyPermissions = true;

        Assert.Equal((true, "1 rights could not be classified. They are not reported as safe."),
            (changes.Contains(nameof(section.Statements)), section.Statements.Single().Title));
    }

    [Fact]
    public void P248ClassificationUnavailableDoesNotBecomeZeroRisk()
    {
        var permissions = Permissions(Ace(0, Holder, 0x40000));
        var section = new PermissionsSectionViewModel(Definition(), permissions, PermissionVocabulary.Shipped, null,
            "This run has no saved permission classification.") { HighlightRiskyPermissions = true };

        var counter = section.Counters.Single(value => value.Label == "Dangerous");

        Assert.Equal(((int?)null, "This run has no saved permission classification."), (counter.Value, counter.Explanation));
    }

    [Fact]
    public void P248ClassificationHiddenSavedCountsAreNotUncomputed()
    {
        var section = Section(Permissions(Ace(0, Holder, 0x40000)));

        var counter = section.Counters.Single(value => value.Label == "Dangerous");

        Assert.Equal("Not shown", counter.Status);
    }

    [Fact]
    public void P248ClassificationUnknownHasAnExplanationWithoutADangerMark()
    {
        var section = Section(Permissions(Ace(0, Holder, 0x200)));
        section.HighlightRiskyPermissions = true;

        var right = section.Principals.Single().Entries.Single().Rights.Single();

        Assert.Equal((PermissionRisk.None, "The access mask carries bits this build has no word for, so what they grant has not been assessed. They are not being reported as safe."),
            (right.Mark, right.ClassificationReason));
    }

    [Fact]
    public void P248ClassificationMixedRightsStillCountOneEntry()
    {
        var section = Section(Permissions(Ace(0, Holder, 0xE0000)));
        section.HighlightRiskyPermissions = true;

        Assert.Equal(1, section.Counters.Single(value => value.Label == "Dangerous").Value);
    }

    [Theory]
    [InlineData(DaclState.Empty, DaclCompleteness.Complete, true, "The captured permission list contains no entries. This alone does not establish effective access.")]
    [InlineData(DaclState.Present, DaclCompleteness.Unknown, true, "The captured permission list is incomplete. Missing entries may change access; this view does not establish effective access.")]
    [InlineData(DaclState.Present, DaclCompleteness.Complete, false, "The captured permission list was not in canonical order. Entries retain their captured order within each principal.")]
    public void P248ClassificationWarningsDoNotClaimEffectiveAccess(DaclState state, DaclCompleteness completeness, bool canonical, string expected)
    {
        var section = Section(Permissions() with { DaclState = state, DaclCompleteness = completeness, DaclWasCanonical = canonical });

        Assert.Contains(expected, section.Statements.Select(value => value.Detail).Concat([section.Emptiness?.Detail]));
    }

    private static ObjectSectionDefinition Definition() => ObjectSectionCatalog.For("user").Single(value => value.Key == ObjectSectionCatalog.Permissions);
    [Theory]
    [InlineData(DescriptorAvailability.NotAttempted)]
    [InlineData(DescriptorAvailability.Unreadable)]
    public void P248ClassificationUnreadDescriptorDoesNotInventAnObservedList(DescriptorAvailability availability)
    {
        var section = Section(Permissions() with { Availability = availability, DaclState = DaclState.Unreadable,
            DaclCompleteness = DaclCompleteness.Unknown, DaclWasCanonical = false });

        Assert.Empty(section.Statements);
    }

    private static PermissionsSectionViewModel Section(ObjectPermissions permissions) =>
        new(Definition(), permissions, null, new PermissionClassificationProducer(SchemaGuidCatalog.Embedded).CreateObjectResult(permissions), null);
}
