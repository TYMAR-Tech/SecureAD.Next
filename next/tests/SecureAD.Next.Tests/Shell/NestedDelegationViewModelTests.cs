using SecureAD.Evidence;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class NestedDelegationViewModelTests
{
    [Fact]
    public void NewScreensIncludeGroupHeldPermissionsByDefaultWithoutClaimingEffectiveAccess()
    {
        var screen = new AssetsViewModel(new FakeAssetSource());

        Assert.True(screen.IncludeGroupHeldPermissions);
        Assert.Contains("group-held entries linked by captured membership", screen.DelegationBoundary);
        Assert.Contains("does not prove effective access", screen.DelegationBoundary);
    }

    [Fact]
    public async Task TogglingGroupsDiscardsTheOldAnswerAndRestoresDirectOnlyLookup()
    {
        var (screen, source) = DelegationViewModelTests.Model();
        await DelegationViewModelTests.SelectPrincipal(screen);
        await screen.FindDelegationsCommand.ExecuteAsync(null);
        Assert.True(screen.HasDelegationAnswer);
        screen.IncludeGroupHeldPermissions = true;
        Assert.False(screen.HasDelegationAnswer);
        Assert.Empty(screen.Delegations);
        await screen.FindDelegationsCommand.ExecuteAsync(null);
        Assert.True(source.DelegationQueries[^1].Query.IncludeGroupHeldPermissions);
        Assert.True(screen.HasViewRefusal);
        Assert.Contains("does not match", screen.ViewRefusal!.Detail);
        screen.IncludeGroupHeldPermissions = false;
        await screen.FindDelegationsCommand.ExecuteAsync(null);

        Assert.False(source.DelegationQueries[^1].Query.IncludeGroupHeldPermissions);
        Assert.True(screen.HasDelegationAnswer);
        Assert.Contains("Only entries naming the selected SID", screen.DelegationBoundary);
    }

    [Fact]
    public async Task GroupPagesShowTheHolderChainAndMembershipLimitationsSeparatelyFromCaptureGaps()
    {
        var (screen, source) = DelegationViewModelTests.Model();
        await DelegationViewModelTests.SelectPrincipal(screen);
        var selected = screen.SelectedDelegationPrincipal!.Principal;
        source.Delegations = (_, _) => Result<DelegationPage>.Success(GroupPage(selected));
        screen.IncludeGroupHeldPermissions = true;

        await screen.FindDelegationsCommand.ExecuteAsync(null);

        Assert.True(screen.HasDelegationAnswer);
        var row = Assert.Single(screen.Delegations);
        Assert.Contains("Operators", row.PermissionHeldBy);
        Assert.Contains("Membership chain", row.Detail);
        Assert.Contains("primary group", row.Detail);
        Assert.Contains("Membership limitations", screen.DelegationCoverage);
        Assert.Contains("Capture gaps: 0", screen.DelegationCoverage);
        Assert.Contains("1 recorded entries on this page", screen.DelegationStatus);
    }

    internal static DelegationPage GroupPage(DelegationPrincipal selected)
    {
        var group = new DelegationPrincipal(5, "S-1-5-21-1-2-3-2200", "Operators", "CN=Operators,DC=contoso,DC=com", "contoso.com");
        var membership = new DelegationMembership(Guid.NewGuid(), new string('a', 64), 1,
            [new(1, selected.Sid, "", null, false, null) { Principal = selected },
             new(2, group.Sid, "", null, true, true) { Principal = group }],
            [new(1, 2, true)], ["A containing group was not captured."]);
        var entry = new DelegationEntry("OU=People,DC=contoso,DC=com", "contoso.com", 7,
            new(0, "AccessAllowed", new(group.Sid, group.Name, group.DistinguishedName, group.DomainFqdn, null, null, null),
                0x100, null, null, false, 0, 0, false, false, []), DaclCompleteness.Complete, null)
        { ObjectId = 9, HolderMembershipId = 2 };
        return new([entry], null, new(true, [], 0, 0, 0, 0)) { Membership = membership };
    }
}
