using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Fact]
    public void ServiceRegistrationReadsTheActualExistingRuleWithoutRejudgingOrWholeRoutes()
    {
        var directory = KerberoastablePrivilegedAccountTests.ServiceRegistrationRun();
        Finding original;
        using (var reader = JudgementReader.Open(directory).Value) original = Assert.Single(reader.Read().Findings);
        var proof = Assert.IsType<KerberoastableAccountEvidence>(original.Evidence);
        var before = CoverageFiles(directory);
        using var source = new BundleAssetSource();
        using var counts = new FindingsVerificationCounts(directory);
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
            Assert.Equal(0L, counts.Heavy);
            var read = source.ReadServiceRegistrations(directory, row.Reference!.Value, null);
            Assert.True(read.IsSuccess, read.Error?.Description);
            Assert.True(read.Value.Context.Matches(row));
            Assert.Equal(proof.ObjectSid, read.Value.Context.Sid);
            Assert.Equal(proof.ServicePrincipalNames, read.Value.Names.Select(value => value.Value));
            Assert.Equal(proof.MembershipRoutes.IncompleteReasons, read.Value.Context.MembershipLimits);
            var groups = source.ReadInitialMemberships(directory, row.Reference.Value, null);
            Assert.True(groups.IsSuccess, groups.Error?.Description);
            Assert.Equal(proof.MembershipRoutes.Memberships.Select(value => value.InitialMembership), groups.Value.Memberships.Select(value => value.Principal));
            var selected = groups.Value.Memberships[0];
            var routes = source.ReadMembershipRoutes(directory, row.Reference.Value, selected.Ordinal, null);
            Assert.True(routes.IsSuccess, routes.Error?.Description);
            Assert.Equal(proof.MembershipRoutes.Memberships[0].Routes[0].Steps[^1].Principal, routes.Value.Routes[0].RootPrincipal);
            var steps = source.ReadMembershipSteps(directory, row.Reference.Value, selected.Ordinal, routes.Value.Routes[0].Ordinal, null);
            Assert.True(steps.IsSuccess, steps.Error?.Description);
            Assert.Equal(proof.MembershipRoutes.Memberships[0].Routes[0].Steps.Select(value => value.Principal),
                steps.Value.Steps.Select(value => value.Principal));
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Theory]
    [InlineData("names")]
    [InlineData("groups")]
    [InlineData("routes")]
    [InlineData("steps")]
    public void ServiceRegistrationEveryLevelUsesLiteralFiftyRowPagesWithoutLosingOccurrences(string level)
    {
        var directory = ServiceFixture(level);
        using var source = new BundleAssetSource();
        var reference = ServiceReference(source, directory);
        var ordinals = new List<int>();
        if (level == "names")
        {
            ServiceNameMark? mark = null;
            do
            {
                var read = source.ReadServiceRegistrations(directory, reference, mark);
                Assert.True(read.IsSuccess, read.Error?.Description); Assert.InRange(read.Value.Names.Count, 1, 50);
                ordinals.AddRange(read.Value.Names.Select(value => value.Ordinal));
                Assert.Equal(read.Value.Names.Select(value => value.Value), read.Value.Names.Select(value => ServiceName(value.Ordinal)));
                mark = read.Value.Next;
            } while (mark is not null);
        }
        else if (level == "groups")
        {
            InitialMembershipMark? mark = null;
            do
            {
                var read = source.ReadInitialMemberships(directory, reference, mark);
                Assert.True(read.IsSuccess, read.Error?.Description); Assert.InRange(read.Value.Memberships.Count, 1, 50);
                ordinals.AddRange(read.Value.Memberships.Select(value => value.Ordinal)); mark = read.Value.Next;
            } while (mark is not null);
        }
        else if (level == "routes")
        {
            MembershipRouteMark? mark = null;
            do
            {
                var read = source.ReadMembershipRoutes(directory, reference, 0, mark);
                Assert.True(read.IsSuccess, read.Error?.Description); Assert.InRange(read.Value.Routes.Count, 1, 50);
                ordinals.AddRange(read.Value.Routes.Select(value => value.Ordinal)); mark = read.Value.Next;
            } while (mark is not null);
        }
        else
        {
            MembershipStepMark? mark = null;
            do
            {
                var read = source.ReadMembershipSteps(directory, reference, 0, 0, mark);
                Assert.True(read.IsSuccess, read.Error?.Description); Assert.InRange(read.Value.Steps.Count, 1, 50);
                ordinals.AddRange(read.Value.Steps.Select(value => value.Ordinal)); mark = read.Value.Next;
            } while (mark is not null);
        }
        Assert.Equal(Enumerable.Range(0, 123), ordinals);
    }

    [Theory]
    [InlineData("groups")]
    [InlineData("routes")]
    [InlineData("steps")]
    public void ServiceRegistrationDoesNotReadUnrequestedSiblingOrLaterStepPayloads(string level)
    {
        var directory = ServiceFixture(level, branches: true);
        ChangeFindingsDatabase(directory, level switch
        {
            "groups" => "UPDATE membership_route SET authorization='Broken' WHERE membership_ordinal=1",
            "routes" => "UPDATE membership_route SET authorization='Broken' WHERE route_ordinal=1",
            _ => "UPDATE membership_route_step SET sid='Broken' WHERE step_ordinal=100",
        });
        using var source = new BundleAssetSource();
        var reference = ServiceReference(source, directory);
        Assert.True(source.ReadServiceRegistrations(directory, reference, null).IsSuccess);
        Assert.True(source.ReadInitialMemberships(directory, reference, null).IsSuccess);
        Assert.True(source.ReadMembershipSteps(directory, reference, 0, 0, null).IsSuccess);
        if (level == "groups") Assert.False(source.ReadMembershipRoutes(directory, reference, 1, null).IsSuccess);
        else if (level == "routes") Assert.False(source.ReadMembershipSteps(directory, reference, 0, 1, null).IsSuccess);
        else
        {
            var first = source.ReadMembershipSteps(directory, reference, 0, 0, null).Value;
            var second = source.ReadMembershipSteps(directory, reference, 0, 0, first.Next).Value;
            Assert.False(source.ReadMembershipSteps(directory, reference, 0, 0, second.Next).IsSuccess);
        }
    }

    public static IEnumerable<object[]> ServiceForeignMarks() => new[] { "names", "groups", "routes", "steps" }
        .SelectMany(level => new[] { "generation", "finding", "account" }.Select(defect => new object[] { level, defect }));

    [Theory]
    [MemberData(nameof(ServiceForeignMarks))]
    public void ServiceRegistrationRejectsAnotherRunFindingOrAccountCursorAtEveryLevel(string level, string defect)
    {
        var directory = ServiceFixture(level);
        using var source = new BundleAssetSource();
        var reference = ServiceReference(source, directory);
        var account = source.ReadServiceRegistrations(directory, reference, null).Value.Context.Account.ObjectGuid;
        var generation = defect == "generation" ? Guid.NewGuid() : reference.GenerationId;
        var finding = defect == "finding" ? reference.FindingId + 1 : reference.FindingId;
        if (defect == "account") account = Guid.NewGuid();
        var success = level switch
        {
            "names" => source.ReadServiceRegistrations(directory, reference, new(generation, finding, account, 49)).IsSuccess,
            "groups" => source.ReadInitialMemberships(directory, reference, new(generation, finding, account, 49)).IsSuccess,
            "routes" => source.ReadMembershipRoutes(directory, reference, 0, new(generation, finding, account, 0, 49)).IsSuccess,
            _ => source.ReadMembershipSteps(directory, reference, 0, 0, new(generation, finding, account, 0, 0, 49)).IsSuccess,
        };
        Assert.False(success);
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(2u)]
    [InlineData(512u)]
    [InlineData(514u)]
    public void ServiceRegistrationPreservesRawAccountControlAndIndependentSpnVisibility(uint control)
    {
        var directory = ServiceFixture("names", control: control, unreadable: 3);
        using var source = new BundleAssetSource();
        var read = source.ReadServiceRegistrations(directory, ServiceReference(source, directory), null);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal(control, read.Value.Context.SavedAccountControl);
        Assert.Equal(3, read.Value.Context.UnreadableServiceNames);
        Assert.Equal(MembershipRouteIncompleteReason.None, read.Value.Context.MembershipLimits);
    }

    [Theory]
    [InlineData("route")]
    [InlineData("step-membership")]
    [InlineData("step-route")]
    public void ServiceRegistrationRejectsCursorsFromAnotherMembershipBranch(string branch)
    {
        var directory = ServiceFixture(branch == "route" ? "routes" : "steps");
        using var source = new BundleAssetSource();
        var reference = ServiceReference(source, directory);
        if (branch == "route")
        {
            var first = source.ReadMembershipRoutes(directory, reference, 0, null).Value;
            Assert.False(source.ReadMembershipRoutes(directory, reference, 0, first.Next!.Value with { MembershipOrdinal = 1 }).IsSuccess);
        }
        else
        {
            var first = source.ReadMembershipSteps(directory, reference, 0, 0, null).Value;
            var mark = first.Next!.Value;
            mark = branch == "step-membership" ? mark with { MembershipOrdinal = 1 } : mark with { RouteOrdinal = 1 };
            Assert.False(source.ReadMembershipSteps(directory, reference, 0, 0, mark).IsSuccess);
        }
    }

    [Fact]
    public void ServiceRegistrationPreservesTheSavedClassSpellingWithinTheUserScope()
    {
        var directory = ServiceFixture("small", objectClass: "USER");
        using var source = new BundleAssetSource();
        var read = source.ReadServiceRegistrations(directory, ServiceReference(source, directory), null);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal("USER", read.Value.Context.Account.ObjectClass);
    }

    [Theory]
    [InlineData(MembershipRouteAuthorization.SecurityEnabled, false, MembershipRouteIncompleteReason.None)]
    [InlineData(MembershipRouteAuthorization.DistributionGroup, false, MembershipRouteIncompleteReason.NodeBudgetReached)]
    [InlineData(MembershipRouteAuthorization.UnknownGroupType, true, MembershipRouteIncompleteReason.MembershipEvidenceIncomplete)]
    public void ServiceRegistrationRetainsAuthorizationPrimaryAndProtectionAsSeparateSavedAnswers(
        MembershipRouteAuthorization authorization, bool primary, MembershipRouteIncompleteReason limits)
    {
        var directory = ServiceFixture("small", primary: primary, authorization: authorization, limits: limits);
        using var source = new BundleAssetSource();
        var reference = ServiceReference(source, directory);
        var read = source.ReadMembershipRoutes(directory, reference, 0, null);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal(primary, read.Value.Membership.IsPrimaryGroup);
        var route = Assert.Single(read.Value.Routes);
        Assert.Equal(authorization, route.Authorization);
        Assert.Equal(!primary, route.EstablishesProtection);
        Assert.Equal(limits, read.Value.Context.MembershipLimits);
    }

    [Fact]
    public void ServiceRegistrationRetainsDirectProtectionWithZeroSavedMemberships()
    {
        var directory = ServiceFixture("direct");
        using var source = new BundleAssetSource();
        var reference = ServiceReference(source, directory);
        var read = source.ReadInitialMemberships(directory, reference, null);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Empty(read.Value.Memberships);
        Assert.Null(read.Value.Next);
        Assert.Equal("Recorded direct protection", read.Value.Context.DirectProtectionName);
    }

    [Theory]
    [InlineData("sid")]
    [InlineData("catalogue")]
    [InlineData("spn")]
    [InlineData("group")]
    public void ServiceRegistrationRefusesMissingOrInconsistentRequestedFacts(string defect)
    {
        var directory = ServiceFixture("small");
        if (defect == "sid") ChangeCoverageProof(directory, "UPDATE finding_kerberoastable_account SET object_sid='Broken'");
        else if (defect == "catalogue") ChangeFindingsDatabase(directory, "UPDATE finding SET protection_catalogue_version=99");
        else if (defect == "spn") ChangeCoverageProof(directory, "DELETE FROM finding_kerberoastable_account_spn");
        else ChangeFindingsDatabase(directory, "DELETE FROM membership_route_step WHERE step_ordinal=1");
        using var source = new BundleAssetSource();
        var reference = ServiceReference(source, directory);
        Assert.False((defect == "group" ? source.ReadInitialMemberships(directory, reference, null).IsSuccess
            : source.ReadServiceRegistrations(directory, reference, null).IsSuccess));
    }

    private static FindingReference ServiceReference(BundleAssetSource source, string directory) =>
        Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;

    private static string ServiceName(int ordinal) => ordinal % 2 == 0 ? "HTTP/Same.ad.lab:443" : "http/same.ad.lab:443";

    private static string ServiceFixture(string level, bool branches = false, uint control = 512, int unreadable = 0,
        bool primary = false, MembershipRouteAuthorization authorization = MembershipRouteAuthorization.SecurityEnabled,
        MembershipRouteIncompleteReason limits = MembershipRouteIncompleteReason.None, string objectClass = "user")
    {
        var directory = KerberoastablePrivilegedAccountTests.ServiceRegistrationRun();
        Finding finding;
        using (var reader = JudgementReader.Open(directory).Value) finding = Assert.Single(reader.Read().Findings);
        var original = Assert.IsType<KerberoastableAccountEvidence>(finding.Evidence);
        var groupCount = level == "groups" ? branches ? 2 : 123 : level == "direct" ? 0 : 1;
        var routeCount = level == "routes" ? branches ? 2 : 123 : 1;
        var stepCount = level == "steps" ? 123 : 3;
        var account = new MembershipRoutePrincipal(original.ObjectSid, null, finding.DistinguishedName);
        var groups = Enumerable.Range(0, groupCount).Select(group =>
        {
            var initial = new MembershipRoutePrincipal("S-1-5-21-1-2-3-" + (2000 + group), "ad.lab", $"CN=Group {group},DC=ad,DC=lab");
            var routes = Enumerable.Range(0, routeCount).Select(route =>
            {
                var steps = Enumerable.Range(0, stepCount).Select(step => new MembershipRouteStep(step == 0 ? account : step == 1 ? initial
                    : new("S-1-5-21-1-2-3-" + (3000 + step), "ad.lab", $"CN=Step {step},DC=ad,DC=lab"), step == 1 && primary)).ToArray();
                return new MembershipRoute(1 + route, "Recorded root " + route, authorization, !primary, steps);
            }).ToArray();
            return new InitialMembershipRoutes(initial, routes, limits);
        }).ToArray();
        var evidence = original with
        {
            ServicePrincipalNames = Enumerable.Range(0, level == "names" ? 123 : 2).Select(ServiceName).ToArray(),
            UserAccountControl = control, UnreadableServiceNames = unreadable,
            MembershipRoutes = new(groups, limits), ProtectionCatalogueVersion = 2,
            DirectProtectionCatalogueEntryId = 500, DirectProtectionName = "Recorded direct protection",
        };
        WriteFindingsFixture(directory, [finding with { Evidence = evidence, ObjectClass = objectClass }]);
        return directory;
    }
}
