using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

public sealed class MembershipRoutePersistenceTests
{
    [Fact]
    public void AllInitialMembershipsRootsChainsAndNamesSurviveTheStore()
    {
        var (directory, before) = Store();
        using var reader = DerivationReader.Open(directory).Value!;
        var product = reader.Read().ProtectedPrincipals.Value!;
        var account = product.Lookup("S-1-5-21-11-22-33-1100", null)!;
        Assert.Equal(2, account.MembershipRoutes.Memberships.Count);
        Assert.Equal(3, account.MembershipRoutes.Memberships.Sum(m => m.Routes.Count));
        Assert.True(account.MembershipRoutes.IsComplete);
        Assert.Equal(Describe(before.MembershipRoutesBySid[3]), Describe(account.MembershipRoutes));
        Assert.Equal(OwnerAcceptance.Accepted, account.OwnerAcceptance);
        Assert.Equal(ProtectedPrincipalBasisKind.DirectPrincipalClaim, product.Principals[0].Basis!.Kind);
        Assert.Equal(ProtectedPrincipalBasisKind.DirectPrincipalClaim, before.BasisFor(0)!.Kind);
    }

    [Theory]
    [InlineData(MembershipRouteIncompleteReason.MembershipEvidenceIncomplete)]
    [InlineData(MembershipRouteIncompleteReason.NodeBudgetReached)]
    [InlineData(MembershipRouteIncompleteReason.EdgeBudgetReached)]
    [InlineData(MembershipRouteIncompleteReason.StorageBudgetReached)]
    [InlineData(MembershipRouteIncompleteReason.TimeBudgetReached)]
    [InlineData(MembershipRouteIncompleteReason.ForestIdentityUnknown | MembershipRouteIncompleteReason.ForestMaskUnreadable)]
    public void EveryStoppingReasonSurvivesWithoutDiscardingKnownMemberships(MembershipRouteIncompleteReason reason)
    {
        var (directory, _) = Store(reason);
        using var reader = DerivationReader.Open(directory).Value!;
        var summary = reader.Read().ProtectedPrincipals.Value!.Principals[3].MembershipRoutes;
        Assert.False(summary.IsComplete);
        Assert.Equal(reason, summary.IncompleteReasons);
        Assert.Equal(2, summary.Memberships.Count);
    }

    [Fact]
    public void ASealedStoreMissingARouteCompletenessRecordIsRefused()
    {
        var (directory, _) = Store();
        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation).Value!;
        var path = BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Derivation, generation.GenerationId);
        using (var connection = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA foreign_keys = OFF; DELETE FROM membership_route_summary WHERE subject_id = '3'";
            command.ExecuteNonQuery();
        }
        BundleSealing.Seal(path, BundleLayout.AnalysisGenerationSealPath(directory, AnalysisStoreKind.Derivation, generation.GenerationId));
        var opened = DerivationReader.Open(directory);
        Assert.False(opened.IsSuccess);
        Assert.Equal("Evidence.DerivationUnreadable", opened.Error!.Code);
        Assert.Contains("completeness", opened.Error.Description, StringComparison.OrdinalIgnoreCase);
    }

    internal static (string Directory, ProtectedPrincipalClosure Product) Store(MembershipRouteIncompleteReason reason = MembershipRouteIncompleteReason.None)
    {
        var directory = Path.Combine(Path.GetTempPath(), "membership-route-store", Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(directory);
        File.WriteAllText(BundleLayout.EvidencePath(directory), "route evidence fixture");
        BundleSealing.Seal(BundleLayout.EvidencePath(directory), BundleLayout.SealPath(directory));
        var sids = new SidInterner();
        foreach (var rid in new[] { 512, 519, 1200, 1100 })
            sids.Intern($"S-1-5-21-11-22-33-{rid}", null);
        var rows = Enumerable.Range(0, 4).Select(id => new PrincipalRow(id, Guid.NewGuid(), id != 3,
            unchecked((int)0x80000002), null) { DistinguishedName = $"CN=renamed-{id},DC=ad,DC=lab" }).ToArray();
        var graph = NestingGraph.Build(new NestingFacts(sids, [], rows,
            [new(0, 1), new(1, 2), new(2, 3), new(0, 3)], [], 0, 0, string.Empty));
        var product = ProtectedPrincipalDeriver.Derive(graph, sids, ProtectedGroupCatalogue.NarrowedBy(string.Empty),
            false, CancellationToken.None, "S-1-5-21-11-22-33",
            new HashSet<string>(StringComparer.Ordinal), []);
        product = product with
        {
            MembershipRoutesBySid = product.MembershipRoutesBySid.Select(s => s.WithIncompleteReasons(reason)).ToArray(),
        };
        using var writer = DerivationWriter.Create(directory, BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!.Hash, DateTimeOffset.UtcNow);
        writer.WriteSids(sids.InIdOrder(), Enumerable.Range(0, sids.Count).Select(sids.ScopeOf).ToArray());
        writer.WriteProtectedPrincipals(product);
        writer.RecordPhase(ProtectedPrincipalDeriver.PhaseName, reason == MembershipRouteIncompleteReason.None
            ? DerivationPhaseOutcome.Succeeded : DerivationPhaseOutcome.Degraded, null);
        writer.RecordCompleteness(new DerivationCompleteness(true, [], [], [], writer.GenerationId, ExpansionLimit.None));
        writer.Complete(DateTimeOffset.UtcNow);
        return (directory, product);
    }

    internal static string Describe(MembershipRouteSummary summary) => string.Join("|", summary.Memberships.SelectMany(g => g.Routes)
        .Select(r => $"{r.CatalogueEntryId}:{r.RootName}:{r.Authorization}:{r.EstablishesProtection}:"
            + string.Join(",", r.Steps.Select(s => $"{s.Principal.Sid}:{s.Principal.Scope}:{s.Principal.DistinguishedName}:{s.IsPrimaryGroup}"))));
}
