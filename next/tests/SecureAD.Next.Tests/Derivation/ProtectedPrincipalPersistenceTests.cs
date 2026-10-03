using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

public sealed class ProtectedPrincipalPersistenceTests
{
    private static readonly DateTimeOffset Started = new(2026, 8, 30, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = Started.AddMinutes(5);

    [Fact]
    public void Stage2a_ProtectedPrincipalProductsAreWrittenAsOneProduct()
    {
        var directory = NewBundle();
        using var writer = DerivationWriter.Create(directory, EvidenceSealOf(directory), Started);
        writer.WriteSids(Sids, Scopes);

        writer.WriteProtectedPrincipals(Product());

        Assert.Equal(18, Count(directory, "adminsd_catalogue_entry"));
        Assert.Equal(3, Count(directory, "protected_principal"));
        Assert.Equal(3, Count(directory, "protected_principal_path"));
    }

    [Fact]
    public void Stage2a_AProtectedPrincipalProductCannotBeWrittenTwice()
    {
        var directory = NewBundle();
        using var writer = DerivationWriter.Create(directory, EvidenceSealOf(directory), Started);
        writer.WriteSids(Sids, Scopes);
        writer.WriteProtectedPrincipals(Product());

        Assert.Throws<InvalidOperationException>(() => writer.WriteProtectedPrincipals(Product()));
    }

    [Fact]
    public void Stage2a_ACompletedProtectionPhaseRequiresItsProduct()
    {
        var directory = NewBundle();
        using var writer = DerivationWriter.Create(directory, EvidenceSealOf(directory), Started);
        writer.WriteSids(Sids, Scopes);
        writer.RecordPhase(ProtectedPrincipalDeriver.PhaseName, DerivationPhaseOutcome.Succeeded, null);

        Assert.Throws<InvalidOperationException>(() => writer.Complete(Finished));
    }

    [Fact]
    public void Stage2a_AllEvaluationsReasonsBasesAndPathsRoundTrip()
    {
        var directory = NewBundle();
        using (var writer = DerivationWriter.Create(directory, EvidenceSealOf(directory), Started))
        {
            writer.WriteSids(Sids, Scopes);
            writer.WriteProtectedPrincipals(Product());
            writer.RecordPhase(ProtectedPrincipalDeriver.PhaseName, DerivationPhaseOutcome.Succeeded, null);
            writer.RecordCompleteness(Complete(writer.GenerationId));
            writer.Complete(Finished);
        }

        var opened = DerivationReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        using var reader = opened.Value!;
        var product = reader.Read().ProtectedPrincipals;

        Assert.Equal(ProtectedPrincipalProductAvailability.Available, product.Availability);
        Assert.Equal(Product().Catalogue.Version, product.Value!.CatalogueVersion);
        Assert.Equal(3, product.Value.Principals.Count);
        Assert.Equal(ProtectedPrincipalEvaluation.Protected, product.Value.Principals[0].Evaluation);
        Assert.Equal(ProtectedPrincipalBasisKind.MembershipRoot, product.Value.Principals[0].Basis!.Kind);
        Assert.Equal(new[] { 0, 1, 2 }, product.Value.Principals[0].Path);
        Assert.Equal(ProtectedPrincipalEvaluation.Unknown, product.Value.Principals[1].Evaluation);
        Assert.True(product.Value.Principals[1].UnknownReasons.HasFlag(ProtectionUnknownReason.PossibleRootReached));
        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, product.Value.Principals[2].Evaluation);
        Assert.Equal(0, product.Value.Lookup(Sids[0], scope: null)!.SidId);
        Assert.Null(product.Value.Lookup(Sids[0], "another.domain"));
    }

    [Fact]
    public void Stage2a_TheMaskAndCatalogueMetadataRoundTrip()
    {
        var directory = NewBundle();
        using (var writer = DerivationWriter.Create(directory, EvidenceSealOf(directory), Started))
        {
            writer.WriteSids(Sids, Scopes);
            writer.WriteProtectedPrincipals(Product());
            writer.RecordPhase(ProtectedPrincipalDeriver.PhaseName, DerivationPhaseOutcome.Degraded, null);
            writer.RecordCompleteness(Complete(writer.GenerationId) with { IsComplete = false });
            writer.Complete(Finished);
        }

        var opened = DerivationReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        using var reader = opened.Value!;
        var product = reader.Read().ProtectedPrincipals.Value!;

        Assert.Equal('1', product.Mask.Character);
        Assert.Equal(18, product.Catalogue.Count);
        Assert.Contains(product.Catalogue, entry => entry.Rid == 516
            && entry.PrincipalStatus == CatalogueClaimStatus.Established.ToString()
            && entry.PropagationStatus == CatalogueClaimStatus.Unverified.ToString());
    }

    [Theory]
    [InlineData(ProtectedPrincipalEvaluation.NotProtected, true)]
    [InlineData(ProtectedPrincipalEvaluation.Unknown, false)]
    public void Stage2a_AnIncoherentProductIsRefusedRatherThanStored(
        ProtectedPrincipalEvaluation evaluation,
        bool carriesReason)
    {
        var directory = NewBundle();
        using var writer = DerivationWriter.Create(directory, EvidenceSealOf(directory), Started);
        writer.WriteSids(Sids, Scopes);

        var incoherent = new ProtectedPrincipalClosure(
            [evaluation, evaluation, evaluation],
            [
                carriesReason ? ProtectionUnknownReason.PossibleRootReached : ProtectionUnknownReason.None,
                ProtectionUnknownReason.None,
                ProtectionUnknownReason.None,
            ],
            [null, null, null],
            [[], [], []],
            Seeds: [],
            ProtectedGroupCatalogue.NarrowedBy(string.Empty),
            ProtectionUnknownReason.None,
            [OwnerAcceptance.NotAccepted, OwnerAcceptance.NotAccepted, OwnerAcceptance.NotAccepted]);

        Assert.Throws<ArgumentException>(() => writer.WriteProtectedPrincipals(incoherent));
    }

    [Fact]
    public void Stage2a_AProtectedPrincipalWithoutABasisIsRefused()
    {
        var directory = NewBundle();
        using var writer = DerivationWriter.Create(directory, EvidenceSealOf(directory), Started);
        writer.WriteSids(Sids, Scopes);

        var incoherent = new ProtectedPrincipalClosure(
            [ProtectedPrincipalEvaluation.Protected, ProtectedPrincipalEvaluation.NotProtected, ProtectedPrincipalEvaluation.NotProtected],
            [ProtectionUnknownReason.None, ProtectionUnknownReason.None, ProtectionUnknownReason.None],
            [null, null, null],
            [[], [], []],
            Seeds: [],
            ProtectedGroupCatalogue.NarrowedBy(string.Empty),
            ProtectionUnknownReason.None,
            [OwnerAcceptance.NotAccepted, OwnerAcceptance.NotAccepted, OwnerAcceptance.NotAccepted]);

        Assert.Throws<ArgumentException>(() => writer.WriteProtectedPrincipals(incoherent));
    }

    [Theory]
    [InlineData(OwnerAcceptance.SchemaOnly)]
    [InlineData(OwnerAcceptance.SchemaOnlyOtherwiseUnknown)]
    public void ScopedOwnerAcceptanceSurvivesTheStore(OwnerAcceptance acceptance)
    {
        var directory = NewBundle();
        using (var writer = DerivationWriter.Create(directory, EvidenceSealOf(directory), Started))
        {
            writer.WriteSids(Sids, Scopes);
            writer.WriteProtectedPrincipals(Product() with
            {
                OwnerAcceptanceBySid = [acceptance, OwnerAcceptance.NotAccepted, OwnerAcceptance.Accepted],
            });
            writer.RecordPhase(ProtectedPrincipalDeriver.PhaseName, DerivationPhaseOutcome.Succeeded, null);
            writer.RecordCompleteness(Complete(writer.GenerationId));
            writer.Complete(Finished);
        }

        var opened = DerivationReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        using var reader = opened.Value!;
        Assert.Equal(acceptance, reader.Read().ProtectedPrincipals.Value!.Lookup(Sids[0], null)!.OwnerAcceptance);
    }

    private static readonly string[] Sids =
    [
        "S-1-5-21-1-2-3-1104",
        "S-1-5-21-1-2-3-1200",
        "S-1-5-21-1-2-3-512",
    ];

    private static readonly string?[] Scopes = [null, null, null];

    private static ProtectedPrincipalClosure Product()
    {
        var catalogue = ProtectedGroupCatalogue.NarrowedBy("0000000001000001");
        return new ProtectedPrincipalClosure(
            [ProtectedPrincipalEvaluation.Protected, ProtectedPrincipalEvaluation.Unknown, ProtectedPrincipalEvaluation.NotProtected],
            [ProtectionUnknownReason.None, ProtectionUnknownReason.PossibleRootReached, ProtectionUnknownReason.None],
            [new ProtectedPrincipalBasis(ProtectedPrincipalBasisKind.MembershipRoot, 3, 512), null, null],
            [new[] { 0, 1, 2 }, [], []],
            Seeds: [2],
            catalogue,
            ProtectionUnknownReason.None,
            // Index 2 is Domain Admins itself and index 0 reaches it, so both are accepted owners.
            // Index 1 is not under an accepted root - and its protection being Unknown is a
            // separate answer that must not decide this one.
            [OwnerAcceptance.Accepted, OwnerAcceptance.NotAccepted, OwnerAcceptance.Accepted]);
    }

    private static DerivationCompleteness Complete(Guid generationId) => new(
        IsComplete: true,
        PartialGroups: [],
        MissingPartitions: [],
        UnresolvedTrustees: [],
        DerivationGenerationId: generationId,
        Limit: ExpansionLimit.None);

    private static string NewBundle()
    {
        var directory = Path.Combine(Path.GetTempPath(), "protected-principal-store", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var evidencePath = BundleLayout.EvidencePath(directory);
        File.WriteAllText(evidencePath, "protected-principal test evidence");
        BundleSealing.Seal(evidencePath, BundleLayout.SealPath(directory));
        return directory;
    }

    private static string EvidenceSealOf(string directory) =>
        BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!.Hash;

    private static long Count(string directory, string table)
    {
        using var connection = new SqliteConnection($"Data Source={BundleLayout.DerivationPartialPath(directory)};Mode=ReadOnly;Pooling=False");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM {table}";
        return (long)command.ExecuteScalar()!;
    }
}
