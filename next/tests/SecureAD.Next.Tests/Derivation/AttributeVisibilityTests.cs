using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Schema;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

/// <summary>
/// Whether this forest withholds an attribute, and whether the answer survives being stored.
/// </summary>
/// <remarks>
/// <para>
/// <b>This check will answer "not confidential" on every real forest, which is exactly why it needs
/// a fixture that does not.</b> Microsoft ships both LAPS expiration attributes with a
/// <c>searchFlags</c> of 0, and <c>ad.lab</c> returned 0 for both on 2026-09-03. So the confidential
/// branch is unreachable in production and would never be exercised by a lab run - the shape the
/// copilot instructions name first: a check that passes while measuring nothing.
/// </para>
/// <para>
/// <b>The external anchor.</b> Per <c>F-S44-2</c>, a constant a rule names is checked against
/// something outside this repository. 128 is Microsoft's, from <i>Search-Flags</i>: <i>"128
/// (0x00000080) | Mark attribute as confidential."</i> 904 is Microsoft's published
/// <c>SearchFlags</c> for the LAPS password attributes, and the whole value is used here rather
/// than the isolated bit, so the test would fail if the product had transcribed the decomposition
/// wrongly.
/// </para>
/// </remarks>
public sealed class AttributeVisibilityTests
{
    /// <summary>
    /// Microsoft's published <c>SearchFlags</c> for <c>msLAPS-Password</c>, read back from
    /// <c>ad.lab</c> unchanged on 2026-09-03. It includes <c>fCONFIDENTIAL</c>.
    /// </summary>
    private const int PasswordSearchFlags = 904;

    /// <summary>
    /// Microsoft's published <c>SearchFlags</c> for both LAPS expiration attributes, read back from
    /// <c>ad.lab</c> unchanged on 2026-09-03.
    /// </summary>
    private const int ExpirationSearchFlags = 0;

    private static readonly DateTimeOffset Started = new(2026, 9, 3, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = Started.AddMinutes(1);

    [Fact]
    public void TheConfidentialBitIsMicrosoftsPublishedValue() =>
        Assert.Equal(128, SchemaAttributeFlags.Confidential);

    [Fact]
    public void AnAttributeCarryingThePasswordIsWithheld() =>
        Assert.True(SchemaAttributeFlags.IsConfidential(PasswordSearchFlags, systemFlags: null));

    [Fact]
    public void AnExpirationTimestampIsNotWithheld() =>
        Assert.False(SchemaAttributeFlags.IsConfidential(ExpirationSearchFlags, systemFlags: null));

    /// <summary>
    /// The forest this rule exists for: one that marked the expiration timestamp confidential.
    /// </summary>
    /// <remarks>
    /// <b>No lab run will ever reach this.</b> It is the only place the confidential branch is
    /// exercised, and without it the whole absence argument in SEC-091 section 4 would rest on a
    /// branch nothing had run.
    /// </remarks>
    [Fact]
    public void AForestThatHardenedItsSchemaWithholdsTheExpirationTimestamp() =>
        Assert.True(SchemaAttributeFlags.IsConfidential(
            SchemaAttributeFlags.Confidential, systemFlags: null));

    /// <summary>
    /// The half of Microsoft's sentence that is easy to miss.
    /// </summary>
    /// <remarks>
    /// <i>"Ignored for base schema attributes (systemFlags=0x10)."</i> A check reading the bit alone
    /// would report a readable attribute as withheld, and silence a rule that had every right to
    /// speak.
    /// </remarks>
    [Fact]
    public void TheBitIsIgnoredOnABaseSchemaAttribute() =>
        Assert.False(SchemaAttributeFlags.IsConfidential(
            SchemaAttributeFlags.Confidential, SchemaAttributeFlags.BaseSchemaObject));

    [Fact]
    public void FlagsThatWereNeverCapturedAreNotReadAsZero()
    {
        Assert.False(SchemaAttributeFlags.IsConfidential(searchFlags: null, systemFlags: null));

        Assert.Equal(
            AttributeVisibilityAnswer.FlagsNotCaptured,
            new AttributeVisibilityFact("msLAPS-PasswordExpirationTime", null, null).Answer);
    }

    [Fact]
    public void AnAttributeTheSchemaDoesNotCarryIsNotTheSameAsOneItDoes()
    {
        var product = AttributeVisibilityDeriver.Derive(new SchemaAttributeReading(
        [
            new SchemaAttributeDefinition("ms-Mcs-AdmPwdExpirationTime", ExpirationSearchFlags, null),
        ]));

        Assert.Equal(
            AttributeVisibilityAnswer.Readable,
            product.Answer("ms-Mcs-AdmPwdExpirationTime"));

        Assert.Equal(
            AttributeVisibilityAnswer.NotInSchema,
            product.Answer("msLAPS-PasswordExpirationTime"));
    }

    /// <summary>
    /// A capture refused the schema partition says so, rather than saying nothing is withheld.
    /// </summary>
    [Fact]
    public void AnEmptyProductSaysNobodyLookedRatherThanNothingIsWithheld()
    {
        var product = AttributeVisibilityDeriver.Derive(new SchemaAttributeReading([]));

        Assert.Equal(
            AttributeVisibilityAnswer.SchemaNotRead,
            product.Answer("msLAPS-PasswordExpirationTime"));
    }

    [Fact]
    public void TheAnswerIsMatchedWithoutRegardToCase()
    {
        var product = AttributeVisibilityDeriver.Derive(new SchemaAttributeReading(
        [
            new SchemaAttributeDefinition("msLAPS-PasswordExpirationTime", ExpirationSearchFlags, null),
        ]));

        Assert.Equal(
            AttributeVisibilityAnswer.Readable,
            product.Answer("mslaps-passwordexpirationtime"));
    }

    [Fact]
    public void TheProductSurvivesBeingStoredAndReadBack()
    {
        var directory = NewBundle();

        using (var writer = DerivationWriter.Create(directory, EvidenceSealOf(directory), Started))
        {
            writer.WriteSids([], []);
            writer.WriteAttributeVisibility(AttributeVisibilityDeriver.Derive(new SchemaAttributeReading(
            [
                new SchemaAttributeDefinition("msLAPS-Password", PasswordSearchFlags, null),
                new SchemaAttributeDefinition("msLAPS-PasswordExpirationTime", ExpirationSearchFlags, null),
                new SchemaAttributeDefinition("cn", SchemaAttributeFlags.Confidential, SchemaAttributeFlags.BaseSchemaObject),
                new SchemaAttributeDefinition("computer", null, null),
            ])));
            writer.RecordPhase(AttributeVisibilityDeriver.PhaseName, DerivationPhaseOutcome.Succeeded, null);
            writer.RecordCompleteness(Complete(writer.GenerationId));
            writer.Complete(Finished);
        }

        var opened = DerivationReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        using var reader = opened.Value!;
        var product = reader.Read().AttributeVisibility;

        Assert.Equal(AttributeVisibilityAvailability.Available, product.Availability);
        Assert.Equal(4, product.Value!.Attributes.Count);

        // All four answers off one stored product. A reader that dropped a column would give the
        // same answer for two of these, which is the defect P-112 was.
        Assert.Equal(AttributeVisibilityAnswer.Confidential, product.Value.Answer("msLAPS-Password"));
        Assert.Equal(AttributeVisibilityAnswer.Readable, product.Value.Answer("msLAPS-PasswordExpirationTime"));
        Assert.Equal(AttributeVisibilityAnswer.Readable, product.Value.Answer("cn"));
        Assert.Equal(AttributeVisibilityAnswer.FlagsNotCaptured, product.Value.Answer("computer"));
        Assert.Equal(AttributeVisibilityAnswer.NotInSchema, product.Value.Answer("ms-Mcs-AdmPwd"));
    }

    /// <summary>
    /// A store whose phase never ran is not a store saying nothing is withheld.
    /// </summary>
    [Fact]
    public void APhaseThatDidNotRunIsNotAnEmptyAnswer()
    {
        var directory = NewBundle();

        using (var writer = DerivationWriter.Create(directory, EvidenceSealOf(directory), Started))
        {
            writer.WriteSids([], []);
            writer.RecordPhase(AttributeVisibilityDeriver.PhaseName, DerivationPhaseOutcome.DidNotRun, null);
            writer.RecordCompleteness(Complete(writer.GenerationId));
            writer.Complete(Finished);
        }

        var opened = DerivationReader.Open(directory);
        using var reader = opened.Value!;
        var product = reader.Read().AttributeVisibility;

        Assert.Equal(AttributeVisibilityAvailability.DidNotRun, product.Availability);
        Assert.Null(product.Value);
    }

    /// <summary>
    /// A capture refused the schema partition produces a product with nothing in it, which is a
    /// different answer from no product at all.
    /// </summary>
    [Fact]
    public void ACaptureWithNoSchemaPartitionStillProducesAProduct()
    {
        var directory = NewBundle();

        using (var writer = DerivationWriter.Create(directory, EvidenceSealOf(directory), Started))
        {
            writer.WriteSids([], []);
            writer.WriteAttributeVisibility(AttributeVisibilityDeriver.Derive(new SchemaAttributeReading([])));
            writer.RecordPhase(AttributeVisibilityDeriver.PhaseName, DerivationPhaseOutcome.Degraded, null);
            writer.RecordCompleteness(Complete(writer.GenerationId));
            writer.Complete(Finished);
        }

        var opened = DerivationReader.Open(directory);
        using var reader = opened.Value!;
        var product = reader.Read().AttributeVisibility;

        Assert.Equal(AttributeVisibilityAvailability.Available, product.Availability);
        Assert.Empty(product.Value!.Attributes);
        Assert.Equal(
            AttributeVisibilityAnswer.SchemaNotRead,
            product.Value.Answer("msLAPS-PasswordExpirationTime"));
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
        var directory = Path.Combine(
            Path.GetTempPath(), "attribute-visibility-store", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var evidencePath = BundleLayout.EvidencePath(directory);
        File.WriteAllText(evidencePath, "attribute visibility test evidence");
        BundleSealing.Seal(evidencePath, BundleLayout.SealPath(directory));
        return directory;
    }

    private static string EvidenceSealOf(string directory) =>
        BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!.Hash;
}
