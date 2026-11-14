using System.Collections.Immutable;
using System.Globalization;
using SecureAD.Kernel;

namespace SecureAD.Evidence;

public enum GpoTemplateVersionOutcome { NotCaptured, Unavailable, Missing, Unreadable, Invalid, Read }

public sealed record GpoTemplateVersionObservation(GpoTemplateVersionOutcome Outcome, byte[]? OriginalBytes,
    string? OriginalVersion, uint? Version, string? Reason)
{
    internal bool IsConsistent => Enum.IsDefined(Outcome) && Outcome != GpoTemplateVersionOutcome.NotCaptured
        && (Outcome is GpoTemplateVersionOutcome.Read or GpoTemplateVersionOutcome.Invalid) == (OriginalBytes is not null)
        && (Outcome == GpoTemplateVersionOutcome.Read) == (OriginalVersion is not null)
        && (Outcome == GpoTemplateVersionOutcome.Read) == Version.HasValue
        && (Outcome == GpoTemplateVersionOutcome.Read) == (Reason is null)
        && (Reason is null || !string.IsNullOrWhiteSpace(Reason))
        && (OriginalVersion is null || uint.TryParse(OriginalVersion.Trim(' ', '\t'), NumberStyles.None,
            CultureInfo.InvariantCulture, out var value) && value == Version);
}

internal sealed record CapturedGpoTemplateVersion(GpoTemplateVersionOutcome Outcome, string? FileSysPath,
    ImmutableArray<byte>? OriginalBytes, string? OriginalVersion, uint? Version, string? Reason, AuditError? Error);

internal sealed record CapturedGpoProtocolInputs(Guid CaptureGenerationId, CapturedObjectIdentity Policy,
    ObjectAttributes PolicyValues, CapturedGpoTemplateVersion TemplateVersion);
