using SecureAD.Kernel;

namespace SecureAD.Evidence;

/// <summary>A failed controller attempt under 0040, retained as history rather than directory evidence.</summary>
/// <param name="NamingContextDn">The domain being read.</param>
/// <param name="Controller">The controller whose same-controller recovery was exhausted.</param>
/// <param name="Attempt">The one-based position among controllers actually attempted.</param>
/// <param name="StartedUtc">When this controller attempt began.</param>
/// <param name="FailedUtc">When this controller attempt ended.</param>
/// <param name="Error">The original failure, without replacing its cause with a retry outcome.</param>
public sealed record DomainCaptureFailure(
    string NamingContextDn,
    string Controller,
    int Attempt,
    DateTimeOffset StartedUtc,
    DateTimeOffset FailedUtc,
    AuditError Error);
