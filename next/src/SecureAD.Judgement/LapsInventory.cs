using SecureAD.Evidence;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

/// <summary>Which expiration values were captured, not deployment, migration or a security verdict.</summary>
public enum LapsValuePresence
{
    None,
    WindowsOnly,
    LegacyOnly,
    Both,
    WindowsOnLegacyOnly,
}

/// <summary>A timestamp's recorded interpretation, retaining the original value even when unreadable.</summary>
public sealed record StoredLapsTimestamp(string? Raw, LapsTimestampReading Reading, DateTimeOffset? ExpiresUtc,
    bool HasUnsupportedRepresentation = false);

/// <summary>One computer's saved LAPS inventory answer and the captured values supporting it.</summary>
/// <remarks>
/// Classification happens during judging, never in these getters. All captured computers belong here,
/// including healthy computers and those the rules exclude; findings cannot supply this population.
/// </remarks>
public sealed record LapsComputer(
    string DistinguishedName,
    string Name,
    Guid? ObjectGuid,
    string? DomainFqdn,
    StoredLapsTimestamp WindowsLaps,
    StoredLapsTimestamp LegacyLaps,
    string? OperatingSystem,
    string? OperatingSystemVersion,
    string? UserAccountControl,
    string? PrimaryGroupId,
    LapsCapability Capability,
    DomainControllerSignals DomainController,
    LapsAttributes.AccountState AccountState,
    LapsValuePresence ValuePresence)
{
    /// <summary>Whether the saved account state established that the computer was disabled.</summary>
    public bool IsDisabled => AccountState is LapsAttributes.AccountState.Disabled;

    /// <summary>Whether the recorded account and controller states permit the computer rules to apply.</summary>
    public bool IsInRuleScope => AccountState is LapsAttributes.AccountState.Enabled && !DomainController.IsDomainController;
}

/// <summary>A saved inventory page with whole-scope counts and explicit capture shortfalls.</summary>
public sealed record LapsPage(
    IReadOnlyList<LapsComputer> Computers,
    int Total,
    IReadOnlyDictionary<LapsValuePresence, int> CountsByValuePresence,
    bool ComputersAreComplete,
    string? Shortfall)
{
    /// <summary>The next saved-question position, or null when this filtered scope has no further rows.</summary>
    public LapsPageMark? Next { get; init; }

    /// <summary>Counts a state across the selected scope, including zero when it has no recorded computers.</summary>
    public int CountOf(LapsValuePresence state) => CountsByValuePresence.GetValueOrDefault(state);
}

/// <summary>Filters the complete selected saved scope before taking a bounded page.</summary>
public sealed record LapsQuery(string Container, ListingScope Scope, string Search, LapsValuePresence? State);

/// <summary>A stable sort position bound to the saved generation and complete submitted question.</summary>
public sealed record LapsPageMark(Guid GenerationId, string Question, string Name, string DistinguishedName);
