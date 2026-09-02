using Microsoft.Data.Sqlite;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;

namespace SecureAD.Evidence;

/// <summary>
/// What the directory shows about a machine's local administrator password management.
/// </summary>
/// <remarks>
/// <b>This is an inventory state, not a severity.</b> Four of the five are perfectly healthy or
/// perfectly ordinary, which is the whole reason the inventory cannot be built out of the findings
/// store: <c>SEC-091</c> and <c>SEC-094</c> report two of these states and say nothing about the
/// rest, and <i>which machines are managed</i> is a question about all of them.
/// </remarks>
public enum LapsManagement
{
    /// <summary>
    /// Neither timestamp. Nothing visible in this directory is rotating the password - the state
    /// <c>SEC-091</c> reports, on the machines it is in scope for.
    /// </summary>
    NotManaged,

    /// <summary>
    /// The modern timestamp only. The healthy state, and the confirmation Microsoft names for a
    /// successful Windows LAPS deployment.
    /// </summary>
    WindowsLaps,

    /// <summary>
    /// The legacy timestamp only. On a Windows LAPS-capable machine this is what <c>SEC-094</c>
    /// reports; on an older machine it is the best that was ever available.
    /// </summary>
    LegacyLaps,

    /// <summary>
    /// Both timestamps. A migrated machine: Windows LAPS is managing it and the legacy value
    /// survives because no migration step ever clears it.
    /// </summary>
    Migrated,

    /// <summary>
    /// A modern timestamp on a machine Microsoft says cannot run Windows LAPS.
    /// </summary>
    /// <remarks>
    /// <b>Surfaced here rather than as a finding</b>, on the owner's decision of 2026-09-03. The
    /// machine is managed and there is no exposure to report, and
    /// <c>docs/decisions/0081</c> carries no <c>Info</c> severity - it says instead that the
    /// product has other ways to tell an operator a fact about the forest. This grid is that way.
    /// </remarks>
    Unexpected,
}

/// <summary>
/// One computer as the LAPS inventory shows it.
/// </summary>
/// <remarks>
/// <para>
/// <b>The raw values are carried and every answer is computed.</b> <see cref="Management"/>,
/// <see cref="Capability"/> and <see cref="DomainController"/> are derived here from the same types
/// the rules use - <see cref="LapsCapability"/>, <see cref="DomainControllerSignals"/> and
/// <see cref="LapsTimestamp"/> - so the grid cannot call a machine capable while <c>SEC-094</c>
/// calls it legacy-only. The predecessor's LAPS feature tested for a domain controller three
/// different ways in one screen, and this is what ends that.
/// </para>
/// <para>
/// <b>Domain controllers and disabled accounts are listed, not filtered out.</b> Both rules exclude
/// them, and an operator who cannot see them has no way to tell a machine the product deliberately
/// ignored from one it never captured. The columns say which is which.
/// </para>
/// </remarks>
/// <param name="DistinguishedName">The object's name, as the controller gave it.</param>
/// <param name="Name">The first relative name, for showing.</param>
/// <param name="ObjectGuid">The identity that survives a rename, or null when it did not arrive.</param>
/// <param name="DomainFqdn">The domain it was read from.</param>
/// <param name="WindowsLapsExpiration">The raw <c>msLAPS-PasswordExpirationTime</c>, or null.</param>
/// <param name="LegacyLapsExpiration">The raw <c>ms-Mcs-AdmPwdExpirationTime</c>, or null.</param>
/// <param name="OperatingSystem">The <c>operatingSystem</c> value, or null.</param>
/// <param name="OperatingSystemVersion">The <c>operatingSystemVersion</c> value, or null.</param>
/// <param name="UserAccountControl">The account's flags, or null where none was captured.</param>
/// <param name="PrimaryGroupId">Its <c>primaryGroupID</c>, or null where none was captured.</param>
public sealed record LapsComputer(
    string DistinguishedName,
    string Name,
    Guid? ObjectGuid,
    string? DomainFqdn,
    string? WindowsLapsExpiration,
    string? LegacyLapsExpiration,
    string? OperatingSystem,
    string? OperatingSystemVersion,
    uint? UserAccountControl,
    int? PrimaryGroupId)
{
    /// <summary>The Windows LAPS timestamp, and what it amounts to.</summary>
    public LapsTimestamp WindowsLaps => LapsTimestamp.Of(WindowsLapsExpiration);

    /// <summary>The legacy Microsoft LAPS timestamp, and what it amounts to.</summary>
    public LapsTimestamp LegacyLaps => LapsTimestamp.Of(LegacyLapsExpiration);

    /// <summary>What this machine could run, and what that answer rests on.</summary>
    public LapsCapability Capability =>
        LapsCapability.Of(OperatingSystem, OperatingSystemVersion);

    /// <summary>Whether this is a domain controller, and whether the three signals agree.</summary>
    public DomainControllerSignals DomainController =>
        DomainControllerSignals.Of(UserAccountControl, PrimaryGroupId, DistinguishedName);

    /// <summary>
    /// Whether the account is disabled, which takes the machine out of both LAPS rules.
    /// </summary>
    /// <remarks>
    /// Shown rather than hidden: the first <c>ad.lab</c> run reported two disabled leftover
    /// accounts as findings, and this column is where they belong instead.
    /// </remarks>
    public bool IsDisabled => (UserAccountControl & 0x2) != 0;

    /// <summary>
    /// Whether either LAPS rule is in scope for this machine, so an operator can see why a machine
    /// he expected to be reported is not.
    /// </summary>
    public bool IsJudged => !DomainController.IsDomainController && !IsDisabled;

    /// <summary>What the directory shows about this machine's password management.</summary>
    public LapsManagement Management
    {
        get
        {
            var modern = WindowsLaps.IsPresent;
            var legacy = LegacyLaps.IsPresent;

            if (modern && Capability.Kind is LapsCapabilityKind.LegacyLapsOnly)
                return LapsManagement.Unexpected;

            return (modern, legacy) switch
            {
                (true, true) => LapsManagement.Migrated,
                (true, false) => LapsManagement.WindowsLaps,
                (false, true) => LapsManagement.LegacyLaps,
                _ => LapsManagement.NotManaged,
            };
        }
    }
}

/// <summary>
/// One page of the LAPS inventory, and what is true about the whole listing it came from.
/// </summary>
/// <remarks>
/// <b>The counts are of the whole listing, not of this page</b>, for the reason
/// <see cref="ObjectPage"/> gives: a pager that counts only what it fetched can say "1-100 of 100"
/// about a container holding forty thousand machines. An operator watching a rollout is reading the
/// counts far more than the rows.
/// </remarks>
/// <param name="Computers">The computers on this page, ordered by name.</param>
/// <param name="Total">How many computers the whole listing holds.</param>
/// <param name="ComputersAreComplete">
/// Whether every part of the directory this listing covers was read in full. False means the list
/// is short by an unknown amount. Named for its subject rather than for the type, as
/// <see cref="ObjectPage.ObjectsAreComplete"/> is, so that the collection and the statement about it
/// cannot be read apart.
/// </param>
/// <param name="Shortfall">
/// What was not read, in terms an operator can act on, or null when
/// <paramref name="ComputersAreComplete"/> is true.
/// </param>
public sealed record LapsPage(
    IReadOnlyList<LapsComputer> Computers,
    int Total,
    IReadOnlyDictionary<LapsManagement, int> CountsByState,
    bool ComputersAreComplete,
    string? Shortfall)
{
    /// <summary>
    /// How many computers in the whole listing are in one state.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A state nothing is in answers zero rather than being absent.</b> A count list that omits
    /// what it did not find reads as a shorter question than the one that was asked: an operator
    /// who cannot see <i>Not managed 0</i> has to work out whether it was measured at all. Asking
    /// per state rather than handing back a collection of the states that happened to occur is what
    /// makes that true for every caller rather than for the ones that remember.
    /// </para>
    /// <para>
    /// <b>The number is only meaningful beside <see cref="ComputersAreComplete"/></b>, which is why
    /// it is answered by this type rather than by a record of its own: a count that cannot say
    /// whether the listing behind it was whole is the bare count gate 4 refuses.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to count.</param>
    public int CountOf(LapsManagement state) => CountsByState.GetValueOrDefault(state);
}
