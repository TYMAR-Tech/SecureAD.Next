namespace SecureAD.Evidence.Findings;

/// <summary>
/// What a LAPS expiration timestamp on a computer object amounted to.
/// </summary>
/// <remarks>
/// <b>Three states, because absent and unreadable are different and both differ from present.</b>
/// For an attribute most computers in an unmanaged forest do not carry, absence is the ordinary
/// case and must not be reported as an unread input, or the rule names a missing attribute against
/// nearly every object in the forest and reads as a broken capture. A value that was present and
/// could not be decoded is the opposite: it must never be silently skipped, because the machine may
/// well be managed. <c>SEC-027</c> section 9 is the worked example of getting this wrong.
/// </remarks>
public enum LapsTimestampReading
{
    /// <summary>
    /// No value. Given a readable attribute, this is a fact about the machine: nothing has written
    /// an expiration time to it.
    /// </summary>
    Absent,

    /// <summary>
    /// A value was there and this build could not decode it. The machine may be managed, so nothing
    /// may be concluded from it either way.
    /// </summary>
    Unreadable,

    /// <summary>A value was there and decoded. Something is rotating this password.</summary>
    Present,
}

/// <summary>
/// What SEC-091 and SEC-094 rested on: both LAPS expiration timestamps, and what the machine was
/// capable of running.
/// </summary>
/// <remarks>
/// <para>
/// <b>One evidence kind for two rules, on purpose.</b> The two rules are separate because
/// acceptance is per finding and suppression is per rule - an estate running legacy emulation mode
/// deliberately must be able to silence SEC-094 without silencing SEC-091. But what an operator
/// needs to see is the same in both cases: which timestamps this machine carries and what it could
/// run. <see cref="UserAccountControlEvidence"/> is already shared by several rules for the same
/// reason.
/// </para>
/// <para>
/// <b>Both timestamps travel, even the one the rule fired on the absence of.</b> A SEC-091 finding
/// carries two absences and a SEC-094 finding carries one of each, and in both cases the pair is
/// what an operator is really asking about. Showing only the attribute that decided the finding
/// would leave him to guess at the other.
/// </para>
/// <para>
/// <b>The raw values are carried and the dates are computed.</b> Active Directory stores these as
/// a Windows FILETIME in a text attribute; the decoded date is derived from it here rather than
/// stored beside it, so the two cannot disagree - the rule the delegation, pre-authentication and
/// SID history evidence all follow.
/// </para>
/// <para>
/// <b>The capability travels with its basis</b>, because a capability decided from a build number
/// and the same answer guessed from an operating system name are not equally good, and a finding
/// reporting only the conclusion lets a reader believe they are. See <see cref="LapsCapability"/>.
/// </para>
/// </remarks>
/// <param name="WindowsLapsExpiration">
/// The raw <c>msLAPS-PasswordExpirationTime</c>, or null where the object carried none.
/// </param>
/// <param name="LegacyLapsExpiration">
/// The raw <c>ms-Mcs-AdmPwdExpirationTime</c>, or null where the object carried none.
/// </param>
/// <param name="Capability">What this machine could run, and what that rests on.</param>
public sealed record LapsDeploymentEvidence(
    string? WindowsLapsExpiration,
    string? LegacyLapsExpiration,
    LapsCapability Capability) : FindingEvidence
{
    /// <summary>What the Windows LAPS timestamp amounted to.</summary>
    public LapsTimestampReading WindowsLaps => LapsTimestamp.Of(WindowsLapsExpiration).Reading;

    /// <summary>What the legacy Microsoft LAPS timestamp amounted to.</summary>
    public LapsTimestampReading LegacyLaps => LapsTimestamp.Of(LegacyLapsExpiration).Reading;

    /// <summary>When Windows LAPS next expects to rotate, where that could be decoded.</summary>
    public DateTimeOffset? WindowsLapsExpiresUtc => LapsTimestamp.Of(WindowsLapsExpiration).ExpiresUtc;

    /// <summary>When legacy LAPS next expected to rotate, where that could be decoded.</summary>
    public DateTimeOffset? LegacyLapsExpiresUtc => LapsTimestamp.Of(LegacyLapsExpiration).ExpiresUtc;
}
