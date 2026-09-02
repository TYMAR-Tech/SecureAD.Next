namespace SecureAD.Evidence.Findings;

/// <summary>
/// What SEC-021 read to reach its conclusion.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every service name, not only the first.</b> An operator deciding whether the account really
/// runs a service needs to see what it claims to run - a stale name left over from a test is the
/// common case, and it is the only one where the remedy is simply to remove it. One name would
/// answer a narrower question than the one he has.
/// </para>
/// <para>
/// <b><c>IsDisabled</c> is derived from the value beside it rather than stored.</b> Same reasoning
/// as <see cref="UserAccountControlEvidence"/>: a stored column would be a second account of a fact
/// already present and could disagree with it.
/// </para>
/// <para>
/// <b>Why the whole <c>userAccountControl</c> is here at all.</b> The rule does not decide anything
/// from it - a disabled account is still reported, because no Microsoft source establishes that a
/// key distribution centre refuses a service ticket for one. It is carried so the finding can say
/// so, and so a reader can see the account's other flags without a second finding in front of him.
/// </para>
/// </remarks>
/// <param name="ObjectSid">The identity the derivation was asked about.</param>
/// <param name="ServicePrincipalNames">The service names that were read, as captured.</param>
/// <param name="UserAccountControl">The whole value the disabled state is read from.</param>
/// <param name="UnreadableServiceNames">How many service names were present but had no text.</param>
public sealed record KerberoastableAccountEvidence(
    string ObjectSid,
    IReadOnlyList<string> ServicePrincipalNames,
    uint UserAccountControl,
    int UnreadableServiceNames = 0) : FindingEvidence
{
    /// <summary>
    /// Whether every service name the account carried was read, so this is the whole of what it
    /// claims to run.
    /// </summary>
    /// <remarks>
    /// <b>False does not weaken the finding.</b> One readable service name is enough to make the
    /// account kerberoastable, and refusing to report a privileged account over an unreadable
    /// sibling would lose a true Critical finding. What this says is that the account may claim to
    /// run <i>more</i> than is listed, so an operator deciding whether it really runs anything has
    /// not seen the whole picture.
    /// </remarks>
    public bool IsComplete => UnreadableServiceNames == 0;
    /// <summary>
    /// Whether the account is disabled, read from <c>ADS_UF_ACCOUNTDISABLE</c> of the value above.
    /// </summary>
    /// <remarks>
    /// <b>False for most findings, and it does not weaken them.</b> Where it is true the exposure is
    /// dormant rather than absent: re-enabling the account restores it, and the service name is
    /// still registered in the meantime.
    /// </remarks>
    public bool IsDisabled => (UserAccountControl & 0x00000002) != 0;
}
