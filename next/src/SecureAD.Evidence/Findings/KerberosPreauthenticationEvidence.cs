namespace SecureAD.Evidence.Findings;

/// <summary>
/// What SEC-022 read to reach its conclusion.
/// </summary>
/// <remarks>
/// <para>
/// <b>The whole value is kept, not just the bit that fired.</b> Storing a bare "yes" would leave a
/// reader unable to tell a plain user account from a disabled one or a domain controller, and every
/// one of those questions is answered by other bits of the same integer. It is one attribute read
/// once, so there is no second copy to drift.
/// </para>
/// <para>
/// <b><c>IsDisabled</c> is derived here rather than stored.</b> It is <c>ADS_UF_ACCOUNTDISABLE</c>
/// (<c>0x2</c>) of the value beside it, so a stored column would be a second account of a fact
/// already present and could disagree with it. The same reasoning keeps the two computed answers out
/// of <see cref="UnconstrainedDelegationEvidence"/>.
/// </para>
/// <para>
/// <b>Why a disabled account is reported at all.</b> The predecessor excluded them. No Microsoft
/// source states that a key distribution centre refuses an AS-REQ for a disabled account, so
/// excluding them would rest on nothing, and the rule reports them with this flag set instead of
/// silently dropping them. An operator can then triage; the product does not decide for him on an
/// unevidenced belief.
/// </para>
/// </remarks>
/// <param name="UserAccountControl">The value the pre-authentication flag was read from.</param>
public sealed record KerberosPreauthenticationEvidence(uint UserAccountControl) : FindingEvidence
{
    /// <summary>
    /// Whether the account is disabled, read from <c>ADS_UF_ACCOUNTDISABLE</c> of the value above.
    /// </summary>
    public bool IsDisabled => (UserAccountControl & 0x00000002) != 0;
}
