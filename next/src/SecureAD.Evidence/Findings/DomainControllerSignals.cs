namespace SecureAD.Evidence.Findings;

/// <summary>
/// Whether an object is a domain controller, and whether the three ways of asking agree.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why three signals and not one.</b> A domain controller legitimately holds settings that
/// would be alarming anywhere else - unconstrained delegation most of all - so several rules must
/// exclude one. Getting that exclusion wrong in the generous direction hides the object an
/// attacker most wants hidden.
/// </para>
/// <para>
/// <b>Only one of the three is set by the directory itself.</b> <c>SERVER_TRUST_ACCOUNT</c> is
/// written during promotion. The other two are writable: an attacker who can set
/// <c>primaryGroupID</c> to 516, or move a computer into the Domain Controllers container, makes
/// it look like a domain controller. Microsoft names that first technique explicitly - its own
/// guidance warns that <c>primaryGroupID</c> "might be used as an attempt to hide group
/// membership" and calls it "a stealthy way for an attacker to escalate privileges without
/// triggering normal auditing".
/// </para>
/// <para>
/// <b>So disagreement is reported rather than resolved.</b> <see cref="SignalsDisagree"/> is true
/// when some signals say domain controller and others do not, and that is a fact about the forest
/// an auditor wants told. <c>docs/decisions/0015</c> - the product names a pattern and never
/// explains one away - is why it is surfaced instead of being quietly settled by a majority.
/// </para>
/// <para>
/// <b>The primary group values are Microsoft's.</b> 516 is Domain Controllers and 521 is Read-only
/// Domain Controllers, published in the Defender for Identity account assessments alongside 513
/// for users and 515 for computers. They were taken from there rather than from the predecessor,
/// whose catalogue of well-known values was found to carry wrong entries.
/// </para>
/// </remarks>
/// <param name="ServerTrustAccountBit">
/// The account carries <c>SERVER_TRUST_ACCOUNT</c>. The directory sets this during promotion.
/// </param>
/// <param name="PrimaryGroupIsDomainController">
/// The primary group is Domain Controllers (516) or Read-only Domain Controllers (521).
/// </param>
/// <param name="UnderDomainControllersOu">
/// The object sits under the Domain Controllers container. The weakest of the three: it is a
/// naming convention rather than anything the directory enforces.
/// </param>
public sealed record DomainControllerSignals(
    bool ServerTrustAccountBit,
    bool PrimaryGroupIsDomainController,
    bool UnderDomainControllersOu)
{
    private const uint ServerTrustAccount = 0x00002000;
    private const int DomainControllersGroup = 516;
    private const int ReadOnlyDomainControllersGroup = 521;

    /// <summary>
    /// Whether this is a domain controller, on the strength of any signal.
    /// </summary>
    /// <remarks>
    /// Any signal is enough, which is the generous direction and is chosen knowingly: a real
    /// domain controller wrongly judged an ordinary computer produces a loud false finding on
    /// every domain controller in the forest, and an operator learns to ignore the rule. The
    /// evasion this admits is answered by <see cref="SignalsDisagree"/> rather than by tightening
    /// this into a test a legitimate controller could fail.
    /// </remarks>
    public bool IsDomainController =>
        ServerTrustAccountBit || PrimaryGroupIsDomainController || UnderDomainControllersOu;

    /// <summary>
    /// Whether the signals disagree, so that something claims to be a domain controller by one
    /// measure and not by another.
    /// </summary>
    public bool SignalsDisagree =>
        IsDomainController
        && !(ServerTrustAccountBit && PrimaryGroupIsDomainController && UnderDomainControllersOu);

    /// <summary>
    /// Reads the three signals from a captured object.
    /// </summary>
    /// <param name="subject">The object to test.</param>
    public static DomainControllerSignals Of(ObjectAttributes subject)
    {
        ArgumentNullException.ThrowIfNull(subject);

        var control = AttributeReading.UnsignedInteger(subject, "userAccountControl");
        var primaryGroup = AttributeReading.SignedInteger(subject, "primaryGroupID");

        return new DomainControllerSignals(
            ServerTrustAccountBit: control is { } bits && (bits & ServerTrustAccount) != 0,
            PrimaryGroupIsDomainController: primaryGroup is DomainControllersGroup
                or ReadOnlyDomainControllersGroup,
            UnderDomainControllersOu: subject.DistinguishedName.Contains(
                ",OU=Domain Controllers,", StringComparison.OrdinalIgnoreCase));
    }
}
