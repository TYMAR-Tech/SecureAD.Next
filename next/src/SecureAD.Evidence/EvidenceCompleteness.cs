namespace SecureAD.Evidence;

/// <summary>
/// What the connection an object was read over could have withheld without saying so.
/// </summary>
/// <remarks>
/// <para>
/// <b>It says only what is observable, which is why it is not called completeness of the object.</b>
/// Nothing in a bundle can state that everything about an object is present: a controller returns
/// what the caller is entitled to read and does not report what it withheld, so an under-privileged
/// run and a fully privileged one are indistinguishable from the client side (<c>F-S30-6</c>).
/// </para>
/// <para>
/// <b>It is an enum rather than a boolean because a boolean would have to overclaim.</b> A member
/// called <c>IsComplete</c> means <i>everything about this object is here</i>, which is not
/// supportable. These two values mean something narrower and true: whether the protection on the
/// connection was sufficient for a controller to have returned confidential attributes at all.
/// </para>
/// </remarks>
public enum EvidenceCompleteness
{
    /// <summary>
    /// The connection was encrypted, so nothing was withheld on account of its protection.
    /// </summary>
    Complete,

    /// <summary>
    /// The connection was not encrypted, so confidential attributes may have been stripped from the
    /// results with no error returned to the client.
    /// </summary>
    /// <remarks>
    /// A Windows Server 2025 controller removes confidential attributes from an unencrypted search
    /// and says nothing about having done so (<c>F-S24-1</c>). Treating that silence as a fact about
    /// the forest is what <c>docs/decisions/0002</c> forbids. This is reachable without anyone
    /// choosing it: <c>ConnectionSecurityLevel.Signed</c> requires no declared allowance, so an
    /// ordinary run can land here with no operator action.
    /// </remarks>
    MayBeMissingConfidentialValues,
}

/// <summary>
/// What a read over one rung of the connection ladder can be said to have covered.
/// </summary>
/// <remarks>
/// <b>One mapping rather than two.</b> <see cref="EvidenceObject"/> states this for an object on
/// its way into a bundle, and <see cref="ObjectAttributesReader"/> states it again for the same
/// object on the way back out. Two copies of a rule that must agree is how the distinguished-name
/// helpers ended up with three near-identical ways to ask one question, so the rule is written
/// once and both sides call it.
/// </remarks>
internal static class ReadCoverage
{
    /// <summary>
    /// Whether a read over <paramref name="connectionSecurity"/> could have been served
    /// confidential attributes at all.
    /// </summary>
    /// <param name="connectionSecurity">The rung the partition was actually read over.</param>
    public static EvidenceCompleteness Over(ConnectionSecurityLevel connectionSecurity) =>
        connectionSecurity switch
        {
            ConnectionSecurityLevel.Ldaps or ConnectionSecurityLevel.SignedAndSealed =>
                EvidenceCompleteness.Complete,
            _ => EvidenceCompleteness.MayBeMissingConfidentialValues,
        };
}
