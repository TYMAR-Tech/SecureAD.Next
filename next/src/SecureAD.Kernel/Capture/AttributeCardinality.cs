namespace SecureAD.Kernel.Capture;

/// <summary>
/// Whether an attribute holds one value or many.
/// </summary>
/// <remarks>
/// This is not a cosmetic label. A domain controller returns at most <c>MaxValRange</c> values of a
/// single attribute on a single object - 1,500 by default, and capped at 5,000 on Windows Server
/// 2008 and later regardless of what the LDAP policy says
/// (<see href="https://learn.microsoft.com/troubleshoot/windows-server/active-directory/view-set-ldap-policy-using-ntdsutil">LDAP
/// administration limits</see>,
/// <see href="https://learn.microsoft.com/troubleshoot/windows-server/active-directory/domain-controller-returns-500-values-ldap-response">the
/// hard-coded maximums</see>). Past that the values do not come back under the name they were
/// asked for: Microsoft describes the result as one that "may appear truncated or incomplete", and
/// says that "in some occasions, you may not get any results". Either way there is no error, and a
/// reader that does not ask for the rest reports a group of nine thousand members as a group of
/// five thousand.
///
/// <para>
/// So <see cref="MultiValued"/> means range-liable, for every attribute rather than for
/// <c>member</c> alone. That is the whole reason cardinality is carried here rather than being
/// tested for by name where the values are read: an <c>if</c> naming one attribute is correct until
/// somebody adds the next large multi-valued one, and then it is silently wrong.
/// </para>
/// </remarks>
public enum AttributeCardinality
{
    /// <summary>One value at most. Never range-liable.</summary>
    SingleValued,

    /// <summary>
    /// Any number of values, so subject to the server's value limit and requiring range retrieval.
    /// </summary>
    MultiValued,
}
