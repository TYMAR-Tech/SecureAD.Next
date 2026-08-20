namespace SecureAD.Evidence;

/// <summary>
/// How well protected a connection to one domain controller turned out to be.
/// </summary>
/// <remarks>
/// <para>
/// A named level rather than a boolean, per
/// <c>docs/decisions/0018-connection-security-is-an-ordered-ladder.md</c>. There are four answers
/// and there may one day be five; a flag has nowhere to put a third state, and adding a member to
/// a list is additive where splitting a flag is not.
/// </para>
/// <para>
/// The order of the members is the order the ladder is walked, from the most protected downwards.
/// <c>ConnectionSecurityLadder</c> in <c>SecureAD.Audit</c> asserts that its rungs agree with this
/// list: they are two halves of one statement, and a product in which they disagreed would climb a
/// ladder whose rungs were not the ones it reports.
/// </para>
/// <para>
/// <b>Why this lives in the evidence library rather than beside the ladder.</b> It was defined next
/// to that ladder until 2026-08-13. It moved because the level is not only a fact about how a
/// connection was made, it is a fact the bundle has to record: <c>F-S24-1</c> found that a signed
/// but unencrypted session against a Windows Server 2025 controller has confidential attributes
/// stripped from its results with no error returned to the client, so a run that read a partition
/// over a weak rung must say so rather than let a reader assume coverage. That statement is stored
/// on the coverage row, which is defined here, so the level is defined here too. The ladder keeps
/// the walking; this keeps the vocabulary.
/// </para>
/// </remarks>
public enum ConnectionSecurityLevel
{
    /// <summary>
    /// LDAP over TLS on port 636. The channel is encrypted before anything is sent, including the
    /// bind.
    /// </summary>
    Ldaps,

    /// <summary>
    /// Port 389, with the SASL layer both signing and encrypting. Signing gives integrity - nothing
    /// in transit can be altered undetected - and sealing gives confidentiality.
    /// </summary>
    /// <remarks>
    /// This needs no certificate on the controller, which is why it is the rung most captures will
    /// actually land on: <i>"If LDAP sessions are signed or encrypted by using an SASL logon, the
    /// sessions are secure from Man-In-the-Middle (MITM) attacks"</i>
    /// (<see href="https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-session-security-settings-requirements-adv190023">LDAP
    /// session security settings and requirements after ADV190023 is installed</see>).
    /// </remarks>
    SignedAndSealed,

    /// <summary>
    /// Port 389, signed but not encrypted. Nothing can be altered in transit; anything can be read.
    /// </summary>
    /// <remarks>
    /// <b>The rung that both succeeds and misleads.</b> A Windows Server 2025 controller
    /// <i>"allow[s] LDAP only to add, search, and modify operations that involve confidential
    /// attributes when the connection is encrypted"</i>, and strips them from an unencrypted search
    /// while returning no error - the event table for Event ID 3079 lists <i>"User error (returned
    /// to the client): None"</i>. So a capture that lands here reads a forest with every
    /// confidential attribute silently missing and is told nothing. That is <c>F-S24-1</c>, and it
    /// is why this level is recorded against every partition rather than only logged.
    /// </remarks>
    Signed,

    /// <summary>
    /// Port 389, with neither signing nor encryption. Reached only where the run carried a declared
    /// allowance, and never as a fallback.
    /// </summary>
    /// <remarks>
    /// The bind is still Negotiate, so no credential crosses the wire in clear text at any point on
    /// this ladder - a simple bind is not a rung. What is unprotected is the evidence: what the
    /// controller sends back could have been altered on the way, and a run that used this rung
    /// says so.
    /// </remarks>
    Unprotected,
}
