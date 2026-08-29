namespace SecureAD.Evidence.Findings;

/// <summary>What an unconstrained-delegation finding rests on.</summary>
/// <remarks>
/// This is durable finding data rather than executable rule logic, so it remains in Evidence while
/// the rules that produce it belong to Judgement.
/// </remarks>
/// <param name="UserAccountControl">The value the flag was read from.</param>
/// <param name="IsComputer">Whether the object declared the computer class, which decides which rule applies.</param>
/// <param name="DomainController">How the domain controller question was answered for this object.</param>
public sealed record UnconstrainedDelegationEvidence(
    uint UserAccountControl,
    bool IsComputer,
    DomainControllerSignals DomainController) : FindingEvidence;
