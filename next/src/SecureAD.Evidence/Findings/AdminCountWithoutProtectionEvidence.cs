namespace SecureAD.Evidence.Findings;

/// <summary>
/// What SEC-030 read to reach its conclusion.
/// </summary>
/// <remarks>
/// <para>
/// <b>Deliberately narrow.</b> It carries what the finding rests on and nothing that would let a
/// reader reconstruct a claim the rule refuses to make - there is no "was privileged until" here,
/// because present-state evidence cannot establish it.
/// </para>
/// <para>
/// <b>There is no deleted flag, and that is a limit rather than an omission.</b> Capture does not
/// read <c>isDeleted</c>, so every object a bundle carries is a live one. Were tombstones ever
/// captured, they would need reporting separately - each has a non-inheriting DACL as a consequence
/// of deletion - which is why <c>docs/decisions/0091</c> puts them outside this rule rather than
/// inside it unmarked.
/// </para>
/// </remarks>
/// <param name="Sid">The principal's security identifier, as the derivation keyed it.</param>
public sealed record AdminCountWithoutProtectionEvidence(string Sid) : FindingEvidence;
