namespace SecureAD.Evidence.Findings;

/// <summary>
/// What an operator is told about a rule: what it is about, why it matters, and what to do.
/// </summary>
/// <remarks>
/// <para>
/// <b>Separate from <see cref="RuleDefinition"/>, and that separation is the point.</b>
/// <c>docs/decisions/0010</c> is Accepted and requires the fields that decide behaviour - identity,
/// severity - to be reviewable apart from the copy an operator reads. Its objection was concrete: in
/// the predecessor, changing a severity and fixing a typo in remediation text were the same edit to
/// the same file, and arrived at review indistinguishable. A reviewer can be asked to treat a small
/// behavioural file as security-relevant only if the prose that changes weekly is not in it.
/// </para>
/// <para>
/// <b>This is guidance, not a claim that the problem is solved.</b>
/// <see cref="WhatToDo"/> names an action and what it may cost. It must never say the customer is
/// then safe: that is a statement about every route to the object, which <c>AC-15</c> and
/// <c>AC-21</c> require to be proven and which belongs to stage 8. <c>RuleGuidanceTests</c> refuses
/// wording that crosses the line, because guidance copy is exactly where it gets crossed by
/// accident.
/// </para>
/// <para>
/// <b>It is current advice rather than part of the sealed finding, deliberately.</b> Guidance is not
/// written into the judgement store. A finding records what was true about one object - and that is
/// reproducible - while the advice beside it should improve as we learn more, and an operator
/// reopening last month's run wants today's best advice rather than last month's. <c>AC-19</c> is met
/// because the finding is reconstructable from the recorded rule version and inputs; the advice is
/// not evidence and is not presented as any.
/// </para>
/// </remarks>
/// <param name="RuleId">The rule this describes, matching <see cref="RuleDefinition.Id"/>.</param>
/// <param name="Category">
/// The family a reader groups this with, such as <c>Kerberos</c> or <c>Delegation</c>. The
/// predecessor showed this beside the title and it is what an administrator scans by.
/// </param>
/// <param name="MitreTechnique">
/// The MITRE ATT&amp;CK technique, such as <c>T1558.004</c>, or null where no mapping has been
/// established from a first-party source.
/// <para>
/// <b>Null is an honest answer and is used.</b> A mapping invented to fill the field would be an
/// unverified claim printed beside verified ones, which is the habit this product exists to break.
/// The predecessor mapped a resource-based delegation rule to <c>T1558.001</c>, which is Golden
/// Ticket - a different thing.
/// </para>
/// </param>
/// <param name="WhyItMatters">
/// What an attacker gains, in plain language, and what it costs the organisation.
/// </param>
/// <param name="WhatToDo">The action to take, and what taking it may break.</param>
/// <param name="About">
/// What this rule looks for, and <b>what it does not</b>.
/// <para>
/// <b>The third kind of copy, and the one that makes a bounded rule honest.</b> A finding says what
/// is true of one object and <see cref="WhyItMatters"/> says why that matters; neither can say what
/// the rule cannot see. A rule reporting a subset of a problem is not free to let its silence read
/// as <i>nothing else is wrong</i>, and until this field existed the only place to say so was the
/// per-finding text - which repeats the statement once per object, attaches it to the machines that
/// fired rather than to the rule, and never reaches the operator who most needs it: the one looking
/// at a rule that reported nothing.
/// </para>
/// <para>
/// <b>Required on every rule, on the owner's decision of 2026-09-03.</b> Optional was the cheaper
/// choice and was refused: a field populated for some rules and empty for others renders as
/// <i>this rule has no limitations</i>, which for a bounded rule is the exact false statement the
/// section exists to prevent. Being made to write it is also how an unstated limit gets found, which
/// is the same reason a rule declares its inputs.
/// </para>
/// <para>
/// <b>It describes the rule, not the forest.</b> Nothing here may depend on what a run found, since
/// the same words are shown whether the rule fired once or not at all.
/// </para>
/// </param>
/// <param name="MicrosoftReference">
/// The Microsoft page the reasoning rests on, or null where the claim rests on something else.
/// Carried because a customer who can check a statement is the difference between this product and
/// one that asserts.
/// </param>
public sealed record RuleGuidance(
    string RuleId,
    string Category,
    string? MitreTechnique,
    string WhyItMatters,
    string WhatToDo,
    string About,
    string? MicrosoftReference);
