namespace SecureAD.Derivation;

/// <summary>
/// One SID and the principal it identifies.
/// </summary>
/// <param name="SidId">The SID.</param>
/// <param name="PrincipalSidId">The current SID of the principal it identifies.</param>
/// <param name="Kind">Whether this is that principal's own SID or one it carries from a migration.</param>
internal readonly record struct SidIdentityRow(int SidId, int PrincipalSidId, SidIdentityKind Kind);

/// <summary>
/// Everything about one principal that a membership question needs, other than its edges.
/// </summary>
/// <remarks>
/// <b><paramref name="GroupType"/> is null for two different reasons and the difference matters.</b>
/// A principal that is not a group has no group type; a group whose <c>groupType</c> the capture
/// did not record has one nobody knows. <paramref name="IsGroup"/> is what tells them apart, which
/// is why it is carried separately rather than inferred from this being null.
/// </remarks>
/// <param name="SidId">The principal's current SID.</param>
/// <param name="ObjectGuid">The object's GUID, so a derived fact can name something durable.</param>
/// <param name="IsGroup">Whether <c>objectClass</c> called it a group.</param>
/// <param name="GroupType">The raw <c>groupType</c> flags word, when one was captured.</param>
/// <param name="PrimaryGroupSidId">
/// The group named by <c>primaryGroupID</c>, when the principal is an account that had one. Held
/// here rather than as an edge: it is real membership, but it is also the most uniform fact in the
/// directory, and materialising it would add one row per account all pointing at Domain Users.
/// </param>
internal readonly record struct PrincipalRow(
    int SidId,
    Guid ObjectGuid,
    bool IsGroup,
    int? GroupType,
    int? PrimaryGroupSidId);

/// <summary>
/// One directory nesting relationship: <paramref name="MemberSidId"/> is directly in
/// <paramref name="GroupSidId"/>.
/// </summary>
/// <remarks>
/// <b>A struct because there are more of these than of anything else.</b> A forest's nesting is
/// millions of these, and as a class each one would be a separate heap allocation for the garbage
/// collector to trace. Two integers in a struct is the whole edge.
/// </remarks>
/// <param name="GroupSidId">The containing group.</param>
/// <param name="MemberSidId">The principal directly inside it.</param>
internal readonly record struct NestingEdge(int GroupSidId, int MemberSidId);
