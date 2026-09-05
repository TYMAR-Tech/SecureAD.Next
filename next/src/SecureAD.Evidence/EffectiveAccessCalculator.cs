using SecureAD.Kernel.Security;

namespace SecureAD.Evidence;

/// <summary>
/// What one trustee effectively holds over an object, after the whole DACL has been applied.
/// </summary>
/// <param name="Trustee">Who holds it.</param>
/// <param name="Mask">
/// The access mask left after deny entries have been applied the way Active Directory applies them.
/// </param>
/// <param name="FirstGrantingEntry">
/// The entry that first granted any of this, kept because it is the one an operator would change.
/// A later, wider entry names a scope that is not the cause.
/// </param>
public sealed record EffectiveAccess(
    PermissionTrustee Trustee,
    int Mask,
    PermissionEntry FirstGrantingEntry);

/// <summary>
/// Whether the question could be answered at all, and if not, why not.
/// </summary>
/// <remarks>
/// <b>Absent, unreadable and clean are three states.</b> An empty list of holders means nobody holds
/// anything only when the descriptor was read and its entries parsed. Reporting an object as
/// granting nothing when nobody read its permissions is the one thing an audit tool must not do -
/// a production domain returned 19,927 of 100,000 objects with no readable descriptor.
/// </remarks>
public enum EffectiveAccessOutcome
{
    /// <summary>The DACL was read and the holders are the answer.</summary>
    Computed,

    /// <summary>Nobody read the security descriptor, so nothing is known about who holds what.</summary>
    DescriptorNotRead,

    /// <summary>
    /// The DACL pointer was null, which grants every principal full access to the object.
    /// </summary>
    /// <remarks>
    /// <b>This is the opposite of an empty answer and must never render as one.</b> A list of
    /// holders cannot express "everyone", so the outcome carries it instead.
    /// </remarks>
    GrantsEveryoneEverything,

    /// <summary>
    /// The DACL declared entries and none of them could be parsed, so what it grants is unknown.
    /// </summary>
    EntriesUnparsed,
}

/// <summary>
/// Who effectively holds what over one object, and whether that answer can be relied on.
/// </summary>
/// <param name="Outcome">Whether the question could be answered.</param>
/// <param name="Holders">
/// One entry per trustee holding anything. Empty is meaningful only when
/// <paramref name="Outcome"/> is <see cref="EffectiveAccessOutcome.Computed"/>.
/// </param>
/// <param name="EveryDeclaredEntryArrived">
/// Whether every entry the DACL declared was parsed. Where it was not, a right nobody can see may
/// still be granted, so a silence here is not an answer.
/// </param>
/// <param name="DaclWasCanonical">
/// Whether the entries are in the order Windows would evaluate them in. Carried because a
/// non-canonical list is <b>more open</b> than it reads - an allow ahead of a deny survives it -
/// and an operator comparing this against a directory tool needs to know which they are looking at.
/// </param>
public sealed record EffectiveAccessResult(
    EffectiveAccessOutcome Outcome,
    IReadOnlyList<EffectiveAccess> Holders,
    bool EveryDeclaredEntryArrived,
    bool DaclWasCanonical)
{
    /// <summary>Whether this is a real answer rather than a silence.</summary>
    public bool IsComplete =>
        Outcome is EffectiveAccessOutcome.Computed && EveryDeclaredEntryArrived;
}

/// <summary>
/// Works out what each trustee actually holds over an object, from the entries stored on it.
/// </summary>
/// <remarks>
/// <para>
/// <b>What this is for, in plain terms.</b> A permission list is not a list of what people can do.
/// The same trustee can appear several times, some entries take rights away rather than grant them,
/// and some entries are sitting on the object only so they can be copied to the objects underneath
/// it. Reading a list entry by entry and believing each one is how a tool ends up telling a customer
/// that somebody has a permission they do not have.
/// </para>
/// <para>
/// <b>It lives here rather than inside a rule because two rules needed it and a third would have
/// been the copy that drifted.</b> This computation was private to SEC-090. SEC-060 needs the same
/// answer, and the repository has already paid for near-identical helpers once - the DN helpers
/// ended up with three ways to ask one question. Lifting it also means a correction is made once.
/// </para>
/// <para>
/// <b>Three things it honours, and each one was a way of being wrong.</b>
/// </para>
/// <list type="number">
/// <item>
/// <b>Inherit-only entries grant nothing here.</b> <c>INHERIT_ONLY_ACE</c> marks an entry that does
/// not control access to the object it is attached to; it is there to be copied downwards. MS-ADTS
/// 6.1.3 states it plainly: the flag <i>"identifies an ineffective ACE, which does not control
/// access to the object to which it is attached"</i>. Counting one would report a container as
/// giving away control it does not give away.
/// </item>
/// <item>
/// <b>Denies are applied in stored order, not blanket-subtracted.</b> Active Directory gathers
/// granted and denied masks across the whole list and a deny only removes rights not already
/// granted by an earlier entry. So an allow appearing before a deny keeps that deny from taking
/// effect - which is why a non-canonical list is more open than it reads, and why
/// <see cref="ObjectPermissions.DaclWasCanonical"/> exists.
/// </item>
/// <item>
/// <b>An entry scoped to an object type does not answer a question about the object as a whole.</b>
/// Whether an entry carries a scope is read from <c>HasObjectType</c> and never from whether the
/// GUID is null, because an object entry carrying no GUID narrows nothing.
/// </item>
/// </list>
/// </remarks>
public static class EffectiveAccessCalculator
{
    /// <summary>
    /// What each trustee effectively holds, for one question about scope.
    /// </summary>
    /// <param name="permissions">The object's permissions, as the bundle stored them.</param>
    /// <param name="objectTypeGuid">
    /// The object type being asked about - an attribute or extended right GUID - or null to ask
    /// about the object as a whole.
    /// <para>
    /// <b>Null is a narrower question, not a wider one.</b> Asking about the object as a whole is
    /// answered only by entries that carry no scope, because an entry limited to one attribute does
    /// not confer anything over the object generally. Asking about a named type is answered by
    /// entries scoped to that type <i>and</i> by unscoped entries, which reach everything.
    /// </para>
    /// </param>
    /// <returns>
    /// The holders, and whether the question could be answered at all. The outcome is checked
    /// before the list is believed - see <see cref="EffectiveAccessOutcome"/>.
    /// </returns>
    public static EffectiveAccessResult Over(
        ObjectPermissions permissions, string? objectTypeGuid)
    {
        ArgumentNullException.ThrowIfNull(permissions);

        // THE THREE SILENCES, SEPARATED BEFORE ANY ENTRY IS READ. Each of these would otherwise
        // hand back an empty list that reads as "nobody holds anything", and per
        // docs/decisions/0002 unavailable output is never rendered as an empty result.
        if (permissions.Availability is not DescriptorAvailability.Read)
            return NoAnswer(EffectiveAccessOutcome.DescriptorNotRead, permissions);

        if (permissions.DaclState is DaclState.Null)
            return NoAnswer(EffectiveAccessOutcome.GrantsEveryoneEverything, permissions);

        if (permissions.DaclState is DaclState.Unreadable)
            return NoAnswer(EffectiveAccessOutcome.EntriesUnparsed, permissions);

        var granted = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var denied = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var cause = new Dictionary<string, PermissionEntry>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in permissions.Entries)
        {
            // CREATOR OWNER and OWNER RIGHTS are placeholders rather than principals, and one lab
            // bundle credited 1,708 entries to two of them.
            if (!entry.Trustee.HoldsThePermission)
                continue;

            // The entry is on this object but does not govern it. See the remarks above.
            if (EntryReachReader.FromPropagationFlags(entry.PropagationFlags)
                is EntryReach.DescendantsOnly)
            {
                continue;
            }

            if (!Reaches(entry, objectTypeGuid))
                continue;

            var sid = entry.Trustee.Sid;
            var isDeny = entry.AceType.Contains("Denied", StringComparison.OrdinalIgnoreCase);
            var alreadyGranted = granted.GetValueOrDefault(sid);

            if (isDeny)
            {
                denied[sid] = denied.GetValueOrDefault(sid) | (entry.AccessMask & ~alreadyGranted);
                continue;
            }

            granted[sid] = alreadyGranted | entry.AccessMask;

            // The entry that first granted a right is the one worth showing an operator, because it
            // is the one to change. A later, wider entry would name a scope that is not the cause.
            cause.TryAdd(sid, entry);
        }

        var holders = new List<EffectiveAccess>();

        foreach (var (sid, mask) in granted)
        {
            var effective = mask & ~denied.GetValueOrDefault(sid);

            if (effective == 0)
                continue;

            holders.Add(new EffectiveAccess(cause[sid].Trustee, effective, cause[sid]));
        }

        return new EffectiveAccessResult(
            EffectiveAccessOutcome.Computed,
            holders,
            permissions.DaclCompleteness is DaclCompleteness.Complete,
            permissions.DaclWasCanonical);
    }

    /// <summary>A result carrying no holders, because the question could not be answered.</summary>
    private static EffectiveAccessResult NoAnswer(
        EffectiveAccessOutcome outcome, ObjectPermissions permissions) =>
        new(outcome, [], permissions.DaclCompleteness is DaclCompleteness.Complete,
            permissions.DaclWasCanonical);

    /// <summary>Whether the entry bears on the scope being asked about.</summary>
    private static bool Reaches(PermissionEntry entry, string? objectTypeGuid)
    {
        if (!entry.HasObjectType)
            return true;

        return objectTypeGuid is not null
            && string.Equals(
                entry.ObjectTypeGuid, objectTypeGuid, StringComparison.OrdinalIgnoreCase);
    }
}
