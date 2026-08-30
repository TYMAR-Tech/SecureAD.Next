using SecureAD.Audit.Capture;
using SecureAD.Evidence.Run;

namespace SecureAD.Audit.Sysvol;

/// <summary>
/// The Group Policy objects a capture saw in the directory, and which of them can have their files
/// read.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is where the SYSVOL denominator comes from, and the order is the point.</b> The policies
/// are collected as the directory is read, before the share is touched at all. That is what earns
/// SYSVOL the right to record coverage under <c>docs/decisions/0044</c>: a run that later fails to
/// read three folders knows there should have been four hundred, because this list was made
/// without asking the share anything.
/// </para>
/// <para>
/// <b>A policy that cannot be targeted is carried rather than dropped.</b> A
/// <c>groupPolicyContainer</c> whose <c>gPCFileSysPath</c> did not come back cannot be read, and
/// quietly leaving it out would shrink the denominator to the set of things that went well - which
/// is the arithmetic that makes a partial run look complete.
/// </para>
/// </remarks>
public sealed class GpoInventory
{
    /// <summary>The class that marks an object as a Group Policy object.</summary>
    private const string GroupPolicyContainerClass = "groupPolicyContainer";

    private const string ObjectClassAttribute = "objectClass";
    private const string DisplayNameAttribute = "displayName";
    private const string FileSysPathAttribute = "gPCFileSysPath";

    private readonly List<GpoTarget> _policies = [];
    private readonly List<GpoCoverage> _unlocatable = [];

    internal readonly record struct Checkpoint(int Policies, int Unlocatable);

    internal Checkpoint Mark() => new(_policies.Count, _unlocatable.Count);

    internal void Restore(Checkpoint checkpoint)
    {
        if (_policies.Count > checkpoint.Policies)
            _policies.RemoveRange(checkpoint.Policies, _policies.Count - checkpoint.Policies);

        if (_unlocatable.Count > checkpoint.Unlocatable)
            _unlocatable.RemoveRange(
                checkpoint.Unlocatable, _unlocatable.Count - checkpoint.Unlocatable);
    }

    /// <summary>
    /// The policies whose files can be read, in the order the directory returned them.
    /// </summary>
    public IReadOnlyList<GpoTarget> Policies => _policies;

    /// <summary>
    /// The policies nothing can be attempted against, already shaped as the coverage they will be
    /// reported as.
    /// </summary>
    /// <remarks>
    /// Named <c>Errors</c>-fashion rather than hidden, because this list and
    /// <see cref="Policies"/> are only meaningful together: a short <see cref="Policies"/> means
    /// nothing until it is read beside this one.
    /// </remarks>
    public IReadOnlyList<GpoCoverage> UnlocatablePolicies => _unlocatable;

    /// <summary>
    /// Whether <see cref="Policies"/> is the whole of what the directory declared.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What vouches for the target list under gate 4, and it is not ceremony. A caller handed a
    /// list of four hundred policies cannot otherwise tell it from a list of four hundred that was
    /// really four hundred and three, and the three that fell out are the ones nothing will ever
    /// report on.
    /// </para>
    /// <para>
    /// False means the directory returned a policy without saying where its files are. The policies
    /// concerned are in <see cref="UnlocatablePolicies"/>, already shaped as the coverage they will
    /// be reported as, so they stay in the denominator rather than vanishing from it.
    /// </para>
    /// </remarks>
    public bool DeclaredPoliciesAreComplete => _unlocatable.Count == 0;

    /// <summary>
    /// Takes a policy out of a captured object, if that is what it is.
    /// </summary>
    /// <param name="capturedObject">An object the capture just read.</param>
    /// <param name="objectGuid">
    /// The object's <c>objectGUID</c>, or null where the directory did not return one.
    /// </param>
    public void Observe(CapturedObject capturedObject, Guid? objectGuid)
    {
        ArgumentNullException.ThrowIfNull(capturedObject);

        if (!IsAGroupPolicyObject(capturedObject))
        {
            return;
        }

        var displayName = SingleValueOf(capturedObject, DisplayNameAttribute)
            ?? capturedObject.DistinguishedName;

        if (objectGuid is not { } guid || guid == Guid.Empty)
        {
            // Without an identifier the policy cannot be named in the coverage record or joined to
            // anything else in the bundle, so there is nothing this inventory can honestly do with
            // it. It is left to the directory half of the evidence, which recorded the object
            // itself and its missing attribute.
            return;
        }

        var fileSysPath = SingleValueOf(capturedObject, FileSysPathAttribute);

        if (string.IsNullOrWhiteSpace(fileSysPath))
        {
            _unlocatable.Add(GpoCoverage.Unlocatable(
                guid,
                displayName,
                "The directory returned this policy without a gPCFileSysPath, so where its files "
                + "live is unknown and none of them could be read. What this policy configures is "
                + "not in this audit."));
            return;
        }

        _policies.Add(GpoTarget.Of(guid, displayName, fileSysPath));
    }

    private static bool IsAGroupPolicyObject(CapturedObject capturedObject) =>
        capturedObject.Attributes
            .Where(a => string.Equals(
                a.LdapDisplayName, ObjectClassAttribute, StringComparison.OrdinalIgnoreCase))
            .SelectMany(a => a.Values)
            .OfType<string>()
            .Any(v => string.Equals(
                v, GroupPolicyContainerClass, StringComparison.OrdinalIgnoreCase));

    private static string? SingleValueOf(CapturedObject capturedObject, string ldapDisplayName) =>
        capturedObject.Attributes
            .Where(a => string.Equals(
                a.LdapDisplayName, ldapDisplayName, StringComparison.OrdinalIgnoreCase))
            .SelectMany(a => a.Values)
            .OfType<string>()
            .FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
}
