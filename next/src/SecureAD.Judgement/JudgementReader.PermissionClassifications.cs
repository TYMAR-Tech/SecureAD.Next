namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    /// <summary>Reads one object's saved per-right interpretations without invoking permission analysis.</summary>
    /// <param name="distinguishedName">The object to read.</param>
    /// <param name="carriedDescriptor">
    /// Which stored descriptor the <b>evidence</b> says this object carries, or <c>null</c> when it
    /// kept none. <see cref="Evidence.ObjectPermissions.DescriptorId"/> is where it comes from.
    /// </param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <remarks>
    /// <b>The descriptor is a parameter and not something this reader looks up</b> (<c>P-280</c>).
    /// The saved interpretations are stored once per descriptor, so an object reaches its own
    /// permissions through a descriptor identity — and this reader holds only the judgement
    /// connection, by design, so it cannot reach the evidence that is entitled to state which
    /// descriptor that is. Were the judgement allowed to answer it, a store saying <i>X uses D2</i>
    /// where the evidence says <i>X uses D1</i> would validate every fingerprint it holds and
    /// attribute D2's permissions to X. The caller brings the answer across; this refuses any
    /// disagreement.
    /// </remarks>
    public SavedPermissionClassification ReadPermissionClassification(string distinguishedName,
        long? carriedDescriptor, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Description.State is not (JudgementRunState.Completed or JudgementRunState.CompletedDegraded))
            throw new InvalidOperationException(PermissionClassificationStorage.Message("Unavailable"));
        return PermissionClassificationStorage.Read(_connection, Description, distinguishedName, carriedDescriptor, cancellationToken);
    }
}
