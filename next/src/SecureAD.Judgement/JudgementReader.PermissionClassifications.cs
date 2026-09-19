namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    /// <summary>Reads one object's saved per-right interpretations without invoking permission analysis.</summary>
    public SavedPermissionClassification ReadPermissionClassification(string distinguishedName,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Description.State is not (JudgementRunState.Completed or JudgementRunState.CompletedDegraded))
            throw new InvalidOperationException(PermissionClassificationStorage.Message("Unavailable"));
        return PermissionClassificationStorage.Read(_connection, Description, distinguishedName, cancellationToken);
    }
}
