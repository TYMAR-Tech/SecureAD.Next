namespace SecureAD.Kernel.Capture;

/// <summary>The operation currently running, not a percentage or publication verdict.</summary>
public enum CaptureWorkPhase
{
    /// <summary>Reading the selected directory partitions.</summary>
    DirectoryRead,
    /// <summary>Combining completed domain reads.</summary>
    Merging,
    /// <summary>Reading the captured policy inventory's files.</summary>
    PolicyFiles,
    /// <summary>Preparing and checking the immutable evidence.</summary>
    Sealing,
}

/// <summary>The last reported state of a directory read, independently of the bundle's seal.</summary>
public enum CaptureReadState
{
    /// <summary>No read has started.</summary>
    Waiting,
    /// <summary>The current read attempt is running.</summary>
    Reading,
    /// <summary>The directory read finished, not necessarily the bundle.</summary>
    ReadComplete,
    /// <summary>The last attempt failed; recovery may still follow.</summary>
    AttemptFailed,
    /// <summary>The read was stopped without confirmed completion.</summary>
    Stopped,
}

/// <summary>A selected resource and the count retained by its current read attempt.</summary>
/// <param name="NamingContext">The exact partition identity, never a guessed domain suffix.</param>
/// <param name="DisplayName">The domain name or forest-partition kind.</param>
/// <param name="IsDomain">Whether this is a domain rather than shared forest data.</param>
/// <param name="ObjectsRead">Null until a count was reported; zero is an observed zero.</param>
/// <param name="State">Directory-read state, not a claim that evidence is sealed.</param>
public sealed record CaptureScopeProgress(
    string NamingContext, string DisplayName, bool IsDomain, long? ObjectsRead, CaptureReadState State);

/// <summary>An immutable, ordered snapshot of observed capture work; never persisted as evidence.</summary>
/// <param name="Sequence">The ordering within this capture invocation.</param>
/// <param name="Phase">The operation being performed.</param>
/// <param name="Scopes">All selected scopes, including those without a reported count.</param>
/// <param name="PoliciesProcessed">Policy outcomes recorded so far, not policies successfully read.</param>
public sealed record CaptureProgress(
    long Sequence, CaptureWorkPhase Phase, IReadOnlyList<CaptureScopeProgress> Scopes, long? PoliciesProcessed)
{
    /// <summary>The declared policy inventory, not a time or success estimate.</summary>
    public long? PoliciesTotal { get; init; }
}
