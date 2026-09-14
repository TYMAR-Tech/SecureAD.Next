namespace SecureAD.Kernel.Capture;

/// <summary>
/// The two permitted object-class scopes for a new capture; DNS remains excluded in both.
/// </summary>
public sealed record CaptureObjectScope
{
    private static readonly IReadOnlyList<string> DnsExclusions = Array.AsReadOnly(
        CapturedAttributeCatalog.UnreadObjectClasses.ToArray());

    private static readonly IReadOnlyList<string> DefaultExclusions = Array.AsReadOnly<string>(
        [.. CapturedAttributeCatalog.UnreadObjectClasses, .. CapturedAttributeCatalog.EnatelSsoObjectClasses]);

    private CaptureObjectScope(bool includeEnatelSso) => IncludeEnatelSso = includeEnatelSso;

    /// <summary>Whether the three Enatel SSO classes are included in this run.</summary>
    public bool IncludeEnatelSso { get; }

    /// <summary>The classes deliberately not read by this capture.</summary>
    public IReadOnlyList<string> ExcludedClasses => IncludeEnatelSso ? DnsExclusions : DefaultExclusions;

    /// <summary>New runs exclude DNS and the three Enatel SSO metadata classes.</summary>
    public static CaptureObjectScope Default { get; } = new(false);

    /// <summary>The inclusion-only override restores Enatel objects while leaving DNS excluded.</summary>
    public static CaptureObjectScope WithEnatelSso { get; } = new(true);

    /// <summary>Resolves the run's explicit Enatel inclusion choice.</summary>
    /// <param name="includeEnatelSso">Whether to include Enatel SSO metadata objects.</param>
    public static CaptureObjectScope For(bool includeEnatelSso) =>
        includeEnatelSso ? WithEnatelSso : Default;
}
