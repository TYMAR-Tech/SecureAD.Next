namespace SecureAD.Kernel.Capture;

/// <summary>Optional evidence reads selected for one capture and never remembered for another.</summary>
public sealed record CaptureOptions(bool ScanGppPasswords)
{
    /// <summary>The ordinary capture: optional, high-cost reads are disabled.</summary>
    public static CaptureOptions Default { get; } = new(ScanGppPasswords: false);
}
