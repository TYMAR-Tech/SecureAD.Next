using SecureAD.Evidence.Run;
using SecureAD.Kernel;

namespace SecureAD.Shell.Services;

/// <summary>
/// The runs in a library, as the shell asks for them.
/// </summary>
/// <remarks>
/// <para>
/// A seam over <see cref="RunLibrary"/>, and the reason it exists is testability rather than
/// ceremony: a view model given this can be shown an empty library, a damaged run, or an
/// unreachable root without a disk being arranged to produce one.
/// </para>
/// <para>
/// <b>The root is a parameter rather than a constructor argument</b>, because the operator can
/// change where their runs live while the product is open, and a catalogue bound to a root at
/// startup would keep answering about the old one.
/// </para>
/// </remarks>
internal interface IRunCatalog
{
    /// <summary>Lists the runs held in <paramref name="libraryRoot"/>.</summary>
    /// <param name="libraryRoot">The directory the operator chose.</param>
    Result<IReadOnlyList<RunListing>> List(string libraryRoot);

    /// <summary>
    /// Records what the operator has called the run at <paramref name="bundleDirectory"/>.
    /// </summary>
    /// <param name="bundleDirectory">The run's bundle directory, as listed.</param>
    /// <param name="annotation">The name and notes to record.</param>
    Result<RunAnnotation> Annotate(string bundleDirectory, RunAnnotation annotation);
}
