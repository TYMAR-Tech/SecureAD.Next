namespace SecureAD.Evidence;

/// <summary>
/// The files a bundle is made of, and what each is called.
/// </summary>
/// <remarks>
/// <para>
/// A bundle is one directory. The evidence itself is a single SQLite database, but only once the
/// run has finished with it: write-ahead logging keeps recent changes in a <c>-wal</c> file
/// beside the database until a checkpoint folds them back, so during a run the evidence is spread
/// across more than one file and cannot be treated as one.
/// </para>
/// <para>
/// <b>The name is the mechanism.</b> A run writes <see cref="PartialFileName"/>. Renaming it to
/// <see cref="EvidenceFileName"/> is the last act, after the checkpoint and after the seal is
/// written. A reader opens <see cref="EvidenceFileName"/>, so a run that was interrupted has no
/// file by that name to offer it - which is what stops a half-written bundle being read as a
/// whole one, without depending on anyone remembering to check.
/// </para>
/// <para>
/// <b>Which files are present says what became of the run.</b> A finished bundle holds the
/// evidence, its seal and the annotations. A run that ended badly holds the partial file and
/// <see cref="OutcomeFileName"/> saying which ending it was. A run still capturing holds the
/// partial file alone - and is told apart from one that was interrupted by asking the file system
/// whether anything still holds that file open, which is
/// <c>docs/decisions/0029-a-run-that-ends-badly-says-so.md</c> and is performed by
/// <see cref="Run.RunStateReader"/>. This paragraph previously argued the opposite, that a running
/// run and an interrupted one cannot be distinguished; <c>0029</c> decided two days later that
/// they can, and the argument was left standing.
/// </para>
/// <para>
/// Where a bundle lives is not decided here. It is an argument the operator supplies, because a
/// tool that chooses for itself where several gigabytes of evidence go is a tool that fills the
/// wrong disk.
/// </para>
/// </remarks>
public static class BundleLayout
{
    /// <summary>The evidence database of a finished bundle.</summary>
    public const string EvidenceFileName = "evidence.db";

    /// <summary>
    /// The evidence database of a run that has not finished. Deliberately not a name any reader
    /// asks for.
    /// </summary>
    public const string PartialFileName = "evidence.db.partial";

    /// <summary>The seal covering <see cref="EvidenceFileName"/>.</summary>
    public const string SealFileName = "evidence.db.seal";

    /// <summary>
    /// The customer's annotations - acceptances, notes, declared scope.
    /// </summary>
    /// <remarks>
    /// A separate file, and that is the whole point of it. An acceptance written into the evidence
    /// would invalidate the seal that proves the evidence is unmodified, so a customer could not
    /// annotate a bundle without destroying its own proof. Keeping annotations outside means
    /// nothing a user does can touch the sealed file, which is what makes
    /// <c>docs/decisions/0015</c> and <c>docs/decisions/0052</c> enforceable rather than promised.
    /// It is created when the bundle is sealed, so that opening a bundle never writes to it.
    /// </remarks>
    public const string AnnotationsFileName = "annotations.db";

    /// <summary>
    /// The note a run leaves when it ends badly, saying which ending it was.
    /// </summary>
    /// <remarks>
    /// Only a bad ending writes one, per <c>docs/decisions/0029-a-run-that-ends-badly-says-so.md</c>:
    /// a finished bundle's evidence and intact seal already say it succeeded, and a second artefact
    /// saying so would be a second answer to one question. It sits outside the seal and has to - a
    /// failed run has no <see cref="EvidenceFileName"/> for a seal to cover - so it is not evidence
    /// and nothing may present it as proof of anything. Its contents are
    /// <see cref="Run.RunOutcomeFile"/>'s; only the name is here, because a bundle's file names have
    /// one owner.
    /// </remarks>
    public const string OutcomeFileName = "run-outcome.json";

    /// <summary>
    /// What preflight proved about each domain before any capture traffic was sent.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Written before the capture starts, per
    /// <c>docs/decisions/0048-preflight-proves-a-controller-before-a-run-commits.md</c>, which is
    /// also where what it contains is decided. It is a file rather than a row in the evidence
    /// because it exists before the evidence database does, and it survives a run that dies before
    /// sealing - which is the unattended case, and the case where an operator has nothing else to
    /// read in the morning.
    /// </para>
    /// <para>
    /// Like <see cref="OutcomeFileName"/> it sits outside the seal and is not evidence. Nothing
    /// that reads it may present it as proof of anything.
    /// </para>
    /// </remarks>
    public const string PreflightFileName = "preflight.json";

    /// <summary>The evidence database of a finished bundle in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string EvidencePath(string bundleDirectory) =>
        Combine(bundleDirectory, EvidenceFileName);

    /// <summary>The evidence database of a run in progress in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string PartialPath(string bundleDirectory) =>
        Combine(bundleDirectory, PartialFileName);

    /// <summary>The seal file in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string SealPath(string bundleDirectory) =>
        Combine(bundleDirectory, SealFileName);

    /// <summary>The annotations database in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string AnnotationsPath(string bundleDirectory) =>
        Combine(bundleDirectory, AnnotationsFileName);

    /// <summary>The run-outcome file in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string OutcomePath(string bundleDirectory) =>
        Combine(bundleDirectory, OutcomeFileName);

    /// <summary>The preflight file in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string PreflightPath(string bundleDirectory) =>
        Combine(bundleDirectory, PreflightFileName);

    private static string Combine(string bundleDirectory, string fileName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        return Path.Combine(bundleDirectory, fileName);
    }
}
