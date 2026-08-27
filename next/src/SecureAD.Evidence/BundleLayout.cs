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
/// evidence, its seal and the annotations, and a judged one also holds the judgement and its own
/// seal. A run that ended badly holds the partial file and
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
    /// What the rules concluded about this bundle.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Beside the evidence and never inside it.</b> The evidence is sealed at the end of
    /// capture, before any rule has run, and that seal is what lets the product say <i>this is what
    /// the directory said</i> about a bundle judged many times. A finding written into the sealed
    /// file would either invalidate that seal or force it to be reissued, and a reissued seal means
    /// only <i>unchanged since we last wrote to it</i>.
    /// </para>
    /// <para>
    /// <b>One per bundle, and rebuildable.</b> Re-judging replaces this file rather than adding
    /// another beside it, so there is one current answer about one capture and no question of which
    /// of several is meant. Nothing is lost by deleting it: the evidence is untouched and the
    /// bundle can be judged again.
    /// </para>
    /// <para>
    /// <b>It records the evidence it judged, and a reader refuses a mismatch.</b> This file can be
    /// copied, and two captures of one forest produce bundles of the same shape with the same file
    /// names - so a judgement moved into the wrong bundle would resolve most of its objects and be
    /// quietly wrong about all of them. The seal over <see cref="EvidenceFileName"/> is a permanent
    /// fingerprint of exactly one capture, so a judgement naming it can be checked rather than
    /// trusted. Copying one between bundles is possible and is not supported; the check is what
    /// makes the attempt safe rather than silent.
    /// </para>
    /// </remarks>
    public const string JudgementFileName = "judgement.db";

    /// <summary>
    /// The judgement of a run that has not finished. Deliberately not a name any reader asks for.
    /// </summary>
    /// <remarks>
    /// The same mechanism <see cref="PartialFileName"/> uses, for the same reason: a judgement is
    /// written under this name and renamed only after every scheduled rule has finished and the
    /// seal is written, so an interrupted judgement has no file by the name a reader asks for. A
    /// half-judged bundle showing some of its findings would be the more dangerous half of
    /// <c>docs/decisions/0002</c> - fewer findings than the truth, presented as the truth.
    /// </remarks>
    public const string JudgementPartialFileName = "judgement.db.partial";

    /// <summary>The seal covering <see cref="JudgementFileName"/>.</summary>
    /// <remarks>
    /// Separate from <see cref="SealFileName"/> because the two cover different artefacts made at
    /// different times, and they can disagree: evidence may verify under a judgement that does not.
    /// Anything presenting both to an operator has to say which is which.
    /// </remarks>
    public const string JudgementSealFileName = "judgement.db.seal";

    /// <summary>
    /// The derived facts of a finished derivation in a bundle directory.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A third file rather than more tables in <see cref="JudgementFileName"/>, because the two
    /// have different lifetimes.</b> A judgement is rebuilt from scratch every time a bundle is
    /// judged. Derived facts are expensive - group expansion over a forest is the costliest thing
    /// the product does - and nothing about them changes when the rules do. Keeping them apart is
    /// what lets a bundle be re-judged without deriving it again.
    /// </para>
    /// <para>
    /// It sits outside the seal for the same reason a judgement does: it is what the product
    /// worked out, not what the directory said. It is disposable and can be deleted and rebuilt
    /// from the evidence at any time.
    /// </para>
    /// </remarks>
    public const string DerivationFileName = "derivation.db";

    /// <summary>The derived facts of a derivation in progress in a bundle directory.</summary>
    /// <remarks>
    /// A derivation writes here and is renamed only once every phase has finished, exactly as
    /// <see cref="JudgementPartialFileName"/> is. A partial closure presented as a complete one
    /// is the same failure as a partial judgement presented as a complete one, and worse: a rule
    /// resting on it would report a clean result it never established.
    /// </remarks>
    public const string DerivationPartialFileName = "derivation.db.partial";

    /// <summary>The seal covering <see cref="DerivationFileName"/>.</summary>
    /// <remarks>
    /// A third seal, separate from <see cref="SealFileName"/> and
    /// <see cref="JudgementSealFileName"/>, covering a third artefact made at a third time. All
    /// three can disagree, and anything presenting them to an operator has to say which is which.
    /// </remarks>
    public const string DerivationSealFileName = "derivation.db.seal";

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

    /// <summary>
    /// What the run said it was doing while it did it, and what went wrong.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One log for the whole run, appended to by the capture, then the derivation, then the judging,
    /// so a bundle reads top to bottom in the order things happened. Per
    /// <c>docs/decisions/0088-a-run-writes-a-log.md</c>, which exists because a defect in the derive
    /// stage reached an operator as a bare SQLite message with no run, no phase and no subject.
    /// </para>
    /// <para>
    /// Like <see cref="OutcomeFileName"/> and <see cref="PreflightFileName"/> it sits outside the
    /// seal, and cannot do otherwise: it is written <i>during</i> the run whose evidence is sealed
    /// at the end. It is diagnostic and not evidence, and nothing may present it as proof of
    /// anything - a rule reads the evidence, never this.
    /// </para>
    /// <para>
    /// It is kept when a run dies before sealing, which is the unattended case and the one where it
    /// is worth most.
    /// </para>
    /// </remarks>
    public const string RunLogFileName = "run.log";

    /// <summary>The evidence database of a finished bundle in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string EvidencePath(string bundleDirectory) =>
        Combine(bundleDirectory, EvidenceFileName);

    /// <summary>The run's log in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string RunLogPath(string bundleDirectory) =>
        Combine(bundleDirectory, RunLogFileName);

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

    /// <summary>The judgement of a finished bundle in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string JudgementPath(string bundleDirectory) =>
        Combine(bundleDirectory, JudgementFileName);

    /// <summary>The judgement of a run in progress in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string JudgementPartialPath(string bundleDirectory) =>
        Combine(bundleDirectory, JudgementPartialFileName);

    /// <summary>The judgement seal in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string JudgementSealPath(string bundleDirectory) =>
        Combine(bundleDirectory, JudgementSealFileName);

    /// <summary>The derived facts of a finished derivation in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string DerivationPath(string bundleDirectory) =>
        Combine(bundleDirectory, DerivationFileName);

    /// <summary>The derived facts of a derivation in progress in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string DerivationPartialPath(string bundleDirectory) =>
        Combine(bundleDirectory, DerivationPartialFileName);

    /// <summary>The derivation seal in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string DerivationSealPath(string bundleDirectory) =>
        Combine(bundleDirectory, DerivationSealFileName);

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
