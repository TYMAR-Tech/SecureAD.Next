using System.Globalization;

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
    /// A derivation writes here and is renamed only once every phase has finished.
    /// A partial closure presented as a complete one
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

    /// <summary>
    /// The one file of a run that may leave the environment the run happened in.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>It exists because <see cref="RunLogFileName"/> cannot travel.</b> The log records the
    /// forest, the controller each partition was read from, naming contexts as distinguished names,
    /// and the directory's own words when something failed - all of which a customer is right to
    /// keep inside their environment. Without a second file, bringing anything back at all means
    /// bringing back all of that, so nothing comes back and a defect cannot be diagnosed.
    /// </para>
    /// <para>
    /// <b>It is assembled, never filtered.</b> Nothing here is derived by stripping the log: a
    /// denylist over free text eventually misses a distinguished name quoted inside an error
    /// message, and a file that claims to be safe and is not would be worse than no file. It is
    /// built from typed values - counts, durations, product codes, and domain names through
    /// <c>PortableNames.DomainNameOf</c> - so there is no call a name could be passed to.
    /// </para>
    /// <para>
    /// <b>Short, and plain text, because a person has to check it.</b> The operator carrying it out
    /// is the one answering for it, so he has to be able to read the whole thing and see for
    /// himself what is in it. Owner-requested 2026-09-22; see <c>P-263</c>.
    /// </para>
    /// </remarks>
    public const string PortableSummaryFileName = "run-summary.txt";

    /// <summary>
    /// The database one parallel reader writes before its rows are folded into the bundle.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A shard is scaffolding, not evidence.</b> Under
    /// <c>docs/decisions/0041-capture-reads-domains-in-parallel.md</c> each domain is read into its
    /// own database and merged afterwards, because SQLite takes one writer at a time and nine
    /// readers sharing one file would spend the parallelism waiting for the lock. A shard holds
    /// real captured rows, but it is never sealed, never named <see cref="EvidenceFileName"/> and
    /// never opened by a reader - it exists between the read and the merge and then stops existing.
    /// </para>
    /// <para>
    /// <b>It carries the suffix a reader refuses, and that is deliberate.</b> The name ends in
    /// <c>.partial</c> for the same reason <see cref="PartialFileName"/> does: nothing asks for it,
    /// so a run interrupted mid-merge leaves files that cannot be mistaken for a bundle. The shard
    /// index is in the middle rather than the extension so that a directory listing sorts them
    /// together and an operator can see at a glance how many readers a run had.
    /// </para>
    /// <para>
    /// <b>In the bundle directory, by the owner's decision of 2026-09-13.</b> A shard could live in
    /// the system temporary directory, and that would keep the bundle directory clean. It lives
    /// here instead so that the peak-disk figure <c>RunResourceWatch</c> records is the truth: a run
    /// needing forty gigabytes of scratch beside its evidence must report forty gigabytes, not hide
    /// it on whichever volume <c>TEMP</c> happens to name. An operator sizing a disk for a capture
    /// is asking about this number.
    /// </para>
    /// </remarks>
    public const string ShardFileNameFormat = "evidence.shard-{0}.db.partial";

    /// <summary>The evidence database of a finished bundle in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string EvidencePath(string bundleDirectory) =>
        Combine(bundleDirectory, EvidenceFileName);

    /// <summary>The run's log in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string RunLogPath(string bundleDirectory) =>
        Combine(bundleDirectory, RunLogFileName);

    /// <summary>The run's portable summary in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string PortableSummaryPath(string bundleDirectory) =>
        Combine(bundleDirectory, PortableSummaryFileName);

    /// <summary>The evidence database of a run in progress in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string PartialPath(string bundleDirectory) =>
        Combine(bundleDirectory, PartialFileName);

    /// <summary>The seal file in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string SealPath(string bundleDirectory) =>
        Combine(bundleDirectory, SealFileName);

    /// <summary>The one publication boundary for captured Evidence, navigation and Dashboard overview.</summary>
    public static string CaptureManifestPath(string bundleDirectory) => Combine(bundleDirectory, "evidence.current.json");

    /// <summary>The private navigation staging file, never opened for browsing.</summary>
    public static string NavigationPartialPath(string bundleDirectory) => Combine(bundleDirectory, "navigation.db.partial");

    /// <summary>The immutable navigation product for one captured generation.</summary>
    public static string NavigationPath(string bundleDirectory, Guid generationId) =>
        Combine(bundleDirectory, $"navigation.{generationId:N}.db");

    /// <summary>The private Dashboard overview staging file, never opened for browsing.</summary>
    public static string OverviewPartialPath(string bundleDirectory) => Combine(bundleDirectory, "overview.db.partial");

    /// <summary>The independently sealed Dashboard overview for one captured generation.</summary>
    public static string OverviewPath(string bundleDirectory, Guid generationId) =>
        Combine(bundleDirectory, $"overview.{generationId:N}.db");

    /// <summary>The independently sealed proof and inventory products belonging to one judgement.</summary>
    internal static IReadOnlyList<StoreSegmentRole> JudgementParts { get; } = Array.AsReadOnly(
        new[] { StoreSegmentRole.PermissionProof, StoreSegmentRole.PathProof, StoreSegmentRole.JudgementFacts });

    /// <summary>The exact immutable file declared for an analysis product.</summary>
    public static string AnalysisSegmentDataPath(string bundleDirectory, AnalysisStoreGeneration generation, StoreSegmentRole role)
    {
        ArgumentNullException.ThrowIfNull(generation);
        if (role == StoreSegmentRole.Derivation && generation.Kind == AnalysisStoreKind.Derivation
            || role == StoreSegmentRole.Judgement && generation.Kind == AnalysisStoreKind.Judgement)
            return AnalysisGenerationDataPath(bundleDirectory, generation.Kind, generation.GenerationId);
        if (generation.Kind != AnalysisStoreKind.Judgement) throw new ArgumentException("The product is not part of this analysis.");
        return Combine(bundleDirectory, $"judgement.{generation.GenerationId:N}.{PartName(role)}.db");
    }

    private static string PartName(StoreSegmentRole role) => role switch
    {
        StoreSegmentRole.PermissionProof => "permission-proof",
        StoreSegmentRole.PathProof => "path-proof",
        StoreSegmentRole.JudgementFacts => "facts",
        _ => throw new ArgumentOutOfRangeException(nameof(role), role, "Unknown judgement part."),
    };

    /// <summary>The annotations database in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string AnnotationsPath(string bundleDirectory) =>
        Combine(bundleDirectory, AnnotationsFileName);

    /// <summary>The judgement of a finished bundle in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string JudgementPath(string bundleDirectory) =>
        Combine(bundleDirectory, JudgementFileName);

    internal static string JudgementWriteLockPath(string bundleDirectory) =>
        Combine(bundleDirectory, "judgement.write.lock");

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

    /// <summary>The private Derivation staging database; Judgement writes directly to unselected generation paths.</summary>
    public static string AnalysisStagingPath(string bundleDirectory, AnalysisStoreKind kind)
    {
        if (kind != AnalysisStoreKind.Derivation)
            throw new ArgumentOutOfRangeException(nameof(kind), kind, "Judgement uses unique generation paths, not a shared staging file.");
        return DerivationPartialPath(bundleDirectory);
    }

    /// <summary>The manifest selecting the current generation of a disposable analysis store.</summary>
    public static string AnalysisManifestPath(string bundleDirectory, AnalysisStoreKind kind) =>
        Combine(bundleDirectory, AnalysisPrefix(kind) + ".current.json");

    /// <summary>The immutable database for one disposable analysis generation.</summary>
    public static string AnalysisGenerationDataPath(
        string bundleDirectory,
        AnalysisStoreKind kind,
        Guid generationId) =>
        Combine(bundleDirectory, $"{AnalysisPrefix(kind)}.{generationId:N}.db");

    /// <summary>The seal for one disposable analysis generation.</summary>
    public static string AnalysisGenerationSealPath(
        string bundleDirectory,
        AnalysisStoreKind kind,
        Guid generationId) =>
        Combine(bundleDirectory, $"{AnalysisPrefix(kind)}.{generationId:N}.db.seal");

    /// <summary>The run-outcome file in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string OutcomePath(string bundleDirectory) =>
        Combine(bundleDirectory, OutcomeFileName);

    /// <summary>The preflight file in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static string PreflightPath(string bundleDirectory) =>
        Combine(bundleDirectory, PreflightFileName);

    /// <summary>
    /// The scratch database one parallel reader writes, in <paramref name="bundleDirectory"/>.
    /// </summary>
    /// <remarks>
    /// <see cref="BundleShard.Whole"/> has no shard file: an unsharded run writes
    /// <see cref="PartialFileName"/> directly, exactly as the product always has. Asking this for
    /// the whole bundle is a caller that has confused the two, so it is refused rather than
    /// answered with a file name that would quietly become a second database beside the evidence.
    /// </remarks>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    /// <param name="shard">Which parallel reader's database is wanted.</param>
    public static string ShardPath(string bundleDirectory, BundleShard shard)
    {
        if (shard.Index == BundleShard.Whole.Index)
        {
            throw new ArgumentOutOfRangeException(
                nameof(shard),
                $"The whole bundle has no shard file - it is written to '{PartialFileName}' "
                + "directly. Asking for a shard path for BundleShard.Whole means a caller has "
                + "confused a sharded run with an unsharded one, and answering would create a "
                + "second database beside the evidence.");
        }

        return Combine(
            bundleDirectory,
            string.Format(CultureInfo.InvariantCulture, ShardFileNameFormat, shard.Index));
    }

    private static string Combine(string bundleDirectory, string fileName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        return Path.Combine(bundleDirectory, fileName);
    }

    private static string AnalysisPrefix(AnalysisStoreKind kind) => kind switch
    {
        AnalysisStoreKind.Derivation => "derivation",
        AnalysisStoreKind.Judgement => "judgement",
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown analysis store kind."),
    };
}
