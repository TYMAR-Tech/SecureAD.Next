namespace SecureAD.Evidence.Run;

/// <summary>
/// What happened when the run tried to read one Group Policy object's files.
/// </summary>
/// <remarks>
/// <b>Three members, where <see cref="ForestPartitionReadOutcome"/> has two.</b> The middle one is
/// the point of this whole record. A partition is one capture unit and is read or is not; a policy
/// is a folder tree, and a run that read its settings but was refused the permissions on its
/// scripts folder has done neither. Collapsing that into <c>Read</c> would tell a customer his
/// policy was examined when a third of it was not.
/// </remarks>
public enum GpoReadOutcome
{
    /// <summary>Everything this product reads from the policy's folder was read.</summary>
    Read,

    /// <summary>Some of the policy's files or folders were read and some were not.</summary>
    PartiallyRead,

    /// <summary>Nothing in the policy's folder could be read.</summary>
    Unreadable,
}

/// <summary>What became of the optional SEC-083 scan beneath one policy folder.</summary>
public enum GppPasswordScanOutcome
{
    /// <summary>The operator left the optional scan disabled.</summary>
    NotRequested,

    /// <summary>Every XML file beneath this policy was enumerated, read and parsed.</summary>
    Read,

    /// <summary>Known XML evidence was retained, but some files were unreadable or unparseable.</summary>
    PartiallyRead,

    /// <summary>The scan was requested but no complete inventory could be obtained.</summary>
    Unreadable,
}

/// <summary>
/// What became of one Group Policy object's files on the SYSVOL share.
/// </summary>
/// <remarks>
/// <para>
/// The policy is named as well as identified, and both are deliberate. The GUID is what the
/// evidence joins on; the display name is what an administrator recognises, and a report that
/// names three unreadable policies by GUID alone has told him that something is wrong without
/// telling him what to go and look at.
/// </para>
/// <para>
/// <b>The reason is never invented.</b> It is what the file system said - access denied, the path
/// is not there, the share did not answer. Per
/// <c>docs/decisions/0044-sysvol-coverage-is-recorded-beside-the-capture-units.md</c> a SYSVOL
/// failure does not end the run, so this text is the only account of it that will ever reach an
/// operator.
/// </para>
/// </remarks>
public sealed record GpoCoverage
{
    private GpoCoverage(
        Guid gpoGuid,
        string displayName,
        string? fileSysPath,
        GpoReadOutcome outcome,
        string? reason,
        GppPasswordScanOutcome gppPasswordScanOutcome = GppPasswordScanOutcome.NotRequested,
        string? gppPasswordScanReason = null)
    {
        GpoGuid = gpoGuid;
        DisplayName = displayName;
        FileSysPath = fileSysPath;
        Outcome = outcome;
        Reason = reason;
        GppPasswordScanOutcome = gppPasswordScanOutcome;
        GppPasswordScanReason = gppPasswordScanReason;
    }

    /// <summary>The policy's <c>objectGUID</c>, which is what its folder on the share is named.</summary>
    public Guid GpoGuid { get; }

    /// <summary>The policy's display name, as an administrator would recognise it.</summary>
    public string DisplayName { get; }

    /// <summary>
    /// The policy's folder on the share, from its <c>gPCFileSysPath</c>. Null only where the
    /// directory returned the policy without saying where its files are, which is a policy nothing
    /// could even attempt to read.
    /// </summary>
    public string? FileSysPath { get; }

    /// <summary>What happened when the run tried to read it.</summary>
    public GpoReadOutcome Outcome { get; }

    /// <summary>
    /// Why it was not read in full, in words an operator can act on. Null when
    /// <see cref="Outcome"/> is <see cref="GpoReadOutcome.Read"/>, and never null otherwise.
    /// </summary>
    public string? Reason { get; }

    /// <summary>Whether the optional SEC-083 XML scan ran for this policy.</summary>
    public GppPasswordScanOutcome GppPasswordScanOutcome { get; }

    /// <summary>Why the requested SEC-083 scan was incomplete; null when disabled or complete.</summary>
    public string? GppPasswordScanReason { get; }

    /// <summary>Returns this policy coverage with its independently measured SEC-083 scan result.</summary>
    public GpoCoverage WithGppPasswordScan(GppPasswordScanOutcome outcome, string? reason = null)
    {
        var complete = outcome is GppPasswordScanOutcome.NotRequested or GppPasswordScanOutcome.Read;
        if (complete != string.IsNullOrWhiteSpace(reason))
        {
            throw new ArgumentException(
                "A disabled or complete GPP password scan has no failure reason; an incomplete scan requires one.",
                nameof(reason));
        }

        return new GpoCoverage(
            GpoGuid, DisplayName, FileSysPath, Outcome, Reason, outcome,
            complete ? null : Require(reason!));
    }

    /// <summary>Records a policy whose files were all read.</summary>
    /// <param name="gpoGuid">The policy's <c>objectGUID</c>.</param>
    /// <param name="displayName">The policy's display name.</param>
    /// <param name="fileSysPath">The policy's folder on the share.</param>
    public static GpoCoverage Read(Guid gpoGuid, string displayName, string fileSysPath) =>
        new(RequireGuid(gpoGuid), Require(displayName), Require(fileSysPath), GpoReadOutcome.Read, reason: null);

    /// <summary>Records a policy some of whose files could not be read.</summary>
    /// <param name="gpoGuid">The policy's <c>objectGUID</c>.</param>
    /// <param name="displayName">The policy's display name.</param>
    /// <param name="fileSysPath">The policy's folder on the share.</param>
    /// <param name="reason">What the file system said about the part that was refused.</param>
    public static GpoCoverage PartiallyRead(
        Guid gpoGuid, string displayName, string fileSysPath, string reason) =>
        new(RequireGuid(gpoGuid), Require(displayName), Require(fileSysPath),
            GpoReadOutcome.PartiallyRead, Require(reason));

    /// <summary>Records a policy whose folder could not be read at all.</summary>
    /// <param name="gpoGuid">The policy's <c>objectGUID</c>.</param>
    /// <param name="displayName">The policy's display name.</param>
    /// <param name="fileSysPath">The policy's folder on the share.</param>
    /// <param name="reason">What the file system said.</param>
    public static GpoCoverage Unreadable(
        Guid gpoGuid, string displayName, string fileSysPath, string reason) =>
        new(RequireGuid(gpoGuid), Require(displayName), Require(fileSysPath),
            GpoReadOutcome.Unreadable, Require(reason));

    /// <summary>
    /// Records a policy the directory declared without saying where its files are.
    /// </summary>
    /// <remarks>
    /// Rare and real: a <c>groupPolicyContainer</c> whose <c>gPCFileSysPath</c> did not come back,
    /// either because the attribute is absent or because the reader was not allowed it. It is
    /// recorded rather than dropped from the denominator, because a policy quietly removed from the
    /// list of what should have been read is precisely the hole <c>docs/decisions/0044</c> requires
    /// to have edges.
    /// </remarks>
    /// <param name="gpoGuid">The policy's <c>objectGUID</c>.</param>
    /// <param name="displayName">The policy's display name.</param>
    /// <param name="reason">Why nothing could be attempted.</param>
    public static GpoCoverage Unlocatable(Guid gpoGuid, string displayName, string reason) =>
        new(RequireGuid(gpoGuid), Require(displayName), fileSysPath: null,
            GpoReadOutcome.Unreadable, Require(reason));

    private static Guid RequireGuid(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException(
                "A policy with no identifier cannot be named to an operator, which is the one thing "
                + "this record exists to do.",
                nameof(value));
        }

        return value;
    }

    private static string Require(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value.Trim();
    }
}
