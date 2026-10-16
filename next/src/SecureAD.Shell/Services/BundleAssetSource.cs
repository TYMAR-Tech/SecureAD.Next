using System.IO;
using SecureAD.Evidence;
using SecureAD.Evidence.Inventory;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Schema;
using SecureAD.Shell.ViewModels;

namespace SecureAD.Shell.Services;

/// <summary>
/// The asset source, over real bundles on a real disk.
/// </summary>
/// <remarks>Evidence and findings share the selected run's protected files, not a shared query connection.</remarks>
internal sealed partial class BundleAssetSource : IAssetSource, IDisposable
{
    private readonly RunProtectionSessions? _protection;
    /// <summary>Creates the owner of a selected run's protected reading lifetime.</summary>
    public BundleAssetSource() { }
    internal BundleAssetSource(RunProtectionSessions protection) => _protection =
        protection ?? throw new ArgumentNullException(nameof(protection));

    private OpenedRunResults OpenResults(string path) => new(path, _protection?.TakeForViewing(path));

    /// <inheritdoc/>
    public Task<T> ReadAsync<T>(string bundleDirectory, Func<IAssetReader, CancellationToken, T> read,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(read);
        cancellationToken.ThrowIfCancellationRequested();
        var path = Path.GetFullPath(bundleDirectory);
        OpenedRunResults session;
        lock (_sessionGate)
        {
            if (_closed) throw new InvalidOperationException(SavedPathText.Get("GenerationChanged"));
            _results ??= OpenResults(path);
            session = _results;
            if (!string.Equals(session.Directory, path, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(SavedPathText.Get("GenerationChanged"));
        }
        // Capture the actual protected lifetime before queuing, not a path that a later selection can reuse.
        var request = new AssetReadRequest(session, () => Holds(session), cancellationToken);
        return Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Holds(session)) throw new InvalidOperationException(SavedPathText.Get("GenerationChanged"));
            var value = read(request, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            if (!Holds(session)) throw new InvalidOperationException(SavedPathText.Get("GenerationChanged"));
            return value;
        }, cancellationToken);
    }

    /// <inheritdoc/>
    public Func<bool> CaptureReadValidity()
    {
        OpenedRunResults? session;
        lock (_sessionGate) session = _results;
        return () => session is not null && Holds(session) && session.IsCurrent;
    }

    private bool Holds(OpenedRunResults session)
    {
        lock (_sessionGate) return !_closed && ReferenceEquals(_results, session);
    }

    /// <inheritdoc/>
    public Result<ObjectSearchPage> SearchObjects(string bundleDirectory, string search, ObjectSearchMark? after) =>
        WithRun(bundleDirectory, reader => reader.SearchObjects(bundleDirectory, search, after));

    /// <inheritdoc/>
    public Result<DelegationPrincipalPage> FindDelegationPrincipals(string bundleDirectory, string search, DelegationPrincipalMark? after) =>
        WithRun(bundleDirectory, reader => reader.FindDelegationPrincipals(bundleDirectory, search, after));

    /// <inheritdoc/>
    public Result<DelegationPage> ReadDelegations(string bundleDirectory, DelegationQuery query, DelegationPageMark? after) =>
        WithRun(bundleDirectory, reader => reader.ReadDelegations(bundleDirectory, query, after));

    /// <inheritdoc/>
    public Result<SavedPermissionClassification> ReadPermissionClassification(string bundleDirectory, string distinguishedName) =>
        WithRun(bundleDirectory, reader => reader.ReadPermissionClassification(bundleDirectory, distinguishedName));

    /// <inheritdoc/>
    public Result<ControlEdgePage> ReadControlEdges(string bundleDirectory, string? target, string? holderSid,
        string? holderScope, bool includeExpected, long afterId) =>
        WithRun(bundleDirectory, reader => reader.ReadControlEdges(bundleDirectory, target, holderSid, holderScope, includeExpected, afterId));

    /// <inheritdoc/>
    public Result<SelfMembershipAssessmentSet> ReadSelfMembershipAssessments(string bundleDirectory, string? target, string? requester) =>
        WithRun(bundleDirectory, reader => reader.ReadSelfMembershipAssessments(bundleDirectory, target, requester));

    private readonly object _sessionGate = new();
    private OpenedRunResults? _results;
    private bool _closed;

    /// <inheritdoc/>
    public Result<MemberAttributionDetail> ReadMemberAttribution(string bundleDirectory, string holderSid, string? holderScope, string target) =>
        WithRun(bundleDirectory, reader => reader.ReadMemberAttribution(bundleDirectory, holderSid, holderScope, target));

    /// <inheritdoc/>
    public Result<MemberPermissionPage> ReadPermissionsThroughMembership(string bundleDirectory, string memberSid, string? memberScope, bool includeExpected, long afterId) =>
        WithRun(bundleDirectory, reader => reader.ReadPermissionsThroughMembership(bundleDirectory, memberSid, memberScope, includeExpected, afterId));
    /// <inheritdoc/>
    public Result<DirectoryTree> ReadTree(string bundleDirectory)
    {
        return WithRun(bundleDirectory, reader => reader.ReadTree(bundleDirectory));
    }

    public Result<GroupInventoryPage> ReadGroups(string bundleDirectory, GroupInventoryQuery query, GroupInventoryMark? after) =>
        WithRun(bundleDirectory, reader => reader.ReadGroups(bundleDirectory, query, after));

    public Result<CapturedMemberReferences> ResolveMembershipReferences(string bundleDirectory, IReadOnlyList<string> names) =>
        WithRun(bundleDirectory, reader => reader.ResolveMembershipReferences(bundleDirectory, names));

    public Result<ObjectPage> ListObjects(string bundleDirectory, string containerDn, ListingScope scope, ObjectPageMark? after) =>
        WithRun(bundleDirectory, reader => reader.ListObjects(bundleDirectory, containerDn, scope, after));

    public Result<CapturedObjectIdentity?> ReadObjectIdentity(string bundleDirectory, string distinguishedName) =>
        WithRun(bundleDirectory, reader => reader.ReadObjectIdentity(bundleDirectory, distinguishedName));

    public Result<CapturedMembershipPage?> ReadCapturedMembership(string bundleDirectory, string distinguishedName,
        bool parents, CapturedMembershipMark? after) =>
        WithRun(bundleDirectory, reader => reader.ReadCapturedMembership(bundleDirectory, distinguishedName, parents, after));

    public Result<ObjectAttributes?> ReadObjectAttributes(string bundleDirectory, string distinguishedName,
        IReadOnlyCollection<string> attributes) =>
        WithRun(bundleDirectory, reader => reader.ReadObjectAttributes(bundleDirectory, distinguishedName, attributes));

    /// <inheritdoc/>
    public Result<LapsPage> ListLapsComputers(
        string bundleDirectory, LapsQuery query, LapsPageMark? after)
    {
        ArgumentNullException.ThrowIfNull(query);

        return WithRun(bundleDirectory, reader => reader.ListLapsComputers(bundleDirectory, query, after));
    }

    /// <inheritdoc/>
    public Result<ObjectPermissions?> ReadPermissions(
        string bundleDirectory, string distinguishedName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);

        return WithRun(bundleDirectory, reader => reader.ReadPermissions(bundleDirectory, distinguishedName));
    }

    /// <inheritdoc/>
    public Result<ObjectAttributes?> ReadObjectAttributes(
        string bundleDirectory, string distinguishedName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);

        return WithRun(bundleDirectory, reader => reader.ReadObjectAttributes(bundleDirectory, distinguishedName));
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Reads authoritative saved overview rows rather than recounting the captured object catalogue.
    /// Its verified file is shared for the selected lifetime, not its returned presentation values.
    /// </remarks>
    public Result<ForestInventory> ReadInventory(string bundleDirectory)
    {
        return WithRun(bundleDirectory, reader => reader.ReadInventory(bundleDirectory));
    }

    /// <inheritdoc/>
    public Result<int?> ReadGroupsWithUnidentifiedMembers(string bundleDirectory)
    {
        return WithRun(bundleDirectory, reader => reader.ReadGroupsWithUnidentifiedMembers(bundleDirectory));
    }

    /// <inheritdoc/>
    public Result<SchemaGuidCatalog> ReadSchemaGuids(string bundleDirectory)
    {
        return WithRun(bundleDirectory, reader => reader.ReadSchemaGuids(bundleDirectory));
    }

    /// <inheritdoc/>
    public Result<FindingListPage> ReadFindingsList(string bundleDirectory, FindingsQuery query) =>
        WithRun(bundleDirectory, reader => reader.ReadFindingsList(bundleDirectory, query));

    public Result<FindingsPage> ReadFindings(string bundleDirectory, FindingsQuery query)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(query);

        return WithRun(bundleDirectory, reader => reader.ReadFindings(bundleDirectory, query));
    }

    /// <inheritdoc/>
    public Result<StoredRuleExecutions> ReadRuleExecutions(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        return WithRun(bundleDirectory, reader => reader.ReadRuleExecutions(bundleDirectory));
    }

    /// <inheritdoc/>
    public Result<FindingsFilterValues> ReadFindingsFilterValues(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        return WithRun(bundleDirectory, reader => reader.ReadFindingsFilterValues(bundleDirectory));
    }

    /// <inheritdoc/>
    public void Dispose() => DetachRun()?.Dispose();

    internal async Task CloseRunAsync()
    {
        if (DetachRun() is { } previous) await previous.DisposeAsync().ConfigureAwait(false);
    }

    private OpenedRunResults? DetachRun()
    {
        OpenedRunResults? previous;
        lock (_sessionGate) { previous = _results; _results = null; _closed = true; }
        return previous;
    }

    /// <inheritdoc/>
    public void CloseRun() => Dispose();

    /// <inheritdoc/>
    public void SelectRun(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        var path = Path.GetFullPath(bundleDirectory);
        OpenedRunResults? previous;
        lock (_sessionGate)
        {
            if (_results is { } current && string.Equals(current.Directory, path, StringComparison.OrdinalIgnoreCase)
                && current.IsCurrent) return;
            previous = _results;
            _results = OpenResults(path);
            _closed = false;
        }
        previous?.Dispose();
    }

    private Result<T> WithRun<T>(string bundleDirectory, Func<IAssetReader, Result<T>> read)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        var path = Path.GetFullPath(bundleDirectory);
        OpenedRunResults? session;
        lock (_sessionGate)
        {
            if (!_closed) _results ??= OpenResults(path);
            session = _results;
        }
        return read(new AssetReadRequest(session, () => session is not null && Holds(session), CancellationToken.None));
    }
}
