using SecureAD.Evidence;
using SecureAD.Evidence.Inventory;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Schema;

namespace SecureAD.Shell.Services;

/// <summary>
/// What a run captured, as the shell asks for it.
/// </summary>
/// <remarks>
/// <para>
/// A seam over <see cref="BundleReader"/>, and it exists for testability rather than ceremony: a
/// view model given this can be shown a refused seal, a tree with gaps in it, or a listing that is
/// short, without a sealed bundle being arranged on a disk to produce one.
/// </para>
/// <para>
/// <b>One seam for the tree and the objects, not two.</b> Verifying a bundle's seal re-reads every
/// byte of the evidence and is deliberately never cached - a cache whose purpose is to skip an
/// integrity check is a way for that check to quietly never run. So a source that opened the
/// bundle for each question would re-hash a file of several gigabytes on every page an operator
/// turned. Holding the two questions together lets one implementation open the bundle once, when
/// the operator arrives at a run, and answer both from it.
/// </para>
/// </remarks>
internal interface IAssetSource : IAssetReader
{
    /// <summary>Executes one navigation request against the run selected before work is scheduled.</summary>
    Task<T> ReadAsync<T>(string bundleDirectory, Func<IAssetReader, CancellationToken, T> read,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var value = read(this, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(value);
    }

    /// <summary>Selects the run whose completed results subsequent requests may describe.</summary>
    void SelectRun(string bundleDirectory) { }

    /// <summary>Releases the selected run and cancels its outstanding reads.</summary>
    void CloseRun() { }

    /// <summary>The bundle implementation performs cancellable validation on a worker; in-memory sources may complete immediately.</summary>
    Task<Result<SavedTier0Path?>> ReadSavedTier0PathAsync(string bundleDirectory, string distinguishedName,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(ReadSavedTier0Path(bundleDirectory, distinguishedName));
    }
}

/// <summary>Queries against a selected run, without the authority to select or close that run.</summary>
internal interface IAssetReader
{
    /// <summary>Unverified sources cannot vouch for retained data; protected readers supply their own check.</summary>
    Func<bool> CaptureReadValidity() => () => false;

    /// <summary>Finds captured user/group identities for direct permission lookup.</summary>
    Result<DelegationPrincipalPage> FindDelegationPrincipals(string bundleDirectory, string search, DelegationPrincipalMark? after);

    /// <summary>Reads a bounded page of original captured entries naming the selected principal.</summary>
    Result<DelegationPage> ReadDelegations(string bundleDirectory, DelegationQuery query, DelegationPageMark? after);

    /// <summary>Reads one object's completed saved permission classification without new analysis.</summary>
    Result<SavedPermissionClassification> ReadPermissionClassification(string bundleDirectory, string distinguishedName);

    /// <summary>Reads one saved path and its coverage from the same validated generation, without new analysis.</summary>
    Result<SavedTier0Path?> ReadSavedTier0Path(string bundleDirectory, string distinguishedName);

    /// <summary>Reads a selected saved qualification group; the continuation is bound to its original generation.</summary>
    Result<SavedTier0Path?> ReadSavedTier0Path(string bundleDirectory, string distinguishedName,
        PathRiskVerdict group, PathRiskPageMark? after);

    /// <summary>Reads whole-run SEC-071 counts, independent of the findings grid's current filters and page.</summary>
    Result<Tier0FindingSummary?> ReadTier0FindingSummary(string bundleDirectory);

    /// <summary>Reads a page of stored control statements, with coverage and hidden expected counts.</summary>
    Result<ControlEdgePage> ReadControlEdges(string bundleDirectory, string? target, string? holderSid,
        string? holderScope, bool includeExpected, long afterId);

    /// <summary>Reads stored concrete Self-Membership requester assessments in either direction.</summary>
    Result<SelfMembershipAssessmentSet> ReadSelfMembershipAssessments(string bundleDirectory, string? target, string? requester);

    /// <summary>Reads stored group-member attribution for a source permission.</summary>
    Result<MemberAttributionDetail> ReadMemberAttribution(string bundleDirectory, string holderSid, string? holderScope, string target);

    /// <summary>Reads group-held source permissions through persisted member attribution.</summary>
    Result<MemberPermissionPage> ReadPermissionsThroughMembership(string bundleDirectory, string memberSid, string? memberScope, bool includeExpected, long afterId);

    /// <summary>Reads the directory tree of the bundle in <paramref name="bundleDirectory"/>.</summary>
    /// <param name="bundleDirectory">The run's bundle directory.</param>
    Result<DirectoryTree> ReadTree(string bundleDirectory);

    /// <summary>Lists one page of the objects in a container.</summary>
    /// <param name="bundleDirectory">The run's bundle directory.</param>
    /// <param name="containerDn">The container the operator selected.</param>
    /// <param name="scope">How much of what is beneath it to include.</param>
    /// <param name="pageNumber">The page to fetch, counting from one.</param>
    Result<ObjectPage> ListObjects(
        string bundleDirectory, string containerDn, ListingScope scope, int pageNumber);

    /// <summary>Lists one page of completed saved LAPS inventory for a container, without reclassification.</summary>
    /// <remarks>
    /// Separate from <see cref="ListObjects"/> because it answers a different question: it lists
    /// computers only, and carries what the directory says about each machine's password
    /// management rather than its class and parent.
    /// </remarks>
    /// <param name="bundleDirectory">The run's bundle directory.</param>
    /// <param name="containerDn">The container the operator selected.</param>
    /// <param name="scope">How much of what is beneath it to include.</param>
    /// <param name="pageNumber">The page to fetch, counting from one.</param>
    Result<LapsPage> ListLapsComputers(
        string bundleDirectory, string containerDn, ListingScope scope, int pageNumber);

    /// <summary>Reads the permissions on one object.</summary>
    /// <param name="bundleDirectory">The run's bundle directory.</param>
    /// <param name="distinguishedName">The object the operator opened.</param>
    /// <returns>
    /// What the bundle holds, or a success carrying null when it captured no object by that name.
    /// Null is not a failure: the bundle was read, and the answer is that the object is not in it.
    /// </returns>
    Result<ObjectPermissions?> ReadPermissions(string bundleDirectory, string distinguishedName);

    /// <summary>Reads the attribute values captured for one object.</summary>
    /// <param name="bundleDirectory">The run's bundle directory.</param>
    /// <param name="distinguishedName">The object the operator opened.</param>
    /// <returns>
    /// Every attribute the catalogue names, with a value where one arrived, or a success carrying
    /// null when the bundle captured no object by that name.
    /// </returns>
    Result<ObjectAttributes?> ReadObjectAttributes(
        string bundleDirectory, string distinguishedName);

    /// <summary>Reads the schema-GUID catalogue this run captured, over the shipped one.</summary>
    /// <param name="bundleDirectory">The run's bundle directory.</param>
    /// <remarks>
    /// <b>Asked once for a run, not once for an object.</b> A forest's schema runs to thousands of
    /// definitions and nearly every access control entry names a GUID, so resolving names per
    /// object would re-read the whole schema for every screen an operator turned.
    /// </remarks>
    Result<SchemaGuidCatalog> ReadSchemaGuids(string bundleDirectory);

    /// <summary>Reads what a run captured, counted per domain beside its coverage.</summary>
    /// <param name="bundleDirectory">The run's bundle directory.</param>
    /// <remarks>
    /// <b>One question, not five.</b> The dashboard needs users, computers, groups, organisational
    /// units and policies for every domain at once, and asking for each separately would let a
    /// screen show four kinds counted and one refused with nothing saying the two came from
    /// different readings of the same bundle.
    /// </remarks>
    Result<ForestInventory> ReadInventory(string bundleDirectory);

    /// <summary>
    /// Reads how many groups claimed a member the run could not identify, or null where the
    /// membership has not been derived.
    /// </summary>
    /// <param name="bundleDirectory">The run's bundle directory.</param>
    /// <remarks>
    /// <b>Three answers, not two, and the third is the point.</b> A number is a count of groups
    /// whose membership cannot be vouched for; zero says every member named was identified; null
    /// says deriving has not run, so nobody has looked. A screen that collapsed null into zero
    /// would tell an operator his groups are fully known on the strength of a stage that never
    /// happened. P-164.
    /// </remarks>
    Result<int?> ReadGroupsWithUnidentifiedMembers(string bundleDirectory);

    /// <summary>Reads one page of the findings a judging produced.</summary>
    /// <param name="bundleDirectory">The run's bundle directory.</param>
    /// <param name="query">Which findings, and where to carry on from.</param>
    /// <remarks>
    /// <b>The judgement is a different file from the evidence, and may not be there at all.</b> A
    /// bundle that has been captured but not judged has no findings to page, and that is a fact
    /// about the judging rather than about the forest - so it is a failure a screen states, not an
    /// empty grid.
    /// </remarks>
    Result<FindingsPage> ReadFindings(string bundleDirectory, FindingsQuery query);

    /// <summary>Reads what the findings grid's filters may offer.</summary>
    /// <param name="bundleDirectory">The run's bundle directory.</param>
    /// <remarks>
    /// <b>Asked once for a run, not once for a page.</b> The values are for the whole judgement, so
    /// a list that changed as the operator moved about the tree would be a filter clearing itself.
    /// </remarks>
    Result<FindingsFilterValues> ReadFindingsFilterValues(string bundleDirectory);

    /// <summary>Reads what every scheduled rule did to this bundle.</summary>
    /// <remarks>
    /// Separate from <see cref="ReadFindings"/> because it answers the other half of the question:
    /// a page of findings says what was wrong, and this says what was checked - including the rules
    /// that checked and found nothing, which no list of findings can contain.
    /// </remarks>
    /// <param name="bundleDirectory">The run's bundle directory.</param>
    Result<StoredRuleExecutions> ReadRuleExecutions(string bundleDirectory);
}
