using SecureAD.Evidence;
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
internal interface IAssetSource
{
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

    /// <summary>Lists one page of the LAPS inventory for a container.</summary>
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
}
