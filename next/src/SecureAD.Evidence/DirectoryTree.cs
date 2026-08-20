using Microsoft.Data.Sqlite;
using SecureAD.Kernel.Naming;

namespace SecureAD.Evidence;

/// <summary>
/// How a node in the tree came to be known.
/// </summary>
public enum TreeNodeOrigin
{
    /// <summary>
    /// A naming context the run read. These are the roots, and they are named by
    /// <c>partition_coverage</c> rather than derived from any object's name.
    /// </summary>
    Partition,

    /// <summary>The container is a captured object, and objects were captured under it.</summary>
    Captured,

    /// <summary>
    /// Objects were captured whose name places them under this container, and the container itself
    /// was never captured.
    /// </summary>
    /// <remarks>
    /// The node exists so the objects beneath it can be reached at all. Dropping it would make a
    /// whole branch unreachable from the tree while its objects sit in the evidence, which is a
    /// gap in the capture rendered as a smaller directory - what
    /// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> forbids. It is reported in
    /// <see cref="DirectoryTree.Gaps"/> as well as marked here.
    /// </remarks>
    NeverCaptured,
}

/// <summary>
/// One container in the offline rebuild of the directory tree.
/// </summary>
/// <param name="DistinguishedName">The container's name, as the evidence holds it.</param>
/// <param name="Name">
/// The first relative name, for showing. Taken with <see cref="DnHelper.ExtractFirstRdn"/>, so a
/// name carrying an escaped comma is not split at it.
/// </param>
/// <param name="ObjectGuid">
/// The container's identity when the container was itself captured, and null when it was not or
/// when the identity did not arrive. Never invented, per <c>docs/decisions/0002</c>.
/// </param>
/// <param name="Origin">How this node came to be known.</param>
/// <param name="Children">The containers directly beneath it, ordered by name.</param>
public sealed record TreeNode(
    string DistinguishedName,
    string Name,
    Guid? ObjectGuid,
    TreeNodeOrigin Origin,
    IReadOnlyList<TreeNode> Children);

/// <summary>
/// Why part of the directory is not in the tree, or is in it only in part.
/// </summary>
/// <remarks>
/// Each value is a different remedy, and they are held apart for the reason
/// <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c> gives: a part of the
/// directory nobody looked at and a part that could not be read are opposite findings.
/// </remarks>
public enum TreeGapReason
{
    /// <summary>A declared domain was not read in full.</summary>
    DomainNotFullyRead,

    /// <summary>A forest-wide partition was not read in full.</summary>
    ForestPartitionNotFullyRead,

    /// <summary>
    /// A partition the forest declared and this product does not read - in practice the DNS zone
    /// partitions, per <c>docs/decisions/0042-dns-zones-and-records-are-out-of-scope.md</c>.
    /// </summary>
    PartitionNotRead,

    /// <summary>
    /// Objects name this container as their parent and the container was never captured, so what
    /// else it holds is unknown.
    /// </summary>
    ContainerNeverCaptured,
}

/// <summary>
/// One part of the directory the tree cannot show, and why.
/// </summary>
/// <param name="DistinguishedName">
/// What the gap is about: a naming context, or the container that was never captured.
/// </param>
/// <param name="Reason">Which kind of gap it is.</param>
/// <param name="Detail">
/// What the run recorded about it, in terms an operator can act on. Never empty, so a caller
/// rendering the detail never renders a blank.
/// </param>
public sealed record TreeGap(string DistinguishedName, TreeGapReason Reason, string Detail);

/// <summary>
/// The directory tree as the evidence can rebuild it, and a statement of where it is not the
/// directory.
/// </summary>
/// <remarks>
/// <para>
/// <b>The tree is what was observed, not what the directory has.</b> A node is here because the
/// run read a naming context, or because objects were captured whose names place them under it.
/// Nothing here is inferred from an object class, and nothing is invented above a root.
/// </para>
/// <para>
/// <b>A container the run captured but read nothing under has no node</b>, and that is a known
/// limit rather than an oversight. Recognising it would mean deciding by object class which
/// captured objects are containers, and a hand-written list of class names is wrong the first time
/// a forest holds a container class nobody listed - which drops a real branch. Containment that
/// was actually observed cannot be wrong that way. The cost is that an empty organisational unit
/// is absent from the tree; it is still an object in its parent's listing, and it filters to
/// nothing either way. <b>If that absence turns out to matter on a screen, this is the decision to
/// re-open.</b>
/// </para>
/// <para>
/// <b><see cref="Gaps"/> is what stops the tree being read as the directory.</b> A branch the run
/// could not read, and a partition it never read, both produce a tree that is smaller than the
/// forest - and a smaller tree looks exactly like a smaller directory. Every such branch is stated
/// here, and <see cref="BranchesAreComplete"/> is the one question a caller has to answer before
/// presenting the tree as though it were the whole of it.
/// </para>
/// </remarks>
/// <param name="Roots">The naming contexts read, ordered by name.</param>
/// <param name="Gaps">
/// Every part of the directory the tree does not show whole. Empty means the run read every unit
/// it declared and every container it saw named.
/// </param>
public sealed record DirectoryTree(IReadOnlyList<TreeNode> Roots, IReadOnlyList<TreeGap> Gaps)
{
    /// <summary>
    /// Whether the tree shows every branch the run declared. False means part of the directory is
    /// missing from it, and <see cref="Gaps"/> says which part and why.
    /// </summary>
    public bool BranchesAreComplete => Gaps.Count == 0;
}

/// <summary>
/// Rebuilds the directory tree from the names a bundle already holds.
/// </summary>
/// <remarks>
/// <para>
/// <b>A pure function of what is on disk.</b> It reads distinguished names, partitions and
/// coverage, and needs nothing capture does not already store.
/// </para>
/// <para>
/// <b>Assembled in memory, in one pass.</b> The tree is containers, not objects - tens of
/// thousands in a large forest where the objects are millions - so the whole of it is built at
/// once rather than a level at a time. A lazily expanded tree would issue a query per node
/// expanded and could not answer <see cref="DirectoryTree.BranchesAreComplete"/> until the
/// operator had clicked on everything.
/// </para>
/// </remarks>
internal static class DirectoryTreeReader
{
    /// <summary>
    /// The object classes that put an object in the tree whether or not anything was captured
    /// under it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>An empty container is still a container.</b> A directory holds organisational units and
    /// containers that hold nothing today, and an administrator navigating his own directory
    /// expects to see them; a tree built only from observed containment silently drops every one.
    /// </para>
    /// <para>
    /// <b>This list is not complete and cannot be.</b> A hand-written list of names is the shape of
    /// defect this repository has been bitten by before - it agrees with the directory on the day
    /// it is written. What makes it safe is that it is a <i>union</i> with observed containment:
    /// an object of some class nobody listed still appears in the tree the moment anything is
    /// captured under it. So the whole cost of an omission here is that an <i>empty</i> container
    /// of an unusual class is missing, and never that a branch of the directory disappears.
    /// </para>
    /// </remarks>
    private static readonly string[] ContainerClasses =
    [
        "domainDNS", "builtinDomain", "organizationalUnit", "container", "lostAndFound",
        "msDS-QuotaContainer", "configuration", "dMD", "rpcContainer",
        "msTPM-InformationObjectsContainer",
    ];

    /// <summary>
    /// Reads the tree from an open bundle.
    /// </summary>
    /// <param name="connection">The open evidence database.</param>
    public static DirectoryTree Read(SqliteConnection connection)
    {
        var nodes = new Dictionary<string, Node>(StringComparer.OrdinalIgnoreCase);
        var gaps = new List<TreeGap>();

        var roots = ReadRoots(connection);
        foreach (var root in roots)
            nodes[root] = new Node(root, TreeNodeOrigin.Partition);

        foreach (var parentDn in ReadObservedParents(connection))
            AddWithItsAncestors(nodes, roots, parentDn);

        foreach (var containerDn in ReadContainersByClass(connection))
            AddWithItsAncestors(nodes, roots, containerDn);

        FillInIdentities(connection, nodes);
        CollectGaps(connection, nodes, gaps);

        Attach(nodes, roots);

        return new DirectoryTree(
            [.. roots.Where(nodes.ContainsKey).Select(r => nodes[r].Freeze())
                     .Concat(nodes.Values.Where(n => n.IsOrphanRoot).Select(n => n.Freeze()))
                     .OrderBy(n => n.DistinguishedName, StringComparer.OrdinalIgnoreCase)],
            gaps);
    }

    /// <summary>
    /// The naming contexts the run read. These and only these are roots: a root is a partition the
    /// run recorded reading, never a name inferred from an object beneath it.
    /// </summary>
    private static List<string> ReadRoots(SqliteConnection connection)
    {
        var roots = new List<string>();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT DISTINCT naming_context_dn FROM partition_coverage";

        using var reader = command.ExecuteReader();
        while (reader.Read())
            roots.Add(reader.GetString(0));

        return roots;
    }

    /// <summary>
    /// Every container something was actually captured under.
    /// </summary>
    private static List<string> ReadObservedParents(SqliteConnection connection)
    {
        var parents = new List<string>();
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT DISTINCT parent_dn FROM captured_object WHERE parent_dn IS NOT NULL";

        using var reader = command.ExecuteReader();
        while (reader.Read())
            parents.Add(reader.GetString(0));

        return parents;
    }

    /// <summary>
    /// Every captured object whose class makes it a container, whether or not anything was
    /// captured inside it.
    /// </summary>
    private static List<string> ReadContainersByClass(SqliteConnection connection)
    {
        var names = new List<string>();
        var placeholders = string.Join(", ", ContainerClasses.Select((_, i) => "$c" + i));

        using var command = connection.CreateCommand();
        command.CommandText =
            $"""
            SELECT o.distinguished_name
            FROM captured_object AS o
            WHERE EXISTS (
                SELECT 1 FROM {BundleSchema.ValueTableNameFor("objectClass")} AS v
                WHERE v.object_id = o.object_id
                  AND v.value COLLATE NOCASE IN ({placeholders}))
            """;

        for (var i = 0; i < ContainerClasses.Length; i++)
            command.Parameters.AddWithValue("$c" + i, ContainerClasses[i]);

        using var reader = command.ExecuteReader();
        while (reader.Read())
            names.Add(reader.GetString(0));

        return names;
    }

    /// <summary>
    /// Adds a container and the containers between it and its root.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The intermediate names are real containment and not a guess: an object named
    /// <c>CN=Alice,OU=Staff,OU=People,DC=contoso,DC=com</c> is under <c>OU=People</c> whether or
    /// not anything was captured directly in it. Without them a branch would hang off nothing and
    /// be unreachable.
    /// </para>
    /// <para>
    /// <b>The walk stops at a root and never climbs past one.</b> A name above every root was
    /// never read and inventing a node for it would put a container in the tree that no evidence
    /// mentions.
    /// </para>
    /// </remarks>
    private static void AddWithItsAncestors(
        Dictionary<string, Node> nodes, List<string> roots, string dn)
    {
        for (var current = dn; current is not null; current = DnHelper.GetParentDn(current))
        {
            if (nodes.ContainsKey(current))
                return;

            // A name above every root is not part of this tree, and is not added.
            //
            // Seen on screen 2026-08-18: a captured domain root DC=ad,DC=lab carries the parent
            // name DC=lab, which is not an object in the directory at all - the forest root domain
            // IS ad.lab. Adding it put a container in the tree that no evidence mentions, and then
            // reported it as one the run had failed to capture. Both were inventions.
            //
            // The earlier guard only stopped the WALK at a root; it still added the first name
            // above one. The test for it passed because no test captured a partition root object,
            // which is the only object whose parent lies outside the tree.
            if (!roots.Any(root => IsAtOrUnder(current, root)))
                return;

            nodes[current] = new Node(current, TreeNodeOrigin.NeverCaptured);
        }
    }

    /// <summary>
    /// Whether one distinguished name is the given root or sits beneath it.
    /// </summary>
    /// <remarks>
    /// A suffix test, and it is enough because both names come from the same evidence and neither
    /// is rewritten on the way in. The comma is included in the comparison so that
    /// <c>DC=contoso,DC=com</c> does not appear to contain <c>DC=notcontoso,DC=com</c>.
    /// </remarks>
    private static bool IsAtOrUnder(string dn, string root) =>
        dn.Equals(root, StringComparison.OrdinalIgnoreCase)
        || dn.EndsWith("," + root, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Marks the containers that were themselves captured, and gives them the identity that
    /// survives a rename or a move.
    /// </summary>
    /// <remarks>
    /// One query for the containers something was captured under, which the name index serves, and
    /// then a lookup each for the few that are left - the containers between an object and its
    /// root that hold no object directly.
    /// </remarks>
    private static void FillInIdentities(
        SqliteConnection connection, Dictionary<string, Node> nodes)
    {
        using (var command = connection.CreateCommand())
        {
            command.CommandText =
                """
                SELECT distinguished_name, object_guid
                FROM captured_object
                WHERE distinguished_name IN
                      (SELECT DISTINCT parent_dn FROM captured_object WHERE parent_dn IS NOT NULL)
                """;

            using var reader = command.ExecuteReader();
            while (reader.Read())
                Capture(nodes, reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetString(1));
        }

        var remaining = nodes.Values
            .Where(n => n.Origin == TreeNodeOrigin.NeverCaptured)
            .Select(n => n.DistinguishedName)
            .ToList();

        foreach (var dn in remaining)
        {
            using var command = connection.CreateCommand();
            command.CommandText =
                "SELECT object_guid FROM captured_object WHERE distinguished_name = $dn LIMIT 1";
            command.Parameters.AddWithValue("$dn", dn);

            using var reader = command.ExecuteReader();
            if (reader.Read())
                Capture(nodes, dn, reader.IsDBNull(0) ? null : reader.GetString(0));
        }
    }

    /// <summary>
    /// Records that a node is a captured object. A root stays a root: which partition a run read
    /// is a fact about the run, and is not overwritten by the partition also having been captured
    /// as an object.
    /// </summary>
    private static void Capture(Dictionary<string, Node> nodes, string dn, string? objectGuid)
    {
        if (!nodes.TryGetValue(dn, out var node))
            return;

        node.ObjectGuid = objectGuid is null ? null : Guid.Parse(objectGuid);
        if (node.Origin == TreeNodeOrigin.NeverCaptured)
            node.Origin = TreeNodeOrigin.Captured;
    }

    /// <summary>
    /// Everything the tree cannot show, taken from what the run recorded rather than from the
    /// shape of the tree itself.
    /// </summary>
    private static void CollectGaps(
        SqliteConnection connection, Dictionary<string, Node> nodes, List<TreeGap> gaps)
    {
        Collect(
            connection,
            "SELECT domain_fqdn, outcome, reason FROM domain_coverage WHERE outcome <> 'Read'",
            TreeGapReason.DomainNotFullyRead,
            "The domain",
            gaps);

        Collect(
            connection,
            "SELECT naming_context_dn, outcome, reason FROM forest_partition_coverage "
            + "WHERE outcome <> 'Read'",
            TreeGapReason.ForestPartitionNotFullyRead,
            "The partition",
            gaps);

        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT naming_context_dn FROM unread_partition";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                gaps.Add(new TreeGap(
                    reader.GetString(0),
                    TreeGapReason.PartitionNotRead,
                    "This product does not read this partition, so nothing beneath it is in the "
                    + "tree or in the evidence."));
            }
        }

        foreach (var node in nodes.Values.Where(n => n.Origin == TreeNodeOrigin.NeverCaptured))
        {
            gaps.Add(new TreeGap(
                node.DistinguishedName,
                TreeGapReason.ContainerNeverCaptured,
                "Objects name this container as their parent and the container itself was never "
                + "captured, so what else it holds is unknown."));
        }
    }

    private static void Collect(
        SqliteConnection connection,
        string sql,
        TreeGapReason reason,
        string subject,
        List<TreeGap> gaps)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var outcome = reader.GetString(1);
            var why = reader.IsDBNull(2) ? null : reader.GetString(2);
            gaps.Add(new TreeGap(
                reader.GetString(0),
                reason,
                $"{subject} was recorded as {outcome}."
                + (why is null ? string.Empty : " " + why)));
        }
    }

    /// <summary>
    /// Hangs every node off its parent. A node whose parent is not in the set is left where it is
    /// - it is either a root or an orphan, and both are shown rather than dropped.
    /// </summary>
    private static void Attach(Dictionary<string, Node> nodes, List<string> roots)
    {
        foreach (var node in nodes.Values)
        {
            if (roots.Contains(node.DistinguishedName, StringComparer.OrdinalIgnoreCase))
                continue;

            var parentDn = DnHelper.GetParentDn(node.DistinguishedName);
            if (parentDn is not null && nodes.TryGetValue(parentDn, out var parent))
            {
                parent.Children.Add(node);
                node.IsOrphanRoot = false;
            }
            else
            {
                node.IsOrphanRoot = true;
            }
        }
    }

    /// <summary>
    /// A node while the tree is being assembled, when its children are not yet all known.
    /// </summary>
    private sealed class Node(string distinguishedName, TreeNodeOrigin origin)
    {
        public string DistinguishedName { get; } = distinguishedName;

        public TreeNodeOrigin Origin { get; set; } = origin;

        public Guid? ObjectGuid { get; set; }

        public bool IsOrphanRoot { get; set; }

        public List<Node> Children { get; } = [];

        public TreeNode Freeze() => new(
            DistinguishedName,
            DnHelper.ExtractFirstRdn(DistinguishedName),
            ObjectGuid,
            Origin,
            [.. Children
                .OrderBy(c => DnHelper.ExtractFirstRdn(c.DistinguishedName), StringComparer.OrdinalIgnoreCase)
                .Select(c => c.Freeze())]);
    }
}
