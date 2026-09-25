using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Measure;

/// <summary>
/// Describes the <i>shape</i> of a sealed capture - counts, distributions and how often each
/// published schema GUID appears - carrying nothing that identifies the forest, so a profile of a
/// production directory can be brought out of the environment that holds it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> Every figure <c>P-280</c> rests on came off a synthetic bundle that this
/// codebase generated, so it could only contain the assumptions the code already held. It has no
/// object-type GUIDs at all, no variation in <c>SELF</c>, no control edges and - measured while
/// fixing <c>P-284</c> - not one unreadable or partly parsed descriptor. A bench like that cannot
/// disagree with us, and a set of checks anchored to our own beliefs is <c>F-S44-2</c> exactly: the
/// captured attribute catalogue had three sound test suites agreeing with each other in both
/// directions while fifteen attributes nobody had written a rule for were silently missing.
/// </para>
/// <para>
/// <b>The owner cannot export a bundle.</b> He works only inside the production environment, so the
/// anchor has to be something small enough to carry and harmless enough to be allowed out. That is
/// what this is: numbers, and the GUIDs anyone can already look up in Microsoft's schema reference.
/// </para>
/// <para>
/// <b>One gate, not a habit of care.</b> Every string that reaches the output passes through
/// <see cref="Publishable"/>. Spreading the decision across each field would mean a field added
/// later could leak by being written in a different style, and the check would still pass.
/// </para>
/// <para>
/// <b>It reads and never writes, and it does not open the bundle immutable</b>, for the reason
/// <see cref="JudgementForecast"/> gives at length: that flag asserts the file cannot be changing
/// underneath, which is a claim only a verified seal earns.
/// </para>
/// </remarks>
internal static class ShapeProfile
{
    /// <summary>
    /// Decides what may be written down, and is the only route by which any string reaches a
    /// profile.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The rule is the one <see cref="SchemaGuidSource"/> already states.</b> Its own summary
    /// puts the distinction better than a new one would: <i>"Microsoft publishes this GUID as
    /// <c>userAccountControl</c>" can be checked by anyone against the schema reference. "Your
    /// forest says this GUID is <c>contoso-PayrollId</c>" is true of that forest on that day and
    /// nowhere else.</i> The first may leave; the second is the name of something somebody at the
    /// audited organisation created, and it stays.
    /// </para>
    /// </remarks>
    internal static class Publishable
    {
        /// <summary>
        /// What a GUID is called, if the catalogue shipped with the product knows it - and
        /// <c>null</c> for every GUID it does not.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <b>Asked of <see cref="SchemaGuidCatalog.Embedded"/> and never of the bundle's own
        /// captured schema</b>, which is the whole correctness of this method. The captured layer
        /// re-reads the base schema out of the forest as well as the extensions, so a GUID being
        /// in it says nothing about whether Microsoft publishes it. Testing against the capture
        /// would let <c>contoso-PayrollId</c> out on the grounds that the forest had heard of it.
        /// </para>
        /// <para>
        /// The shipped catalogue needs no capture, no network and no directory, so this answer is
        /// the same in every forest and can be checked by a reader against Microsoft's published
        /// schema.
        /// </para>
        /// </remarks>
        internal static string? SchemaName(string? guid)
        {
            if (string.IsNullOrWhiteSpace(guid))
                return null;

            var known = SchemaGuidCatalog.Embedded.FindByGuid(guid);
            return known.Count == 0 ? null : known[0].LdapName;
        }

        /// <summary>
        /// Whether a GUID may be written down at all. A GUID the shipped catalogue does not know
        /// is counted in one bucket and its value never appears.
        /// </summary>
        internal static bool Schema(string? guid) => SchemaName(guid) is not null;

        /// <summary>
        /// What a trustee is called, if it is one of the SIDs that mean the same thing in every
        /// Active Directory - and <c>null</c> for every other.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <b>This is also how a domain SID is excluded, without recognising one.</b> A profile
        /// that tested for the <c>S-1-5-21</c> prefix would be a list of the shapes somebody
        /// thought of; asking instead whether the catalogue recognises the SID admits only the
        /// fixed, universal set and refuses everything else by default. <c>S-1-5-21-…</c> falls out
        /// as a consequence rather than as a case that had to be remembered.
        /// </para>
        /// </remarks>
        internal static string? TrusteeName(string? sid) =>
            WellKnownSidCatalog.FindBySid(sid)?.DisplayName;

        /// <summary>Whether a trustee SID may be written down at all.</summary>
        internal static bool Trustee(string? sid) => TrusteeName(sid) is not null;
    }

    /// <summary>
    /// The spread of a measurement, rather than its average.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>An average alone is what got the 344 million wrong.</b> That figure was entries times
    /// reuse, which is exact only if a descriptor's entry count and its reuse count are unrelated
    /// across the forest; the measurement came in 3.8% under, so they are not. A generator handed
    /// only a mean would rebuild the forest with that assumption baked back in, and the bench would
    /// agree with us again for the same reason it does now.
    /// </para>
    /// <para>
    /// <b>Percentiles are nearest-rank on a sorted array</b>, not interpolated. A directory's entry
    /// counts are whole numbers and a value halfway between two real descriptors is not a
    /// descriptor anything could be built to match.
    /// </para>
    /// </remarks>
    internal sealed record Distribution(
        long Count,
        long Minimum,
        long P50,
        long P90,
        long P99,
        long Maximum,
        double Mean,
        long Total)
    {
        /// <summary>
        /// The spread of <paramref name="values"/>, which is sorted in place.
        /// </summary>
        /// <remarks>
        /// Takes an array rather than a sequence deliberately. Every caller here measures something
        /// there is one of per object or per descriptor - at most 940,067 on the production capture
        /// - and a field tempted to take percentiles across 330 million occurrences cannot reach
        /// this without first admitting it would have to hold them all.
        /// </remarks>
        internal static Distribution Of(long[] values)
        {
            ArgumentNullException.ThrowIfNull(values);
            if (values.Length == 0)
                return new Distribution(0, 0, 0, 0, 0, 0, 0, 0);

            Array.Sort(values);

            long total = 0;
            foreach (var value in values)
                total += value;

            return new Distribution(
                Count: values.Length,
                Minimum: values[0],
                P50: At(values, 0.50),
                P90: At(values, 0.90),
                P99: At(values, 0.99),
                Maximum: values[^1],
                Mean: Math.Round(total / (double)values.Length, 2),
                Total: total);
        }

        private static long At(long[] sorted, double fraction)
        {
            var rank = (int)Math.Ceiling(fraction * sorted.Length) - 1;
            return sorted[Math.Clamp(rank, 0, sorted.Length - 1)];
        }
    }

    /// <summary>
    /// How two measurements vary together, as a grid of counts.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the one thing a pair of distributions cannot say.</b> The specification records
    /// the worry plainly: descriptors high in the tree are plausibly both the most reused and the
    /// ones carrying the deepest inherited lists, and that cannot be checked from a summary. Two
    /// separate histograms of entry count and reuse count are consistent with any relationship
    /// between them, including the one that moved the occurrence total by 12 million rows.
    /// </para>
    /// <para>
    /// <b>Buckets are powers of two, and the top one is open.</b> A directory's reuse counts span
    /// one to tens of thousands, so fixed-width buckets would put almost everything in the first
    /// and tell a generator nothing. The edges are recorded beside the counts so a reader is never
    /// inferring what a row means.
    /// </para>
    /// </remarks>
    /// <param name="RowEdges">Lower bound of each row bucket. The last row is everything above it.</param>
    /// <param name="ColumnEdges">Lower bound of each column bucket, read the same way.</param>
    /// <param name="Counts">One row per row bucket, each holding one count per column bucket.</param>
    internal sealed record Grid(
        string Rows,
        string Columns,
        IReadOnlyList<long> RowEdges,
        IReadOnlyList<long> ColumnEdges,
        IReadOnlyList<IReadOnlyList<long>> Counts)
    {
        private static readonly long[] Edges =
            [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1_024, 4_096, 16_384, 65_536, 262_144, 1_048_576];

        /// <summary>Buckets <paramref name="pairs"/> into a grid of counts and nothing else.</summary>
        internal static Grid Of(string rows, string columns, IEnumerable<(long Row, long Column)> pairs)
        {
            ArgumentNullException.ThrowIfNull(pairs);

            var counts = new long[Edges.Length][];
            for (var i = 0; i < counts.Length; i++)
                counts[i] = new long[Edges.Length];

            foreach (var (row, column) in pairs)
                counts[Bucket(row)][Bucket(column)]++;

            return new Grid(rows, columns, Edges, Edges, counts);
        }

        private static int Bucket(long value)
        {
            var index = 0;
            while (index + 1 < Edges.Length && value >= Edges[index + 1])
                index++;

            return index;
        }
    }

    /// <summary>The shape of one capture, and nothing that says whose it is.</summary>
    /// <param name="ObjectsWithNoDescriptorStored">
    /// Captured, but the bundle kept no descriptor bytes. <b>Not the same as holding no
    /// permissions</b> - 280,871 of the production capture's 940,067 objects are in this state, and
    /// a generator that built them as permission-free objects would model a third of the forest as
    /// something it is not.
    /// </param>
    /// <param name="EntriesPerDescriptor">
    /// How long the stored permission lists are, counted from the descriptor's own bytes rather
    /// than from the deduplicated projection.
    /// </param>
    /// <param name="ObjectsPerDescriptor">How many objects carry each descriptor.</param>
    /// <param name="EntriesAgainstReuse">
    /// The two above, together. A generator built from the two distributions alone would reproduce
    /// the marginals and be free to get their relationship wrong.
    /// </param>
    /// <param name="ObjectsPerDomain">
    /// Sorted descending and unlabelled. How lopsided the forest is decides how much a descriptor
    /// high in one domain is reused; which domain is which decides nothing.
    /// </param>
    internal sealed record Profile(
        string Bundle,
        long ObjectsCaptured,
        long ObjectsWithADescriptorStored,
        long ObjectsWithNoDescriptorStored,
        long ObjectsWithReadablePermissions,
        long ObjectsWithAnUnreadableDescriptor,
        long ObjectsWithAPartiallyParsedDescriptor,
        long ObjectsWhoseDescriptorReportedErrors,
        long DescriptorsStored,
        long DescriptorsUsedByObjects,
        long Occurrences,
        Distribution NameBytesPerObject,
        Distribution NameDepthPerObject,
        Distribution EntriesPerDescriptor,
        Distribution ObjectsPerDescriptor,
        Grid EntriesAgainstReuse,
        long Domains,
        IReadOnlyList<long> ObjectsPerDomain,
        bool EveryNameIsAscii,
        AceShape Aces,
        IReadOnlyList<Named> ObjectTypes,
        IReadOnlyList<Named> InheritedObjectTypes,
        IReadOnlyList<Named> Trustees,
        IReadOnlyList<MaskCount> AccessMasks,
        string BuildSha256,
        string BuildSha256Covers,
        string AssemblyVersion,
        string Runtime)
    {
        /// <summary>
        /// Every database in the bundle was opened read-only, so none of them can have been
        /// written.
        /// </summary>
        /// <remarks>
        /// Deliberately not "nothing was written", for the reason
        /// <see cref="JudgementForecast.Forecast.OpenedReadOnly"/> records: SQLite touches its own
        /// shared-memory scratch beside the evidence, that scratch is outside the seal and is not
        /// evidence, but a bundle directory whose contents changed is not one where nothing was
        /// written and an audit tool may not be the thing that rounds a claim up.
        /// </remarks>
        public bool OpenedReadOnly => true;

        /// <summary>
        /// Stated as a field so it travels with the document rather than with whoever sent it.
        /// </summary>
        public string Contains =>
            "Counts, distributions, and the GUIDs and SIDs that mean the same thing in every "
            + "Active Directory. No distinguished name, no domain SID, no trustee that is not "
            + "well-known, no GUID outside the catalogue shipped with the product, and no "
            + "descriptor bytes.";
    }

    /// <summary>
    /// How often each ACE shape occurs, as counts only. The mask is a bit field and the flags are
    /// bytes, so none of this names anything in the forest.
    /// </summary>
    /// <param name="CarryingAnObjectType">
    /// 72% of the production capture's occurrences, and <b>zero</b> of the bench's. This is the
    /// single number that most justifies the profile existing: the part of the <c>P-280</c> model
    /// that prices 14.9 GB of duplicated GUID text has never been checked against a real judgement.
    /// </param>
    /// <param name="CarryingPrincipalSelf">
    /// The <c>P-285</c> measurement. <c>S-1-5-10</c> is in the default access control list of
    /// essentially every user and computer, and because the resolved trustee name is inside the
    /// sharing identity, every one of those gets its own <c>permission_entry</c> row.
    /// </param>
    internal sealed record AceShape(
        long Allow,
        long Deny,
        long Inherited,
        long NotInherited,
        long CarryingAnObjectType,
        long CarryingAnInheritedObjectType,
        long InheritOnly,
        long ContainerInherit,
        long ObjectInherit,
        long NoPropagateInherit,
        long CarryingApplicationData,
        long CarryingPrincipalSelf,
        long CarryingAWellKnownTrustee,
        long CarryingATrusteeThatIsNotWellKnown,
        long ObjectTypesOutsideTheShippedCatalogue,
        long InheritedObjectTypesOutsideTheShippedCatalogue,
        long DistinctObjectTypesOutsideTheShippedCatalogue,
        long DistinctInheritedObjectTypesOutsideTheShippedCatalogue);

    /// <summary>Something the shipped catalogue can name, and how often it was seen.</summary>
    /// <remarks>
    /// The name is carried beside the GUID because a reader deciding whether this document is safe
    /// to send should be able to see for himself that <c>bf967a86-…</c> is <c>computer</c> and not
    /// something local. A GUID with no name never reaches this record.
    /// </remarks>
    internal sealed record Named(string Value, string Name, long Occurrences);

    /// <summary>One access mask and how often it was seen.</summary>
    /// <remarks>
    /// A bit field defined by <c>[MS-ADTS]</c>, identical in meaning in every forest. Reported in
    /// hexadecimal because that is how the rights read: <c>0x000F01FF</c> is recognisably full
    /// control and <c>983551</c> is not.
    /// </remarks>
    internal sealed record MaskCount(string Mask, long Occurrences);

    /// <summary>Descriptors parsed between progress lines, so a long scan does not look hung.</summary>
    private const int ProgressEvery = 20_000;

    /// <summary>How many of each named thing are listed. The rest are counted, never named.</summary>
    private const int TopNamed = 200;

    // --shape-profile BUNDLE_DIRECTORY [OUTPUT_FILE]
    internal static int Run(string[] args)
    {
        if (args.Length is not (1 or 2))
            throw new ArgumentException("BUNDLE_DIRECTORY is required, and an output file is optional.");

        Profile profile;
        try
        {
            profile = Of(Path.GetFullPath(args[0]));
        }
        catch (InvalidDataException refused)
        {
            Console.Error.WriteLine(refused.Message);
            return 1;
        }

        var json = JsonSerializer.Serialize(profile, new JsonSerializerOptions { WriteIndented = true });

        if (args.Length == 2)
        {
            // Written where the operator asked, which on a locked-down machine is the only way to
            // get it off the screen. Nothing is written inside the bundle.
            File.WriteAllText(args[1], json);
            Console.Error.WriteLine($"Profile written to {args[1]}.");
        }
        else
        {
            Console.WriteLine(json);
        }

        Report(profile);
        return 0;
    }

    /// <summary>
    /// A summary for the person deciding whether this document may leave, printed to standard
    /// error so it never contaminates a profile being redirected to a file.
    /// </summary>
    /// <remarks>
    /// <b>It says what is absent, not only what is present.</b> Somebody has to look at this and
    /// judge it, and a page of numbers with no statement of what was deliberately left out gives
    /// him nothing to check the numbers against.
    /// </remarks>
    private static void Report(Profile p)
    {
        var to = Console.Error;
        to.WriteLine();
        to.WriteLine("Opened read-only. Nothing in the bundle was written.");
        to.WriteLine();
        to.WriteLine($"  Objects captured                          {p.ObjectsCaptured,18:N0}");
        to.WriteLine($"  Of those, with a descriptor stored        {p.ObjectsWithADescriptorStored,18:N0}");
        to.WriteLine($"  Of those, with permissions we could read  {p.ObjectsWithReadablePermissions,18:N0}");
        to.WriteLine($"  Permission occurrences                    {p.Occurrences,18:N0}");
        to.WriteLine($"  Descriptors used by an object             {p.DescriptorsUsedByObjects,18:N0}");
        to.WriteLine($"  Domains                                   {p.Domains,18:N0}");
        to.WriteLine();
        to.WriteLine($"  Entries per descriptor    p50 {p.EntriesPerDescriptor.P50,8:N0}  p99 {p.EntriesPerDescriptor.P99,8:N0}  max {p.EntriesPerDescriptor.Maximum,8:N0}");
        to.WriteLine($"  Objects per descriptor    p50 {p.ObjectsPerDescriptor.P50,8:N0}  p99 {p.ObjectsPerDescriptor.P99,8:N0}  max {p.ObjectsPerDescriptor.Maximum,8:N0}");
        to.WriteLine($"  Name, bytes               p50 {p.NameBytesPerObject.P50,8:N0}  p99 {p.NameBytesPerObject.P99,8:N0}  max {p.NameBytesPerObject.Maximum,8:N0}");
        to.WriteLine();
        to.WriteLine($"  Occurrences carrying an object type       {p.Aces.CarryingAnObjectType,18:N0}");
        to.WriteLine($"  Occurrences carrying PRINCIPAL SELF       {p.Aces.CarryingPrincipalSelf,18:N0}");
        to.WriteLine("  The second is the P-285 measurement: every one of those gets its own");
        to.WriteLine("  permission_entry row, because the resolved name is inside the identity.");
        to.WriteLine();
        to.WriteLine("  WHAT THIS DOCUMENT DOES NOT CONTAIN");
        to.WriteLine("  No distinguished name, and no part of one. No domain SID. No trustee that");
        to.WriteLine("  is not well-known in every Active Directory. No schema GUID outside the");
        to.WriteLine("  catalogue shipped with this product. No descriptor bytes. No file path.");
        to.WriteLine();
        to.WriteLine($"  Schema GUIDs named                        {p.ObjectTypes.Count + p.InheritedObjectTypes.Count,18:N0}");
        to.WriteLine($"  Schema GUIDs counted but not named        {p.Aces.DistinctObjectTypesOutsideTheShippedCatalogue + p.Aces.DistinctInheritedObjectTypesOutsideTheShippedCatalogue,18:N0}");
        to.WriteLine($"  Trustees named                            {p.Trustees.Count,18:N0}");
        to.WriteLine($"  Occurrences whose trustee was not named   {p.Aces.CarryingATrusteeThatIsNotWellKnown,18:N0}");
        to.WriteLine();
        to.WriteLine("  The second and fourth of those are the forest's own: extensions somebody");
        to.WriteLine("  created and principals it holds. They are counted and never identified.");
    }

    /// <summary>Profiles the bundle in <paramref name="bundle"/>.</summary>
    /// <exception cref="InvalidDataException">
    /// The directory holds no sealed evidence, or was written by a build this tool does not read.
    /// Said by name rather than by stack trace, which is the <c>P-274</c> repair.
    /// </exception>
    internal static Profile Of(string bundle)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundle);

        var evidence = BundleLayout.EvidencePath(bundle);
        if (!File.Exists(evidence))
        {
            throw new InvalidDataException(
                $"There is no sealed evidence file in '{bundle}'. Name the run's own folder rather "
                + "than the library that holds several of them.");
        }

        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = evidence,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        connection.Open();

        foreach (var table in new[] { "captured_object", "security_descriptor", "object_security_descriptor" })
        {
            if (!HasTable(connection, table))
            {
                throw new InvalidDataException(
                    $"This bundle has no '{table}' table, so its shape cannot be profiled. "
                    + "It was written by a build this tool does not read.");
            }
        }

        return Measure(connection, bundle);
    }

    private static Profile Measure(SqliteConnection connection, string bundle)
    {
        var objectsCaptured = Scalar(connection, "SELECT COUNT(*) FROM captured_object");
        var descriptorsStored = Scalar(connection, "SELECT COUNT(*) FROM security_descriptor");

        // PASS ONE: one row per object that has a descriptor stored. Three things come out of it,
        // and the distinguished name is read for all three and kept for none.
        //
        // THE NAME IS A GROUP KEY AND A LENGTH, AND IS DISCARDED BEFORE ANYTHING IS WRITTEN. It is
        // the one field that must never leave the environment, so it is worth saying exactly what
        // happens to it: its byte length and character length go into a distribution, its comma
        // count goes into another, its DC= suffix is hashed into a per-domain tally whose key is
        // thrown away and whose counts are sorted and emitted unlabelled. Nothing downstream of
        // this loop has access to it.
        var uses = new Dictionary<long, long>();
        var nameBytes = new List<long>();
        var nameDepths = new List<long>();
        var perDomain = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        var everyNameIsAscii = true;

        using (var command = connection.CreateCommand())
        {
            command.CommandText =
                """
                SELECT o.descriptor_id,
                       c.distinguished_name,
                       length(CAST(c.distinguished_name AS BLOB))
                FROM object_security_descriptor AS o
                JOIN captured_object AS c ON c.object_id = o.object_id
                """;

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var descriptorId = reader.GetInt64(0);
                var name = reader.GetString(1);
                var bytes = reader.GetInt64(2);

                nameBytes.Add(bytes);
                nameDepths.Add(name.Count(c => c == ',') + 1);
                if (bytes != name.Length)
                    everyNameIsAscii = false;

                var domain = DomainOf(name);
                perDomain[domain] = perDomain.GetValueOrDefault(domain) + 1;

                uses[descriptorId] = uses.GetValueOrDefault(descriptorId) + 1;
            }
        }

        if (uses.Count == 0)
        {
            throw new InvalidDataException(
                "No object in this bundle has a stored security descriptor, so there is no "
                + "permission shape to profile.");
        }

        // PASS TWO: each descriptor an object uses, parsed exactly as ObjectPermissions.EntriesOf
        // parses it - out of the stored bytes, where nothing is dropped and nothing is reordered.
        // Reading descriptor_entry instead would describe the canonical projection, which is sorted
        // and deduplicated by ace_hash, and a generator taught to match that would build a forest
        // whose DACLs never repeat a grant. The directory's do.
        var entriesPerDescriptor = new List<long>();
        var objectsPerDescriptor = new List<long>();
        var pairs = new List<(long, long)>();
        var objectTypes = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        var inheritedTypes = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        var trustees = new Dictionary<string, long>(StringComparer.Ordinal);
        var masks = new Dictionary<int, long>();
        var unnamedObjectTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var unnamedInheritedTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        long occurrences = 0, parsed = 0;
        long objectsUnreadable = 0, objectsPartlyParsed = 0, objectsReportingErrors = 0;
        long allow = 0, deny = 0, inherited = 0, notInherited = 0;
        long withObjectType = 0, withInheritedObjectType = 0;
        long inheritOnly = 0, containerInherit = 0, objectInherit = 0, noPropagate = 0;
        long withApplicationData = 0, principalSelf = 0, wellKnown = 0, notWellKnown = 0;
        long unnamedObjectTypeOccurrences = 0, unnamedInheritedTypeOccurrences = 0;

        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT descriptor_id, raw_bytes FROM security_descriptor";

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var descriptorId = reader.GetInt64(0);
                if (!uses.TryGetValue(descriptorId, out var timesUsed))
                    continue;

                var descriptor = SecurityDescriptorParser.Parse((byte[])reader.GetValue(1));
                var aces = descriptor.DaclAces;

                // The P-284 distinction, kept here too. A generator that models these as objects
                // with no permissions would build a forest missing the very cases this profile
                // exists to let the bench find.
                if (descriptor.DaclState == DaclState.Unreadable) objectsUnreadable += timesUsed;
                if (descriptor.DaclCompleteness == DaclCompleteness.Incomplete) objectsPartlyParsed += timesUsed;
                if (descriptor.Errors.Count > 0) objectsReportingErrors += timesUsed;

                entriesPerDescriptor.Add(aces.Count);
                objectsPerDescriptor.Add(timesUsed);
                pairs.Add((aces.Count, timesUsed));
                occurrences += aces.Count * timesUsed;

                foreach (var ace in aces)
                {
                    if (ace.AceType is AceType.AccessAllowed or AceType.AccessAllowedObject) allow += timesUsed;
                    else if (ace.AceType is AceType.AccessDenied or AceType.AccessDeniedObject) deny += timesUsed;

                    if (ace.IsInherited) inherited += timesUsed; else notInherited += timesUsed;

                    if ((ace.InheritanceFlags & 0x08) != 0) inheritOnly += timesUsed;
                    if ((ace.InheritanceFlags & 0x02) != 0) containerInherit += timesUsed;
                    if ((ace.InheritanceFlags & 0x01) != 0) objectInherit += timesUsed;
                    if ((ace.InheritanceFlags & 0x04) != 0) noPropagate += timesUsed;

                    if (ace.ApplicationData.Length > 0) withApplicationData += timesUsed;

                    Count(ace.ObjectTypeGuid, ref withObjectType, ref unnamedObjectTypeOccurrences,
                        objectTypes, unnamedObjectTypes, timesUsed);
                    Count(ace.InheritedObjectTypeGuid, ref withInheritedObjectType,
                        ref unnamedInheritedTypeOccurrences, inheritedTypes, unnamedInheritedTypes, timesUsed);

                    if (ace.TrusteeSid == PrincipalSelf) principalSelf += timesUsed;
                    if (Publishable.Trustee(ace.TrusteeSid))
                    {
                        wellKnown += timesUsed;
                        trustees[ace.TrusteeSid] = trustees.GetValueOrDefault(ace.TrusteeSid) + timesUsed;
                    }
                    else
                    {
                        // Counted, and the SID itself is never put anywhere it could be written out.
                        notWellKnown += timesUsed;
                    }

                    masks[ace.AccessMask] = masks.GetValueOrDefault(ace.AccessMask) + timesUsed;
                }

                if (++parsed % ProgressEvery == 0)
                    Console.Error.WriteLine($"  parsed {parsed,10:N0} of {uses.Count,10:N0} descriptors");
            }
        }

        var build = JudgementForecast.Provenance(
            typeof(ShapeProfile).Assembly.Location, Environment.ProcessPath);

        return new Profile(
            // The bundle is named by its file name alone. A full path carries the operator's
            // account name and often the customer's, and a profile that leaves the environment may
            // not carry either.
            Bundle: Path.GetFileName(Path.TrimEndingDirectorySeparator(bundle)),
            ObjectsCaptured: objectsCaptured,
            ObjectsWithADescriptorStored: nameBytes.Count,
            ObjectsWithNoDescriptorStored: objectsCaptured - nameBytes.Count,
            ObjectsWithReadablePermissions: nameBytes.Count - objectsUnreadable,
            ObjectsWithAnUnreadableDescriptor: objectsUnreadable,
            ObjectsWithAPartiallyParsedDescriptor: objectsPartlyParsed,
            ObjectsWhoseDescriptorReportedErrors: objectsReportingErrors,
            DescriptorsStored: descriptorsStored,
            DescriptorsUsedByObjects: uses.Count,
            Occurrences: occurrences,
            NameBytesPerObject: Distribution.Of([.. nameBytes]),
            NameDepthPerObject: Distribution.Of([.. nameDepths]),
            EntriesPerDescriptor: Distribution.Of([.. entriesPerDescriptor]),
            ObjectsPerDescriptor: Distribution.Of([.. objectsPerDescriptor]),
            EntriesAgainstReuse: Grid.Of("entries per descriptor", "objects per descriptor", pairs),
            Domains: perDomain.Count,
            ObjectsPerDomain: [.. perDomain.Values.OrderByDescending(v => v)],
            EveryNameIsAscii: everyNameIsAscii,
            Aces: new AceShape(
                allow, deny, inherited, notInherited,
                withObjectType, withInheritedObjectType,
                inheritOnly, containerInherit, objectInherit, noPropagate,
                withApplicationData, principalSelf, wellKnown, notWellKnown,
                unnamedObjectTypeOccurrences, unnamedInheritedTypeOccurrences,
                unnamedObjectTypes.Count, unnamedInheritedTypes.Count),
            ObjectTypes: Top(objectTypes),
            InheritedObjectTypes: Top(inheritedTypes),
            Trustees: [.. trustees.OrderByDescending(t => t.Value)
                .Select(t => new Named(t.Key, Publishable.TrusteeName(t.Key)!, t.Value))],
            AccessMasks: [.. masks.OrderByDescending(m => m.Value).Take(32)
                .Select(m => new MaskCount("0x" + m.Key.ToString("X8", CultureInfo.InvariantCulture), m.Value))],
            // The hash names the build; the path it was run from would name the operator's
            // account and often the customer's, so the forecast reports it and this does not.
            BuildSha256: build.Hash,
            BuildSha256Covers: build.Covers,
            AssemblyVersion: typeof(ShapeProfile).Assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                ?? "unknown",
            Runtime: RuntimeInformation.FrameworkDescription);
    }

    /// <summary>
    /// Adds one GUID to the right tally: named if the shipped catalogue knows it, and to a bucket
    /// of anonymous counts if it does not.
    /// </summary>
    private static void Count(
        string? guid,
        ref long present,
        ref long unnamedOccurrences,
        Dictionary<string, long> named,
        HashSet<string> unnamed,
        long timesUsed)
    {
        if (guid is null)
            return;

        present += timesUsed;

        if (Publishable.Schema(guid))
        {
            named[guid] = named.GetValueOrDefault(guid) + timesUsed;
            return;
        }

        // A forest's own extension. How many there are and how often they appear is shape; what
        // they are called, and the value that would let somebody look them up, is not.
        unnamed.Add(guid);
        unnamedOccurrences += timesUsed;
    }

    private static IReadOnlyList<Named> Top(Dictionary<string, long> counts) =>
        [.. counts.OrderByDescending(c => c.Value).Take(TopNamed)
            .Select(c => new Named(c.Key, Publishable.SchemaName(c.Key)!, c.Value))];

    /// <summary>
    /// The <c>DC=</c> suffix of a distinguished name, used as a grouping key and discarded.
    /// </summary>
    /// <remarks>
    /// Returned rather than counted in place only because a dictionary needs a key. The value never
    /// reaches a <see cref="Profile"/>: <see cref="Profile.ObjectsPerDomain"/> takes the tally's
    /// values, sorted, and leaves its keys behind.
    /// </remarks>
    private static string DomainOf(string distinguishedName)
    {
        var first = distinguishedName.IndexOf("DC=", StringComparison.OrdinalIgnoreCase);
        return first < 0 ? string.Empty : distinguishedName[first..];
    }

    /// <summary><c>S-1-5-10</c>, the one well-known SID whose meaning depends on the object.</summary>
    private const string PrincipalSelf = "S-1-5-10";

    private static bool HasTable(SqliteConnection connection, string table)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=$name";
        command.Parameters.AddWithValue("$name", table);
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture) > 0;
    }

    private static long Scalar(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }
}
