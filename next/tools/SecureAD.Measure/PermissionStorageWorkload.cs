using System.Globalization;
using System.Security.AccessControl;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;

namespace SecureAD.Measure;

/// <summary>
/// Writes a synthetic bundle shaped like the measured production capture, so that what permission
/// storage costs can be read off a file rather than projected from one.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> P-271 measured the first sealed nine-domain capture: 141,706,338 access
/// control entry rows holding 481,967 distinct entries, each stored 294 times, in an evidence file
/// of 51.08 GB that is 96% permissions. P-272 changes how those are stored. The owner raised this
/// risk during the original design and was told the design was sound, so the saving is to be
/// <i>measured</i> before and after against the same shape, not argued.
/// </para>
/// <para>
/// <b>Why the existing generator could not be reused.</b>
/// <see cref="RequesterWorkload"/> gives every filler entry a trustee derived from the object
/// counter, so every entry it writes is distinct. That is the exact opposite of the shape under
/// test, and measuring it would show no repetition to remove.
/// </para>
/// <para>
/// <b>The shape is a model of inheritance, and its answers are arithmetic.</b> Every descriptor
/// carries a block of entries that the whole forest inherits, plus a window that advances as the
/// tree is walked - which is what a deep organisational-unit tree produces, and which makes no two
/// descriptors byte-identical while almost every entry in them repeats. How many distinct entries
/// that yields is computed here, in <see cref="Shape"/>, and then checked against what the sealed
/// bundle reports. A generator whose own output is its only description of itself cannot be wrong
/// out loud.
/// </para>
/// <para>
/// <b>Nothing here contacts a directory</b> and nothing is written outside the named output
/// directory.
/// </para>
/// </remarks>
internal static class PermissionStorageWorkload
{
    private const string Root = "DC=measure,DC=lab";
    private static readonly DateTimeOffset When = new(2026, 9, 23, 0, 0, 0, TimeSpan.Zero);

    /// <summary>Objects the production capture read.</summary>
    private const long ProductionObjects = 939_700;

    /// <summary>Objects whose permissions could not be read at all - 30% of the forest.</summary>
    private const long ProductionUnreadable = 280_782;

    /// <summary>Distinct security descriptors the production capture stored.</summary>
    private const long ProductionDescriptors = 271_845;

    /// <summary>Distinct access control entries among the 141,706,338 rows stored.</summary>
    private const long ProductionDistinctEntries = 481_967;

    /// <summary>141,706,338 rows over 271,845 descriptors.</summary>
    private const int EntriesPerDescriptor = 521;

    /// <summary>
    /// Entries every descriptor in the forest carries, standing for what is inherited from the
    /// domain root. This block is what repeats hardest.
    /// </summary>
    private const int SharedEntries = 21;

    /// <summary>The first few of the shared block are explicit, so the data is not uniformly inherited.</summary>
    private const int ExplicitEntries = 3;

    /// <summary>The per-descriptor window, standing for what is inherited from intermediate containers.</summary>
    private const int WindowEntries = EntriesPerDescriptor - SharedEntries;

    /// <summary>
    /// The synthetic shape, scaled from the measured production figures.
    /// </summary>
    /// <param name="Scale">The fraction of production being written.</param>
    /// <param name="Descriptors">Distinct security descriptors, each with its own entry list.</param>
    /// <param name="DistinctEntries">Distinct entries across the whole bundle.</param>
    /// <param name="ReadableObjects">Objects carrying a descriptor, sharing them as production does.</param>
    /// <param name="UnreadableObjects">Objects whose permissions this run could not read.</param>
    private sealed record Shape(
        double Scale, int Descriptors, int DistinctEntries, int ReadableObjects, int UnreadableObjects)
    {
        /// <summary>The pool the advancing window draws from, outside the always-inherited block.</summary>
        public int Pool => DistinctEntries - SharedEntries;

        /// <summary>
        /// How far the window advances per descriptor. Chosen so the windows between them cover the
        /// whole pool exactly once, which is what makes <see cref="DistinctEntries"/> a computed
        /// answer rather than an observed one.
        /// </summary>
        public int Stride => (Pool + Descriptors - 1) / Descriptors;

        /// <summary>Entry rows a reader would see across the bundle, before any sharing.</summary>
        public long Entries => (long)Descriptors * EntriesPerDescriptor;

        public long Objects => ReadableObjects + (long)UnreadableObjects;

        public static Shape Of(double scale)
        {
            if (!double.IsFinite(scale) || scale <= 0 || scale > 1)
                throw new ArgumentOutOfRangeException(nameof(scale), "Scale must be greater than 0 and at most 1.");

            var descriptors = (int)Math.Max(1, Math.Round(ProductionDescriptors * scale));
            var distinct = (int)Math.Max(
                EntriesPerDescriptor + 1L, Math.Round(ProductionDistinctEntries * scale));
            var readable = (int)Math.Max(
                descriptors, Math.Round((ProductionObjects - ProductionUnreadable) * scale));
            var unreadable = (int)Math.Round(ProductionUnreadable * scale);

            var shape = new Shape(scale, descriptors, distinct, readable, unreadable);

            // The windows have to be able to cover the pool without leaving gaps, or the distinct
            // count computed here would be higher than the bundle's and the check below would fail
            // for a reason that is about this generator rather than about storage.
            if (shape.Stride > WindowEntries)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(scale),
                    $"At scale {scale} each descriptor would have to introduce {shape.Stride} new "
                    + $"entries to cover a pool of {shape.Pool}, which is more than the "
                    + $"{WindowEntries} its window holds. Raise the scale.");
            }

            return shape;
        }
    }

    // --permission-storage NEW_OUTPUT SCALE
    internal static int Run(string[] args) =>
        Run(args, Path.Combine(AppContext.BaseDirectory, "measurement-build.json"));

    internal static int Run(string[] args, string build)
    {
        if (args.Length != 2)
            throw new ArgumentException("NEW_OUTPUT and SCALE are required.");

        var output = Path.GetFullPath(args[0]);
        if (Directory.Exists(output) || File.Exists(output))
            throw new IOException("Retain the existing workload; choose a new output directory.");

        var shape = Shape.Of(double.Parse(args[1], CultureInfo.InvariantCulture));
        Directory.CreateDirectory(output);

        try
        {
            if (File.Exists(build))
                File.Copy(build, Path.Combine(output, "measurement-build.json"));

            File.WriteAllText(Path.Combine(output, "requested-shape.json"), JsonSerializer.Serialize(new
            {
                shape.Scale,
                shape.Descriptors,
                EntriesPerDescriptor,
                ExpectedEntryRows = shape.Entries,
                ExpectedDistinctEntries = shape.DistinctEntries,
                shape.ReadableObjects,
                shape.UnreadableObjects,
                shape.Stride,
                CanonicalizationVersion = AceCanonicalization.Version,
                ModelledOn = "The nine-domain production capture sealed 2026-09-23 (P-271).",
                Synthetic = true,
                Executable = Environment.ProcessPath,
                ExecutableSha256 = BundleSealing.HashFile(Environment.ProcessPath!),
                Runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
            }));

            var bundle = Path.Combine(output, "bundle");
            Directory.CreateDirectory(bundle);
            Write(bundle, shape);
            Verify(bundle, shape, output);
            return 0;
        }
        catch (Exception error)
        {
            File.WriteAllText(Path.Combine(output, "failure.txt"), error.ToString());
            Console.Error.WriteLine(error);
            return 1;
        }
    }

    private static void Write(string bundle, Shape shape)
    {
        using var writer = BundleWriter.Create(bundle, When);

        var parent = "OU=Accounts,OU=Operations,OU=Directory,OU=Synthetic," + Root;
        var coverage = new PartitionCoverage(
            Root, NamingContextKind.Domain, "dc01.measure.lab",
            ConnectionSecurityLevel.SignedAndSealed, 1, checked((int)shape.Objects), 1, [], false);
        writer.WriteCoverage(coverage);

        // One descriptor serves several objects, as production's 271,845 descriptors serve its
        // 658,918 readable objects. The bytes are built once per descriptor and normalised once per
        // object, because that is what capture does and the measurement has to cost what capture
        // costs on both sides of the change.
        var descriptor = -1;
        var perDescriptor = (double)shape.ReadableObjects / shape.Descriptors;
        byte[] bytes = [];

        for (var o = 0; o < shape.ReadableObjects; o++)
        {
            var wanted = Math.Min(shape.Descriptors - 1, (int)(o / perDescriptor));
            if (wanted != descriptor)
            {
                descriptor = wanted;
                bytes = DescriptorBytes(shape, descriptor);
            }

            var guid = Guid.NewGuid();
            var id = writer.WriteObject(new(coverage, Dn(parent, $"Object{o:D8}"), guid,
                [Text("objectClass", "top", "user"),
                 Binary("objectSid", Sid.ToBytes($"S-1-5-21-40-50-60-{1_000_000L + o}")!),
                 Text("userAccountControl", "512"), Text("primaryGroupID", "513")], When));

            writer.WriteSecurityDescriptor(
                id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));

            if ((o + 1) % 5_000 == 0)
                Console.WriteLine($"  {o + 1:N0} of {shape.ReadableObjects:N0} objects with permissions");
        }

        // The 30% of the forest whose permissions nobody could read. They are here because they are
        // in production and because they cost rows in a different table, so leaving them out would
        // make the file smaller than the shape being modelled.
        for (var u = 0; u < shape.UnreadableObjects; u++)
        {
            var id = writer.WriteObject(new(coverage, Dn(parent, $"Refused{u:D8}"), Guid.NewGuid(),
                [Text("objectClass", "top", "user")], When));
            writer.WriteUnreadableSecurityDescriptor(id, "The directory refused the security descriptor.");
        }

        writer.Complete(
            RunCoverage.Of(
                CoverageId.ForDomains("measure.lab", ["measure.lab"]),
                [DomainCoverage.Read("measure.lab")],
                [ForestPartitionCoverage.Read("CN=Configuration," + Root, NamingContextKind.Configuration),
                 ForestPartitionCoverage.Read("CN=Schema,CN=Configuration," + Root, NamingContextKind.Schema)],
                SysvolCoverage.Of([])),
            When.AddMinutes(1));
    }

    /// <summary>
    /// One descriptor's bytes: the block the whole forest inherits, then the window this descriptor
    /// sits at.
    /// </summary>
    private static byte[] DescriptorBytes(Shape shape, int descriptor)
    {
        var sddl = new StringBuilder("O:SYG:SYD:");

        for (var i = 0; i < SharedEntries; i++)
            Append(sddl, i);

        for (var k = 0; k < WindowEntries; k++)
            Append(sddl, SharedEntries + (((long)descriptor * shape.Stride + k) % shape.Pool));

        var raw = new RawSecurityDescriptor(sddl.ToString());
        var bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        return bytes;
    }

    /// <summary>
    /// One entry, identified by its index in the pool. The index decides the trustee and whether the
    /// entry is inherited, so the same index is the same entry wherever it appears.
    /// </summary>
    private static void Append(StringBuilder sddl, long index) =>
        sddl.Append(index < ExplicitEntries ? "(A;;RP;;;S-1-5-21-90-91-92-" : "(A;ID;RP;;;S-1-5-21-90-91-92-")
            .Append((2_000_000L + index).ToString(CultureInfo.InvariantCulture))
            .Append(')');

    /// <summary>
    /// Reads the sealed bundle back and refuses a shape that is not the one that was asked for.
    /// </summary>
    /// <remarks>
    /// <b>The counts come from two different tables and one of them is computed here.</b> Reading a
    /// number out of the bundle and comparing it with another number out of the same bundle proves
    /// nothing - that is the check that could never fail, found twice this month. The expected
    /// distinct-entry count is arithmetic done before anything was written.
    /// </remarks>
    private static void Verify(string bundle, Shape shape, string output)
    {
        var evidence = BundleLayout.EvidencePath(bundle);
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = evidence,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        connection.Open();

        var objects = Scalar(connection, "SELECT COUNT(*) FROM captured_object");
        var descriptors = Scalar(connection, "SELECT COUNT(*) FROM security_descriptor");
        var unreadable = Scalar(connection, "SELECT COUNT(*) FROM unreadable_security_descriptor");
        var entries = Scalar(connection, EntryRowCount(connection));
        var distinct = Scalar(connection, DistinctEntryCount(connection));

        if (objects != shape.Objects || descriptors != shape.Descriptors
            || unreadable != shape.UnreadableObjects || entries != shape.Entries
            || distinct != shape.DistinctEntries)
        {
            throw new InvalidDataException(
                $"The sealed bundle holds {objects:N0} objects, {descriptors:N0} descriptors, "
                + $"{unreadable:N0} refused, {entries:N0} entry rows and {distinct:N0} distinct "
                + $"entries. The shape asked for {shape.Objects:N0}, {shape.Descriptors:N0}, "
                + $"{shape.UnreadableObjects:N0}, {shape.Entries:N0} and {shape.DistinctEntries:N0}.");
        }

        var measured = new
        {
            shape.Scale,
            Objects = objects,
            Descriptors = descriptors,
            RefusedPermissions = unreadable,
            EntryRows = entries,
            DistinctEntries = distinct,
            StoredEntryRows = Scalar(connection, StoredEntryRowCount(connection)),
            EvidenceBytes = new FileInfo(evidence).Length,
            EvidenceSha256 = BundleSealing.HashFile(evidence),
            CanonicalizationVersion = AceCanonicalization.Version,
        };

        File.WriteAllText(Path.Combine(output, "verified-shape.json"), JsonSerializer.Serialize(measured));
        Console.WriteLine(JsonSerializer.Serialize(measured));
    }

    /// <summary>
    /// How many entries a reader would see: one per position in every descriptor's list.
    /// </summary>
    /// <remarks>
    /// Written for either storage shape so that the same executable can describe a bundle written
    /// before the change and one written after it. This is a measurement tool and the comparison is
    /// its whole purpose; the product itself carries no such fork.
    /// </remarks>
    private static string EntryRowCount(SqliteConnection connection) =>
        HasTable(connection, "descriptor_entry")
            ? "SELECT COUNT(*) FROM descriptor_entry"
            : "SELECT COUNT(*) FROM ace";

    /// <summary>How many rows the bundle actually holds to say that - the number under test.</summary>
    private static string StoredEntryRowCount(SqliteConnection connection) =>
        HasTable(connection, "access_entry")
            ? "SELECT COUNT(*) FROM access_entry"
            : "SELECT COUNT(*) FROM ace";

    /// <summary>
    /// How many of those entries are distinct from one another, by what Windows defines an entry
    /// by rather than by <c>ace_hash</c>.
    /// </summary>
    private static string DistinctEntryCount(SqliteConnection connection) =>
        """
        SELECT COUNT(*) FROM (
            SELECT DISTINCT trustee_id, access_mask, ace_type, object_type_guid,
                            inherited_object_type_guid, is_inherited, inheritance_flags,
                            propagation_flags
            FROM
        """
        + (HasTable(connection, "access_entry") ? " access_entry)" : " ace)");

    private static bool HasTable(SqliteConnection connection, string table)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = $name";
        command.Parameters.AddWithValue("$name", table);
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture) == 1;
    }

    private static long Scalar(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    /// <summary>A name about as long as production's, whose average is 97 characters.</summary>
    private static string Dn(string parent, string name) =>
        "CN=" + name.PadRight(Math.Max(name.Length, 97 - parent.Length - 4), 'x') + "," + parent;

    private static EvidenceAttribute Text(string name, params string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());

    private static EvidenceAttribute Binary(string name, byte[] value) =>
        new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(value)]);
}
