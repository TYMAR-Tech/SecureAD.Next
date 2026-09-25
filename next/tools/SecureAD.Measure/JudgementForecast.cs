using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Kernel.Security;

namespace SecureAD.Measure;

/// <summary>
/// Reports how large a judgement of a sealed bundle will be before anyone starts one, so the scope
/// of <c>P-280</c> can be chosen from the owner's own forest rather than from a laboratory.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> After <c>P-279</c> a judgement is almost entirely
/// <c>permission_classification_entry</c>, and every row of it carries the object's distinguished
/// name three times - in the row, in the <c>(target, position)</c> primary key and in the
/// <c>(target, ordinal)</c> unique index. Whether an integer identifier alone is enough turns on
/// the average name length, which nobody has measured. The owner works only inside the production
/// environment and cannot export a bundle, so a scope chosen by guesswork costs him a trip.
/// </para>
/// <para>
/// <b>It counts stored entries, not projected ones, and that is the whole correctness of it.</b>
/// <c>descriptor_entry</c> and <c>captured_object.ace_count</c> hold the canonical projection -
/// sorted into evaluation order and deduplicated by <c>ace_hash</c> by
/// <see cref="SecureAD.Kernel.Security.AceNormalizer"/>. Judging writes one row per entry read back
/// out of <c>security_descriptor.raw_bytes</c> (<c>ObjectPermissions.EntriesOf</c>), where nothing
/// is dropped and nothing is reordered; a lab bundle measured 12,603 stored against 12,600
/// projected. Counting the cheap column would therefore under-report, and would do it invisibly -
/// a forecast that passes while measuring the wrong thing. So each descriptor an object actually
/// uses is parsed here exactly as the reader parses it.
/// </para>
/// <para>
/// <b>Each distinct descriptor is parsed once.</b> 271,901 parses rather than 659,196 on the
/// production capture, because a descriptor's entry count does not depend on which object carries
/// it. The uses are counted separately and multiplied in.
/// </para>
/// <para>
/// <b>The three copies of the name are arithmetic on two measured numbers, not an estimate.</b>
/// The cost of one copy is the sum over objects of their own descriptor's entry count times their
/// own name length, so nothing here assumes that entry count and descriptor reuse are unrelated.
/// The specification flags that assumption as unverifiable from a summary and plausibly false,
/// because descriptors high in the tree are both the most reused and the ones carrying the deepest
/// inherited lists. Reporting the occurrence-weighted mean name beside the plain mean makes any
/// such relationship visible as a number rather than argued about.
/// </para>
/// <para>
/// <b>It reads and never writes, and it does not open the bundle immutable.</b>
/// <c>--descriptor-redundancy</c> explains why: that flag asserts the file cannot be changing
/// underneath, which is a claim only a verified seal earns. Read-only writes nothing either way,
/// which is the property that matters on a customer's only copy.
/// </para>
/// </remarks>
internal static class JudgementForecast
{
    /// <summary>
    /// What one occurrence row costs beyond the three copies of the distinguished name.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Measured, not chosen.</b> <c>next/artifacts/p279-after</c> holds a finished judgement of
    /// 7,189,590,016 bytes over 17,164,866 occurrences - 418.9 bytes each - and every object in it
    /// carries a name of exactly 97 bytes, so the three copies account for 291 and this is what is
    /// left. Recalculate rather than adjust it: the number is the output of a measurement, and
    /// editing it by hand would make every projection below unfalsifiable.
    /// </para>
    /// <para>
    /// <b>It is used only when the bundle being forecast has no finished judgement</b>, which is
    /// the production case this mode exists for. When one is present the value is derived from it
    /// instead, and the report says which was used.
    /// </para>
    /// <para>
    /// <b>It is a slight overstatement, and knowingly so.</b> <c>dbstat</c> was not compiled into
    /// the SQLite that measured it, so the whole judgement file stood in for the occurrence table
    /// and this figure carries the other tables' bytes spread across the occurrences. Those tables
    /// are small against 17 million rows - 46,985 object rows and 24,098 distinct entries - and
    /// erring high is the safe direction for a figure an operator uses to decide whether a run will
    /// fit.
    /// </para>
    /// </remarks>
    private const long CalibratedFixedBytesPerOccurrence = 128;

    /// <summary>
    /// What one copy of an integer object identifier would cost in place of the name.
    /// </summary>
    /// <remarks>
    /// SQLite stores an integer in a record as a variable-length value behind a serial-type byte,
    /// so an identifier counting up to a forest's object count - 940,067 on the production capture -
    /// occupies three bytes and a header. Index entries carry it the same way. This is the one
    /// figure below that is reasoned rather than measured, and it is small enough that being wrong
    /// by a byte changes no decision.
    /// </remarks>
    private const long IntegerIdentifierBytesPerCopy = 4;

    /// <summary>How many times the distinguished name appears per occurrence row.</summary>
    /// <remarks>The row, the <c>(target, position)</c> primary key, the <c>(target, ordinal)</c> unique index.</remarks>
    private const long CopiesOfTheName = 3;

    /// <summary>Descriptors parsed between progress lines, so a long scan does not look hung.</summary>
    private const int ProgressEvery = 20_000;

    // --judgement-forecast BUNDLE_DIRECTORY
    internal static int Run(string[] args)
    {
        if (args.Length != 1)
            throw new ArgumentException("BUNDLE_DIRECTORY is required.");

        Forecast forecast;
        try
        {
            forecast = Of(Path.GetFullPath(args[0]));
        }
        catch (InvalidDataException refused)
        {
            Console.Error.WriteLine(refused.Message);
            return 1;
        }

        Console.WriteLine(JsonSerializer.Serialize(forecast, new JsonSerializerOptions { WriteIndented = true }));
        Report(forecast);
        return 0;
    }

    /// <summary>Forecasts the judgement of the bundle in <paramref name="bundle"/>.</summary>
    /// <exception cref="InvalidDataException">
    /// The directory holds no sealed evidence, was written by a build this tool does not read, or
    /// holds no object with a readable descriptor. Each is said by name rather than by stack trace,
    /// which is the <c>P-274</c> repair applied here from the start.
    /// </exception>
    internal static Forecast Of(string bundle)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundle);

        var evidence = BundleLayout.EvidencePath(bundle);
        if (!File.Exists(evidence))
        {
            throw new InvalidDataException(
                $"There is no sealed evidence file in '{bundle}'. Name the run's own folder rather "
                + "than the library that holds several of them.");
        }

        // READ-ONLY, and deliberately not immutable=1, for the reason given on the type.
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = evidence,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        connection.Open();

        // P-274: a bundle written by another build must be refused by name rather than by stack
        // trace. These three tables predate and survive P-272, so a bundle of either schema is
        // forecast rather than turned away - but one that has neither is said so plainly.
        string[] required = ["captured_object", "security_descriptor", "object_security_descriptor"];
        foreach (var table in required)
        {
            if (!HasTable(connection, table))
            {
                throw new InvalidDataException(
                    $"This bundle has no '{table}' table, so its judgement cannot be forecast. "
                    + "It was written by a build this tool does not read.");
            }
        }

        return Measure(connection, bundle, evidence);
    }

    /// <summary>What one bundle's judgement was forecast to cost.</summary>
    /// <param name="Occurrences">
    /// The exact number of rows <c>permission_classification_entry</c> will hold: the sum over
    /// objects of their own descriptor's stored entry count. This replaces the specification's
    /// approximate 344 million, which was entries times reuse off the deduplicated projection.
    /// </param>
    /// <param name="DistinguishedNameBytesAcrossOccurrences">
    /// One copy of the name across every occurrence row, weighted per object rather than averaged.
    /// </param>
    /// <param name="MeanNameBytesPerOccurrence">
    /// Compare with <paramref name="MeanNameBytesPerObject"/>. If the occurrence-weighted mean is
    /// the larger, objects with longer names carry more entries and any projection built on the
    /// plain average understates the cost.
    /// </param>
    internal sealed record Forecast(
        string Bundle,
        long ObjectsCaptured,
        long ObjectsWithReadablePermissions,
        long DescriptorsStored,
        long DescriptorsUsedByObjects,
        long Occurrences,
        long NameBytesAcrossObjects,
        double MeanNameBytesPerObject,
        double MeanNameCharactersPerObject,
        long LongestNameBytes,
        long DistinguishedNameBytesAcrossOccurrences,
        double MeanNameBytesPerOccurrence,
        long ThreeCopiesOfTheNameBytes,
        long FixedBytesPerOccurrence,
        string FixedBytesPerOccurrenceSource,
        long ProjectedOccurrenceBytes,
        long ProjectedWithIntegerIdentifierBytes,
        long ProjectedSavingBytes,
        Shapes Shapes,
        MeasuredJudgement? Judgement,
        string? Executable,
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
        /// <b>Deliberately not "nothing was written".</b> That was the wording until a forecast of
        /// <c>next/artifacts/p279-after</c> left both databases byte for byte identical and both
        /// <c>-shm</c> files carrying a new timestamp. A shared-memory index is SQLite's own
        /// scratch, is not evidence, and is outside the seal - but a bundle directory whose
        /// contents changed is not a bundle where nothing was written, and an audit tool may not
        /// be the thing that rounds a claim up.
        /// </remarks>
        public bool OpenedReadOnly => true;

        /// <summary>
        /// The floor, stated as a field so it is not read as a total. The calibration bundle
        /// derived no control edges at all, so a real forest adds that whole phase on top.
        /// </summary>
        public bool ProjectionIsAFloor => true;
    }

    /// <summary>
    /// A judgement this bundle already holds, read so the forecast can be checked against it.
    /// </summary>
    /// <remarks>
    /// This is what stops the forecast being a calculation nobody can falsify. On a bundle with a
    /// finished judgement, <see cref="ForecastOccurrences"/> must equal <see cref="OccurrenceRows"/>
    /// exactly - the forecast and the thing forecast are then the same number, counted two
    /// different ways - and the projected bytes must land near the observed bytes.
    /// </remarks>
    internal sealed record MeasuredJudgement(
        string Generation,
        long OccurrenceRows,
        long ForecastOccurrences,
        bool OccurrenceCountAgrees,
        long ObjectRows,
        long JudgementFileBytes,
        long OccurrenceStorageBytes,
        string OccurrenceStorageSource,
        double ObservedBytesPerOccurrence,
        double ImpliedFixedBytesPerOccurrence);

    private static Forecast Measure(SqliteConnection connection, string bundle, string evidence)
    {
        var objectsCaptured = Scalar(connection, "SELECT COUNT(*) FROM captured_object");
        var descriptorsStored = Scalar(connection, "SELECT COUNT(*) FROM security_descriptor");

        // PASS ONE: every object that has a descriptor, with its own name length. Both lengths are
        // taken in SQL rather than by marshalling 659,196 strings into this process. LENGTH of a
        // BLOB is bytes; LENGTH of TEXT is characters, and the store holds UTF-8, so the byte
        // figure is the one the three copies are actually paid in.
        var uses = new Dictionary<long, long>();
        var nameBytesPerDescriptor = new Dictionary<long, long>();
        long objectsWithPermissions = 0, nameBytesAcrossObjects = 0, nameCharactersAcrossObjects = 0, longestName = 0;

        using (var command = connection.CreateCommand())
        {
            command.CommandText =
                """
                SELECT o.descriptor_id,
                       length(CAST(c.distinguished_name AS BLOB)),
                       length(c.distinguished_name)
                FROM object_security_descriptor AS o
                JOIN captured_object AS c ON c.object_id = o.object_id
                """;

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var descriptorId = reader.GetInt64(0);
                var nameBytes = reader.GetInt64(1);

                objectsWithPermissions++;
                nameBytesAcrossObjects += nameBytes;
                nameCharactersAcrossObjects += reader.GetInt64(2);
                longestName = Math.Max(longestName, nameBytes);

                uses[descriptorId] = uses.GetValueOrDefault(descriptorId) + 1;
                nameBytesPerDescriptor[descriptorId] = nameBytesPerDescriptor.GetValueOrDefault(descriptorId) + nameBytes;
            }
        }

        if (objectsWithPermissions == 0)
        {
            throw new InvalidDataException(
                "No object in this bundle has a readable security descriptor, so a judgement of it "
                + "would hold no permission occurrences and there is nothing to forecast.");
        }

        // PASS TWO: the entry count of each descriptor an object actually uses, read the way the
        // product reads it. A descriptor no object carries is skipped rather than parsed.
        //
        // Three totals come out of the same parse, because each prices a different shape the
        // occurrence table could take. `occurrences` is what it holds today, one row per object per
        // entry. `entryRowsPerDescriptor` is what it would hold if it were keyed the way evidence
        // already keys `descriptor_entry` - once per descriptor, joined to objects through
        // `object_security_descriptor`. The two GUID counts price the columns that are functions of
        // the entry and are copied onto every occurrence of it.
        long occurrences = 0, nameBytesAcrossOccurrences = 0, parsed = 0;
        long entryRowsPerDescriptor = 0;
        long occurrencesWithObjectType = 0, occurrencesWithInheritedObjectType = 0;
        long descriptorRowsWithObjectType = 0, descriptorRowsWithInheritedObjectType = 0;
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT descriptor_id, raw_bytes FROM security_descriptor";

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var descriptorId = reader.GetInt64(0);
                if (!uses.TryGetValue(descriptorId, out var timesUsed))
                    continue;

                var aces = SecurityDescriptorParser.Parse((byte[])reader.GetValue(1)).DaclAces;
                var entries = aces.Count;

                // `object_schema` and `inherited_schema` are written as
                // `entry.ObjectType?.Guid`, and PermissionClassification.Support returns null only
                // when the GUID is null - so the column is non-null exactly when the entry carries
                // one. Counted here rather than assumed.
                long withObjectType = 0, withInheritedObjectType = 0;
                foreach (var ace in aces)
                {
                    if (ace.ObjectTypeGuid is not null) withObjectType++;
                    if (ace.InheritedObjectTypeGuid is not null) withInheritedObjectType++;
                }

                occurrences += entries * timesUsed;
                nameBytesAcrossOccurrences += entries * nameBytesPerDescriptor[descriptorId];
                entryRowsPerDescriptor += entries;
                occurrencesWithObjectType += withObjectType * timesUsed;
                occurrencesWithInheritedObjectType += withInheritedObjectType * timesUsed;
                descriptorRowsWithObjectType += withObjectType;
                descriptorRowsWithInheritedObjectType += withInheritedObjectType;

                if (++parsed % ProgressEvery == 0)
                    Console.Error.WriteLine($"  parsed {parsed,10:N0} of {uses.Count,10:N0} descriptors");
            }
        }

        var judgement = ReadJudgement(bundle, occurrences, nameBytesAcrossOccurrences);
        var build = Provenance(typeof(JudgementForecast).Assembly.Location, Environment.ProcessPath);

        // A judgement of this very bundle beats a constant carried from another one. When one is
        // present the fixed cost is derived from it; otherwise the calibration is used and named.
        var fixedPerOccurrence = judgement is not null
            ? (long)Math.Round(judgement.ImpliedFixedBytesPerOccurrence)
            : CalibratedFixedBytesPerOccurrence;

        var threeCopies = CopiesOfTheName * nameBytesAcrossOccurrences;
        var asItStands = (occurrences * fixedPerOccurrence) + threeCopies;
        var withIdentifier = (occurrences * fixedPerOccurrence)
            + (CopiesOfTheName * IntegerIdentifierBytesPerCopy * occurrences);

        // The distinct entries a normalised table would hold its classification against. P-272
        // already stores them once each, so this is a count rather than a projection.
        var distinctEntries = HasTable(connection, "access_entry")
            ? Scalar(connection, "SELECT COUNT(*) FROM access_entry")
            : 0;

        var shapes = new Shapes(
            AsItStands: RowModel.AsItStands(
                occurrences, nameBytesAcrossOccurrences, occurrencesWithObjectType, occurrencesWithInheritedObjectType),
            WithIntegerIdentifier: RowModel.WithIntegerKey(
                occurrences, occurrencesWithObjectType, occurrencesWithInheritedObjectType),
            PerDescriptor: RowModel.WithIntegerKey(
                entryRowsPerDescriptor, descriptorRowsWithObjectType, descriptorRowsWithInheritedObjectType),
            Normalised: distinctEntries == 0
                ? 0
                : RowModel.Normalised(entryRowsPerDescriptor, distinctEntries),
            OccurrenceRows: occurrences,
            PerDescriptorRows: entryRowsPerDescriptor,
            DistinctEntries: distinctEntries,
            OccurrencesWithObjectType: occurrencesWithObjectType,
            OccurrencesWithInheritedObjectType: occurrencesWithInheritedObjectType,
            ModelledBytesPerOccurrence: occurrences == 0
                ? 0
                : Math.Round(
                    RowModel.AsItStands(
                        occurrences, nameBytesAcrossOccurrences,
                        occurrencesWithObjectType, occurrencesWithInheritedObjectType) / (double)occurrences, 1));

        return new Forecast(
            Bundle: evidence,
            ObjectsCaptured: objectsCaptured,
            ObjectsWithReadablePermissions: objectsWithPermissions,
            DescriptorsStored: descriptorsStored,
            DescriptorsUsedByObjects: uses.Count,
            Occurrences: occurrences,
            NameBytesAcrossObjects: nameBytesAcrossObjects,
            MeanNameBytesPerObject: Math.Round((double)nameBytesAcrossObjects / objectsWithPermissions, 1),
            MeanNameCharactersPerObject: Math.Round((double)nameCharactersAcrossObjects / objectsWithPermissions, 1),
            LongestNameBytes: longestName,
            DistinguishedNameBytesAcrossOccurrences: nameBytesAcrossOccurrences,
            MeanNameBytesPerOccurrence: occurrences == 0
                ? 0
                : Math.Round((double)nameBytesAcrossOccurrences / occurrences, 1),
            ThreeCopiesOfTheNameBytes: threeCopies,
            FixedBytesPerOccurrence: fixedPerOccurrence,
            FixedBytesPerOccurrenceSource: judgement is not null
                ? "Derived from this bundle's own finished judgement."
                : "Calibrated on next/artifacts/p279-after; this bundle has no finished judgement.",
            ProjectedOccurrenceBytes: asItStands,
            ProjectedWithIntegerIdentifierBytes: withIdentifier,
            ProjectedSavingBytes: asItStands - withIdentifier,
            Shapes: shapes,
            Judgement: judgement,
            Executable: Environment.ProcessPath,
            BuildSha256: build.Hash,
            BuildSha256Covers: build.Covers,
            AssemblyVersion: typeof(JudgementForecast).Assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                ?? "unknown",
            Runtime: RuntimeInformation.FrameworkDescription);
    }

    /// <summary>
    /// What the occurrence table would cost in each shape it could take, from the same measurements.
    /// </summary>
    /// <param name="PerDescriptorRows">
    /// One row per descriptor per entry, which is how evidence already keys <c>descriptor_entry</c>.
    /// Objects reach their own rows through <c>object_security_descriptor</c>, which exists already.
    /// </param>
    /// <param name="DistinctEntries">
    /// How many rows a table of classifications would hold, since the classification of an entry is
    /// a function of the entry alone.
    /// </param>
    /// <param name="ModelledBytesPerOccurrence">
    /// The model's own answer for the shape that exists today. Compare it with the observed figure
    /// where a judgement is present: it should be a little under, never over.
    /// </param>
    internal sealed record Shapes(
        long AsItStands,
        long WithIntegerIdentifier,
        long PerDescriptor,
        long Normalised,
        long OccurrenceRows,
        long PerDescriptorRows,
        long DistinctEntries,
        long OccurrencesWithObjectType,
        long OccurrencesWithInheritedObjectType,
        double ModelledBytesPerOccurrence);

    /// <summary>
    /// The finished judgement of this bundle, if it has one, read so the forecast can be checked.
    /// </summary>
    /// <remarks>
    /// Absent on the production capture, which is the case this whole mode exists for, so nothing
    /// here may fail the run. Present on the bench bundle, where it is the only thing standing
    /// between this tool and a projection nobody can contradict.
    /// </remarks>
    private static MeasuredJudgement? ReadJudgement(
        string bundle, long forecastOccurrences, long nameBytesAcrossOccurrences)
    {
        var resolved = AnalysisStoreLifecycle.Resolve(bundle, AnalysisStoreKind.Judgement);
        if (!resolved.IsSuccess)
            return null;

        var path = BundleLayout.AnalysisGenerationDataPath(
            bundle, AnalysisStoreKind.Judgement, resolved.Value.GenerationId);
        if (!File.Exists(path))
            return null;

        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        connection.Open();

        if (!HasTable(connection, "permission_classification_entry"))
            return null;

        var rows = Scalar(connection, "SELECT COUNT(*) FROM permission_classification_entry");
        if (rows == 0)
            return null;

        var fileBytes = new FileInfo(path).Length;
        var (storageBytes, source) = OccurrenceStorage(connection, fileBytes);

        // What is left once this bundle's own three name copies are taken out. The forecast is
        // only as good as this number, so it is reported rather than folded away.
        var implied = Math.Max(0, storageBytes - (CopiesOfTheName * nameBytesAcrossOccurrences))
            / (double)rows;

        return new MeasuredJudgement(
            Generation: resolved.Value.GenerationId.ToString("D"),
            OccurrenceRows: rows,
            ForecastOccurrences: forecastOccurrences,
            OccurrenceCountAgrees: rows == forecastOccurrences,
            ObjectRows: HasTable(connection, "permission_classification_object")
                ? Scalar(connection, "SELECT COUNT(*) FROM permission_classification_object")
                : 0,
            JudgementFileBytes: fileBytes,
            OccurrenceStorageBytes: storageBytes,
            OccurrenceStorageSource: source,
            ObservedBytesPerOccurrence: Math.Round(storageBytes / (double)rows, 1),
            ImpliedFixedBytesPerOccurrence: Math.Round(implied, 1));
    }

    /// <summary>
    /// The bytes the occurrence rows and their two indexes actually occupy.
    /// </summary>
    /// <remarks>
    /// <c>dbstat</c> measures it per table and per index, which is what turns "the file is mostly
    /// this table" from an assumption into a figure. It is a compile-time option and may be absent,
    /// in which case the whole judgement file is used - the same basis as the published 419 bytes
    /// per occurrence - and the report says which was used, because the two are not the same claim.
    /// </remarks>
    private static (long Bytes, string Source) OccurrenceStorage(SqliteConnection connection, long fileBytes)
    {
        try
        {
            using var command = connection.CreateCommand();
            command.CommandText =
                """
                SELECT COALESCE(SUM(pgsize), 0) FROM dbstat
                WHERE name = 'permission_classification_entry'
                   OR name LIKE 'sqlite_autoindex_permission_classification_entry%'
                """;
            var measured = Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
            if (measured > 0)
                return (measured, "dbstat: the occurrence table and its two indexes.");
        }
        catch (SqliteException)
        {
            // dbstat is not compiled into this SQLite. Fall through to the whole file.
        }

        return (fileBytes, "The whole judgement file, because dbstat is unavailable in this build.");
    }

    /// <summary>
    /// Which file names the build that produced these figures, and what hashing it proves.
    /// </summary>
    /// <param name="assemblyLocation">
    /// Where the managed assembly lives, or empty under a single-file publish, which is the
    /// framework's way of saying there is no separate assembly file to point at.
    /// </param>
    /// <param name="processPath">The running executable.</param>
    /// <remarks>
    /// <para>
    /// <b>Two publish shapes, and the right answer is the opposite one in each.</b> An ordinary
    /// framework-dependent publish leaves an executable that is only the apphost launcher: the
    /// Debug and Release ones measured byte-identical at <c>58A0471A..FD68</c>, so hashing it names
    /// no build at all and the assembly is the only thing that does. A single-file publish has no
    /// separate assembly and the executable genuinely contains the code, so there it is exactly
    /// right.
    /// </para>
    /// <para>
    /// <b>Found by running the build the owner would actually carry.</b> The first version hashed
    /// the assembly unconditionally and crashed on startup under a single-file publish, because
    /// <c>Assembly.Location</c> is empty there. A provenance field that stops the tool running is
    /// worse than none, and it would have failed in the production environment rather than here.
    /// </para>
    /// <para>
    /// The choice is reported beside the hash rather than left to be inferred, because "the hash of
    /// the build" means a different file in each case and a reader comparing two runs needs to know
    /// which.
    /// </para>
    /// </remarks>
    internal static (string Hash, string Covers) Provenance(string? assemblyLocation, string? processPath)
    {
        if (!string.IsNullOrEmpty(assemblyLocation))
            return (BundleSealing.HashFile(assemblyLocation), "The managed assembly; the executable is only a launcher.");

        if (!string.IsNullOrEmpty(processPath))
            return (BundleSealing.HashFile(processPath), "The single-file executable, which carries the code.");

        return ("unknown", "Neither an assembly file nor an executable path was available.");
    }

    /// <summary>
    /// What one occurrence row costs, built from SQLite's record format rather than from a single
    /// measured average, so the parts can be priced separately.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why a model at all.</b> The calibrated 128 bytes answers one question - what a row costs
    /// today beyond its name - and cannot answer which of the row's columns that 128 is. Deciding
    /// whether to move the entry-derived columns out needs them priced individually, and no
    /// measurement of a finished judgement can separate them.
    /// </para>
    /// <para>
    /// <b>It is checked, not trusted.</b> On a bundle holding a finished judgement the model's own
    /// total is reported beside the observed one. It should come in a little under, because the
    /// observed figure carries the other tables and SQLite's free pages too; if it comes in over,
    /// the model is wrong and nothing built on it may be believed.
    /// </para>
    /// </remarks>
    internal static class RowModel
    {
        /// <summary>Record header, serial types for nine columns, and the cell's own overhead.</summary>
        internal const long RecordOverhead = 14;

        /// <summary>The 32-byte <c>fingerprint</c> blob.</summary>
        internal const long Fingerprint = 32;

        /// <summary>A GUID stored as text, which is how <c>object_schema</c> holds one.</summary>
        internal const long GuidAsText = 36;

        /// <summary><c>position</c>, <c>ordinal</c>, <c>entry_id</c>, <c>right_count</c>, <c>reading_id</c>.</summary>
        internal const long SmallIntegers = 8;

        /// <summary>What an entry reference costs once the classification columns have moved out.</summary>
        /// <remarks><c>position</c>, <c>ordinal</c> and <c>entry_id</c> only.</remarks>
        internal const long SmallIntegersWhenNormalised = 6;

        /// <summary>Header and cell overhead of one entry in one of the two indexes.</summary>
        internal const long IndexOverhead = 10;

        /// <summary>How many places the row's key is written: the row, the primary key, the unique index.</summary>
        internal const long KeyCopies = 3;

        /// <summary>
        /// What an integer identifier costs in each of those three places.
        /// </summary>
        /// <remarks>
        /// SQLite writes an integer behind a serial-type byte, so an identifier counting to a
        /// forest's object or descriptor count occupies three bytes and a header.
        /// </remarks>
        internal const long IntegerKey = 4;

        /// <summary>The occurrence table as it stands: the name three times, everything else once.</summary>
        internal static long AsItStands(long rows, long keyBytesAcrossRows, long objectTypes, long inheritedTypes) =>
            (KeyCopies * keyBytesAcrossRows)
            + (rows * (RecordOverhead + Fingerprint + SmallIntegers + (2 * IndexOverhead)))
            + (GuidAsText * (objectTypes + inheritedTypes));

        /// <summary>The same table with an integer identifier in place of the name.</summary>
        internal static long WithIntegerKey(long rows, long objectTypes, long inheritedTypes) =>
            AsItStands(rows, rows * IntegerKey, objectTypes, inheritedTypes);

        /// <summary>
        /// Keyed per descriptor rather than per object, and with the entry-derived columns moved
        /// to a table of distinct entries.
        /// </summary>
        /// <remarks>
        /// <c>fingerprint</c>, <c>right_count</c>, <c>reading_id</c>, <c>object_schema</c> and
        /// <c>inherited_schema</c> are all functions of the entry alone, so one copy each per
        /// distinct entry replaces one copy each per occurrence.
        /// </remarks>
        internal static long Normalised(long rows, long distinctEntries) =>
            (KeyCopies * rows * IntegerKey)
            + (rows * (RecordOverhead + SmallIntegersWhenNormalised + (2 * IndexOverhead)))
            + (distinctEntries * (RecordOverhead + Fingerprint + SmallIntegers + (2 * GuidAsText)));
    }

    private static bool HasTable(SqliteConnection connection, string table)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=$name";
        command.Parameters.AddWithValue("$name", table);
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture) > 0;
    }

    private static void Report(Forecast f)
    {
        Console.WriteLine();
        Console.WriteLine("Opened read-only. No database in this bundle was written: the sealed");
        Console.WriteLine("evidence and any judgement are left byte for byte as they were. SQLite");
        Console.WriteLine("may touch its own -shm scratch file beside them, which is not evidence");
        Console.WriteLine("and is outside the seal.");
        Console.WriteLine();
        Console.WriteLine($"  Objects captured                          {f.ObjectsCaptured,18:N0}");
        Console.WriteLine($"  Of those, with readable permissions       {f.ObjectsWithReadablePermissions,18:N0}");
        Console.WriteLine($"  Descriptors stored                        {f.DescriptorsStored,18:N0}");
        Console.WriteLine($"  Descriptors an object actually uses       {f.DescriptorsUsedByObjects,18:N0}");
        Console.WriteLine();
        Console.WriteLine($"  PERMISSION OCCURRENCES, EXACT             {f.Occurrences,18:N0}");
        Console.WriteLine("  One judgement row each. None may be dropped: each is the distinct fact");
        Console.WriteLine("  that this object, at this position, carries that entry.");
        Console.WriteLine();
        Console.WriteLine($"  Average name, per object                  {f.MeanNameBytesPerObject,18:N1} bytes");
        Console.WriteLine($"  Average name, per occurrence              {f.MeanNameBytesPerOccurrence,18:N1} bytes");
        Console.WriteLine($"  Longest name                              {f.LongestNameBytes,18:N0} bytes");
        Console.WriteLine($"  Average name, per object                  {f.MeanNameCharactersPerObject,18:N1} characters");
        Console.WriteLine();
        Console.WriteLine("  If the per-occurrence average is the larger, objects with longer names");
        Console.WriteLine("  carry more entries, and any figure built on the per-object average");
        Console.WriteLine("  understates what the name costs.");
        Console.WriteLine();
        Console.WriteLine($"  The name, three times, across every row   {f.ThreeCopiesOfTheNameBytes,18:N0} bytes");
        Console.WriteLine($"  Everything else, per row                  {f.FixedBytesPerOccurrence,18:N0} bytes");
        Console.WriteLine($"    {f.FixedBytesPerOccurrenceSource}");
        Console.WriteLine();
        Console.WriteLine($"  Judgement as it stands                    {f.ProjectedOccurrenceBytes,18:N0} bytes");
        Console.WriteLine($"  With an integer identifier instead        {f.ProjectedWithIntegerIdentifierBytes,18:N0} bytes");
        Console.WriteLine($"  Saved                                     {f.ProjectedSavingBytes,18:N0} bytes");
        Console.WriteLine();
        Console.WriteLine("  Both figures are a floor. The bundle the fixed cost was calibrated on");
        Console.WriteLine("  derived no control edges at all, so a real forest adds that whole phase");
        Console.WriteLine("  on top of every byte above.");
        ReportShapes(f.Shapes);

        if (f.Judgement is not { } j)
        {
            Console.WriteLine();
            Console.WriteLine("  This bundle holds no finished judgement, so the occurrence count above");
            Console.WriteLine("  could not be checked against a real one.");
            return;
        }

        Console.WriteLine();
        Console.WriteLine("  CHECKED AGAINST THIS BUNDLE'S OWN FINISHED JUDGEMENT");
        Console.WriteLine($"  Generation                                {j.Generation}");
        Console.WriteLine($"  Occurrence rows it actually holds         {j.OccurrenceRows,18:N0}");
        Console.WriteLine($"  Occurrences forecast above                {j.ForecastOccurrences,18:N0}");
        Console.WriteLine($"  Object rows it actually holds             {j.ObjectRows,18:N0}");
        Console.WriteLine($"  Judgement file                            {j.JudgementFileBytes,18:N0} bytes");
        Console.WriteLine($"  Occurrence storage                        {j.OccurrenceStorageBytes,18:N0} bytes");
        Console.WriteLine($"    {j.OccurrenceStorageSource}");
        Console.WriteLine($"  Observed, per occurrence                  {j.ObservedBytesPerOccurrence,18:N1} bytes");
        Console.WriteLine($"  Of which not the name                     {j.ImpliedFixedBytesPerOccurrence,18:N1} bytes");
        Console.WriteLine();
        Console.WriteLine(j.OccurrenceCountAgrees
            ? "  The forecast count and the real one agree exactly."
            : "  THEY DISAGREE. The forecast counts something other than what judging writes,");
        if (!j.OccurrenceCountAgrees)
            Console.WriteLine("  and no projection above may be relied on until that is explained.");
    }

    /// <summary>
    /// The four shapes the occurrence table could take, priced from the same measurements.
    /// </summary>
    private static void ReportShapes(Shapes s)
    {
        Console.WriteLine();
        Console.WriteLine("  WHAT EACH SHAPE WOULD COST");
        Console.WriteLine();
        Console.WriteLine($"  A  As it stands                           {s.AsItStands,18:N0} bytes   {s.OccurrenceRows,15:N0} rows");
        Console.WriteLine($"  B  Integer identifier                     {s.WithIntegerIdentifier,18:N0} bytes   {s.OccurrenceRows,15:N0} rows");
        Console.WriteLine($"  C  Keyed per descriptor                   {s.PerDescriptor,18:N0} bytes   {s.PerDescriptorRows,15:N0} rows");
        if (s.Normalised > 0)
            Console.WriteLine($"  D  Per descriptor, classification moved   {s.Normalised,18:N0} bytes   {s.PerDescriptorRows,15:N0} rows");
        Console.WriteLine();
        Console.WriteLine("  C keys the table the way evidence already keys descriptor_entry, and");
        Console.WriteLine("  reaches objects through object_security_descriptor, which exists already.");
        if (s.Normalised > 0)
        {
            Console.WriteLine($"  D also moves the five columns that are functions of the entry alone onto");
            Console.WriteLine($"  the {s.DistinctEntries,0:N0} distinct entries, instead of copying them onto every occurrence.");
        }
        Console.WriteLine();
        Console.WriteLine($"  Occurrences carrying an object type       {s.OccurrencesWithObjectType,18:N0}");
        Console.WriteLine($"  Occurrences carrying an inherited type    {s.OccurrencesWithInheritedObjectType,18:N0}");
        Console.WriteLine($"  Modelled cost of one row as it stands     {s.ModelledBytesPerOccurrence,18:N1} bytes");
        Console.WriteLine();
        Console.WriteLine("  That modelled figure is the check on all four. Where this bundle holds a");
        Console.WriteLine("  finished judgement it must come in a little UNDER the observed figure");
        Console.WriteLine("  below - the observed one carries the other tables and free pages too. If");
        Console.WriteLine("  it comes in over, the model is wrong and none of A to D may be believed.");
    }

    private static long Scalar(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }
}
