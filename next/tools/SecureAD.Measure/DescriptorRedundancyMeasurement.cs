using System.Globalization;
using System.IO.Compression;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;

namespace SecureAD.Measure;

/// <summary>
/// Measures how much of a sealed bundle's stored descriptor bytes is redundancy, so the decision
/// about <c>raw_bytes</c> can be argued from the owner's own forest rather than from a laboratory.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> <c>P-272</c> removed the repeated access control entries, which leaves
/// <c>security_descriptor.raw_bytes</c> as the largest single thing in a production bundle - 7.73 GB
/// of the 51.08 GB measured on 2026-09-23. Those bytes are not spare copies: they are what the
/// permissions screen reads, because the canonical projection sorts and deduplicates and a lab
/// bundle proved that loses real entries. So the question is not whether to keep them but whether
/// they can be kept smaller, and that turns on a compression ratio nobody has measured on real
/// production descriptors.
/// </para>
/// <para>
/// <b>It reads and never writes.</b> The bundle is opened immutable, which is what makes it safe to
/// run against a customer's only copy on a machine with no room for a second one.
/// </para>
/// <para>
/// <b>It samples, and says so.</b> Compressing 7.73 GB at the smallest setting takes hours and
/// answers a question a few thousand descriptors already answer. The exact total comes from
/// <c>byte_length</c>, which is a column and costs one scan of an integer; only the ratio is
/// sampled. The sample's mean size is reported beside the whole table's, so a sample that is not
/// representative can be seen to be unrepresentative rather than believed.
/// </para>
/// </remarks>
internal static class DescriptorRedundancyMeasurement
{
    /// <summary>Descriptors compressed to establish the ratio, unless the caller asks for more.</summary>
    private const int DefaultSample = 4_000;

    // --descriptor-redundancy BUNDLE_DIRECTORY [SAMPLE]
    internal static int Run(string[] args)
    {
        if (args.Length is not (1 or 2))
            throw new ArgumentException("BUNDLE_DIRECTORY [SAMPLE] are required.");

        var bundle = Path.GetFullPath(args[0]);
        var wanted = args.Length == 2
            ? int.Parse(args[1], CultureInfo.InvariantCulture)
            : DefaultSample;

        if (wanted <= 0)
            throw new ArgumentOutOfRangeException(nameof(args), "The sample must be at least one descriptor.");

        var evidence = BundleLayout.EvidencePath(bundle);
        if (!File.Exists(evidence))
        {
            Console.Error.WriteLine(
                $"There is no sealed evidence file in '{bundle}'. Name the run's own folder rather "
                + "than the library that holds several of them.");
            return 1;
        }

        // READ-ONLY, and deliberately not immutable=1. BundleReader sets that flag only after it
        // has verified the seal, because the flag asserts the file cannot be changing underneath -
        // which is a claim this tool has not earned and must not make. Read-only writes nothing
        // either way, which is the property that matters on a customer's only copy.
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = evidence,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        connection.Open();

        var descriptors = Scalar(connection, "SELECT COUNT(*) FROM security_descriptor");
        if (descriptors == 0)
        {
            Console.Error.WriteLine("This bundle stores no security descriptors, so there is nothing to measure.");
            return 1;
        }

        // Exact, and free: the length is a column, so the total costs no blob reads at all.
        var storedBytes = Scalar(connection, "SELECT COALESCE(SUM(byte_length), 0) FROM security_descriptor");

        var stride = Math.Max(1, descriptors / wanted);
        var measurement = Sample(connection, descriptors, storedBytes, stride, evidence);

        Console.WriteLine(JsonSerializer.Serialize(measurement, new JsonSerializerOptions { WriteIndented = true }));
        Report(measurement);
        return 0;
    }

    /// <summary>What one bundle's descriptor bytes were measured to be.</summary>
    private sealed record Redundancy(
        string Bundle,
        long Descriptors,
        long StoredDescriptorBytes,
        double MeanBytesWholeTable,
        long Sampled,
        long SampledBytes,
        double MeanBytesSampled,
        long SampleStride,
        double DeflateRatio,
        double BrotliRatio,
        long ProjectedDeflateBytes,
        long ProjectedBrotliBytes,
        double SharedDictionaryCeilingRatio,
        string? Executable,
        string ExecutableSha256,
        string Runtime)
    {
        public bool NothingWasWritten => true;
    }

    private static Redundancy Sample(
        SqliteConnection connection, long descriptors, long storedBytes, long stride, string evidence)
    {
        using var command = connection.CreateCommand();

        // Every stride-th row rather than the first N, so the sample is spread across the table
        // instead of being whatever the domain read first. ROWID is the descriptor identifier.
        command.CommandText =
            """
            SELECT raw_bytes FROM security_descriptor
            WHERE (descriptor_id % $stride) = 0
            """;
        command.Parameters.AddWithValue("$stride", stride);

        long sampled = 0, sampledBytes = 0, deflated = 0, brotlied = 0;
        var together = new MemoryStream();

        using (var reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                var bytes = (byte[])reader.GetValue(0);
                sampled++;
                sampledBytes += bytes.Length;
                deflated += Compressed(bytes, deflate: true);
                brotlied += Compressed(bytes, deflate: false);

                // The ceiling: what a shared dictionary could reach, because most of the repetition
                // in a forest is BETWEEN descriptors rather than inside one.
                if (together.Length < 64L * 1024 * 1024)
                    together.Write(bytes, 0, bytes.Length);
            }
        }

        if (sampled == 0)
            throw new InvalidDataException("No descriptor was sampled, so no ratio can be reported.");

        var deflateRatio = (double)sampledBytes / deflated;
        var brotliRatio = (double)sampledBytes / brotlied;

        return new Redundancy(
            Bundle: evidence,
            Descriptors: descriptors,
            StoredDescriptorBytes: storedBytes,
            MeanBytesWholeTable: Math.Round((double)storedBytes / descriptors, 1),
            Sampled: sampled,
            SampledBytes: sampledBytes,
            MeanBytesSampled: Math.Round((double)sampledBytes / sampled, 1),
            SampleStride: stride,
            DeflateRatio: Math.Round(deflateRatio, 2),
            BrotliRatio: Math.Round(brotliRatio, 2),
            ProjectedDeflateBytes: (long)(storedBytes / deflateRatio),
            ProjectedBrotliBytes: (long)(storedBytes / brotliRatio),
            SharedDictionaryCeilingRatio: Math.Round(
                (double)together.Length / Math.Max(1, Compressed(together.ToArray(), deflate: false)), 2),
            Executable: Environment.ProcessPath,
            ExecutableSha256: BundleSealing.HashFile(Environment.ProcessPath!),
            Runtime: System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription);
    }

    /// <summary>
    /// The compressed length of one descriptor.
    /// </summary>
    /// <remarks>
    /// <c>Optimal</c> rather than <c>SmallestSize</c>: the smallest setting takes several times as
    /// long for a few percent, and what is being decided here is an order of magnitude. A scheme
    /// that shipped would be free to choose differently, and would then be measured again.
    /// </remarks>
    private static long Compressed(byte[] bytes, bool deflate)
    {
        using var output = new MemoryStream();
        using (Stream compressor = deflate
            ? new DeflateStream(output, CompressionLevel.Optimal, leaveOpen: true)
            : new BrotliStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            compressor.Write(bytes, 0, bytes.Length);
        }

        return output.Length;
    }

    private static void Report(Redundancy m)
    {
        Console.WriteLine();
        Console.WriteLine("Read only - nothing was written to the bundle.");
        Console.WriteLine();
        Console.WriteLine($"  Descriptors stored                {m.Descriptors,15:N0}");
        Console.WriteLine($"  Their bytes                       {m.StoredDescriptorBytes,15:N0}");
        Console.WriteLine($"  Average descriptor                {m.MeanBytesWholeTable,15:N0} bytes");
        Console.WriteLine($"  Sampled for the ratio             {m.Sampled,15:N0}");
        Console.WriteLine($"  Average sampled descriptor        {m.MeanBytesSampled,15:N0} bytes");
        Console.WriteLine();
        Console.WriteLine($"  Compressed per descriptor, deflate           {m.DeflateRatio,8:N2}x");
        Console.WriteLine($"  Compressed per descriptor, brotli            {m.BrotliRatio,8:N2}x");
        Console.WriteLine($"  Ceiling with a shared dictionary             {m.SharedDictionaryCeilingRatio,8:N2}x");
        Console.WriteLine();
        Console.WriteLine($"  These bytes would become          {m.ProjectedBrotliBytes,15:N0} (brotli, per descriptor)");
        Console.WriteLine();
        Console.WriteLine("  The two averages above should be close. If they are not, the sample is");
        Console.WriteLine("  not representative and the ratio should not be trusted.");
    }

    private static long Scalar(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }
}
