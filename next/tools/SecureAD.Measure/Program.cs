using System.Diagnostics;
using System.Globalization;
using System.Security.AccessControl;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;

namespace SecureAD.Measure;

/// <summary>
/// Measures what automatic Self-Membership discovery costs, so a production processing budget can
/// be argued from numbers rather than chosen.
/// </summary>
/// <remarks>
/// <para>
/// <b>The comparison is the measurement.</b> Each synthetic capture is judged twice: once with the
/// scan configured and once with no budget at all. Everything else - opening the bundle, streaming
/// every object, deriving control edges, sealing and publishing - happens both times, so the
/// difference between the two runs is the cost of discovery and the assessments it produced, and
/// nothing else. Timing the scan alone would fold in work that happens whether or not a budget is
/// ever configured.
/// </para>
/// <para>
/// <b>Filler objects are the point, not padding.</b> A real forest is mostly objects the scan looks
/// at once and moves past. A shape made only of groups carrying relevant permissions would measure
/// the interesting fraction of a directory and call it the whole.
/// </para>
/// </remarks>
internal static class Program
{
    private static readonly DateTimeOffset When = new(2026, 9, 7, 0, 0, 0, TimeSpan.Zero);
    private const string SelfMembership = "bf9679c0-0de6-11d0-a285-00aa003049e2";
    private const string Domain = "DC=measure,DC=lab";

    /// <param name="Objects">Total captured objects, most of them filler the scan passes over.</param>
    /// <param name="Groups">Target groups carrying one Self-Membership entry each.</param>
    /// <param name="MembersPerGroup">Captured members of the trustee group; each becomes one pair.</param>
    private sealed record Shape(int Objects, int Groups, int MembersPerGroup,
        int Domains = 1, long? AccessControlEntries = null)
    {
        public long Aces => AccessControlEntries ?? Groups;
        public long MinimumObjects => Domains + ((long)Groups * (MembersPerGroup + 2L));

        public override string ToString() =>
            $"{Objects,6:N0} objects, {Groups,5:N0} groups, {MembersPerGroup,4:N0} members, "
            + $"{Domains} domains, {Aces:N0} ACEs";
    }

    private sealed record Measurement(Shape Shape, int Repeat, double ScanMs, double BaselineMs,
        long ScanBytes, long StoredBytes, long BaselineStoredBytes, long Assessments, long Pairs,
        bool Completed);


    private static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--requester-generate")
            return RequesterWorkload.Run(args[1..]);
        if (args.Length > 0 && args[0] == "--requester")
            return RequesterMeasurement.Run(args[1..]);
        if (args.Length > 0 && args[0] == "--permission-storage")
            return PermissionStorageWorkload.Run(args[1..]);
        if (args.Length > 0 && args[0] == "--descriptor-redundancy")
            return DescriptorRedundancyMeasurement.Run(args[1..]);

        var repeats = args.Length > 0 && int.TryParse(args[0], NumberStyles.Integer,
            CultureInfo.InvariantCulture, out var value) && value > 0 ? value : 3;

        // Objects grow while relevance stays proportional, then relevance grows while the object
        // count is held still. Two different budget fields bound those two costs, and a single
        // series would not tell them apart.
        var shapes = new[]
        {
            new Shape(1_000, 100, 5),
            new Shape(5_000, 500, 5),
            new Shape(10_000, 1_000, 5),
            new Shape(20_000, 2_000, 5),
            new Shape(27_001, 1_000, 25),
            new Shape(20_401, 200, 100),
        };

        // ONE SHAPE ON DEMAND, because the full sweep runs for minutes and most questions do not
        // need it. Diagnosing where the time goes needs a single small shape with the right ratio
        // of pairs to objects; only the final curve needs every point.
        //   SecureAD.Measure <repeats> <objects> <groups> <membersPerGroup>
        if (args.Length >= 4
            && int.TryParse(args[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var objects)
            && int.TryParse(args[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var groups)
            && int.TryParse(args[3], NumberStyles.Integer, CultureInfo.InvariantCulture, out var members))
        {
            var domains = args.Length >= 5 ? int.Parse(args[4], CultureInfo.InvariantCulture) : 1;
            long? aces = args.Length >= 6 ? long.Parse(args[5], CultureInfo.InvariantCulture) : null;
            shapes = [new Shape(objects, groups, members, domains, aces)];
        }

        // Production volume is opt-in. Relevance is synthetic, not a claim about the owner's
        // memberships: 750 target/holder pairs and ten users per holder at full scale.
        if (args.Length == 3 && args[1] == "--production")
        {
            var scale = double.Parse(args[2], CultureInfo.InvariantCulture);
            if (!double.IsFinite(scale) || scale <= 0 || scale > 1)
                throw new ArgumentOutOfRangeException(nameof(args), "Scale must be greater than 0 and at most 1.");
            shapes = [new Shape((int)(347_000 * scale), Math.Max(1, (int)(750 * scale)),
                10, 9, (long)(5_900_000 * scale))];
        }

        foreach (var shape in shapes)
        {
            if (shape.Domains <= 0 || shape.Groups < 0 || shape.MembersPerGroup < 0
                || shape.Objects < shape.MinimumObjects || shape.Aces < shape.Groups)
                throw new ArgumentException($"Invalid shape: {shape}. At least {shape.MinimumObjects:N0} objects are required.");
        }

        var root = Path.Combine(Path.GetTempPath(), "SecureAD-measure-"
            + DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)
            + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);

        Console.Out.WriteLine("Synthetic offline measurement. No directory is contacted; nothing is written");
        Console.Out.WriteLine("outside " + root + ", and each capture is deleted once measured.");
        Console.Out.WriteLine($"Repeats per shape: {repeats}");
        Console.Out.WriteLine();

        var results = new List<Measurement>();

        foreach (var shape in shapes)
        {
            Console.Out.Write($"Building {shape} ... ");
            var built = Stopwatch.StartNew();
            var bundle = Build(root, shape);
            built.Stop();
            Console.Out.WriteLine($"{built.Elapsed.TotalSeconds,5:N1} s, "
                + $"{Directory.GetFiles(bundle).Sum(f => new FileInfo(f).Length) / 1024 / 1024,5:N0} MB");
            VerifyShape(bundle, shape);

            for (var repeat = 1; repeat <= repeats; repeat++)
            {
                var baseline = Judge(bundle, null);
                var scan = Judge(bundle, Unbounded);
                var expectedPairs = (long)shape.Groups * shape.MembersPerGroup;
                if (!scan.Completed || scan.Pairs != expectedPairs || scan.Assessments != expectedPairs * 2
                    || baseline.Pairs != 0 || baseline.Assessments != 0)
                    throw new InvalidOperationException("The measured requester work does not match the generated shape.");
                var measured = new Measurement(shape, repeat, scan.Ms, baseline.Ms, scan.Bytes,
                    scan.Stored, baseline.Stored, scan.Assessments, scan.Pairs, scan.Completed);
                results.Add(measured);

                Console.Out.WriteLine(
                    $"    run {repeat}: with {measured.ScanMs,7:N0} ms  without {measured.BaselineMs,7:N0} ms"
                    + $"  cost {measured.ScanMs - measured.BaselineMs,7:N0} ms"
                    + $"  pairs {measured.Pairs,6:N0}"
                    + $"  stored +{(measured.StoredBytes - measured.BaselineStoredBytes) / 1024,6:N0} KB");
            }

            // Generate once and reuse across repetitions, then release the large synthetic capture.
            foreach (var line in Directory.EnumerateFiles(bundle, "*.log").SelectMany(File.ReadAllLines).Where(l => l.Contains("self-membership", StringComparison.Ordinal)).TakeLast(2)) Console.Out.WriteLine("      " + line.Trim());
            try { Directory.Delete(bundle, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }


        var report = Path.Combine(root, "measurements.csv");
        File.WriteAllLines(report, new[]
        {
            "Objects,Groups,MembersPerGroup,Domains,Aces,Repeat,WithScanMs,WithoutScanMs,CostMs,"
            + "ScanAllocatedBytes,StoredBytes,BaselineStoredBytes,StoredCostBytes,Assessments,Pairs,ScanCompleted",
        }.Concat(results.Select(r => string.Join(char.Parse(","),
            r.Shape.Objects, r.Shape.Groups, r.Shape.MembersPerGroup, r.Shape.Domains, r.Shape.Aces, r.Repeat,
            F(r.ScanMs), F(r.BaselineMs), F(r.ScanMs - r.BaselineMs),
            r.ScanBytes, r.StoredBytes, r.BaselineStoredBytes, r.StoredBytes - r.BaselineStoredBytes,
            r.Assessments, r.Pairs, r.Completed))));

        Console.Out.WriteLine();
        Console.Out.WriteLine("Median cost of the scan, by shape:");
        Console.Out.WriteLine("  shape                                           cost     pairs   per-pair   per-object  stored/pair");
        foreach (var group in results.GroupBy(r => r.Shape))
        {
            var cost = Median(group.Select(r => r.ScanMs - r.BaselineMs));
            var stored = Median(group.Select(r => (double)(r.StoredBytes - r.BaselineStoredBytes)));
            var pairs = group.First().Pairs;
            Console.Out.WriteLine(
                $"  {group.Key}  {cost,7:N0} ms {pairs,8:N0}"
                + $" {(pairs == 0 ? 0 : cost / pairs),8:N3} ms"
                + $" {cost / group.Key.Objects,10:N4} ms"
                + $" {(pairs == 0 ? 0 : stored / pairs),10:N0} B");
        }

        Console.Out.WriteLine();
        Console.Out.WriteLine("Written: " + report);
        Console.Out.WriteLine();
        Console.Out.WriteLine("These figures describe this machine and these synthetic shapes. They are not a");
        Console.Out.WriteLine("published safe threshold for any real forest, and no budget is set by running this.");
        return 0;
    }

    /// <summary>Limits high enough that the scan always finishes, so cost is never a stop.</summary>
    private static SelfMembershipDiscoveryBudget Unbounded { get; } =
        new(long.MaxValue, long.MaxValue, long.MaxValue, int.MaxValue);

    private static string F(double value) => value.ToString("F1", CultureInfo.InvariantCulture);

    private static double Median(IEnumerable<double> values)
    {
        var ordered = values.Order().ToList();
        return ordered.Count == 0 ? 0
            : ordered.Count % 2 == 1 ? ordered[ordered.Count / 2]
            : (ordered[(ordered.Count / 2) - 1] + ordered[ordered.Count / 2]) / 2;
    }

    private static (double Ms, long Bytes, long Stored, long Assessments, long Pairs, bool Completed)
        Judge(string bundle, SelfMembershipDiscoveryBudget? budget)
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var allocated = GC.GetTotalAllocatedBytes(precise: true);
        var watch = Stopwatch.StartNew();

        // No rules: the rule pass is not what a discovery budget bounds, and including it would bury
        // the figure being measured under seventeen unrelated ones.
        using var file = RunLogFile.Open(bundle, "measure", TimeProvider.System) is { IsSuccess: true } opened
            ? opened.Value
            : null;

        var judged = JudgingRun.Judge(bundle, [], budget, When, When,
            JudgingRun.NobodyIsWatching, file ?? RunLog.Discarded, CancellationToken.None);

        watch.Stop();
        var used = GC.GetTotalAllocatedBytes(precise: true) - allocated;

        if (!judged.IsSuccess)
            throw new InvalidOperationException(judged.Error!.Description);

        using var reader = JudgementReader.Open(bundle).Value!;
        var summary = reader.ReadSelfMembershipSummary()
            ?? throw new InvalidOperationException("The judgement carries no requester product.");
        var stored = new FileInfo(BundleLayout.AnalysisGenerationDataPath(
            bundle, AnalysisStoreKind.Judgement, reader.Description.GenerationId)).Length;

        return (watch.Elapsed.TotalMilliseconds, used, stored, summary.AssessmentsStored,
            summary.Discovery.PairsDiscovered, summary.Discovery.InputScanCompleted);
    }


    /// <summary>Writes one sealed synthetic capture of the requested shape.</summary>
    private static string Build(string root, Shape shape)
    {
        var bundle = Path.Combine(root, $"o{shape.Objects}-g{shape.Groups}-m{shape.MembersPerGroup}-d{shape.Domains}-a{shape.Aces}");
        Directory.CreateDirectory(bundle);

        using (var writer = BundleWriter.Create(bundle, When))
        {
            var written = 0;
            var fillerCount = shape.Objects - shape.MinimumObjects;
            var ordinaryAces = shape.Aces - shape.Groups;
            var domains = Enumerable.Range(0, shape.Domains)
                .Select(d => d == 0 ? "measure.lab" : $"domain{d}.measure.lab").ToArray();

            for (var domain = 0; domain < shape.Domains; domain++)
            {
                var domainDn = domain == 0 ? Domain : $"DC=domain{domain},{Domain}";
                var domainSid = $"S-1-5-21-9-{9 + domain}-9";
                var parent = $"OU=Accounts,OU=Operations,OU=Directory,OU=Synthetic,{domainDn}";
                var domainGroups = shape.Groups / shape.Domains + (domain < shape.Groups % shape.Domains ? 1 : 0);
                var fillers = fillerCount / shape.Domains + (domain < fillerCount % shape.Domains ? 1 : 0);
                var domainObjects = checked((int)(1 + ((long)domainGroups * (shape.MembersPerGroup + 2L)) + fillers));
                var coverage = new PartitionCoverage(domainDn, NamingContextKind.Domain, "dc01." + domains[domain],
                    ConnectionSecurityLevel.SignedAndSealed, 3, domainObjects, 1, [], false);
                writer.WriteCoverage(coverage);

                void Write(string dn, string objectClass, string sid, EvidenceAttribute[] extra,
                    string? selfMembershipHolder = null)
                {
                    var evidence = new EvidenceObject(coverage, dn, Guid.NewGuid(),
                    [
                        new("objectClass", StoredAttributeCompleteness.Complete,
                            [EvidenceValue.OfText("top"), EvidenceValue.OfText(objectClass)]),
                        new("objectSid", StoredAttributeCompleteness.Complete,
                            [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)]),
                        .. extra,
                    ], When);
                    var id = writer.WriteObject(evidence);
                    var count = ordinaryAces / shape.Objects + (written < ordinaryAces % shape.Objects ? 1 : 0);
                    if (count > 0 || selfMembershipHolder is not null)
                    {
                        var sddl = "O:SYG:SYD:"
                            + (selfMembershipHolder is null ? "" : $"(OA;;SW;{SelfMembership};;{selfMembershipHolder})")
                            + string.Concat(Enumerable.Range(0, checked((int)count))
                                .Select(i => $"(A;;RP;;;{domainSid}-{10_000_000L + ((long)written * 1000) + i})"));
                        var raw = new RawSecurityDescriptor(sddl);
                        var bytes = new byte[raw.BinaryLength];
                        raw.GetBinaryForm(bytes, 0);
                        writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(
                            evidence.ObjectGuid!.Value, SecurityDescriptorParser.Parse(bytes)));
                    }
                    written++;
                }

                Write(domainDn, "domainDNS", domainSid, []);
                for (var group = 0; group < domainGroups; group++)
                {
                    var holderDn = $"CN=Holder{group},{parent}";
                    var holderSid = $"{domainSid}-{1000L + written + shape.MembersPerGroup}";
                    var members = new List<string>(shape.MembersPerGroup);
                    for (var member = 0; member < shape.MembersPerGroup; member++)
                    {
                        var dn = $"CN=User{group}-{member},{parent}";
                        members.Add(dn);
                        Write(dn, "user", $"{domainSid}-{1000L + written}", [Enabled]);
                    }

                    Write(holderDn, "group", holderSid,
                    [
                        Global,
                        new("member", StoredAttributeCompleteness.Complete, [.. members.Select(EvidenceValue.OfText)]),
                    ]);
                    Write($"CN=Target{group},{parent}", "group", $"{domainSid}-{1000L + written}",
                        [Global, new("member", StoredAttributeCompleteness.Complete, [])], holderSid);
                }

                for (long filler = 0; filler < fillers; filler++)
                    Write($"CN=Filler{filler},{parent}", "user", $"{domainSid}-{1000L + written}", [Enabled]);
                Console.Out.WriteLine($"      generated domain {domain + 1}/{shape.Domains}: {written:N0} objects total");
            }

            if (written != shape.Objects)
                throw new InvalidOperationException("Generated object count differs from the requested shape.");
            writer.Complete(RunCoverage.Of(
                CoverageId.ForDomains("measure.lab", domains),
                domains.Select(DomainCoverage.Read).ToArray(),
                [
                    ForestPartitionCoverage.Read($"CN=Configuration,{Domain}", NamingContextKind.Configuration),
                    ForestPartitionCoverage.Read($"CN=Schema,CN=Configuration,{Domain}", NamingContextKind.Schema),
                ],
                SysvolCoverage.Of([])), When.AddMinutes(1));
        }

        return bundle;
    }

    private static void VerifyShape(string bundle, Shape shape)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.EvidencePath(bundle), Mode = SqliteOpenMode.ReadOnly, Pooling = false,
        }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*), COUNT(DISTINCT domain_fqdn), AVG(LENGTH(distinguished_name)), "
            + "(SELECT COUNT(*) FROM descriptor_entry) FROM captured_object";
        using (var reader = command.ExecuteReader())
        {
            if (!reader.Read() || reader.GetInt64(0) != shape.Objects
                || reader.GetInt64(1) != shape.Domains || reader.GetInt64(3) != shape.Aces)
                throw new InvalidOperationException("Stored objects, domains or ACEs do not match the requested shape.");
            Console.Out.WriteLine($"      verified {reader.GetInt64(0):N0} stored objects, {reader.GetInt64(1)} domains, "
                + $"{reader.GetInt64(3):N0} stored ACEs; mean DN length {reader.GetDouble(2):F1}");
        }
        command.CommandText = "EXPLAIN QUERY PLAN SELECT object_id FROM captured_object "
            + "WHERE distinguished_name = $dn COLLATE NOCASE LIMIT 1";
        command.Parameters.AddWithValue("$dn", Domain);
        using var plan = command.ExecuteReader();
        while (plan.Read()) Console.Out.WriteLine("      DN lookup plan: " + plan.GetString(3));
    }

    private static EvidenceAttribute Enabled { get; } =
        new("userAccountControl", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("512")]);

    private static EvidenceAttribute Global { get; } =
        new("groupType", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("-2147483646")]);

}

