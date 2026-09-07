using System.Diagnostics;
using System.Globalization;
using System.Security.AccessControl;
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
    private sealed record Shape(int Objects, int Groups, int MembersPerGroup)
    {
        public override string ToString() =>
            $"{Objects,6:N0} objects, {Groups,5:N0} groups, {MembersPerGroup,4:N0} members";
    }

    private sealed record Measurement(Shape Shape, int Repeat, double ScanMs, double BaselineMs,
        long ScanBytes, long StoredBytes, long BaselineStoredBytes, long Assessments, long Pairs,
        bool Completed);


    private static int Main(string[] args)
    {
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
            new Shape(10_000, 1_000, 25),
            new Shape(10_000, 200, 100),
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
            shapes = [new Shape(objects, groups, members)];
        }

        var root = Path.Combine(Path.GetTempPath(), "SecureAD-measure-"
            + DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture));
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

            for (var repeat = 1; repeat <= repeats; repeat++)
            {
                var baseline = Judge(bundle, null);
                var scan = Judge(bundle, Unbounded);
                var measured = new Measurement(shape, repeat, scan.Ms, baseline.Ms, scan.Bytes,
                    scan.Stored, baseline.Stored, scan.Assessments, scan.Pairs, scan.Completed);
                results.Add(measured);

                Console.Out.WriteLine(
                    $"    run {repeat}: with {measured.ScanMs,7:N0} ms  without {measured.BaselineMs,7:N0} ms"
                    + $"  cost {measured.ScanMs - measured.BaselineMs,7:N0} ms"
                    + $"  pairs {measured.Pairs,6:N0}"
                    + $"  stored +{(measured.StoredBytes - measured.BaselineStoredBytes) / 1024,6:N0} KB");
            }

            // Deleted immediately: a 20,000-object capture is large, and keeping every shape would
            // measure the disk rather than the scan.
            foreach (var line in Directory.EnumerateFiles(bundle, "*.log").SelectMany(File.ReadAllLines).Where(l => l.Contains("self-membership", StringComparison.Ordinal)).TakeLast(2)) Console.Out.WriteLine("      " + line.Trim());
            try { Directory.Delete(bundle, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }


        var report = Path.Combine(root, "measurements.csv");
        File.WriteAllLines(report, new[]
        {
            "Objects,Groups,MembersPerGroup,Repeat,WithScanMs,WithoutScanMs,CostMs,"
            + "ScanAllocatedBytes,StoredBytes,BaselineStoredBytes,StoredCostBytes,Assessments,Pairs,ScanCompleted",
        }.Concat(results.Select(r => string.Join(char.Parse(","),
            r.Shape.Objects, r.Shape.Groups, r.Shape.MembersPerGroup, r.Repeat,
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
        var bundle = Path.Combine(root, $"o{shape.Objects}-g{shape.Groups}-m{shape.MembersPerGroup}");
        Directory.CreateDirectory(bundle);

        using (var writer = BundleWriter.Create(bundle, When))
        {
            writer.WriteCoverage(Partition(shape.Objects));
            writer.WriteObject(Object(Domain, "domainDNS", "S-1-5-21-9-9-9", []));
            var written = 1;

            for (var group = 0; group < shape.Groups; group++)
            {
                var holderDn = $"CN=Holder{group},{Domain}";
                var holderSid = $"S-1-5-21-9-9-9-{200_000 + group}";
                var members = new List<string>(shape.MembersPerGroup);

                for (var member = 0; member < shape.MembersPerGroup; member++)
                {
                    var dn = $"CN=User{group}-{member},{Domain}";
                    members.Add(dn);
                    writer.WriteObject(Object(dn, "user",
                        $"S-1-5-21-9-9-9-{1_000_000 + (group * 1_000) + member}", [Enabled]));
                    written++;
                }

                writer.WriteObject(Object(holderDn, "group", holderSid,
                [
                    Global,
                    new("member", StoredAttributeCompleteness.Complete,
                        [.. members.Select(EvidenceValue.OfText)]),
                ]));
                written++;

                var target = Object($"CN=Target{group},{Domain}", "group",
                    $"S-1-5-21-9-9-9-{300_000 + group}",
                    [Global, new("member", StoredAttributeCompleteness.Complete, [])]);
                var id = writer.WriteObject(target);
                var raw = new RawSecurityDescriptor($"O:SYG:SYD:(OA;;SW;{SelfMembership};;{holderSid})");
                var bytes = new byte[raw.BinaryLength];
                raw.GetBinaryForm(bytes, 0);
                writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(
                    target.ObjectGuid!.Value, SecurityDescriptorParser.Parse(bytes)));
                written++;
            }

            for (var filler = written; filler < shape.Objects; filler++)
            {
                writer.WriteObject(Object($"CN=Filler{filler},{Domain}", "user",
                    $"S-1-5-21-9-9-9-{5_000_000 + filler}", [Enabled]));
            }

            writer.Complete(RunCoverage.Of(
                CoverageId.ForDomains("measure.lab", ["measure.lab"]),
                [DomainCoverage.Read("measure.lab")],
                [
                    ForestPartitionCoverage.Read($"CN=Configuration,{Domain}", NamingContextKind.Configuration),
                    ForestPartitionCoverage.Read($"CN=Schema,CN=Configuration,{Domain}", NamingContextKind.Schema),
                ],
                SysvolCoverage.Of([])), When.AddMinutes(1));
        }

        return bundle;
    }

    private static EvidenceAttribute Enabled { get; } =
        new("userAccountControl", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("512")]);

    private static EvidenceAttribute Global { get; } =
        new("groupType", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("-2147483646")]);

    private static PartitionCoverage Partition(int objects) =>
        new(Domain, NamingContextKind.Domain, "dc01.measure.lab",
            ConnectionSecurityLevel.SignedAndSealed, 3, objects, 1, [], false);

    private static EvidenceObject Object(string dn, string objectClass, string sid,
        EvidenceAttribute[] extra) =>
        new(Partition(1), dn, Guid.NewGuid(),
        [
            new("objectClass", StoredAttributeCompleteness.Complete,
                [EvidenceValue.OfText("top"), EvidenceValue.OfText(objectClass)]),
            new("objectSid", StoredAttributeCompleteness.Complete,
                [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)]),
            .. extra,
        ], When);
}

