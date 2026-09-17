using System.Globalization;
using System.Security.AccessControl;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;

namespace SecureAD.Measure;

internal static class RequesterWorkload
{
    private const string Root = "DC=measure,DC=lab";
    private const string MemberGuid = "bf9679c0-0de6-11d0-a285-00aa003049e2";
    private static readonly DateTimeOffset When = new(2026, 9, 17, 0, 0, 0, TimeSpan.Zero);

    // --requester-generate NEW_OUTPUT OBJECTS PHYSICAL_ACES DOMAINS RELEVANT_GROUP_SETS MEMBERS_PER_HOLDER
    // Each set has one granting holder, a membership-tail group and a DACL-tail group.
    // This is a synthetic density experiment, never a reconstruction of customer memberships.
    internal static int Run(string[] args)
    {
        if (args.Length != 6) throw new ArgumentException("NEW_OUTPUT OBJECTS PHYSICAL_ACES DOMAINS RELEVANT_GROUP_SETS MEMBERS_PER_HOLDER are required.");
        var output = Path.GetFullPath(args[0]);
        if (Directory.Exists(output) || File.Exists(output)) throw new IOException("Retain the existing workload; choose a new output directory.");
        Directory.CreateDirectory(output);
        try
        {
            var objects = int.Parse(args[1], CultureInfo.InvariantCulture);
            var aces = long.Parse(args[2], CultureInfo.InvariantCulture);
            var domains = int.Parse(args[3], CultureInfo.InvariantCulture);
            var groups = int.Parse(args[4], CultureInfo.InvariantCulture);
            var members = int.Parse(args[5], CultureInfo.InvariantCulture);
            var minimum = checked(3L + 2L * domains + (long)groups * (3 + members));
            if (domains < 1 || groups < domains || members < 1 || objects < minimum || aces < 4L * groups)
                throw new ArgumentException("The shape cannot contain the required independent proof families.");
            var build = Path.Combine(AppContext.BaseDirectory, "measurement-build.json");
            if (!File.Exists(build)) throw new IOException("Missing archived build/source provenance.");
            File.Copy(build, Path.Combine(output, "measurement-build.json"));
            File.WriteAllText(Path.Combine(output, "requested-shape.json"), JsonSerializer.Serialize(new
            {
                Objects = objects, PhysicalAces = aces, Domains = domains, RelevantGroupSets = groups, MembersPerHolder = members,
                MinimumObjects = minimum, SyntheticMemberships = true, CustomerReconstruction = false,
                Executable = Environment.ProcessPath, ExecutableSha256 = BundleSealing.HashFile(Environment.ProcessPath!),
                Runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
            }));
            var bundle = Path.Combine(output, "bundle");
            Directory.CreateDirectory(bundle);
            var written = 0;
            var extraAces = aces - 4L * groups;
            var domainNames = Enumerable.Range(0, domains).Select(d => d == 0 ? "measure.lab" : $"d{d}.measure.lab").ToArray();
            using (var writer = BundleWriter.Create(bundle, When))
            {
                void Write(PartitionCoverage coverage, string dn, string kind, string? sid, EvidenceAttribute[] attributes, string grants = "")
                {
                    var guid = Guid.NewGuid();
                    var id = writer.WriteObject(new(coverage, dn, guid,
                        [Text("objectClass", "top", kind), .. sid is null ? Array.Empty<EvidenceAttribute>() : [Binary("objectSid", Sid.ToBytes(sid)!)], .. attributes], When));
                    var count = extraAces / objects + (written < extraAces % objects ? 1 : 0);
                    var filler = string.Concat(Enumerable.Range(0, checked((int)count)).Select(i => $"(A;;RP;;;S-1-5-21-90-91-92-{10_000_000L + written * 1000L + i})"));
                    var raw = new RawSecurityDescriptor("O:SYG:SYD:" + grants + filler);
                    var bytes = new byte[raw.BinaryLength]; raw.GetBinaryForm(bytes, 0);
                    writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
                    written++;
                }
                var fillers = objects - minimum;
                for (var d = 0; d < domains; d++)
                {
                    var domain = d == 0 ? Root : $"DC=d{d},{Root}";
                    var sid = $"S-1-5-21-40-{50 + d}-60";
                    var parent = "OU=Accounts,OU=Operations,OU=Directory,OU=Synthetic," + domain;
                    string Dn(string name) => "CN=" + name.PadRight(Math.Max(name.Length, 97 - parent.Length - 4), 'x') + "," + parent;
                    var domainGroups = groups / domains + (d < groups % domains ? 1 : 0);
                    var domainFillers = fillers / domains + (d < fillers % domains ? 1 : 0);
                    var coverage = new PartitionCoverage(domain, NamingContextKind.Domain, "dc01." + domainNames[d],
                        ConnectionSecurityLevel.SignedAndSealed, 1, checked((int)(2 + domainGroups * (3L + members) + domainFillers)), 1, [], false);
                    writer.WriteCoverage(coverage);
                    Write(coverage, domain, "domainDNS", sid, []);
                    var coreMembers = new List<string>();
                    var coreGrants = new List<string>();
                    for (var g = 0; g < domainGroups; g++)
                    {
                        var holder = Dn($"Holder{g:D5}");
                        var membership = Dn($"Membership{g:D5}");
                        var dacl = Dn($"Dacl{g:D5}");
                        var holderSid = $"{sid}-{1000L + g * (members + 3L)}";
                        var membershipSid = $"{sid}-{1001L + g * (members + 3L)}";
                        var daclSid = $"{sid}-{1002L + g * (members + 3L)}";
                        var userDns = new List<string>();
                        for (var m = 0; m < members; m++)
                        {
                            var user = Dn($"User{g:D5}-{m:D5}"); userDns.Add(user);
                            Write(coverage, user, "user", $"{sid}-{1003L + g * (members + 3L) + m}",
                                [Text("userAccountControl", "512"), Text("primaryGroupID", "513")]);
                        }
                        Write(coverage, holder, "group", holderSid, [Text("groupType", "-2147483646"), Text("member", [.. userDns])]);
                        var grant = $"(OA;;{(g % 2 == 0 ? "SW" : "WP")};{MemberGuid};;{holderSid})";
                        Write(coverage, membership, "group", membershipSid, [Text("groupType", "-2147483646"), Text("member")], grant);
                        Write(coverage, dacl, "group", daclSid, [Text("groupType", "-2147483646"), Text("member")], grant);
                        coreMembers.Add(membership);
                        coreGrants.Add($"(A;;WD;;;{holderSid})(A;;WD;;;{daclSid})");
                    }
                    Write(coverage, Dn("Domain Admins"), "group", sid + "-512",
                        [Text("groupType", "-2147483646"), Text("member", [.. coreMembers])], string.Concat(coreGrants));
                    for (long f = 0; f < domainFillers; f++)
                        Write(coverage, Dn($"Filler{f:D8}"), "user", $"{sid}-{1_000_000L + f}",
                            [Text("userAccountControl", "512"), Text("primaryGroupID", "513")]);
                    Console.WriteLine($"Retained synthetic generation: domain {d + 1}/{domains}; {written} objects written");
                }
                var schemaDn = "CN=Schema,CN=Configuration," + Root;
                var schema = new PartitionCoverage(schemaDn, NamingContextKind.Schema, "dc01.measure.lab", ConnectionSecurityLevel.SignedAndSealed, 1, 3, 1, [], false);
                writer.WriteCoverage(schema);
                Write(schema, "CN=Member," + schemaDn, "attributeSchema", null,
                    [Text("lDAPDisplayName", "member"), Binary("schemaIDGUID", Guid.Parse(MemberGuid).ToByteArray()),
                     Text("isSingleValued", "FALSE"), Text("systemFlags", "18"), Text("searchFlags", "0")]);
                Write(schema, "CN=Group," + schemaDn, "classSchema", null,
                    [Text("lDAPDisplayName", "group"), Binary("schemaIDGUID", Guid.Parse("bf967a9c-0de6-11d0-a285-00aa003049e2").ToByteArray()), Text("systemFlags", "16")]);
                Write(schema, "CN=User," + schemaDn, "classSchema", null,
                    [Text("lDAPDisplayName", "user"), Binary("schemaIDGUID", Guid.Parse("bf967aba-0de6-11d0-a285-00aa003049e2").ToByteArray()), Text("systemFlags", "16")]);
                writer.Complete(RunCoverage.Of(CoverageId.ForDomains("measure.lab", domainNames), domainNames.Select(DomainCoverage.Read).ToArray(),
                    [ForestPartitionCoverage.Read("CN=Configuration," + Root, NamingContextKind.Configuration), ForestPartitionCoverage.Read(schemaDn, NamingContextKind.Schema)],
                    SysvolCoverage.Of([])), When.AddMinutes(1));
            }
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = BundleLayout.EvidencePath(bundle), Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*),COUNT(DISTINCT domain_fqdn),AVG(LENGTH(distinguished_name)),(SELECT COUNT(*) FROM ace),(SELECT COUNT(*) FROM member_value) FROM captured_object";
            using var rows = command.ExecuteReader();
            if (!rows.Read() || rows.GetInt64(0) != objects || rows.GetInt64(1) != domains || rows.GetInt64(3) != aces || rows.GetInt64(4) != (long)groups * (members + 1))
                throw new InvalidDataException("Independent stored counts disagree with the requested synthetic shape.");
            File.WriteAllText(Path.Combine(output, "verified-shape.json"), JsonSerializer.Serialize(new
            {
                Objects = rows.GetInt64(0), DomainFqdns = rows.GetInt64(1), MeanDnLength = rows.GetDouble(2), PhysicalAces = rows.GetInt64(3),
                MemberValues = rows.GetInt64(4), EvidenceSha256 = BundleSealing.HashFile(BundleLayout.EvidencePath(bundle)),
            }));
            return 0;
        }
        catch (Exception error)
        {
            File.WriteAllText(Path.Combine(output, "failure.txt"), error.ToString());
            Console.Error.WriteLine(error); return 1;
        }
    }

    private static EvidenceAttribute Text(string name, params string[] values) => new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
    private static EvidenceAttribute Binary(string name, byte[] value) => new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(value)]);
}
