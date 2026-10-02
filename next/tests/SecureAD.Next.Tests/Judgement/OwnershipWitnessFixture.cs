using System.Globalization;
using System.Security.AccessControl;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;

namespace SecureAD.Next.Tests.Judgement;

internal static class OwnershipWitnessFixture
{
    internal static readonly DateTimeOffset When = new(2026, 10, 2, 0, 0, 0, TimeSpan.Zero);
    internal const int UsersPerDomain = 64;
    internal const int EntriesPerDescriptor = 512;

    internal static void Capture(string directory, bool repeated, int domains = 9)
    {
        if (Directory.Exists(directory)) throw new IOException("Fixture destinations are single-use.");
        var names = Enumerable.Range(0, domains).Select(index => $"d{index}.witness.invalid").ToArray();
        using var writer = BundleWriter.Create(directory, When.AddMinutes(-2));
        for (var domain = 0; domain < domains; domain++)
        {
            var nc = NamingContext(domain);
            var sid = DomainSid(domain);
            var coverage = new PartitionCoverage(nc, NamingContextKind.Domain, $"dc01.{names[domain]}",
                ConnectionSecurityLevel.SignedAndSealed, 3, 100, 1, [], false);
            writer.WriteCoverage(coverage);
            Write(nc, "domainDNS", sid, [], "O:SYG:SYD:");
            for (var user = 0; user < UsersPerDomain; user++)
                Write(UserDn(domain, user), "user", UserSid(domain, user),
                    [Attribute("userAccountControl", "512")], "O:SYG:SYD:");
            Write(CoreDn(domain), "group", sid + "-512",
                [Attribute("groupType", "-2147483646"), Attribute("member")],
                $"O:SYG:SYD:(A;;WD;;;{sid}-2000)");
            var entries = Enumerable.Range(0, EntriesPerDescriptor).Select(index =>
                $"(A;;{(index < (repeated ? UsersPerDomain : 1) ? "WD" : "RC")};;;{UserSid(domain, index % UsersPerDomain)})");
            Write(TargetDn(domain), "group", sid + "-2000",
                [Attribute("groupType", "-2147483646"), Attribute("member")],
                $"O:{(repeated ? UserSid(domain, 0) : "SY")}G:SYD:" + string.Concat(entries));

            void Write(string dn, string objectClass, string objectSid, EvidenceAttribute[] extra, string sddl)
            {
                var identity = Guid.NewGuid();
                var id = writer.WriteObject(new(coverage, dn, identity,
                    [Attribute("objectClass", "top", objectClass),
                     new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(objectSid)!)]),
                     .. extra], When.AddMinutes(-2)));
                var descriptor = new RawSecurityDescriptor(sddl);
                var bytes = new byte[descriptor.BinaryLength];
                descriptor.GetBinaryForm(bytes, 0);
                writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(identity, SecurityDescriptorParser.Parse(bytes)));
            }
        }
        writer.Complete(RunCoverage.Of(CoverageId.ForDomains("witness.invalid", names),
            names.Select(DomainCoverage.Read).ToArray(),
            [ForestPartitionCoverage.Read("CN=Configuration,DC=witness,DC=invalid", NamingContextKind.Configuration),
             ForestPartitionCoverage.Read("CN=Schema,CN=Configuration,DC=witness,DC=invalid", NamingContextKind.Schema)],
            SysvolCoverage.Of([])), When.AddMinutes(-1));
    }

    internal static void Derive(string directory, CancellationToken cancellationToken)
    {
        var result = Stage2aRun.Derive(directory, ExpansionBudget.Bulk, When.AddSeconds(-30),
            Stage2aRun.Unwatched, RunLog.Discarded, cancellationToken);
        if (!result.IsSuccess) throw new InvalidDataException(result.Error.Description);
    }

    internal static void Judge(string directory, CancellationToken cancellationToken)
    {
        var result = JudgingRun.JudgeAudit(directory, RuleCatalogue.All, PathRequesterPolicy.Disabled,
            When, When, JudgingRun.NobodyIsWatching, RunLog.Discarded, cancellationToken,
            selfMembershipDiscoveryBudget: null);
        if (!result.IsSuccess) throw new InvalidDataException(result.Error.Description);
    }

    internal static string NamingContext(int domain) => $"DC=d{domain.ToString(CultureInfo.InvariantCulture)},DC=witness,DC=invalid";
    internal static string DomainSid(int domain) => $"S-1-5-21-{domain + 1}-2-3";
    internal static string UserSid(int domain, int user) => DomainSid(domain) + "-" + (1100 + user).ToString(CultureInfo.InvariantCulture);
    internal static string UserDn(int domain, int user) => $"CN=User{user.ToString(CultureInfo.InvariantCulture)}," + NamingContext(domain);
    internal static string CoreDn(int domain) => "CN=Domain Admins," + NamingContext(domain);
    internal static string TargetDn(int domain) => "CN=Controlled Group," + NamingContext(domain);
    private static EvidenceAttribute Attribute(string name, params string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
}
