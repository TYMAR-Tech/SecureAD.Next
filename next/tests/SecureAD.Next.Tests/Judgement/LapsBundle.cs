using System.Globalization;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Schema;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// Builds a sealed bundle holding one computer and a schema partition, for the two LAPS rules.
/// </summary>
/// <remarks>
/// <para>
/// <b>The schema partition is written into every bundle here, and that is the point.</b> Both rules
/// declare <c>DerivedFactKind.AttributeVisibility</c>, so a bundle without one is refused by the
/// judging before a rule sees an object. Writing real <c>attributeSchema</c> objects means the
/// visibility answer these tests turn on is derived from schema rows rather than asserted by a test
/// - which is the difference between checking the rule and checking that the rule agrees with
/// itself.
/// </para>
/// <para>
/// <b>Shared by both rules' tests deliberately.</b> SEC-091 and SEC-094 divide one population
/// between them, and a machine that is a positive for one must be a negative for the other. Two
/// builders would let the two rules be tested against two different forests, and the boundary
/// between them is exactly where a defect would sit.
/// </para>
/// </remarks>
internal static class LapsBundle
{
    private const string ModernAttribute = "msLAPS-PasswordExpirationTime";
    private const string LegacyAttribute = "ms-Mcs-AdmPwdExpirationTime";

    private const string Forest = "ad.lab";

    /// <summary>
    /// Writes a bundle holding one computer, and returns the directory it is in.
    /// </summary>
    /// <param name="dn">The computer's distinguished name.</param>
    /// <param name="objectClasses">Its <c>objectClass</c> chain, most derived last.</param>
    /// <param name="operatingSystem">Its <c>operatingSystem</c>, or null for a machine nobody can identify.</param>
    /// <param name="operatingSystemVersion">Its <c>operatingSystemVersion</c>, or null.</param>
    /// <param name="windowsLapsExpiration">The modern timestamp, or null where it carries none.</param>
    /// <param name="legacyLapsExpiration">The legacy timestamp, or null where it carries none.</param>
    /// <param name="userAccountControl">Its <c>userAccountControl</c>, which feeds the domain-controller signals.</param>
    /// <param name="confidential">
    /// Whether this forest has marked both LAPS expiration attributes confidential. No real forest
    /// does, which is why it has to be arranged here.
    /// </param>
    /// <param name="windowsLapsInSchema">
    /// Whether the Windows LAPS schema extension was ever applied to this forest.
    /// </param>
    /// <param name="started">When the capture ran.</param>
    /// <param name="primaryGroupId">
    /// Its <c>primaryGroupID</c>, or null to leave it absent. 516 is Domain Controllers, which is
    /// the domain-controller signal a machine can carry without the trust-account bit.
    /// </param>
    public static string Build(
        string dn,
        IReadOnlyList<string> objectClasses,
        string? operatingSystem,
        string? operatingSystemVersion,
        string? windowsLapsExpiration,
        string? legacyLapsExpiration,
        uint userAccountControl,
        bool confidential,
        bool windowsLapsInSchema,
        DateTimeOffset started,
        int? primaryGroupId = null)
    {
        var directory = Path.Combine(
            Path.GetTempPath(), "securead-laps-tests", Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(directory);

        using (var writer = BundleWriter.Create(directory, started))
        {
            writer.WriteCoverage(Partition);

            // Both partitions' coverage first. Coverage is what the absence of an object is
            // interpreted against, so the writer refuses an object attributed to a partition it has
            // not been told about - which is the same principle as docs/decisions/0002 one layer
            // down.
            writer.WriteCoverage(SchemaPartition);

            var attributes = new List<EvidenceAttribute>
            {
                Multi("objectClass", objectClasses),
                Text("userAccountControl", userAccountControl.ToString(CultureInfo.InvariantCulture)),
                Text("sAMAccountName", NameOf(dn)),
            };

            if (operatingSystem is not null)
                attributes.Add(Text("operatingSystem", operatingSystem));

            if (primaryGroupId is { } group)
            {
                attributes.Add(Text(
                    "primaryGroupID", group.ToString(CultureInfo.InvariantCulture)));
            }

            if (operatingSystemVersion is not null)
                attributes.Add(Text("operatingSystemVersion", operatingSystemVersion));

            if (windowsLapsExpiration is not null)
                attributes.Add(Text(ModernAttribute, windowsLapsExpiration));

            if (legacyLapsExpiration is not null)
                attributes.Add(Text(LegacyAttribute, legacyLapsExpiration));

            writer.WriteObject(
                new EvidenceObject(Partition, dn, Guid.NewGuid(), attributes, started));

            // The schema partition. searchFlags of 0 is what Microsoft ships and what ad.lab
            // returned on 2026-09-03; 128 is the hardened forest that no lab run will produce.
            var flags = confidential ? SchemaAttributeFlags.Confidential : 0;

            if (windowsLapsInSchema)
                WriteSchemaAttribute(writer, ModernAttribute, flags, started);

            WriteSchemaAttribute(writer, LegacyAttribute, flags, started);

            writer.Complete(Coverage, started.AddMinutes(1));
        }

        return directory;
    }

    /// <summary>
    /// Writes a bundle holding several computers, for the inventory rather than for a rule.
    /// </summary>
    /// <remarks>
    /// <b>The same builder, because the grid and the rules must be tested against one forest.</b>
    /// Two builders would let the inventory be exercised against a directory the rules never see,
    /// and the boundary between them is exactly where a disagreement would sit.
    /// </remarks>
    /// <param name="computers">
    /// One entry per machine: its distinguished name, operating system and version, the modern and
    /// legacy timestamps, and its <c>userAccountControl</c>.
    /// </param>
    /// <param name="started">When the capture ran.</param>
    public static string BuildMany(
        IReadOnlyList<(string Dn, string? Os, string? Version, string? Modern, string? Legacy, uint Uac)> computers,
        DateTimeOffset started)
    {
        ArgumentNullException.ThrowIfNull(computers);

        var directory = Path.Combine(
            Path.GetTempPath(), "securead-laps-tests", Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(directory);

        using (var writer = BundleWriter.Create(directory, started))
        {
            writer.WriteCoverage(Partition);
            writer.WriteCoverage(SchemaPartition);

            foreach (var computer in computers)
            {
                var attributes = new List<EvidenceAttribute>
                {
                    Multi("objectClass", ["top", "person", "organizationalPerson", "user", "computer"]),
                    Text("userAccountControl", computer.Uac.ToString(CultureInfo.InvariantCulture)),
                    Text("sAMAccountName", NameOf(computer.Dn)),
                };

                if (computer.Os is not null)
                    attributes.Add(Text("operatingSystem", computer.Os));

                if (computer.Version is not null)
                    attributes.Add(Text("operatingSystemVersion", computer.Version));

                if (computer.Modern is not null)
                    attributes.Add(Text(ModernAttribute, computer.Modern));

                if (computer.Legacy is not null)
                    attributes.Add(Text(LegacyAttribute, computer.Legacy));

                writer.WriteObject(
                    new EvidenceObject(
                        Partition, computer.Dn, Guid.NewGuid(), attributes, started));
            }

            WriteSchemaAttribute(writer, ModernAttribute, 0, started);
            WriteSchemaAttribute(writer, LegacyAttribute, 0, started);

            writer.Complete(Coverage, started.AddMinutes(1));
        }

        return directory;
    }

    /// <summary>
    /// Writes one <c>attributeSchema</c> object, as capture stores it.
    /// </summary>
    /// <remarks>
    /// <c>schemaIDGUID</c> is what marks the row as a schema definition - the reader discriminates
    /// on it rather than on <c>objectClass</c>, which is multi-valued and lives in its own table.
    /// </remarks>
    private static void WriteSchemaAttribute(
        BundleWriter writer, string ldapDisplayName, int searchFlags, DateTimeOffset started) =>
        writer.WriteObject(
            new EvidenceObject(
                SchemaPartition,
                $"CN={ldapDisplayName},CN=Schema,CN=Configuration,DC=ad,DC=lab",
                Guid.NewGuid(),
                [
                    Text("objectClass", "attributeSchema"),
                    Text("lDAPDisplayName", ldapDisplayName),
                    Binary("schemaIDGUID", Guid.NewGuid().ToByteArray()),
                    Text("searchFlags", searchFlags.ToString(CultureInfo.InvariantCulture)),
                ],
                started));

    private static string NameOf(string dn) =>
        dn.Split(',')[0].Replace("CN=", string.Empty, StringComparison.OrdinalIgnoreCase) + "$";

    private static readonly PartitionCoverage Partition = new(
        "DC=ad,DC=lab",
        NamingContextKind.Domain,
        "dc01.ad.lab",
        ConnectionSecurityLevel.SignedAndSealed,
        1,
        1,
        0,
        [],
        false);

    private static readonly PartitionCoverage SchemaPartition = new(
        "CN=Schema,CN=Configuration,DC=ad,DC=lab",
        NamingContextKind.Schema,
        "dc01.ad.lab",
        ConnectionSecurityLevel.SignedAndSealed,
        1,
        1,
        0,
        [],
        false);

    private static readonly RunCoverage Coverage = RunCoverage.Of(
        CoverageId.ForDomains(Forest, [Forest]),
        [DomainCoverage.Read(Forest)],
        [
            ForestPartitionCoverage.Read(
                "CN=Configuration,DC=ad,DC=lab", NamingContextKind.Configuration),
            ForestPartitionCoverage.Read(
                "CN=Schema,CN=Configuration,DC=ad,DC=lab", NamingContextKind.Schema),
        ],
        SysvolCoverage.Of([]));

    private static EvidenceAttribute Text(string name, string value) =>
        new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(value)]);

    private static EvidenceAttribute Multi(string name, IReadOnlyList<string> values) =>
        new(name, StoredAttributeCompleteness.Complete, [.. values.Select(EvidenceValue.OfText)]);

    private static EvidenceAttribute Binary(string name, byte[] bytes) =>
        new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(bytes)]);
}
