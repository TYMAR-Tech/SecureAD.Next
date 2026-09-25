using System.Text.Json;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using SecureAD.Measure;
using Xunit;
using SdBytes = global::SecureAD.Next.Tests.Kernel.Security.SdBytes;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// The shape profile: what it measures, and what it must never carry out of the environment it was
/// taken in.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a profile exists at all.</b> Every <c>P-280</c> figure rests on a synthetic bundle this
/// codebase generated, so it can only hold assumptions the code already held - it has no
/// object-type GUIDs, no <c>SELF</c> variation, no control edges, and not one unreadable or partly
/// parsed descriptor. A bench like that cannot disagree with us, which is <c>F-S44-2</c>. The owner
/// cannot export a bundle, so the anchor has to be small enough to carry and harmless enough to be
/// allowed out.
/// </para>
/// <para>
/// <b>The leak gate is the most valuable test in this file and the easiest to write badly.</b> A
/// check that asserts some secrets are absent from a document that is empty, or from one that never
/// held them, passes while measuring nothing - the failure this repository keeps finding in itself.
/// So every absence assertion here is paired with a positive one proving the profile really did see
/// the thing it refused to write down, and counted it.
/// </para>
/// </remarks>
public sealed class ShapeProfileTests
{
    /// <summary>
    /// The bundle sits inside a directory whose name is itself a marker.
    /// </summary>
    /// <remarks>
    /// <b>Because the first version of the path check could not fail.</b> It asserted that
    /// <c>C:\Users\…</c> was absent from the document, and JSON escapes a backslash as <c>\\</c>,
    /// so the raw path never appeared literally however much of it was emitted - the check passed
    /// with the whole path in the output. A marker with no separator in it is comparable against
    /// the escaped document, which is the only form the assertion ever sees.
    /// </remarks>
    private const string SecretParent = "zqxjvbparent";

    private readonly string _directory = Path.Combine(
        Path.GetTempPath(), "securead-" + SecretParent + "-" + Guid.NewGuid().ToString("N"), "run");

    private static readonly DateTimeOffset Started = new(2026, 9, 25, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 9, 25, 11, 30, 0, TimeSpan.Zero);

    // Markers chosen so that a single occurrence anywhere in the output is unmistakable, and so no
    // ordinary word, GUID or path fragment could produce one by accident.
    private const string SecretDomain = "DC=zqxjvbmarker,DC=example";
    private const string SecretRdn = "CN=Zqxjvb-Secret-Account";
    private const string SecretOu = "OU=Zqxjvb-Secret-Container";
    private const string SecretDn = SecretRdn + "," + SecretOu + "," + SecretDomain;
    private const string SecretDomainSid = "S-1-5-21-1111111111-2222222222-3333333333";
    private const string SecretTrusteeSid = SecretDomainSid + "-1105";

    /// <summary>A GUID no shipped catalogue can know, standing in for a forest's own extension.</summary>
    private const string SecretSchemaGuid = "deadbeef-0000-4000-8000-000000000001";

    /// <summary>One Microsoft publishes, which anyone can check against the schema reference.</summary>
    private const string PublishedSchemaGuid = "ab721a53-1e2f-11d0-9819-00aa0040529b";
    private const string PublishedSchemaName = "User-Change-Password";

    // -------------------------------------------------------------------------------------------
    // The leak gate
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// Nothing that identifies the forest reaches the document.
    /// </summary>
    /// <remarks>
    /// Each marker is a different kind of secret and a different route into the profile: a
    /// distinguished name read in pass one, a trustee SID and a schema GUID read in pass two, and
    /// the path of the bundle itself, which on the owner's machine carries his account name.
    /// </remarks>
    [Theory]
    [InlineData(SecretDn)]
    [InlineData(SecretRdn)]
    [InlineData(SecretOu)]
    [InlineData(SecretDomain)]
    [InlineData("zqxjvbmarker")]
    [InlineData(SecretTrusteeSid)]
    [InlineData(SecretDomainSid)]
    [InlineData(SecretSchemaGuid)]
    [InlineData("deadbeef")]
    public void NothingThatIdentifiesTheForestReachesTheProfile(string secret)
    {
        WriteBundleFullOfSecrets();

        Assert.DoesNotContain(secret, Json(), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The path the bundle was read from does not reach the document either.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Not a hypothetical. The owner's captures live under his own profile directory, so a full
    /// path carries his account name and a customer engagement's would carry the customer's. Only
    /// the run's own folder name is reported.
    /// </para>
    /// <para>
    /// <b>Asserted against a marker in the parent folder's name rather than against the path.</b>
    /// See <see cref="SecretParent"/>: comparing a path to JSON compares an unescaped string to an
    /// escaped document, and a check written that way passed with the whole path in the output.
    /// </para>
    /// </remarks>
    [Fact]
    public void ThePathTheBundleWasReadFromDoesNotReachTheProfile()
    {
        WriteBundleFullOfSecrets();

        Assert.DoesNotContain(SecretParent, Json(), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The run's own folder name is reported, so the document is not anonymous.</summary>
    /// <remarks>
    /// The negative control for the test above: without it, a profile that reported no bundle name
    /// at all would satisfy it, and an operator comparing two profiles could not tell which capture
    /// each came from.
    /// </remarks>
    [Fact]
    public void TheRunsOwnFolderNameIsReported()
    {
        WriteBundleFullOfSecrets();

        Assert.Equal("run", ShapeProfile.Of(_directory).Bundle);
    }

    /// <summary>
    /// The document is not empty, and really does carry what it is allowed to carry.
    /// </summary>
    /// <remarks>
    /// <b>The negative control for every absence above.</b> Without it, a profile that returned an
    /// empty object - or threw and was swallowed - would satisfy all nine of them. A published GUID
    /// and its published name being present proves the document was produced, was populated, and
    /// passed a GUID through the same gate that refused the secret one.
    /// </remarks>
    [Fact]
    public void ThePublishedSchemaGuidAndItsNameDoReachTheProfile()
    {
        WriteBundleFullOfSecrets();

        var json = Json();

        Assert.Contains(PublishedSchemaGuid, json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(PublishedSchemaName, json, StringComparison.Ordinal);
    }

    /// <summary>
    /// The profile saw the secret schema GUID and counted it, rather than quietly dropping it.
    /// </summary>
    /// <remarks>
    /// <b>The second negative control, and the one that makes the redaction useful rather than
    /// merely safe.</b> A profile that discarded everything it could not name would pass the leak
    /// gate perfectly and tell a generator nothing about how much of the forest is locally
    /// extended. Refusing to name a thing and refusing to count it are different acts.
    /// </remarks>
    [Fact]
    public void TheSecretSchemaGuidIsCountedEvenThoughItIsNeverNamed()
    {
        WriteBundleFullOfSecrets();

        var profile = ShapeProfile.Of(_directory);

        Assert.Equal(1, profile.Aces.DistinctObjectTypesOutsideTheShippedCatalogue);
        Assert.True(profile.Aces.ObjectTypesOutsideTheShippedCatalogue > 0);
    }

    /// <summary>
    /// And the same for the trustee that is not well-known.
    /// </summary>
    [Fact]
    public void TheSecretTrusteeIsCountedEvenThoughItIsNeverNamed()
    {
        WriteBundleFullOfSecrets();

        var profile = ShapeProfile.Of(_directory);

        Assert.True(profile.Aces.CarryingATrusteeThatIsNotWellKnown > 0);
    }

    /// <summary>
    /// A well-known trustee is named, because it means the same thing in every Active Directory.
    /// </summary>
    [Fact]
    public void AWellKnownTrusteeIsNamed()
    {
        WriteBundleFullOfSecrets();

        var profile = ShapeProfile.Of(_directory);

        Assert.Contains(profile.Trustees, t => t.Value == "S-1-5-32-544");
    }

    /// <summary>
    /// A GUID the shipped catalogue does not know is refused even when the forest's own captured
    /// schema would have named it.
    /// </summary>
    /// <remarks>
    /// The one way this gate could be built wrong while still looking right. The bundle's captured
    /// schema holds the forest's extensions <i>and</i> re-reads the base schema, so a profile that
    /// asked the capture "do you know this GUID?" would answer yes for <c>contoso-PayrollId</c> and
    /// print it. <see cref="ShapeProfile.Publishable"/> asks
    /// <see cref="SchemaGuidCatalog.Embedded"/>, which needs no capture and is the same in every
    /// forest.
    /// </remarks>
    [Fact]
    public void TheShippedCatalogueDecidesWhatMayBeNamedRatherThanTheForestsOwnSchema()
    {
        Assert.Null(ShapeProfile.Publishable.SchemaName(SecretSchemaGuid));
        Assert.Equal(PublishedSchemaName, ShapeProfile.Publishable.SchemaName(PublishedSchemaGuid));
    }

    /// <summary>A SID the catalogue does not know is refused, without anything testing for a prefix.</summary>
    [Fact]
    public void ASidThatIsNotWellKnownIsNeverNamed()
    {
        Assert.Null(ShapeProfile.Publishable.TrusteeName(SecretTrusteeSid));
        Assert.Equal(@"BUILTIN\Administrators", ShapeProfile.Publishable.TrusteeName("S-1-5-32-544"));
    }

    // -------------------------------------------------------------------------------------------
    // What it measures
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The spread is reported, not just the average, because the average is what got the occurrence
    /// estimate wrong by twelve million rows.
    /// </summary>
    [Fact]
    public void TheSpreadOfEntriesPerDescriptorIsReported()
    {
        var spread = ShapeProfile.Distribution.Of([1, 1, 2, 3, 5, 8, 13, 21, 34, 100]);

        Assert.Equal(10, spread.Count);
        Assert.Equal(1, spread.Minimum);
        Assert.Equal(100, spread.Maximum);
        Assert.Equal(5, spread.P50);
        Assert.Equal(188, spread.Total);
    }

    /// <summary>
    /// A percentile is nearest-rank, so every value it reports is one the forest really holds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Interpolating would report a descriptor carrying 6.5 entries, and a generator cannot build
    /// one. On ten sorted values the p90 is the ninth and the p99 is the tenth.
    /// </para>
    /// <para>
    /// <b>The p99 is asserted because the p50 and the p90 do not discriminate.</b> Shifting the
    /// rank from <c>ceiling(f x n) - 1</c> to <c>floor(f x (n-1))</c> leaves both of those
    /// unchanged on ten values, and a mutation doing exactly that survived a version of this test
    /// that stopped at the p90. The top percentile is where the definitions part, and it is also
    /// the one the tail of a real forest lives in.
    /// </para>
    /// </remarks>
    [Fact]
    public void APercentileIsAValueTheForestActuallyHolds()
    {
        var spread = ShapeProfile.Distribution.Of([1, 1, 2, 3, 5, 8, 13, 21, 34, 100]);

        Assert.Equal(34, spread.P90);
        Assert.Equal(100, spread.P99);
    }

    /// <summary>An empty measurement says nothing rather than dividing by zero.</summary>
    [Fact]
    public void AnEmptyMeasurementReportsZeroesRatherThanFailing()
    {
        var spread = ShapeProfile.Distribution.Of([]);

        Assert.Equal(0, spread.Count);
        Assert.Equal(0, spread.Mean);
    }

    /// <summary>
    /// The grid puts the two measurements together, which two separate distributions cannot.
    /// </summary>
    /// <remarks>
    /// The 344-million estimate assumed entry count and reuse count were unrelated across the
    /// forest and came in 3.8% over. A generator handed only the marginals is free to get their
    /// relationship wrong in exactly that way; a grid pins it.
    /// <para>
    /// Bucket 0 holds 1, and bucket 9 holds 512 to 1,023, so a descriptor of 1,000 entries used
    /// once and one entry used 1,000 times land in opposite corners rather than on the diagonal.
    /// </para>
    /// </remarks>
    [Fact]
    public void TheGridRecordsHowEntryCountAndReuseVaryTogether()
    {
        var grid = ShapeProfile.Grid.Of("entries", "reuse", [(1, 1), (1, 1), (1000, 1), (1, 1000)]);

        Assert.Equal(512, grid.RowEdges[9]);
        Assert.Equal(2, grid.Counts[0][0]);
        Assert.Equal(1, grid.Counts[9][0]);
        Assert.Equal(1, grid.Counts[0][9]);
    }

    /// <summary>
    /// An object with no stored descriptor is counted as such, not as one holding no permissions.
    /// </summary>
    /// <remarks>
    /// 280,871 of the production capture's 940,067 objects are in this state - nearly a third. A
    /// generator that built them as permission-free objects would model a third of the forest as
    /// something it is not.
    /// </remarks>
    [Fact]
    public void AnObjectWithNoStoredDescriptorIsCountedApart()
    {
        WriteBundleFullOfSecrets();

        var profile = ShapeProfile.Of(_directory);

        Assert.Equal(1, profile.ObjectsWithNoDescriptorStored);
        Assert.Equal(3, profile.ObjectsCaptured);
        Assert.Equal(2, profile.ObjectsWithADescriptorStored);
    }

    /// <summary>The domains are counted and their sizes reported, and neither is named.</summary>
    [Fact]
    public void DomainsAreCountedAndTheirSizesReportedWithoutNamingThem()
    {
        WriteBundleFullOfSecrets();

        var profile = ShapeProfile.Of(_directory);

        Assert.Equal(1, profile.Domains);
        Assert.Equal([2], profile.ObjectsPerDomain);
    }

    /// <summary>
    /// A relative name containing <c>DC=</c> does not become a domain of its own.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Found by reading the code before the tool was carried anywhere. The first version searched
    /// for <c>DC=</c> anywhere in the name, so <c>CN=SQLDC=primary</c> was read as a domain and
    /// would have inflated the count of a nine-domain forest to something nobody could check it
    /// against - a wrong number in the one place there is no second opinion.
    /// </para>
    /// <para>
    /// The three objects here sit in two real domains, and one of them carries the trap.
    /// </para>
    /// </remarks>
    [Fact]
    public void ARelativeNameContainingDcDoesNotBecomeADomain()
    {
        const string Other = "DC=zqxjvbsecond,DC=example";
        var raw = SdBytes.SelfRelativeSd(
            ownerSid: null, daclAces: [SdBytes.AllowAce(SdBytes.Administrators, 0x10)]);

        using (var writer = BundleWriter.Create(_directory, Started))
        {
            writer.WriteCoverage(SomeCoverage());
            foreach (var dn in new[]
                     {
                         "CN=Zqxjvb-Plain," + SecretDomain,
                         "CN=SQLDC=primary," + SecretDomain,
                         "CN=Zqxjvb-Elsewhere," + Other,
                     })
            {
                writer.WriteSecurityDescriptor(writer.WriteObject(ObjectAt(dn)), raw, Parsed(raw));
            }

            writer.Complete(OneDomainRead(), Finished);
        }

        var profile = ShapeProfile.Of(_directory);

        Assert.Equal(2, profile.Domains);
        Assert.Equal([2, 1], profile.ObjectsPerDomain);
    }

    /// <summary>A directory that is not a bundle is named as such, not met with a stack trace.</summary>
    [Fact]
    public void ADirectoryThatIsNotABundleIsRefusedByName()
    {
        Directory.CreateDirectory(_directory);

        var error = Assert.Throws<InvalidDataException>(() => ShapeProfile.Of(_directory));
        Assert.Contains("no sealed evidence file", error.Message, StringComparison.Ordinal);
    }

    /// <summary>Profiling a bundle leaves it byte for byte as it was.</summary>
    [Fact]
    public void ProfilingWritesNothingToTheBundle()
    {
        WriteBundleFullOfSecrets();
        var before = BundleSealing.HashFile(BundleLayout.EvidencePath(_directory));

        ShapeProfile.Of(_directory);

        Assert.Equal(before, BundleSealing.HashFile(BundleLayout.EvidencePath(_directory)));
    }

    // -------------------------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// A bundle in which every field the profile reads holds something that must not leave.
    /// </summary>
    /// <remarks>
    /// Two objects carrying descriptors and one without, so the leak gate and the counting checks
    /// share one fixture and neither can pass because the other's data was absent.
    /// </remarks>
    private void WriteBundleFullOfSecrets()
    {
        byte[] secretTrustee = SdBytes.Sid(1, 5, [21, 1111111111, 2222222222, 3333333333, 1105]);

        byte[] raw = SdBytes.SelfRelativeSd(
            ownerSid: secretTrustee,
            daclAces:
            [
                SdBytes.AllowAce(secretTrustee, 0x00000010),
                SdBytes.AllowAce(SdBytes.Administrators, 0x00000020),
                SdBytes.AllowObjectAce(
                    SdBytes.Administrators, 0x00000100,
                    objectType: Guid.Parse(SecretSchemaGuid), inheritedObjectType: null),
                SdBytes.AllowObjectAce(
                    SdBytes.Administrators, 0x00000100,
                    objectType: Guid.Parse(PublishedSchemaGuid), inheritedObjectType: null),
            ]);

        using var writer = BundleWriter.Create(_directory, Started);
        writer.WriteCoverage(SomeCoverage());
        writer.WriteSecurityDescriptor(writer.WriteObject(ObjectAt(SecretDn)), raw, Parsed(raw));
        writer.WriteSecurityDescriptor(
            writer.WriteObject(ObjectAt("CN=Zqxjvb-Second," + SecretDomain)), raw, Parsed(raw));
        writer.WriteObject(ObjectAt("CN=Zqxjvb-NoDescriptor," + SecretDomain));
        writer.Complete(OneDomainRead(), Finished);
    }

    /// <summary>The profile as the operator would see it on disk.</summary>
    private string Json() =>
        JsonSerializer.Serialize(
            ShapeProfile.Of(_directory), new JsonSerializerOptions { WriteIndented = true });

    /// <summary>
    /// What the capturing run recorded, taken from the same bytes the profile will re-read.
    /// </summary>
    /// <remarks>
    /// Derived rather than hand-written so the fixture cannot drift from the descriptor it
    /// describes, and so a change to the parser does not silently leave the two disagreeing.
    /// </remarks>
    private static AceNormalizationResult Parsed(byte[] raw)
    {
        var parsed = SecurityDescriptorParser.Parse(raw);

        return new AceNormalizationResult(
            Guid.Empty,
            parsed.OwnerSid,
            parsed.GroupSid,
            parsed.DaclState,
            parsed.IsDaclProtected,
            [.. parsed.DaclAces.Select(ace => new CanonicalAce(
                ace.AceType,
                ace.TrusteeSid,
                ace.AccessMask,
                ace.ObjectTypeGuid,
                ace.InheritedObjectTypeGuid,
                ace.IsInherited,
                ace.InheritanceFlags,
                ace.PropagationFlags,
                ace.ApplicationData,
                AceHash: $"{ace.AceType}-{ace.TrusteeSid}-{ace.AccessMask:X8}-{ace.ObjectTypeGuid}",
                AceCanonicalization.Version))],
            parsed.Errors,
            parsed.DaclCompleteness,
            parsed.DaclWasCanonical);
    }

    private static RunCoverage OneDomainRead() =>
        RunCoverage.Of(
            CoverageId.ForDomains("zqxjvbmarker.example", ["zqxjvbmarker.example"]),
            [DomainCoverage.Read("zqxjvbmarker.example")],
            [
                ForestPartitionCoverage.Read(
                    "CN=Configuration," + SecretDomain, NamingContextKind.Configuration),
                ForestPartitionCoverage.Read(
                    "CN=Schema,CN=Configuration," + SecretDomain, NamingContextKind.Schema),
            ],
            SysvolCoverage.Of([]));

    private static PartitionCoverage SomeCoverage() => new(
        SecretDomain,
        NamingContextKind.Domain,
        "dc01.zqxjvbmarker.example",
        ConnectionSecurityLevel.SignedAndSealed,
        12,
        4200,
        3,
        [],
        false);

    private static EvidenceObject ObjectAt(string dn) =>
        new(SomeCoverage(), dn, Guid.NewGuid(), [], Started);
}
