using System.Globalization;
using System.Security.AccessControl;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

// What a sealed bundle says about itself. Written after a production capture produced a bundle
// several times the expected size and nothing in the product could report what was inside it.
public sealed class BundleContentsTests
{
    private static readonly DateTimeOffset When = new(2026, 9, 22, 12, 0, 0, TimeSpan.Zero);
    private const string Domain = "DC=ad,DC=lab";

    [Fact]
    public void DescriptorsStoredOnceAndSharedAreReportedAsShared()
    {
        // Five hundred objects over ten descriptors. The reuse factor has one right answer, and a
        // report that counted rows instead of distinct descriptors could not produce it.
        var directory = Write(objects: 500, descriptors: 10);

        var contents = BundleContents.Read(directory, includeWeights: false, CancellationToken.None);

        Assert.True(contents.IsSuccess, contents.Error?.Description);
        Assert.Equal((500L, 10L, 500L, 50d), (
            contents.Value!.Objects,
            contents.Value.DescriptorsStored,
            contents.Value.DescriptorUses,
            contents.Value.ReuseFactor));
    }

    [Fact]
    public void APolicyNobodyCouldOpenIsCountedAgainstEveryPolicyDeclared()
    {
        // The case the owner's production run hit: most policies read, a minority refused. The
        // denominator is the point - "3,275 policies" alone would read as complete coverage.
        var directory = Write(objects: 1, descriptors: 1, policiesRead: 6, policiesRefused: 4);

        var contents = BundleContents.Read(directory, includeWeights: false, CancellationToken.None);

        Assert.True(contents.IsSuccess, contents.Error?.Description);
        Assert.Equal((10L, 6L, 4L), (
            contents.Value!.PoliciesDeclared,
            contents.Value.PoliciesRead,
            contents.Value.PoliciesNotReadInFull));
    }

    [Fact]
    public void WhatTheFileSystemSaidAboutARefusedPolicyIsKept()
    {
        // An operator's first question about a missed policy is whether his account was refused or
        // the folder was gone, because only one of those is fixed by running again as somebody else.
        var directory = Write(objects: 1, descriptors: 1, policiesRead: 0, policiesRefused: 1);

        var contents = BundleContents.Read(directory, includeWeights: false, CancellationToken.None);

        Assert.True(contents.IsSuccess, contents.Error?.Description);
        var refused = Assert.Single(contents.Value!.WhyPoliciesWentUnread);
        Assert.Equal((Refusal, 1L), (refused.Reason, refused.Policies));
    }

    [Fact]
    public void NothingStoredMeansNoShareToReportRatherThanDivisionByZero()
    {
        var directory = Write(objects: 0, descriptors: 0);

        var contents = BundleContents.Read(directory, includeWeights: false, CancellationToken.None);

        Assert.True(contents.IsSuccess, contents.Error?.Description);
        Assert.Null(contents.Value!.ReuseFactor);
    }

    [Fact]
    public void TheHeaviestTableIsNamedWhenSizesAreAskedFor()
    {
        var directory = Write(objects: 200, descriptors: 5);

        var contents = BundleContents.Read(directory, includeWeights: true, CancellationToken.None);

        Assert.True(contents.IsSuccess, contents.Error?.Description);
        Assert.Equal("captured_object", contents.Value!.SpaceByTable![0].Table);
    }

    [Fact]
    public void AnEntryRepeatedAcrossDescriptorsIsCountedOnceAsDistinct()
    {
        // Ten descriptors, each with one entry of its own plus the same inherited entry. Twenty
        // entries stored, eleven distinct: a report that counted rows for both could not tell an
        // inherited entry repeated ten times from ten entries that genuinely differ.
        var directory = Write(objects: 10, descriptors: 10, identicalEntries: true);

        var contents = BundleContents.Read(directory, includeWeights: false, CancellationToken.None);

        Assert.True(contents.IsSuccess, contents.Error?.Description);
        Assert.Equal((20L, 11L), (
            contents.Value!.AccessControlEntries,
            contents.Value.DistinctEntries));
    }

    [Fact]
    public void EntriesThatGenuinelyDifferAreCountedAsDistinct()
    {
        // The other direction, so the member cannot pass by always reporting one.
        var directory = Write(objects: 10, descriptors: 10);

        var contents = BundleContents.Read(directory, includeWeights: false, CancellationToken.None);

        Assert.True(contents.IsSuccess, contents.Error?.Description);
        Assert.Equal((10L, 10L, 1d), (
            contents.Value!.AccessControlEntries,
            contents.Value.DistinctEntries,
            contents.Value.EntryRepetition));
    }

    [Fact]
    public void SizesNotAskedForAreNullRatherThanEmpty()
    {
        // The measurement reads every row of every table, so on a bundle of tens of gigabytes it
        // must not happen merely because somebody asked how many objects there were. Null rather
        // than empty because "nobody measured" and "there is nothing here" are different answers.
        var directory = Write(objects: 200, descriptors: 5);

        var contents = BundleContents.Read(directory, includeWeights: false, CancellationToken.None);

        Assert.True(contents.IsSuccess, contents.Error?.Description);
        Assert.Null(contents.Value!.SpaceByTable);
    }

    [Fact]
    public void AMeasurementThatWasTakenNamesTheHeaviestTable()
    {
        var directory = Write(objects: 200, descriptors: 5);

        var contents = BundleContents.Read(directory, includeWeights: true, CancellationToken.None);

        Assert.True(contents.IsSuccess, contents.Error?.Description);
        Assert.Equal("captured_object", contents.Value!.SpaceByTable![0].Table);
    }

    [Fact]
    public void ARecordSaysWhetherTheSpaceWasMeasuredOrMerelyNotThere()
    {
        // Both directions, because the distinction is the point: null means nobody measured, an
        // empty list would mean the bundle holds nothing. A boolean flag was tried here first and
        // removed - gate 4b proved it could only ever say one thing, and a completeness flag that
        // is always true excuses every other figure on the type while measuring nothing.
        var directory = Write(objects: 200, descriptors: 5);

        var counted = BundleContents.Read(directory, includeWeights: false, CancellationToken.None);
        var measured = BundleContents.Read(directory, includeWeights: true, CancellationToken.None);

        Assert.True(counted.IsSuccess, counted.Error?.Description);
        Assert.True(measured.IsSuccess, measured.Error?.Description);
        Assert.Null(counted.Value!.SpaceByTable);
        Assert.NotEmpty(measured.Value!.SpaceByTable!);
    }

    [Fact]
    public void AFolderWithNoEvidenceIsRefusedRatherThanReportedAsEmpty()
    {
        var directory = Path.Combine(AppContext.BaseDirectory, "describe-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        var contents = BundleContents.Read(directory, includeWeights: false, CancellationToken.None);

        Assert.False(contents.IsSuccess);
        Assert.Equal("Evidence.BundleAbsent", contents.Error!.Code);
    }

    [Fact]
    public void ARunThatNeverFinishedSealingSaysSoRatherThanLookingAbsent()
    {
        // A capture stopped by a full disk leaves its file behind under another name. Reporting
        // that as "no bundle here" would send an operator looking for the wrong problem.
        var directory = Path.Combine(AppContext.BaseDirectory, "describe-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "evidence.db.partial"), "incomplete");

        var contents = BundleContents.Read(directory, includeWeights: false, CancellationToken.None);

        Assert.False(contents.IsSuccess);
        Assert.Equal("Evidence.BundleUnsealed", contents.Error!.Code);
    }

    /// <summary>
    /// A bundle from another schema version is refused by name, rather than crashing part way
    /// through counting tables it does not have.
    /// </summary>
    /// <remarks>
    /// <b>Found by walking into it.</b> This path does not go through <c>BundleReader.Open</c>, so
    /// it had no schema gate at all - it simply counted named tables. That was invisible while one
    /// schema existed; <c>P-272</c> renamed the permission tables, and the first thing anybody
    /// would do with an older bundle is ask what is in it. An operator got a stack trace where the
    /// product knows the answer and can say it.
    /// </remarks>
    [Fact]
    public void ABundleFromAnotherSchemaVersionIsRefusedByName()
    {
        var directory = Write(objects: 1, descriptors: 1);
        SetSchemaVersion(directory, BundleSchema.Version - 1);

        var contents = BundleContents.Read(directory, includeWeights: false, CancellationToken.None);

        Assert.False(contents.IsSuccess);
        Assert.Equal("Evidence.SchemaVersionUnsupported", contents.Error!.Code);

        // The version it was written against and the version this build reads both appear, because
        // "wrong version" without either number tells an operator nothing he can act on.
        Assert.Contains(
            (BundleSchema.Version - 1).ToString(CultureInfo.InvariantCulture),
            contents.Error.Description,
            StringComparison.Ordinal);
        Assert.Contains(
            BundleSchema.Version.ToString(CultureInfo.InvariantCulture),
            contents.Error.Description,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A bundle whose own account of itself cannot be read says that, which is a different answer
    /// from a version this build does not support.
    /// </summary>
    [Fact]
    public void ABundleThatCannotStateItsSchemaIsRefusedAsUnreadable()
    {
        var directory = Write(objects: 1, descriptors: 1);
        Execute(directory, "DROP TABLE bundle");

        var contents = BundleContents.Read(directory, includeWeights: false, CancellationToken.None);

        Assert.False(contents.IsSuccess);
        Assert.Equal("Evidence.EvidenceUnreadable", contents.Error!.Code);
    }

    private static void SetSchemaVersion(string directory, int version) =>
        Execute(directory, $"UPDATE bundle SET schema_version = {version}");

    private static void Execute(string directory, string sql)
    {
        using var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = BundleLayout.EvidencePath(directory),
                Pooling = false,
            }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private const string Refusal = "Access to the path was denied.";

    private static string Write(
        int objects, int descriptors, int policiesRead = 0, int policiesRefused = 0,
        bool identicalEntries = false)
    {
        var directory = Path.Combine(AppContext.BaseDirectory, "describe-" + Guid.NewGuid().ToString("N"));
        var coverage = new PartitionCoverage(
            Domain, NamingContextKind.Domain, "dc1.ad.lab",
            ConnectionSecurityLevel.SignedAndSealed, 1, 1, 1, [], false);

        using (var writer = BundleWriter.Create(directory, When))
        {
            writer.WriteCoverage(coverage);
            for (var i = 0; i < objects; i++)
            {
                var guid = Guid.NewGuid();
                var id = writer.WriteObject(new(
                    coverage,
                    $"CN=user{i},OU=People,{Domain}",
                    guid,
                    [
                        new("objectClass", StoredAttributeCompleteness.Complete,
                            [EvidenceValue.OfText("top"), EvidenceValue.OfText("user")]),
                        new("sAMAccountName", StoredAttributeCompleteness.Complete,
                            [EvidenceValue.OfText($"user{i}")]),
                    ],
                    When));

                if (descriptors == 0)
                    continue;

                // Each descriptor carries one entry unique to it plus one shared by all of them,
                // which is the shape of an inherited entry: present on every descendant, identical
                // every time. Identical whole descriptors would deduplicate at the descriptor
                // level and never reach the entry table twice, so they cannot pose this question.
                var raw = identicalEntries
                    ? new RawSecurityDescriptor($"O:SYG:SYD:(A;;0x{i + 1:X};;;AU)(A;CIID;0x1;;;WD)")
                    : new RawSecurityDescriptor($"O:SYG:SYD:(A;;0x{(i % descriptors) + 1:X};;;AU)");
                var bytes = new byte[raw.BinaryLength];
                raw.GetBinaryForm(bytes, 0);
                writer.WriteSecurityDescriptor(id, bytes,
                    AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
            }

            var policies = new List<GpoCoverage>();
            for (var i = 0; i < policiesRead; i++)
            {
                policies.Add(GpoCoverage.Read(
                    Guid.NewGuid(), $"Readable policy {i}", $"\\\\ad.lab\\SysVol\\ad.lab\\Policies\\read{i}"));
            }

            for (var i = 0; i < policiesRefused; i++)
            {
                policies.Add(GpoCoverage.Unreadable(
                    Guid.NewGuid(), $"Locked policy {i}",
                    $"\\\\ad.lab\\SysVol\\ad.lab\\Policies\\locked{i}", Refusal));
            }

            writer.Complete(
                RunCoverage.Of(
                    CoverageId.ForDomains("ad.lab", ["ad.lab"]),
                    [DomainCoverage.Read("ad.lab")],
                    [
                        ForestPartitionCoverage.Read("CN=Configuration," + Domain, NamingContextKind.Configuration),
                        ForestPartitionCoverage.Read("CN=Schema,CN=Configuration," + Domain, NamingContextKind.Schema),
                    ],
                    SysvolCoverage.Of(policies)),
                When.AddMinutes(1));
        }

        return directory;
    }
}
