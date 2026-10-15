using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using Xunit;
using SdBytes = SecureAD.Next.Tests.Kernel.Security.SdBytes;
using static SecureAD.Next.Tests.Judgement.ControlEdgeDeriverTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class DescriptorPreparationTests
{
    private const string Domain = "DC=contoso,DC=com";
    private const string FirstGuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    private static readonly DateTimeOffset When = new(2026, 9, 28, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void GroupedOrderKeepsEveryAttributeAndPermissionWhilePreparingEachDescriptorOnce()
    {
        var first = DetailedDescriptor();
        var second = SdBytes.SelfRelativeSd(SdBytes.Administrators, daclAces: [SdBytes.DenyAce(SdBytes.Everyone, 0x20000)]);
        string[] names = ["CN=Älice," + Domain, "CN=Other,DC=child," + Domain, "CN=älice," + Domain, @"CN=Smith\, John," + Domain];
        var directory = Bundle([new(names[0], first), new(names[1], second), new(names[2], first), new(names[3], second)], allValues: true);
        var before = Hash(directory);
        using var reference = BundleReader.Open(directory).Value;
        var subjects = reference.StreamObjects().Objects.ToDictionary(value => value.DistinguishedName, Json, StringComparer.Ordinal);
        using var bundle = BundleReader.Open(directory).Value;
        using (var groups = bundle.StreamDescriptorObjects(CancellationToken.None))
        {
            var seen = new List<string>();
            foreach (var subject in groups.Objects)
            {
                seen.Add(subject.DistinguishedName);
                Assert.Equal(subjects[subject.DistinguishedName], Json(subject));
                var reading = groups.ReadPermissions(subject);
                Assert.Equal(Json(reference.ReadPermissions(subject.DistinguishedName)), Json(reading.Permissions));
                reading.RequireCurrent();
            }
            Assert.Equal(new[] { names[0], names[2], names[1], names[3] }, seen);
            Assert.Equal(2, groups.PreparedDescriptors);
            Assert.Equal(7, groups.PreparedEntries);
            Assert.True(groups.OrderingTemporaryBytes > 0);
        }
        using var query = bundle.Connection.CreateCommand();
        query.CommandText = "SELECT COUNT(*) FROM sqlite_temp_master WHERE name LIKE 'descriptor_order_%'";
        Assert.Equal(0L, query.ExecuteScalar());
        Assert.Equal(before, Hash(directory));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AmbiguousNamesKeepTheOriginalSqlitePermissionSelection(bool sameSpelling)
    {
        var dn = "CN=Alice," + Domain;
        var directory = Bundle([new(dn, Simple(0x40000)), new(sameSpelling ? dn : dn.ToLowerInvariant(), Simple(0x20000))]);
        using var reference = BundleReader.Open(directory).Value;
        using var bundle = BundleReader.Open(directory).Value;
        using var groups = bundle.StreamDescriptorObjects(CancellationToken.None);
        var count = 0;
        foreach (var subject in groups.Objects)
        {
            Assert.Equal(Json(reference.ReadPermissions(subject.DistinguishedName)), Json(groups.ReadPermissions(subject).Permissions));
            count++;
        }
        Assert.Equal(2, count);
        Assert.Equal(1, groups.PreparedDescriptors);
    }

    [Theory]
    [InlineData("not-attempted", DescriptorAvailability.NotAttempted, DaclState.Unreadable)]
    [InlineData("unreadable", DescriptorAvailability.Unreadable, DaclState.Unreadable)]
    [InlineData("malformed", DescriptorAvailability.Read, DaclState.Unreadable)]
    [InlineData("partial", DescriptorAvailability.Read, DaclState.Present)]
    [InlineData("null", DescriptorAvailability.Read, DaclState.Null)]
    [InlineData("empty", DescriptorAvailability.Read, DaclState.Empty)]
    public void PreparationKeepsMissingMalformedAndEmptyEvidenceDistinct(string kind, DescriptorAvailability availability, DaclState state)
    {
        byte[]? bytes = kind switch
        {
            "not-attempted" or "unreadable" => null,
            "malformed" => [1, 2, 3],
            "partial" => SdBytes.SelfRelativeSd(null, daclAces: [SdBytes.AllowAce(SdBytes.Everyone, 0x10), [0, 0, 4, 0], SdBytes.DenyAce(SdBytes.Everyone, 0x20)]),
            "null" => SdBytes.SelfRelativeSd(null, daclPresent: false),
            _ => SdBytes.SelfRelativeSd(null, daclAces: []),
        };
        var directory = Bundle([new("CN=First," + Domain, bytes, kind == "unreadable" ? "access denied" : null),
            new("CN=Second," + Domain, bytes, kind == "unreadable" ? "access denied" : null)]);
        using var reference = BundleReader.Open(directory).Value;
        using var bundle = BundleReader.Open(directory).Value;
        using var groups = bundle.StreamDescriptorObjects(CancellationToken.None);
        foreach (var subject in groups.Objects)
        {
            var permissions = groups.ReadPermissions(subject).Permissions;
            Assert.Equal(Json(reference.ReadPermissions(subject.DistinguishedName)), Json(permissions));
            Assert.Equal(availability, permissions.Availability);
            Assert.Equal(state, permissions.DaclState);
            if (kind == "partial")
            {
                Assert.Equal(new[] { 0, 2 }, permissions.Entries.Select(entry => entry.Ordinal));
                Assert.Equal(DaclCompleteness.Incomplete, permissions.DaclCompleteness);
                Assert.NotEmpty(permissions.Errors);
            }
        }
        Assert.Equal(bytes is null ? 0 : 1, groups.PreparedDescriptors);
    }

    [Fact]
    public void PreparedDescriptorDoesNotExposeApplicationDataOrErrorBuffers()
    {
        var directory = Bundle([new("CN=Alice," + Domain, DetailedDescriptor()), new("CN=Bob," + Domain, DetailedDescriptor())]);
        using var bundle = BundleReader.Open(directory).Value;
        using var groups = bundle.StreamDescriptorObjects(CancellationToken.None);
        using var rows = groups.Objects.GetEnumerator();
        Assert.True(rows.MoveNext());
        var first = groups.ReadPermissions(rows.Current);
        first.Permissions.Entries[4].ApplicationData[0] = 255;
        var input = first.Descriptor!.ClassificationInput;
        input.Entries[4].ApplicationData[0] = 254;
        Assert.Throws<NotSupportedException>(() => ((IList<string>)first.Permissions.Errors).Add("invented error"));
        Assert.True(rows.MoveNext());
        var second = groups.ReadPermissions(rows.Current);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, second.Permissions.Entries[4].ApplicationData);
        Assert.Equal("This object (Bob)", second.Permissions.Entries[0].Trustee.Name);
        Assert.Equal("This object (Bob)", second.Permissions.Owner!.Name);
        Assert.Equal(1, groups.PreparedDescriptors);
    }

    [Fact]
    public void ClassificationContextCannotUseAnotherEvidenceStreamWithTheSameNumericIds()
    {
        var firstDirectory = Bundle([new("CN=First," + Domain, Simple(0x40000))]);
        var secondDirectory = Bundle([new("CN=Second," + Domain, Simple(0x20000))]);
        using var first = BundleReader.Open(firstDirectory).Value;
        using var second = BundleReader.Open(secondDirectory).Value;
        using var firstGroups = first.StreamDescriptorObjects(CancellationToken.None);
        using var secondGroups = second.StreamDescriptorObjects(CancellationToken.None);
        using var firstRows = firstGroups.Objects.GetEnumerator();
        using var secondRows = secondGroups.Objects.GetEnumerator();
        Assert.True(firstRows.MoveNext());
        Assert.True(secondRows.MoveNext());
        var a = firstGroups.ReadPermissions(firstRows.Current);
        var b = secondGroups.ReadPermissions(secondRows.Current);
        Assert.Equal(a.Permissions.DescriptorId, b.Permissions.DescriptorId);
        var context = new PermissionClassificationPreparation(firstGroups, SchemaGuidCatalog.Embedded, Guid.NewGuid());
        context.Prepare(a, new(), CancellationToken.None);
        Assert.Throws<InvalidOperationException>(() => context.Prepare(b, new(), CancellationToken.None));
    }

    [Fact]
    public void CapturedCataloguesStayIndependentEvenForTheSamePreparedEvidenceDescriptor()
    {
        var bytes = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
            [SdBytes.AllowObjectAce(SdBytes.Everyone, 0x20, Guid.Parse(FirstGuid), null)]);
        var directory = Bundle([new("CN=First," + Domain, bytes)]);
        using var bundle = BundleReader.Open(directory).Value;
        using var groups = bundle.StreamDescriptorObjects(CancellationToken.None);
        using var rows = groups.Objects.GetEnumerator();
        Assert.True(rows.MoveNext());
        var reading = groups.ReadPermissions(rows.Current);
        using var harmless = new Store(hasCapturedSchema: true);
        using var dangerous = new Store(hasCapturedSchema: true);
        var harmlessContext = new PermissionClassificationPreparation(groups, Catalog("description"), harmless.Generation);
        var dangerousContext = new PermissionClassificationPreparation(groups, Catalog("userAccountControl"), dangerous.Generation);
        harmless.Observe(reading.Permissions);
        dangerous.Observe(reading.Permissions);
        harmless.Write(harmlessContext.Prepare(reading, harmless.Work, CancellationToken.None));
        dangerous.Write(dangerousContext.Prepare(reading, dangerous.Work, CancellationToken.None));
        Assert.Equal(PermissionVerdict.NotDangerous,
            Assert.Single(Assert.Single(harmless.Read(reading.Permissions).Entries).Rights).Assessment.Verdict);
        Assert.Equal(PermissionVerdict.Dangerous,
            Assert.Single(Assert.Single(dangerous.Read(reading.Permissions).Entries).Rights).Assessment.Verdict);
    }

    [Fact]
    public void SharedPreparationPersistsEveryRawOccurrenceAndRendersSelfAgainstEachVerifiedObject()
    {
        var directory = Bundle([new("CN=Alice," + Domain, DetailedDescriptor()), new("CN=Bob," + Domain, DetailedDescriptor())]);
        using var reference = BundleReader.Open(directory).Value;
        using var bundle = BundleReader.Open(directory).Value;
        using var groups = bundle.StreamDescriptorObjects(CancellationToken.None);
        using var store = new Store(hasCapturedSchema: true);
        var catalog = Catalog("userAccountControl");
        var context = new PermissionClassificationPreparation(groups, catalog, store.Generation);
        var expected = new List<PermissionClassification>();
        foreach (var subject in groups.Objects)
        {
            var reading = groups.ReadPermissions(subject);
            expected.Add(new PermissionClassificationProducer(catalog).CreateObjectResult(reference.ReadPermissions(subject.DistinguishedName)!));
            store.Observe(reading.Permissions);
            store.Write(context.Prepare(reading, store.Work, CancellationToken.None));
        }
        store.Complete();
        foreach (var result in expected) Assert.Equal(Json(result), Json(store.Read(result.Permissions)));
        Assert.Equal(1, context.ClassifiedDescriptors);
        Assert.Equal(6, context.ClassifiedEntries);
        Assert.Equal(1, store.Count("permission_classification_descriptor"));
        Assert.Equal(6, store.Count("permission_classification_entry"));
    }

    [Fact]
    public void APreparedObjectLinkCannotFollowTheStreamToAnotherObject()
    {
        var directory = Bundle([new("CN=First," + Domain, Simple(0x40000)), new("CN=Second," + Domain, Simple(0x40000))]);
        using var bundle = BundleReader.Open(directory).Value;
        using var groups = bundle.StreamDescriptorObjects(CancellationToken.None);
        using var rows = groups.Objects.GetEnumerator();
        using var store = new Store();
        Assert.True(rows.MoveNext());
        var reading = groups.ReadPermissions(rows.Current);
        var context = new PermissionClassificationPreparation(groups, SchemaGuidCatalog.Embedded, store.Generation);
        var link = context.Prepare(reading, store.Work, CancellationToken.None);
        store.Observe(reading.Permissions);
        Assert.True(rows.MoveNext());
        Assert.Throws<InvalidOperationException>(() => store.Write(link));
        Assert.Equal(0, store.Count("permission_classification_object"));
    }

    [Fact]
    public void ADisposedEvidenceReaderInvalidatesThePreparedRow()
    {
        var directory = Bundle([new("CN=First," + Domain, Simple(0x40000))]);
        using var bundle = BundleReader.Open(directory).Value;
        using var groups = bundle.StreamDescriptorObjects(CancellationToken.None);
        using var rows = groups.Objects.GetEnumerator();
        Assert.True(rows.MoveNext());
        var reading = groups.ReadPermissions(rows.Current);
        bundle.Dispose();
        Assert.Throws<ObjectDisposedException>(reading.RequireCurrent);
    }

    [Theory]
    [InlineData("application-data")]
    [InlineData("raw-list")]
    [InlineData("errors")]
    [InlineData("classified-list")]
    [InlineData("rights")]
    [InlineData("definitions")]
    [InlineData("members")]
    [InlineData("ambiguity")]
    public void PreparedClassificationsOwnEveryCallerSuppliedBuffer(string changed)
    {
        using var store = new Store(hasCapturedSchema: true);
        var entry = Ace(2, Holder, 0x20, "AccessAllowedCallbackObject", 8) with
        {
            ObjectTypeGuid = FirstGuid, HasObjectType = true, ApplicationData = [1, 2, 3, 4],
        };
        PermissionEntry[] raw = [entry];
        string[] errors = ["recorded capture error"];
        var result = new PermissionClassificationProducer(Catalog("description")).CreateObjectResult(Permissions(raw) with { Errors = errors });
        SchemaGuidEntry[] definitions = [.. result.Entries[0].ObjectType!.Definitions];
        string[] members = ["description"];
        string[] ambiguity = ["retained ambiguity"];
        ClassifiedPermissionRight[] rights = [.. result.Entries[0].Rights];
        ClassifiedPermissionEntry[] entries = [result.Entries[0] with
        {
            Rights = rights, ObjectType = result.Entries[0].ObjectType! with
            { Definitions = definitions, PropertySetMembers = members, AmbiguousNames = ambiguity },
        }];
        result = result with { Entries = entries };
        var expected = Json(result);
        var prepared = PermissionClassificationStorage.Prepare(result, store.Generation, store.Work, CancellationToken.None);
        switch (changed)
        {
            case "application-data": entry.ApplicationData[0] = 99; break;
            case "raw-list": raw[0] = entry with { AccessMask = 0x40000 }; break;
            case "errors": errors[0] = "replaced capture error"; break;
            case "classified-list": entries[0] = entries[0] with { Summary = "replaced summary" }; break;
            case "rights": rights[0] = rights[0] with { Assessment = PermissionAssessment.CannotClassify("replaced assessment") }; break;
            case "definitions": definitions[0] = definitions[0] with { LdapName = "replaced definition" }; break;
            case "members": members[0] = "userAccountControl"; break;
            case "ambiguity": ambiguity[0] = "replaced ambiguity"; break;
        }
        store.Observe(result.Permissions);
        store.Write(prepared, result.Permissions);
        Assert.Equal(expected, Json(store.Read(result.Permissions)));
        Assert.Equal(1, store.Work.Validations);
        Assert.Equal(1, store.Work.Fingerprints);
    }

    [Fact]
    public void CatalogueInputsAndReturnedListsCannotChangeAnExistingAnalysisContext()
    {
        SchemaGuidEntry[] entries = [new(FirstGuid, "ForestSet", SchemaGuidKind.PropertySet, SchemaGuidSource.Captured)];
        string[] members = ["description"];
        var catalogue = new SchemaGuidCatalog(entries, new Dictionary<string, IReadOnlyList<string>> { [FirstGuid] = members });
        var producer = new PermissionClassificationProducer(catalogue);
        entries[0] = entries[0] with { LdapName = "different set" };
        members[0] = "userAccountControl";
        var result = producer.CreateObjectResult(Permissions(Ace(0, Holder, 0x20) with { ObjectTypeGuid = FirstGuid, HasObjectType = true }));
        Assert.Equal("description", Assert.Single(result.Entries[0].ObjectType!.PropertySetMembers!));
        Assert.Equal("ForestSet", Assert.Single(catalogue.Entries).LdapName);
        Assert.Throws<NotSupportedException>(() => ((IList<SchemaGuidEntry>)catalogue.Entries)[0] = entries[0]);
        Assert.Throws<NotSupportedException>(() => ((IList<SchemaGuidEntry>)catalogue.FindByGuid(FirstGuid))[0] = entries[0]);
        Assert.Throws<NotSupportedException>(() => ((IList<string>)catalogue.MembersOfPropertySet(FirstGuid)!)[0] = "changed");
    }

    [Fact]
    public void PreparedClassificationsRejectAnotherJudgementGeneration()
    {
        using var store = new Store();
        var result = new PermissionClassificationProducer(SchemaGuidCatalog.Embedded).CreateObjectResult(Permissions(Ace(0, Holder, 0x40000)));
        var prepared = PermissionClassificationStorage.Prepare(result, Guid.NewGuid(), store.Work, CancellationToken.None);
        store.Observe(result.Permissions);
        Assert.Throws<InvalidDataException>(() => store.Write(prepared, result.Permissions));
        Assert.Equal(0, store.Count("permission_classification_object"));
    }

    [Fact]
    public void RollbackDiscardsPreparedDescriptorIdentitiesButRetryReusesTheOwnedClassification()
    {
        using var store = new Store();
        using var cancellation = new CancellationTokenSource();
        var result = new PermissionClassificationProducer(SchemaGuidCatalog.Embedded)
            .CreateObjectResult(Permissions(Ace(0, Holder, 0x40000), Ace(3, Holder, 0x20000)));
        var prepared = PermissionClassificationStorage.Prepare(result, store.Generation, store.Work, CancellationToken.None);
        store.Observe(result.Permissions);
        store.Connection.CreateFunction("cancel_link", () => { cancellation.Cancel(); return 0; });
        store.Execute("CREATE TRIGGER cancel_link AFTER INSERT ON permission_classification_object BEGIN SELECT cancel_link(); END");
        Assert.Throws<OperationCanceledException>(() => store.Write(prepared, result.Permissions, cancellation.Token));
        Assert.Equal(0, store.Count("permission_classification_descriptor"));
        Assert.Equal(0, store.Count("permission_classification_entry"));
        store.Execute("DROP TRIGGER cancel_link");
        store.Write(prepared, result.Permissions);
        var other = result.Permissions with { DistinguishedName = "CN=Other," + Domain };
        store.Observe(other);
        store.Write(prepared, other);
        Assert.Equal(Json(result), Json(store.Read(result.Permissions)));
        Assert.Equal(1, store.Count("permission_classification_descriptor"));
        Assert.Equal(2, store.Count("permission_classification_entry"));
        Assert.Equal(2, store.Count("permission_classification_object"));
        Assert.Equal(1, store.Work.Validations);
        Assert.Equal(1, store.Work.Fingerprints);
    }

    [Theory]
    [InlineData("object")]
    [InlineData("ordinal")]
    [InlineData("interpretation")]
    public void PreparedWritesKeepAllThreeIndependentPermissionBindings(string damaged)
    {
        using var store = new Store();
        var producer = new PermissionClassificationProducer(SchemaGuidCatalog.Embedded);
        var first = producer.CreateObjectResult(Permissions("CN=First," + Domain, Ace(0, Holder, 0x40000), Ace(2, Holder, 0x20000)) with { DescriptorId = 1 });
        var second = producer.CreateObjectResult(Permissions("CN=Second," + Domain, Ace(0, Holder, 0x40000, "AccessDenied"), Ace(2, Holder, 0x20000)) with { DescriptorId = 2 });
        foreach (var result in new[] { first, second })
        {
            store.Observe(result.Permissions);
            store.Write(PermissionClassificationStorage.Prepare(result, store.Generation, store.Work, CancellationToken.None), result.Permissions);
        }
        switch (damaged)
        {
            case "object":
                store.Execute("UPDATE permission_classification_object SET descriptor_id=2 WHERE target='CN=First,DC=contoso,DC=com'");
                break;
            case "ordinal":
                store.Execute("UPDATE permission_classification_entry SET ordinal=3 WHERE descriptor_id=1 AND ordinal=0");
                break;
            case "interpretation":
                store.Execute("UPDATE permission_classification_value SET reading_id=(SELECT v.reading_id FROM permission_classification_entry e JOIN permission_classification_value v ON v.entry_id=e.entry_id WHERE e.descriptor_id=2 AND e.ordinal=0) WHERE entry_id=(SELECT entry_id FROM permission_classification_entry WHERE descriptor_id=1 AND ordinal=0)");
                break;
        }
        Assert.Throws<InvalidDataException>(() => store.Read(first.Permissions));
    }

    [Fact]
    public void JudgeAuditUsesDescriptorPreparationAndStillPublishesEveryObjectAndOriginalReading()
    {
        var descriptor = Simple(0x20000);
        var directory = Bundle(Enumerable.Range(0, 503).Select(index => new Item($"CN=Computer{index}," + Domain, descriptor)).ToArray());
        var observer = new Observer();
        var log = new Log();
        var before = Hash(directory);
        var result = JudgingRun.JudgeAudit(directory, [observer], PathRequesterPolicy.Disabled, When, When,
            JudgingRun.NobodyIsWatching, log, CancellationToken.None, null);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var evidence = BundleReader.Open(directory).Value;
        using var judgement = JudgementReader.Open(directory).Value;
        var preparation = Assert.Single(log.Lines.Where(line => line.Message == "descriptor preparation"));
        Assert.Equal("1", preparation.Value("preparedDescriptors"));
        Assert.Equal("1", preparation.Value("classifiedDescriptors"));
        Assert.Equal("1", preparation.Value("preparedEntries"));
        Assert.Equal("1", preparation.Value("classifiedEntries"));
        var writes = log.Lines.Last(line => line.Message == "permission write accounted");
        Assert.Equal("503", writes.Value("objects"));
        Assert.Equal("1", writes.Value("validations"));
        Assert.Equal("1", writes.Value("fingerprints"));
        Assert.Equal(503, observer.Subjects.Count);
        var producer = new PermissionClassificationProducer(evidence.ReadSchemaGuids());
        foreach (var subject in evidence.StreamObjects().Objects)
        {
            Assert.Equal(Json(subject), observer.Subjects[subject.DistinguishedName]);
            var permissions = evidence.ReadPermissions(subject.DistinguishedName)!;
            var saved = judgement.ReadPermissionClassification(subject.DistinguishedName, permissions.DescriptorId);
            Assert.Equal(Json(producer.CreateObjectResult(permissions)), Json(saved.Classification));
        }
        using var connection = OpenJudgement(directory);
        // The uncaptured naming-context root has its own explicit unreadable control record.
        Assert.Equal(504L, Scalar(connection, "SELECT COUNT(*) FROM control_object"));
        Assert.Equal(1L, Scalar(connection, "SELECT COUNT(*) FROM control_object WHERE target='DC=contoso,DC=com' AND descriptor_outcome='DescriptorNotRead'"));
        Assert.Equal(503L, Scalar(connection, "SELECT COUNT(*) FROM permission_classification_object"));
        Assert.Equal(503L, Scalar(connection, "SELECT COUNT(*) FROM laps_inventory"));
        Assert.Equal(before, Hash(directory));
    }

    [Fact]
    public void CancellationInTheGroupedPassKeepsThePreviousPublishedGeneration()
    {
        var directory = Bundle([new("CN=First," + Domain, Simple(0x40000)), new("CN=Second," + Domain, Simple(0x40000))]);
        Assert.True(JudgingRun.JudgeAudit(directory, [], PathRequesterPolicy.Disabled, When, When,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, null).IsSuccess);
        var manifestPath = AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement);
        var prior = File.ReadAllBytes(manifestPath);
        using var cancellation = new CancellationTokenSource();
        var observer = new Observer(cancellation.Cancel);
        var log = new Log();
        var thrown = Assert.Throws<OperationCanceledException>(() => JudgingRun.JudgeAudit(directory, [observer],
            PathRequesterPolicy.Disabled, When, When, JudgingRun.NobodyIsWatching, log, cancellation.Token, null));
        Assert.Equal(cancellation.Token, thrown.CancellationToken);
        Assert.Equal(prior, File.ReadAllBytes(manifestPath));
        Assert.Single(observer.Subjects);
        Assert.Single(log.Lines.Where(line => line.Message == "judging cancelled"));
    }

    internal sealed record Item(string Dn, byte[]? Descriptor, string? Unreadable = null);

    internal static string Bundle(Item[] items, bool allValues = false)
    {
        var directory = TempDirectories.Create("descriptor-preparation");
        var coverage = new PartitionCoverage(Domain, NamingContextKind.Domain, "dc.contoso.com",
            ConnectionSecurityLevel.SignedAndSealed, 3, 100, 1, [], false);
        using var writer = BundleWriter.Create(directory, When);
        writer.WriteCoverage(coverage);
        var sharedGuid = Guid.NewGuid();
        for (var index = 0; index < items.Length; index++)
        {
            var item = items[index];
            var attributes = allValues
                ? BundleSchema.MultiValuedTables.Select(attribute => new EvidenceAttribute(attribute.LdapDisplayName,
                    StoredAttributeCompleteness.Complete, Enumerable.Range(0, 2).Select(ordinal => attribute.Storage == AttributeStorage.Binary
                        ? EvidenceValue.OfBytes([(byte)index, (byte)ordinal, 255])
                        : EvidenceValue.OfText($"{attribute.LdapDisplayName}-{index}-{ordinal}")).ToArray())).ToArray()
                : new EvidenceAttribute[] { new("objectClass", StoredAttributeCompleteness.Complete,
                    [EvidenceValue.OfText("top"), EvidenceValue.OfText("user"), EvidenceValue.OfText("computer")]) };
            var id = writer.WriteObject(new(coverage, item.Dn, index == 0 ? null : sharedGuid, attributes, When));
            if (item.Descriptor is { } bytes)
                writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(sharedGuid, SecurityDescriptorParser.Parse(bytes)));
            else if (item.Unreadable is { } reason) writer.WriteUnreadableSecurityDescriptor(id, reason);
        }
        writer.Complete(RunCoverage.Of(CoverageId.ForDomains("contoso.com", ["contoso.com"]),
            [DomainCoverage.Read("contoso.com")],
            [ForestPartitionCoverage.Read("CN=Configuration," + Domain, NamingContextKind.Configuration),
                ForestPartitionCoverage.Read("CN=Schema,CN=Configuration," + Domain, NamingContextKind.Schema)],
            SysvolCoverage.Of([])), When.AddMinutes(1));
        return directory;
    }

    internal static byte[] Simple(int mask) => SdBytes.SelfRelativeSd(SdBytes.LocalSystem,
        daclAces: [SdBytes.AllowAce(SdBytes.Everyone, mask)]);

    private static byte[] DetailedDescriptor()
    {
        var self = Sid.ToBytes(PermissionTrustee.PrincipalSelfSid)!;
        var callback = SdBytes.SimpleAce(0x09, 0, 0x40000, self).Concat(new byte[] { 1, 2, 3, 4 }).ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(callback.AsSpan(2), (ushort)callback.Length);
        return SdBytes.SelfRelativeSd(self, daclAces:
        [
            SdBytes.AllowAce(self, 0x10000000), SdBytes.AllowAce(self, 0x10000000),
            SdBytes.DenyAce(SdBytes.Everyone, 0x20000),
            SdBytes.AllowObjectAce(SdBytes.Administrators, 0x20, Guid.Parse(FirstGuid),
                Guid.Parse("bf967a9c-0de6-11d0-a285-00aa003049e2"), 0x1a),
            callback, SdBytes.SimpleAce(0x7f, 0, 0x200, SdBytes.Everyone),
        ], daclProtected: true);
    }

    private static SchemaGuidCatalog Catalog(string member) => SchemaGuidCatalog.CapturedOver(
        [new(FirstGuid, "ForestSet", SchemaGuidKind.PropertySet, SchemaGuidSource.Captured)],
        SchemaGuidCatalog.Embedded, new Dictionary<string, IReadOnlyList<string>> { [FirstGuid] = new[] { member } });
    private static string Json<T>(T value) => JsonSerializer.Serialize(value);
    private static string Hash(string directory) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(BundleLayout.EvidencePath(directory))));
    private static long Scalar(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar());
    }
    private static SqliteConnection OpenJudgement(string directory)
    {
        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value;
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        { DataSource = BundleLayout.AnalysisGenerationDataPath(directory, generation.Kind, generation.GenerationId),
            Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        connection.Open();
        TestSealing.AttachJudgementParts(connection, directory, generation.GenerationId);
        return connection;
    }

    private sealed class Observer(Action? observed = null) : IObjectRule
    {
        internal Dictionary<string, string> Subjects { get; } = new(StringComparer.Ordinal);
        public RuleDefinition Definition { get; } = new("TEST-DESCRIPTOR", "Descriptor preparation observer", Severity.Low, 1,
            [], ["objectClass"], []);
        public RuleVerdict Judge(ObjectAttributes subject)
        {
            Subjects.Add(subject.DistinguishedName, Json(subject));
            observed?.Invoke();
            return RuleVerdict.Judged([]);
        }
    }
    private sealed record Line(string Message, IReadOnlyList<RunLogDetail> Detail)
    {
        internal string? Value(string name) => Detail.FirstOrDefault(value => value.Name == name).Value;
    }
    private sealed class Log : IRunLog
    {
        internal ConcurrentQueue<Line> Lines { get; } = new();
        public void Note(string phase, string message, IReadOnlyList<RunLogDetail> detail) => Lines.Enqueue(new(message, detail.ToArray()));
        public void Record(string phase, AuditError error, IReadOnlyList<RunLogDetail> detail) => Lines.Enqueue(new(error.Code, detail.ToArray()));
    }

    private sealed class Store : IDisposable
    {
        internal SqliteConnection Connection { get; } = new("Data Source=:memory:;Foreign Keys=True");
        internal Guid Generation { get; } = Guid.NewGuid();
        internal PermissionWriteWork Work { get; } = new();
        private readonly PermissionWriteSession _session = new();
        private readonly PreparedStatements _statements;
        private long _objects;
        private bool _complete;
        internal Store(bool hasCapturedSchema = false)
        {
            Connection.Open();
            _statements = new(Connection);
            JudgementSchema.CreateTables(Connection);
            ControlEdgeStorage.Start(Connection, true);
            PermissionClassificationStorage.Start(Connection, Generation, hasCapturedSchema);
        }
        internal void Observe(ObjectPermissions permissions) => StorageWrites.ControlEdges(Connection,
            new(permissions.DistinguishedName, null, null, "Computed", ControlUncertainty.None, []), null);
        internal void Write(PermissionClassificationPreparation.ObjectWrite link) => Commit(transaction =>
            link.Write(Connection, transaction, Generation, Work, _statements, _session, CancellationToken.None), CancellationToken.None);
        internal void Write(PermissionClassificationStorage.Prepared prepared, ObjectPermissions carried, CancellationToken token = default) =>
            Commit(transaction => prepared.Write(Connection, transaction, Generation, carried, Work, _statements, _session, token), token);
        private void Commit(Action<SqliteTransaction> write, CancellationToken token)
        {
            try
            {
                using var transaction = Connection.BeginTransaction();
                write(transaction);
                token.ThrowIfCancellationRequested();
                transaction.Commit();
            }
            catch { _session.Discard(); throw; }
            _session.Promote();
            _objects++;
        }
        internal PermissionClassification Read(ObjectPermissions carried)
        {
            Complete();
            return PermissionClassificationStorage.Read(Connection,
                new(new string('a', 64), Generation, null, JudgementRunState.Completed, When, When, When),
                carried.DistinguishedName, carried.DescriptorId, CancellationToken.None).Classification;
        }
        internal void Complete()
        {
            if (_complete) return;
            PermissionClassificationStorage.Complete(Connection, _objects);
            _complete = true;
        }
        internal long Count(string table) => Scalar(Connection, "SELECT COUNT(*) FROM " + table);
        internal void Execute(string sql)
        {
            using var command = Connection.CreateCommand();
            command.CommandText = sql;
            command.ExecuteNonQuery();
        }
        public void Dispose() { _statements.Dispose(); Connection.Dispose(); }
    }
}
