using System.Security.AccessControl;
using System.Text.Json;
using System.Windows.Controls;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    private const string ServingRoot = "DC=contoso,DC=com";
    private static readonly GroupInventoryQuery ServingGroups = new(null, ListingScope.Subtree, "Serve-",
        GroupInventoryScope.All, GroupInventoryKind.All, false, GroupInventorySort.Name);

    [Theory]
    [InlineData(900)]
    [InlineData(1300)]
    public void Arch04CombinedOverviewFlowKeepsGroupsAndTier0OnLightweightProducts(int width) =>
        ObjectNavigationViewTests.OnSta(() => OneThread.Run(async () =>
        {
            var directory = OverviewServingRun(123);
            Tier0OverviewPage expected;
            using (var reader = JudgementReader.Open(directory).Value)
                expected = reader.ReadTier0Overview(Tier0OverviewScope.Supported, null, CancellationToken.None)!;
            using var counts = new FindingsVerificationCounts(directory);
            using var source = new BundleAssetSource();
            var screen = new AssetsViewModel(source) { Pane = AssetsPane.Groups };
            using (var heavy = new FindingsHeavyLocks(directory))
            {
                screen.Show(directory, false);
                await screen.ReadCompletion;
                Assert.Null(screen.Refusal);
                Assert.Null(screen.ViewRefusal);
                Assert.Equal(125, screen.GroupTotal);
                screen.GroupSearchText = "Serve-";
                screen.SearchGroupsCommand.Execute(null);
                await screen.ReadCompletion;
                Assert.Equal(123, screen.GroupTotal);
                var first = screen.Groups.Select(row => row.DistinguishedName).ToArray();
                Assert.Equal(50, first.Length);
                screen.NextGroupPageCommand.Execute(null);
                await screen.ReadCompletion;
                Assert.Equal(50, screen.Groups.Count);
                Assert.False(first.Intersect(screen.Groups.Select(row => row.DistinguishedName)).Any());
                screen.NextGroupPageCommand.Execute(null);
                await screen.ReadCompletion;
                Assert.Equal(23, screen.Groups.Count);
                Assert.False(screen.NextGroupPageCommand.CanExecute(null));
                screen.PreviousGroupPageCommand.Execute(null);
                await screen.ReadCompletion;
                screen.PreviousGroupPageCommand.Execute(null);
                await screen.ReadCompletion;
                Assert.Equal(first, screen.Groups.Select(row => row.DistinguishedName));
                var selected = screen.Groups[0];
                Assert.True(selected.HasCycle);
                Assert.Equal((2, "1"), (selected.DirectMembers, selected.KnownTotal));
                screen.OpenGroupFindingsCommand.Execute(selected);
                await screen.ObjectReadCompletion;
                Assert.Null(screen.ObjectRefusal);
                Assert.Null(screen.Opened!.Refusal);
                Assert.Single(Assert.IsType<FindingsSectionViewModel>(screen.Opened.Content).Findings);
                screen.CloseObject();
                await screen.ReadCompletion;
                Assert.Same(selected, screen.SelectedGroup);
                Assert.Equal(first, screen.Groups.Select(row => row.DistinguishedName));
                screen.GroupsOnlyCycles = true;
                await screen.ReadCompletion;
                Assert.Equal(1, screen.GroupTotal);
                Assert.Equal(ServingGroup(0), Assert.Single(screen.Groups).DistinguishedName);
                screen.ClearGroupFiltersCommand.Execute(null);
                await screen.ReadCompletion;
                screen.GroupKind = GroupInventoryKind.Distribution;
                await screen.ReadCompletion;
                Assert.Equal(61, screen.GroupTotal);
                Assert.All(screen.Groups, row => Assert.Equal("Distribution", row.Kind));
                var groupsView = GroupsViewTests.View(screen);
                DrawBrowsing(groupsView, width);
                var groupsGrid = Assert.Single(ObjectNavigationViewTests.Descendants<DataGrid>(groupsView));
                Assert.Equal(screen.Groups.Count, groupsGrid.Items.Count);
                Assert.True(groupsGrid.ActualHeight > 50);
                Assert.Contains(ObjectNavigationViewTests.Descendants<TextBlock>(groupsView),
                    text => text.Text == screen.Groups[0].Name && text.ActualHeight > 0 && text.ActualWidth > 0);

                screen.Pane = AssetsPane.Tier0;
                await screen.ReadCompletion;
                Assert.Null(screen.ViewRefusal);
                Assert.Equal(JsonSerializer.Serialize(expected.Objects),
                    JsonSerializer.Serialize(screen.Tier0Objects.Select(row => row.Value)));
                Assert.Equal((expected.Summary.ClassifiedTier0Objects, expected.Summary.OtherObjectsWithSupportedRoute,
                    expected.Summary.UnresolvedObjects, expected.Summary.UnassessedObjects),
                    (screen.Tier0ClassifiedCount, screen.Tier0OtherSupportedCount, screen.Tier0UnresolvedCount, screen.Tier0UnassessedCount));
                Assert.True(screen.NextTier0PageCommand.CanExecute(null));
                screen.NextTier0PageCommand.Execute(null);
                await screen.ReadCompletion;
                Assert.True(screen.PreviousTier0PageCommand.CanExecute(null));
                screen.PreviousTier0PageCommand.Execute(null);
                await screen.ReadCompletion;
                Assert.Equal(JsonSerializer.Serialize(expected.Objects),
                    JsonSerializer.Serialize(screen.Tier0Objects.Select(row => row.Value)));
                screen.Tier0OverviewScope = Tier0OverviewScope.All;
                await screen.ReadCompletion;
                Assert.False(screen.PreviousTier0PageCommand.CanExecute(null));
                var tier0First = JsonSerializer.Serialize(screen.Tier0Objects.Select(row => row.Value));
                screen.SelectedTier0Object = Assert.Single(screen.Tier0Objects, row => row.DistinguishedName == UserDn);
                screen.OpenTier0FindingsCommand.Execute(null);
                await screen.ObjectReadCompletion;
                Assert.Null(screen.ObjectRefusal);
                Assert.Null(screen.Opened!.Refusal);
                Assert.Equal(ObjectSectionCatalog.Findings, screen.Opened.SelectedKey);
                screen.CloseObject();
                await screen.ReadCompletion;
                Assert.Equal(tier0First, JsonSerializer.Serialize(screen.Tier0Objects.Select(row => row.Value)));
                var tier0View = ProductionViewThemeTests.View("Tier0OverviewView.xaml", screen);
                DrawBrowsing(tier0View, width);
                var tier0Grid = Assert.Single(ObjectNavigationViewTests.Descendants<DataGrid>(tier0View));
                Assert.Equal(screen.Tier0Objects.Count, tier0Grid.Items.Count);
                Assert.True(tier0Grid.ActualHeight > 50);
                Assert.Contains(ObjectNavigationViewTests.Descendants<TextBlock>(tier0View),
                    text => text.Text == screen.SelectedTier0Object.Name && text.ActualHeight > 0 && text.ActualWidth > 0);
                Assert.Equal((1L, 0L), (counts.Count("judgement"), counts.Heavy));
                screen.Suspend();
                source.CloseRun();
                screen.Show(directory, false);
                await screen.ReadCompletion;
                Assert.Null(screen.ViewRefusal);
                Assert.Equal(tier0First, JsonSerializer.Serialize(screen.Tier0Objects.Select(row => row.Value)));
                Assert.Equal((2L, 0L), (counts.Count("judgement"), counts.Heavy));
            }
            screen.SelectedTier0Object = Assert.Single(screen.Tier0Objects, row => row.DistinguishedName == UserDn);
            screen.OpenTier0PathCommand.Execute(null);
            await screen.ObjectReadCompletion;
            Assert.Null(screen.ObjectRefusal);
            Assert.Null(screen.Opened!.Refusal);
            var detail = source.ReadSavedTier0Path(directory, UserDn);
            Assert.True(detail.IsSuccess, detail.Error?.Description);
            Assert.True(detail.Value!.IsBound);
            Assert.Equal(2, detail.Value.Routes!.Distance.SupportedDistance);
            Assert.Equal(2, detail.Value.Routes.ShortestSteps.Count);
            Assert.Equal((1L, 1L), (counts.Count("permission"), counts.Count("path")));
            screen.CloseObject();
            await screen.ReadCompletion;
            Assert.Null(screen.ViewRefusal);
            screen.Suspend();
        }));

    [Theory]
    [InlineData(GroupInventorySort.Name)]
    [InlineData(GroupInventorySort.NameDescending)]
    [InlineData(GroupInventorySort.Direct)]
    [InlineData(GroupInventorySort.DirectDescending)]
    public async Task Arch04GroupsServingRetainsExactWholeQuestionValuesAndPages(GroupInventorySort sort)
    {
        var directory = OverviewServingRun(123);
        var query = ServingGroups with { Sort = sort };
        using var source = new BundleAssetSource();
        var expected = ReadServingGroups(source, directory, query);
        Assert.Equal(123, expected.Count);
        Assert.Equal((2, 1), (expected.Single(row => row.DistinguishedName == ServingGroup(0)).DirectMembers,
            expected.Single(row => row.DistinguishedName == ServingGroup(0)).MembershipTotal.KnownMembers));
        var incomplete = expected.Single(row => row.DistinguishedName == ServingGroup(122));
        Assert.Equal(1, incomplete.MembershipTotal.UnresolvedReferences);
        source.CloseRun();
        using var counts = new FindingsVerificationCounts(directory);
        using var heavy = new FindingsHeavyLocks(directory);
        source.SelectRun(directory);
        var actual = ReadServingGroups(source, directory, query);
        Assert.Equal(JsonSerializer.Serialize(expected), JsonSerializer.Serialize(actual));
        Assert.Equal((1L, 0L), (counts.Count("judgement"), counts.Heavy));
        var first = source.ReadGroups(directory, query, null).Value;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => source.ReadAsync(directory,
            (reader, _) => reader.ReadGroups(directory, query, null), new CancellationToken(true)));
        Assert.False(source.ReadGroups(directory, query with { Search = "another question" }, first.Next).IsSuccess);
    }

    [Theory]
    [InlineData(Tier0OverviewScope.Supported)]
    [InlineData(Tier0OverviewScope.All)]
    public void Arch04Tier0ServingRetainsOriginalProofAnswersAndWholeRunSummary(Tier0OverviewScope scope)
    {
        var directory = OverviewServingRun(123);
        var expected = new List<Tier0OverviewRow>();
        Tier0RunSummary summary;
        using (var reader = JudgementReader.Open(directory).Value)
        {
            summary = reader.ReadTier0RunSummary()!;
            Tier0OverviewMark? after = null;
            do
            {
                var page = reader.ReadTier0Overview(Tier0OverviewScope.All, after, CancellationToken.None)!;
                foreach (var row in page.Objects)
                {
                    var original = reader.ReadTier0ObjectDistance(row.Subject.DistinguishedName)!;
                    var route = reader.ReadBestSupportedRoute(row.Subject.DistinguishedName)!;
                    expected.Add(new(original.Subject, original.Facts, route.Selection.Best?.Grade));
                }
                after = page.Next;
            } while (after is not null);
        }
        Assert.Equal(summary.RecordedSubjects, expected.Count);
        if (scope == Tier0OverviewScope.Supported)
            expected = expected.Where(row => row.Distance.Classification == Tier0State.Established
                || row.Distance.SupportedDistance is not null).ToList();
        Assert.True(expected.Count > 50);
        using var counts = new FindingsVerificationCounts(directory);
        using var heavy = new FindingsHeavyLocks(directory);
        using var source = new BundleAssetSource();
        var actual = new List<Tier0OverviewRow>();
        Tier0OverviewMark? mark = null;
        do
        {
            var result = source.ReadTier0Overview(directory, scope, mark);
            Assert.True(result.IsSuccess, result.Error?.Description);
            var page = Assert.IsType<Tier0OverviewPage>(result.Value);
            Assert.Equal(summary, page.Summary);
            Assert.InRange(page.Objects.Count, 1, 50);
            actual.AddRange(page.Objects);
            mark = page.Next;
        } while (mark is not null);
        Assert.Equal(JsonSerializer.Serialize(expected), JsonSerializer.Serialize(actual));
        Assert.Equal((1L, 0L), (counts.Count("judgement"), counts.Heavy));
        Assert.True(source.CaptureReadValidity()());
    }

    [Theory]
    [InlineData(true, "bytes")]
    [InlineData(false, "bytes")]
    [InlineData(true, "missing")]
    [InlineData(false, "missing")]
    [InlineData(true, "seal")]
    [InlineData(false, "seal")]
    [InlineData(true, "generation")]
    [InlineData(false, "generation")]
    [InlineData(true, "evidence")]
    [InlineData(false, "evidence")]
    [InlineData(true, "derivation")]
    [InlineData(false, "derivation")]
    [InlineData(true, "schema")]
    [InlineData(false, "schema")]
    [InlineData(true, "product")]
    [InlineData(false, "product")]
    public async Task Arch04OverviewServingRefusesMissingCorruptOrForeignProducts(bool groups, string defect)
    {
        var directory = OverviewServingRun();
        var root = FindingsPublication(directory);
        var path = Path.Combine(directory, root.Segment(StoreSegmentRole.Judgement).FileName);
        if (defect == "bytes") File.AppendAllText(path, "corrupt");
        else if (defect == "missing") File.Delete(path);
        else if (defect == "seal") File.Delete(path + ".seal");
        else ChangeFindingsDatabase(directory, defect switch
        {
            "generation" => "UPDATE judgement SET judgement_generation_id='11111111-2222-3333-4444-555555555555'",
            "evidence" => "UPDATE judgement SET evidence_seal='foreign evidence'",
            "derivation" => "UPDATE judgement SET derivation_generation_id='11111111-2222-3333-4444-555555555555'",
            "schema" => "UPDATE judgement SET schema_version=999",
            "product" => groups ? "DELETE FROM group_inventory_product" : "DELETE FROM tier0_distance_product",
            _ => throw new ArgumentOutOfRangeException(nameof(defect)),
        });
        using var heavy = new FindingsHeavyLocks(directory, publication: root);
        using var source = new BundleAssetSource();
        var screen = new AssetsViewModel(source) { Pane = groups ? AssetsPane.Groups : AssetsPane.Tier0 };
        screen.Show(directory, false);
        await screen.ReadCompletion;
        Assert.NotNull(screen.ViewRefusal);
        Assert.Empty(screen.Groups);
        Assert.Empty(screen.Tier0Objects);
        Assert.False(screen.HasListingResult);
        Assert.False(screen.IsLoading);
        screen.Suspend();
    }

    [Theory]
    [InlineData("identity-scope")]
    [InlineData("identity-binding")]
    [InlineData("distance")]
    [InlineData("grade")]
    [InlineData("grade-value")]
    [InlineData("unfinished")]
    public void Arch04Tier0ServingRefusesInvalidOrUnboundDisplayValues(string defect)
    {
        var directory = OverviewServingRun();
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = defect switch
            {
                "identity-scope" => "UPDATE tier0_distance SET identity_json=json_set(identity_json,'$.SidScope','foreign') WHERE target=$target",
                "identity-binding" => "UPDATE tier0_distance SET identity_json=json_set(identity_json,'$.ObjectGuid','11111111-2222-3333-4444-555555555555') WHERE target=$target",
                "distance" => "UPDATE tier0_distance SET supported_distance=3 WHERE target=$target",
                "grade" => "UPDATE tier0_distance SET best_grade=json_set(best_grade,'$.Confidence','Low') WHERE target=$target",
                "grade-value" => "UPDATE tier0_distance SET best_grade=json_set(best_grade,'$.Length',-1) WHERE target=$target",
                "unfinished" => "UPDATE tier0_distance SET overview_fingerprint=NULL WHERE target=$target",
                _ => throw new ArgumentOutOfRangeException(nameof(defect)),
            };
            command.Parameters.AddWithValue("$target", UserDn);
            Assert.Equal(1, command.ExecuteNonQuery());
            if (defect is "identity-scope" or "grade-value")
            {
                command.CommandText = """
                    SELECT d.identity_json,d.best_grade,hex(c.fingerprint) FROM tier0_distance d
                    CROSS JOIN tier0_path_calculation c WHERE d.target=$target
                    """;
                string identity, grade, calculation;
                using (var row = command.ExecuteReader())
                {
                    Assert.True(row.Read());
                    identity = row.GetString(0); grade = row.GetString(1); calculation = row.GetString(2);
                }
                command.CommandText = "UPDATE tier0_distance SET overview_fingerprint=$hash WHERE target=$target";
                command.Parameters.AddWithValue("$hash", Tier0DistanceStorage.OverviewFingerprint(calculation, identity, grade));
                Assert.Equal(1, command.ExecuteNonQuery());
            }
        });
        using var source = new BundleAssetSource();
        var result = source.ReadTier0Overview(directory, Tier0OverviewScope.All, null);
        Assert.False(result.IsSuccess);
        Assert.Equal("Shell.Tier0OverviewUnreadable", result.Error.Code);
    }

    [Fact]
    public void Arch04Tier0ServingPublicationValidationRejectsAnUnfinishedGradeProjection()
    {
        var directory = OverviewServingRun();
        JudgementDescription description;
        using (var reader = JudgementReader.Open(directory).Value) description = reader.Description;
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            Tier0DistanceStorage.RequirePublishable(connection, description, CancellationToken.None);
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE tier0_distance SET overview_fingerprint=NULL WHERE target=$target";
            command.Parameters.AddWithValue("$target", UserDn);
            Assert.Equal(1, command.ExecuteNonQuery());
            Assert.Throws<InvalidDataException>(() =>
                Tier0DistanceStorage.RequirePublishable(connection, description, CancellationToken.None));
        });
    }

    [Fact]
    public void Arch04Tier0ServingLeavesOriginalProofUntouchedAndRefusesItWhenRequested()
    {
        var directory = OverviewServingRun();
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE tier0_best_route SET fingerprint=zeroblob(32) WHERE target=$target";
            command.Parameters.AddWithValue("$target", UserDn);
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        var before = Directory.GetFiles(directory, "*", SearchOption.AllDirectories)
            .Where(path => !path.EndsWith("-shm", StringComparison.Ordinal) && !path.EndsWith("-wal", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal).Select(path => (path, Hash: BundleSealing.HashFile(path))).ToArray();
        using var source = new BundleAssetSource();
        var page = source.ReadTier0Overview(directory, Tier0OverviewScope.All, null);
        Assert.True(page.IsSuccess, page.Error?.Description);
        Assert.Equal(2, page.Value!.Objects.Single(row => row.Subject.DistinguishedName == UserDn).BestGrade!.Length);
        Assert.False(source.ReadSavedTier0Path(directory, UserDn).IsSuccess);
        Assert.Equal(before, Directory.GetFiles(directory, "*", SearchOption.AllDirectories)
            .Where(path => !path.EndsWith("-shm", StringComparison.Ordinal) && !path.EndsWith("-wal", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal).Select(path => (path, Hash: BundleSealing.HashFile(path))).ToArray());
    }

    private static List<GroupInventoryRow> ReadServingGroups(BundleAssetSource source, string directory, GroupInventoryQuery query)
    {
        var rows = new List<GroupInventoryRow>();
        GroupInventoryMark? mark = null;
        do
        {
            var result = source.ReadGroups(directory, query, mark);
            Assert.True(result.IsSuccess, result.Error?.Description);
            Assert.Equal(123, result.Value.Total);
            Assert.InRange(result.Value.Groups.Count, 1, 50);
            rows.AddRange(result.Value.Groups);
            mark = result.Value.Next;
        } while (mark is not null);
        return rows;
    }

    private static string ServingGroup(int index) => $"CN=Serve-{index:000},OU=Percent_%,{ServingRoot}";

    private static string OverviewServingRun(int groups = 3)
    {
        var directory = Bundle(members: [UserDn], sddl: "O:SYG:SYD:", writeAdditional: (writer, partition) =>
        {
            for (var index = 0; index < groups; index++)
            {
                var members = new[] { UserDn, UserDn }.Concat(index == 0 ? [ServingGroup(index)] : Array.Empty<string>())
                    .Concat(index == groups - 1 ? ["CN=Missing," + ServingRoot] : Array.Empty<string>());
                Write(ServingGroup(index), $"S-1-5-21-1-2-3-{2000 + index}",
                    [Text("sAMAccountName", $"GRP-{index:000}"), Text("groupType", index % 2 == 0 ? "-2147483646" : "8"),
                        Text("member", members.ToArray())]);
            }
            Write(CoreDn, "S-1-5-21-1-2-3-512",
                [Text("groupType", "-2147483646"), Text("member", Enumerable.Range(0, groups).Select(ServingGroup).ToArray())]);

            void Write(string dn, string sid, EvidenceAttribute[] attributes)
            {
                var guid = Guid.NewGuid();
                var id = writer.WriteObject(new(partition, dn, guid,
                    [Text("objectClass", "top", "group"), new("objectSid", StoredAttributeCompleteness.Complete,
                        [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)]), .. attributes], Started));
                var descriptor = new RawSecurityDescriptor("O:SYG:SYD:");
                var bytes = new byte[descriptor.BinaryLength];
                descriptor.GetBinaryForm(bytes, 0);
                writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
            }
        });
        Derive(directory);
        var result = JudgingRun.JudgeWithTier0Discovery(directory, [new CircularGroupMembership()], Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, selfMembershipDiscoveryBudget: null);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return directory;

        static EvidenceAttribute Text(string name, params string[] values) =>
            new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
    }
}
