using System.Xml.Linq;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class ControlEdgePresentationTests
{
    [Fact]
    public void BothViewsKeepGeneralAndSelfMembershipSeparateAndShowTheirLimits()
    {
        var evaluation = Judgement.GroupMembershipControlTests.Membership(Judgement.ControlEdgeDeriverTests.Permissions(
            Judgement.GroupMembershipControlTests.Scoped(0, 0x28)));
        var vm = new ControlEdgesSectionViewModel(new(ObjectSectionCatalog.ControlEdges, "Control edges", []));
        vm.Configure(true, false, (_, _, _) => Result<ControlEdgePage>.Success(new(evaluation.Edges, 0, 2, 0, 1, true, true, false, 2) { GenerationId = Guid.Empty }),
            _ => Result<SelfMembershipAssessmentSet>.Success(new([], true, Guid.Empty)));
        foreach (var byHolder in new[] { false, true })
        {
            vm.ByHolder = byHolder;
            Assert.Equal(2, vm.Rows.Count);
            Assert.Contains(vm.Rows, row => row.Capability.Contains("no own-account restriction") && row.Evaluation == "Established");
            var self = Assert.Single(vm.Rows.Where(row => row.Capability.Contains("Self-Membership")));
            Assert.Contains("own account only", self.Capability);
            Assert.Equal("Unknown", self.Evaluation);
            Assert.Contains("MembershipEscalation", self.Evidence);
            Assert.Contains("AddedMemberSid == RequesterSid: Unknown", self.Evidence);
            Assert.Contains("named-holder requester operations remain unknown", vm.SupportedScope);
            Assert.Contains("Counts include unknown candidates", vm.Coverage);
        }
    }

    [Fact]
    public void RequesterRowsUseOneStoredAnswerInBothDirections()
    {
        var value = new SelfMembershipAssessment(new("CN=Alice", "CN=Target", SelfMembershipOperation.Remove, null),
            Guid.Empty, null, new('a', 64), Guid.NewGuid(), "S-1-5-21-1-2-3-1", Guid.NewGuid(),
            "S-1-5-21-1-2-3-2", Guid.NewGuid(), "S-1-5-21-1-2-3-1", ControlEvaluationState.Established,
            ControlEvaluationState.Established, ControlEvaluationState.Established, "Computed", DateTimeOffset.UnixEpoch,
            512, true, [SelfMembershipIssue.LiveOperationNotEvaluated], [], [9]);
        foreach (var selectedIsUser in new[] { false, true })
        {
            var vm = new ControlEdgesSectionViewModel(new(ObjectSectionCatalog.ControlEdges, "Control edges", []));
            vm.Configure(true, selectedIsUser,
                (_, _, _) => Result<ControlEdgePage>.Success(new([], 0, 0, 0, 0, true, true, false, 0) { GenerationId = Guid.Empty }),
                _ => Result<SelfMembershipAssessmentSet>.Success(new([value], true, Guid.Empty)));
            var row = Assert.Single(vm.RequesterAssessments);
            Assert.Equal("Established", row.Authorization);
            Assert.Contains("do not add to holder-edge counts", vm.RequesterCoverage);
    }
    }

    [Theory]
    [InlineData("Counts")]
    [InlineData("Coverage")]
    [InlineData("Rows")]
    [InlineData("SelectedEdge.Evidence, Mode=OneWay")]
    public void RealControlTemplateKeepsTheAnswerAndItsEvidence(string binding)
    {
        var path = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell", "Views", "Sections", "ObjectSectionTemplates.xaml");
        var document = System.Xml.Linq.XDocument.Load(path);
        var template = document.Descendants().Single(element => element.Name.LocalName == "DataTemplate"
            && element.Attributes().Any(attribute => attribute.Name.LocalName == "DataType" && attribute.Value == "{x:Type vm:ControlEdgesSectionViewModel}"));
        Assert.Contains(template.Descendants().Attributes(), attribute => attribute.Value == "{Binding " + binding + "}");
    }

    [Fact]
    public void BothDirectionsResetPagingAndAlwaysStateTheExpectedHiddenCount()
    {
        var queries = new List<(bool Holder, bool Expected, long After)>();
        var vm = new ControlEdgesSectionViewModel(new(ObjectSectionCatalog.ControlEdges, "Control edges", []));
        var generation = Guid.NewGuid();
        vm.Configure(true, false, (holder, expected, after) =>
        {
            queries.Add((holder, expected, after));
            return Result<ControlEdgePage>.Success(new([], 2, 3, 7, 1, true, false, true, 100) { GenerationId = generation });
        }, _ => Result<SelfMembershipAssessmentSet>.Success(new([], true, generation)));
        Assert.Contains("7 expected (hidden)", vm.Counts);
        Assert.Contains("incomplete", vm.Coverage);
        vm.NextPageCommand.Execute(null);
        Assert.Equal(100, queries[^1].After);
        vm.ByHolder = true;
        Assert.Equal((true, false, 0L), queries[^1]);
        Assert.Contains("whole capture", vm.Coverage);
        vm.IncludeExpected = true;
        Assert.Equal((true, true, 0L), queries[^1]);
        Assert.Contains("7 expected (shown)", vm.Counts);
    }

    [Fact]
    public void UnrunAndChangedGenerationAreNotEmptyCompleteAnswers()
    {
        var vm = new ControlEdgesSectionViewModel(new(ObjectSectionCatalog.ControlEdges, "Control edges", []));
        vm.Configure(false, false, (_, _, _) => Result<ControlEdgePage>.Success(new([], 0, 0, 0, 0, false, false, false, 0)),
            _ => Result<SelfMembershipAssessmentSet>.Success(new([], false, null)));
        Assert.Contains("not derived", vm.Coverage);
        Assert.Contains("unknown", vm.Counts);
        var generation = Guid.NewGuid();
        vm.Configure(true, false, (_, _, _) => Result<ControlEdgePage>.Success(new([], 0, 0, 0, 0, true, true, true, 100) { GenerationId = generation }),
            _ => Result<SelfMembershipAssessmentSet>.Success(new([], true, generation)));
        Assert.True(vm.HasMore);
        generation = Guid.NewGuid();
        vm.NextPageCommand.Execute(null);
        Assert.Contains("changed", vm.Coverage);
        Assert.False(vm.HasMore);
    }

    [Fact]
    public void EveryObjectHasAReachableControlSection()
    {
        Assert.Contains(ObjectSectionCatalog.For("user"), section => section.Key == ObjectSectionCatalog.ControlEdges);
        Assert.Contains(ObjectSectionCatalog.For(null), section => section.Key == ObjectSectionCatalog.ControlEdges);
    }
}
