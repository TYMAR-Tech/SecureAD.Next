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
        vm.Configure(true, (_, _, _) => Result<ControlEdgePage>.Success(new(evaluation.Edges, 0, 2, 0, 1, true, true, false, 2)));
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
            Assert.Contains("requester operations remain unknown", vm.SupportedScope);
            Assert.Contains("Counts include unknown candidates", vm.Coverage);
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
        vm.Configure(true, (holder, expected, after) =>
        {
            queries.Add((holder, expected, after));
            return Result<ControlEdgePage>.Success(new([], 2, 3, 7, 1, true, false, true, 100) { GenerationId = generation });
        });
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
        vm.Configure(false, (_, _, _) => Result<ControlEdgePage>.Success(new([], 0, 0, 0, 0, false, false, false, 0)));
        Assert.Contains("not derived", vm.Coverage);
        Assert.Contains("unknown", vm.Counts);
        vm.Configure(true, (_, _, _) => Result<ControlEdgePage>.Success(new([], 0, 0, 0, 0, true, true, true, 100) { GenerationId = Guid.NewGuid() }));
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
