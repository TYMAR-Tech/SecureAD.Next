using System.Reflection;
using System.Text.RegularExpressions;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Proves that a template reads the state a view model actually publishes.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists - <c>F-S50-4</c>.</b> A mark was lost in a rewrite with a green build. WPF
/// resolves a binding path at runtime against whatever the data context happens to be, and a path
/// that matches nothing is not an error: the binding silently produces nothing and the element
/// renders empty. So renaming a view model property, or deleting a binding, compiles, passes every
/// test, and removes something from the screen that nobody notices until an operator reads an audit
/// that is missing a fact.
/// </para>
/// <para>
/// <b>This is the one failure the shell's other gates cannot catch.</b>
/// <c>ShellMvvmGateTests</c> stops logic leaking into views and
/// <c>ViewColourLiteralGateTests</c> stops a view inventing a colour. Neither reads a binding path.
/// Between them a screen can be perfectly layered, perfectly themed, and bound to nothing.
/// </para>
/// <para>
/// It scans in two directions, because the two failures are different. Every path a template names
/// must exist on something - that catches a rename. And the facts that matter most must still be
/// named by a template - that catches a deletion, which no amount of path-checking would notice.
/// </para>
/// </remarks>
public sealed class ViewBindingGateTests
{
    /// <summary>
    /// Every <c>{Binding ...}</c> in the shell's XAML, with everything up to the first brace that
    /// closes it or opens a nested markup extension.
    /// </summary>
    /// <remarks>
    /// Matched against whole file text rather than line by line, because a binding is routinely
    /// written across two lines and its <c>RelativeSource</c> is often on the second. A per-line
    /// scan reads the first half of such a binding as though it bound to the data context, and
    /// reports a rename that has not happened.
    /// </remarks>
    private static readonly Regex BindingExpression =
        new(@"\{Binding([^}]*)", RegexOptions.Compiled);

    /// <summary>
    /// Members the shell's view models publish, by name.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Gathered by reflection rather than from a list written down here, so the gate cannot drift
    /// from the code it is checking.
    /// </para>
    /// <para>
    /// <b>It spans the product's assemblies, not just the shell's.</b> A template legitimately
    /// binds an item template to a domain record - the linked-policies list binds
    /// <c>PolicyLink</c>, which belongs to the kernel - and a gate that knew only about view
    /// models would report every one of those as a broken path.
    /// </para>
    /// </remarks>
    private static readonly HashSet<string> PublishedMembers = Published();

    // -------------------------------------------------------------------------------------------
    // Direction one: a template may not name state nothing publishes.
    // -------------------------------------------------------------------------------------------

    [Fact]
    public void EveryBindingNamesSomethingAViewModelPublishes()
    {
        var offences = new List<string>();

        foreach (var file in XamlFiles())
        {
            var text = File.ReadAllText(file);

            foreach (var (path, index) in BindingsIn(text))
            {
                if (PublishedMembers.Contains(path))
                    continue;

                var line = text.Take(index).Count(c => c == '\n') + 1;
                offences.Add($"  {Path.GetFileName(file)}({line}): {path}");
            }
        }

        Assert.True(
            offences.Count == 0,
            "A template binds to a path nothing publishes. WPF does not fail a binding it "
            + "cannot resolve - it renders nothing - so this is a fact silently missing from a "
            + "screen rather than an error anybody would see. Either the property was renamed and "
            + "the template was not, or the path is a typo:"
            + Environment.NewLine + string.Join(Environment.NewLine, offences));
    }

    // -------------------------------------------------------------------------------------------
    // Direction two: the facts that matter must still be on the screen.
    //
    // F-S50-4 is a mark that WAS bound and stopped being bound. No path check catches that, because
    // a deleted binding names nothing at all. These name the bindings that may not go quiet.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The classifier's verdict, which is the whole subject of the permissions screen's toggle.
    /// </summary>
    /// <remarks>
    /// <b>These name <see cref="PermissionRightViewModel"/> and not the entry.</b> The mark moved
    /// to the right that earned it, because a row is one access control entry and an entry's mask
    /// is a set of rights judged independently. If it ever moves back to the row, this is the gate
    /// that should be argued with first.
    /// </remarks>
    [Theory]
    [InlineData(nameof(PermissionRightViewModel.Name))]
    [InlineData(nameof(PermissionRightViewModel.Mark))]
    [InlineData(nameof(PermissionRightViewModel.RiskReason))]
    [InlineData(nameof(PermissionRightViewModel.IsMarked))]
    [InlineData(nameof(PermissionEntryViewModel.Rights))]
    [InlineData(nameof(PermissionsSectionViewModel.HighlightRiskyPermissions))]
    [InlineData(nameof(PermissionsSectionViewModel.Counters))]
    public void ThePermissionsTemplateStillBindsTheClassifiersAnswer(string member)
    {
        Assert.Contains(member, PermissionsTemplate(), StringComparison.Ordinal);
    }

    /// <summary>
    /// A counter that stopped saying it was not computed would be a counter showing a bare dash,
    /// and a dash nobody explains is a thing an operator guesses at.
    /// </summary>
    [Theory]
    [InlineData(nameof(PermissionCounter.Display))]
    [InlineData(nameof(PermissionCounter.Label))]
    [InlineData(nameof(PermissionCounter.Explanation))]
    [InlineData(nameof(PermissionCounter.IsNotComputed))]
    public void TheCounterStripStillBindsEveryPartOfACounter(string member)
    {
        Assert.Contains(member, PermissionsTemplate(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The four emptinesses the permissions section exists to keep apart. A null list grants
    /// everyone everything and an empty one grants nobody anything; a template that stopped
    /// showing which is which would render the most open object in the forest as a blank table.
    /// </summary>
    [Theory]
    [InlineData(nameof(PermissionsSectionViewModel.Emptiness))]
    [InlineData(nameof(PermissionsSectionViewModel.IsEmpty))]
    [InlineData(nameof(PermissionsSectionViewModel.Statements))]
    [InlineData(nameof(PermissionsSectionViewModel.Errors))]
    public void ThePermissionsTemplateStillExplainsAnEmptyOrCaveatedList(string member)
    {
        Assert.Contains(member, PermissionsTemplate(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("FindingsView.xaml", "SelectedFinding.")]
    [InlineData("ObjectSectionTemplates.xaml", "")]
    public void BothFindingSurfacesBindMembershipEvidenceAndCompleteness(string fileName, string prefix)
    {
        var file = XamlFiles().Single(path => Path.GetFileName(path) == fileName);
        var document = System.Xml.Linq.XDocument.Load(file);
        var paths = document.Descendants().SelectMany(element => element.Attributes()).Select(attribute =>
            Regex.Match(attribute.Value, @"^\{Binding\s+([^,}\s]+)").Groups[1].Value).ToArray();
        foreach (var member in new[] { nameof(FindingRowViewModel.HasMembershipEvidence),
            nameof(FindingRowViewModel.MembershipCompleteness), nameof(FindingRowViewModel.MembershipDetails) })
            Assert.Contains(prefix + member, paths);
    }

    // -------------------------------------------------------------------------------------------
    // The scanner self-test. A gate that scans nothing passes.
    // -------------------------------------------------------------------------------------------

    [Fact]
    public void TheGateReadsTheRealTemplatesAndKnowsTheRealViewModels()
    {
        var files = XamlFiles();

        Assert.NotEmpty(files);
        Assert.Contains(files, f => Path.GetFileName(f) == "ObjectSectionTemplates.xaml");
        Assert.NotEmpty(PermissionsTemplate());

        // It knows what the view models publish.
        Assert.Contains(nameof(PermissionsSectionViewModel.Counters), PublishedMembers);
        Assert.Contains(nameof(PermissionRightViewModel.Mark), PublishedMembers);

        // And it does not merely believe everything is published.
        Assert.DoesNotContain("APropertyNothingHasEverDeclared", PublishedMembers);
    }

    [Fact]
    public void TheGateExtractsPathsAndIgnoresTheFormsThatAreNotOne()
    {
        // The ordinary shapes, including one wrapped in a converter.
        Assert.Equal(["Counters"], PathsIn("<ItemsControl ItemsSource=\"{Binding Counters}\" />"));
        Assert.Equal(
            ["IsNotComputed"],
            PathsIn("Visibility=\"{Binding IsNotComputed, Converter={StaticResource Shown}}\""));

        // A dotted path is checked by its first segment, which is the part a rename breaks.
        Assert.Equal(["Emptiness"], PathsIn("Text=\"{Binding Emptiness.Title}\""));

        // Forms that name no member of the data context, and would otherwise be false alarms.
        // Every one of these was reported by this gate on its first run against the real shell.
        Assert.Empty(PathsIn("Text=\"{Binding Mode=OneWay}\""));
        Assert.Empty(PathsIn("<views:BindingProxy x:Key=\"Section\" Data=\"{Binding}\" />"));
        Assert.Empty(PathsIn(
            "Visibility=\"{Binding Data.HighlightRiskyPermissions, "
            + "Source={StaticResource Section}, Converter={StaticResource Shown}}\""));

        // A binding written across two lines, whose RelativeSource is on the second. Read a line
        // at a time this reads as a plain path and reports a rename that never happened.
        Assert.Empty(PathsIn(
            "IsChecked=\"{Binding IsExpanded, Mode=TwoWay,"
            + Environment.NewLine
            + "            RelativeSource={RelativeSource TemplatedParent}}\""));

        // WPF's current-item syntax. The property being named is still Objects.
        Assert.Equal(["Objects"], PathsIn("CommandParameter=\"{Binding Objects/}\""));
    }

    /// <summary>
    /// The two halves of the check, composed: a path the scanner extracts, and a name nothing
    /// publishes, is an offence. Without this the self-test proves the parser works and the
    /// reflection works while saying nothing about the gate they are wired into.
    /// </summary>
    [Fact]
    public void TheGateWouldFailOnABindingToSomethingNothingPublishes()
    {
        const string Broken = "<TextBlock Text=\"{Binding CountersThatNobodyDeclared}\" />";

        var extracted = PathsIn(Broken);

        Assert.Equal(["CountersThatNobodyDeclared"], extracted);
        Assert.DoesNotContain(extracted[0], PublishedMembers);
    }

    /// <summary>
    /// And the same shape, with a name that IS published, is not an offence - so the gate is
    /// discriminating rather than simply hostile to bindings.
    /// </summary>
    [Fact]
    public void TheGateWouldPassABindingToSomethingReal()
    {
        var extracted = PathsIn("<ItemsControl ItemsSource=\"{Binding Counters}\" />");

        Assert.Equal([nameof(PermissionsSectionViewModel.Counters)], extracted);
        Assert.Contains(extracted[0], PublishedMembers);
    }

    // -------------------------------------------------------------------------------------------
    // Scanning.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The binding paths a line names, excluding the forms that do not name a view model member.
    /// </summary>
    /// <remarks>
    /// <b>What is deliberately skipped, and why the gate is still worth having.</b> A binding with
    /// an explicit <c>Source</c>, <c>ElementName</c> or <c>RelativeSource</c> resolves against
    /// something other than the data context, so this cannot know what it should name.
    /// <c>{Binding}</c> binds the item itself. Skipping them keeps the gate from crying wolf,
    /// which is how a check ends up deleted.
    /// </remarks>
    private static List<string> PathsIn(string text) =>
        [.. BindingsIn(text).Select(b => b.Path)];

    /// <summary>
    /// The binding paths some text names, with where each was found, excluding the forms that do
    /// not name a member of the data context.
    /// </summary>
    /// <remarks>
    /// <b>What is deliberately skipped, and why the gate is still worth having.</b> A binding with
    /// an explicit <c>Source</c>, <c>ElementName</c> or <c>RelativeSource</c> resolves against
    /// something other than the data context, so this cannot know what it should name.
    /// <c>{Binding}</c> binds the item itself. Skipping them keeps the gate from crying wolf,
    /// which is how a check ends up switched off.
    /// </remarks>
    private static List<(string Path, int Index)> BindingsIn(string text)
    {
        var found = new List<(string, int)>();

        foreach (Match match in BindingExpression.Matches(text))
        {
            var expression = match.Groups[1].Value;

            // Resolves against something that is not the data context.
            if (expression.Contains("Source=", StringComparison.Ordinal)
                || expression.Contains("ElementName=", StringComparison.Ordinal))
            {
                continue;
            }

            var path = expression.Split(',')[0].Trim();

            if (path.StartsWith("Path=", StringComparison.Ordinal))
                path = path["Path=".Length..];

            // "Objects/" is WPF's current-item syntax: it binds the current item OF the
            // collection, and the property being named is still Objects.
            path = path.TrimEnd('/');

            if (path.Length == 0 || path.Contains('=', StringComparison.Ordinal))
                continue;

            // A dotted path is checked by its first segment: the rest belongs to a type this gate
            // would have to walk the whole chain to know, and the first segment is what a rename
            // of a published property breaks.
            var first = path.Split('.')[0].Trim();

            // "Items[0]" indexes into a collection, and the property being named is still Items.
            // Stripping the indexer keeps the member checkable rather than skipping the binding:
            // "Itms[0]" is still an offence.
            var indexer = first.IndexOf('[', StringComparison.Ordinal);
            if (indexer > 0)
                first = first[..indexer];

            if (first.Length > 0)
                found.Add((first, match.Index));
        }

        return found;
    }

    private static HashSet<string> Published()
    {
        var members = new HashSet<string>(StringComparer.Ordinal);

        var assemblies = new[]
        {
            typeof(PermissionsSectionViewModel).Assembly,
            typeof(SecureAD.Kernel.GroupPolicy.PolicyLink).Assembly,
            typeof(SecureAD.Evidence.ObjectPermissions).Assembly,
        };

        foreach (var type in assemblies.Distinct().SelectMany(a => a.GetTypes()))
        {
            foreach (var property in type.GetProperties(
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance))
            {
                members.Add(property.Name);
            }
        }

        // A group header's data context is not a view model. WPF supplies a CollectionViewGroup,
        // so Name, ItemCount and Items are the members available there and this gate would
        // otherwise report every one of them as a path nothing publishes.
        //
        // Its own members are added rather than the paths being exempted, because the point of the
        // gate survives either way only if a TYPO still fails: ItmCount is not a member of
        // CollectionViewGroup and is still caught. An exemption keyed on the file, or on the paths
        // themselves, would have switched the check off for the one template hardest to eyeball.
        foreach (var property in typeof(System.Windows.Data.CollectionViewGroup).GetProperties(
            BindingFlags.Public | BindingFlags.Instance))
        {
            members.Add(property.Name);
        }

        return members;
    }

    private static string PermissionsTemplate()
    {
        var file = XamlFiles()
            .Single(f => Path.GetFileName(f) == "ObjectSectionTemplates.xaml");

        var text = File.ReadAllText(file);
        var start = text.IndexOf(
            "vm:PermissionsSectionViewModel", StringComparison.Ordinal);

        Assert.True(start >= 0, "The permissions data template is not in the section templates.");

        return text[start..];
    }

    private static string ShellRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null && !Directory.Exists(Path.Combine(directory.FullName, "src")))
            directory = directory.Parent;

        Assert.NotNull(directory);

        return Path.Combine(directory!.FullName, "src", "SecureAD.Shell");
    }

    private static List<string> XamlFiles() =>
        Directory.EnumerateFiles(ShellRoot(), "*.xaml", SearchOption.AllDirectories)
            .Where(NotBuildOutput)
            .ToList();

    private static bool NotBuildOutput(string path) =>
        !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
        && !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal);
}
