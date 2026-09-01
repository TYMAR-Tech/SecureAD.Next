using CommunityToolkit.Mvvm.ComponentModel;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel.Naming;

namespace SecureAD.Shell.ViewModels;

/// <summary>
/// How many objects a page holds, said where the shell can read it without reaching into the
/// evidence layer's internals.
/// </summary>
internal static class ObjectPaging
{
    /// <summary>How many objects one page holds.</summary>
    public const int PageSize = 100;
}

/// <summary>
/// One container in the tree, as a screen shows it.
/// </summary>
/// <remarks>
/// <b>The state is a state and not a sentence.</b> A view keys a treatment off <see cref="State"/>,
/// which is a <see cref="FactState"/>, and never off the text beside it - the four state marks were
/// once set with the words rather than the values, nothing matched, and every mark fell through to
/// the one meaning <i>not established</i>.
/// </remarks>
internal sealed partial class TreeNodeViewModel : ObservableObject
{
    private readonly TreeNode _node;

    /// <summary>
    /// Whether this container is the one selected.
    /// </summary>
    /// <remarks>
    /// <b>Selection lives on the node because a tree cannot report it any other way.</b> A
    /// <c>TreeView</c>'s selected item is read-only and cannot be bound, so the alternative is an
    /// event handled in the view's code-behind - which is where logic goes to avoid being tested,
    /// and which <c>ShellMvvmGateTests</c> fails the build for.
    /// </remarks>
    [ObservableProperty]
    private bool _isSelected;

    /// <summary>Creates a screen's view of one container.</summary>
    /// <param name="node">The container as the evidence rebuilt it.</param>
    public TreeNodeViewModel(TreeNode node)
    {
        ArgumentNullException.ThrowIfNull(node);

        _node = node;
        Children = [.. node.Children.Select(c => new TreeNodeViewModel(c))];
    }

    /// <summary>The container's name, for showing.</summary>
    public string Name => _node.Name;

    /// <summary>The container's full name, for an operator who needs to be certain which it is.</summary>
    public string DistinguishedName => _node.DistinguishedName;

    /// <summary>The containers directly beneath it.</summary>
    public IReadOnlyList<TreeNodeViewModel> Children { get; }

    /// <summary>
    /// What this run established about the container itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A container that was never captured is <see cref="FactState.NotEstablished"/> and not a
    /// fault: nothing is claimed about it either way, which is exactly true - objects name it as
    /// their parent and the run never read it, so what else it holds is unknown.
    /// </para>
    /// <para>
    /// <b>Nothing here is ever <see cref="FactState.EstablishedBad"/>.</b> That would be a
    /// judgement about the customer's directory, and this screen makes none.
    /// </para>
    /// </remarks>
    public FactState State => _node.Origin == TreeNodeOrigin.NeverCaptured
        ? FactState.NotEstablished
        : FactState.EstablishedGood;

    /// <summary>
    /// What is known about the container, where that is not simply "it was read". Null when the
    /// container was captured like any other object.
    /// </summary>
    public string? Detail => _node.Origin == TreeNodeOrigin.NeverCaptured
        ? "This container was never captured. Objects beneath it were, so it is shown to reach "
          + "them, but what else it holds is unknown."
        : null;

    /// <summary>Whether there is a detail worth a line of its own.</summary>
    public bool HasDetail => Detail is not null;

    /// <summary>This container and every container beneath it.</summary>
    /// <remarks>
    /// So the screen can listen to all of them for a selection. A tree reports selection on the
    /// item, and the item is wherever the operator clicked.
    /// </remarks>
    public IEnumerable<TreeNodeViewModel> ThisAndBelow() =>
        new[] { this }.Concat(Children.SelectMany(c => c.ThisAndBelow()));
}

/// <summary>
/// One part of the directory the tree cannot show, as a screen states it.
/// </summary>
/// <remarks>
/// This exists to keep an enumeration member off the screen, for the reason
/// <see cref="RunSummaryViewModel"/> gives: <c>DomainNotFullyRead</c> is a name chosen to be
/// unambiguous to a compiler, and an operator has to work out what it means.
/// </remarks>
internal sealed class TreeGapViewModel
{
    private readonly TreeGap _gap;

    /// <summary>Creates a screen's view of one gap.</summary>
    /// <param name="gap">The gap as the evidence reported it.</param>
    public TreeGapViewModel(TreeGap gap)
    {
        ArgumentNullException.ThrowIfNull(gap);

        _gap = gap;
    }

    /// <summary>What the gap is about.</summary>
    public string Subject => _gap.DistinguishedName;

    /// <summary>What kind of gap it is, in words rather than in a member name.</summary>
    public string Kind => _gap.Reason switch
    {
        TreeGapReason.DomainNotFullyRead => "A domain was not read in full",
        TreeGapReason.ForestPartitionNotFullyRead => "A forest partition was not read in full",
        TreeGapReason.PartitionNotRead => "A partition this product does not read",
        TreeGapReason.ContainerNeverCaptured => "A container was never captured",
        _ => "Something was not read",
    };

    /// <summary>What the run recorded about it, in the evidence layer's own words.</summary>
    public string Detail => _gap.Detail;

    /// <summary>
    /// What this means for what is on the screen.
    /// </summary>
    /// <remarks>
    /// A partition this product does not read is a decision, not a failure, and its mark says so.
    /// Both leave the same hole in the tree, and an operator's remedy differs: one is a run to
    /// repeat, the other is a scope to know about.
    /// </remarks>
    public FactState State => _gap.Reason switch
    {
        TreeGapReason.DomainNotFullyRead => FactState.Fault,
        TreeGapReason.ForestPartitionNotFullyRead => FactState.Fault,
        _ => FactState.NotEstablished,
    };
}

/// <summary>
/// One object in the listing, as a screen shows it.
/// </summary>
internal sealed class ListedObjectViewModel
{
    private readonly ListedObject _listed;

    /// <summary>Creates a screen's view of one object.</summary>
    /// <param name="listed">The object as the evidence holds it.</param>
    public ListedObjectViewModel(ListedObject listed)
    {
        ArgumentNullException.ThrowIfNull(listed);

        _listed = listed;
    }

    /// <summary>The object's name.</summary>
    public string Name => _listed.Name;

    /// <summary>The object's full name, for an operator who needs to be certain which it is.</summary>
    public string DistinguishedName => _listed.DistinguishedName;

    /// <summary>
    /// What kind of object it is. Says so plainly when the class did not arrive, rather than
    /// leaving a blank cell that reads as though the object had no class.
    /// </summary>
    public string ObjectType => _listed.ObjectClass ?? "not recorded";

    /// <summary>
    /// The class as the directory spells it, or null when it did not arrive.
    /// </summary>
    /// <remarks>
    /// Beside <see cref="ObjectType"/> rather than instead of it, because they answer different
    /// questions. That one is words for a cell and reads "not recorded" when nothing arrived; this
    /// one is the schema's own spelling, and is what decides which sections an object opened from
    /// this row has. Wording it would make "not recorded" a class name.
    /// </remarks>
    public string? ObjectClass => _listed.ObjectClass;

    /// <summary>The container it sits in, named as an operator would say it.</summary>
    public string Parent => _listed.ParentDistinguishedName is { } parent
        ? DnHelper.ExtractFirstRdn(parent)
        : string.Empty;

    /// <summary>
    /// What this run established about the object.
    /// </summary>
    /// <remarks>
    /// Never <see cref="FactState.EstablishedBad"/>. That would be a judgement about the
    /// customer's directory, and this screen makes none.
    /// </remarks>
    public FactState State => _listed.ObjectClass is null
        ? FactState.NotEstablished
        : FactState.EstablishedGood;
}

/// <summary>
/// One finding, as the findings grid shows it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every column comes off the stored finding.</b> Nothing here reaches into the evidence to
/// resolve a name, because the evidence is a separate sealed file and a grid that opened it per row
/// would pay for it on every page and every re-sort. What was true when the judging ran is what the
/// judging wrote down.
/// </para>
/// <para>
/// <b>Coverage is a column rather than a footnote.</b> A finding resting on evidence that may be
/// incomplete is not the same claim as one resting on a complete read, and an operator deciding
/// what to act on first needs to see the difference in the row rather than by opening it.
/// </para>
/// </remarks>
internal sealed class FindingRowViewModel
{
    private readonly Finding _finding;

    /// <summary>Creates a screen's view of one finding.</summary>
    /// <param name="finding">The finding as the judgement holds it.</param>
    public FindingRowViewModel(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        _finding = finding;
    }

    /// <summary>How serious this is, in the word an operator reads.</summary>
    public string Severity => _finding.Severity.ToString();

    /// <summary>
    /// How serious this is, as the value a view keys a colour off.
    /// </summary>
    /// <remarks>
    /// Beside <see cref="Severity"/> rather than instead of it, for the reason
    /// <see cref="ListedObjectViewModel.ObjectClass"/> gives: a treatment keyed off the word breaks
    /// silently the day the word changes, and the four state marks in this shell were once set that
    /// way and every one of them fell through.
    /// </remarks>
    public Severity Rank => _finding.Severity;

    /// <summary>The rule that produced it, such as <c>SEC-011</c>.</summary>
    public string Rule => _finding.RuleId;

    /// <summary>Who or what the finding is about.</summary>
    public string Principal => _finding.Subject.Key;

    /// <summary>The object it is about, named as an operator would say it.</summary>
    public string Target => DnHelper.ExtractNameFromDn(_finding.DistinguishedName);

    /// <summary>The object's full name, for an operator who needs to be certain which it is.</summary>
    public string DistinguishedName => _finding.DistinguishedName;

    /// <summary>The domain it was found in.</summary>
    public string Domain => _finding.DomainFqdn;

    /// <summary>What was found, said plainly enough to act on.</summary>
    public string Detail => _finding.Detail;

    /// <summary>
    /// Whether the evidence this rests on was complete, in words.
    /// </summary>
    /// <remarks>
    /// <b>Said rather than left blank.</b> An empty cell beside a finding reads as though the
    /// question was not worth asking, and the answer here changes what the finding is worth.
    /// </remarks>
    public string Coverage => _finding.Coverage == EvidenceCompleteness.Complete
        ? "Complete"
        : "May be incomplete";

    /// <summary>
    /// What this run established about the evidence behind the finding.
    /// </summary>
    /// <remarks>
    /// <b>Never <see cref="FactState.EstablishedBad"/>.</b> This states whether the evidence was
    /// whole, not whether the finding is serious - severity already says that, and colouring a row
    /// twice for two different things is how a screen comes to mean nothing.
    /// </remarks>
    public FactState State => _finding.Coverage == EvidenceCompleteness.Complete
        ? FactState.EstablishedGood
        : FactState.NotEstablished;

    /// <summary>
    /// The guidance written for the rule that produced this, or null where none is recorded.
    /// </summary>
    /// <remarks>
    /// <b>Looked up rather than stored on the finding.</b> Guidance is current advice, not part of
    /// what the judging established, so an operator reopening an older run gets today's wording
    /// rather than the wording that shipped that month. See <c>RuleGuidance</c> for why.
    /// </remarks>
    private RuleGuidance? Guidance => RuleGuidanceCatalogue.For(_finding.RuleId);

    /// <summary>Whether there is guidance to show for this finding's rule.</summary>
    /// <remarks>
    /// <b>It can be false, even though every catalogue rule has guidance.</b> A stored judgement
    /// outlives the build that made it, so a bundle can carry a finding from a rule this build no
    /// longer runs. The screen says so rather than showing an empty panel.
    /// </remarks>
    public bool HasGuidance => Guidance is not null;

    /// <summary>What an attacker gains from this, and what it costs the organisation.</summary>
    /// <remarks>
    /// <b>An absent answer says it is absent</b>, per <c>docs/decisions/0002</c>. Blank space where
    /// an explanation belongs reads as "there is nothing to say about this", which is a different
    /// claim from "this build has no guidance for that rule" and would be the wrong one.
    /// </remarks>
    public string WhyItMatters => Guidance?.WhyItMatters
        ?? $"No guidance is recorded for {_finding.RuleId} in this build. The finding stands; the "
            + "explanation beside it does not exist here.";

    /// <summary>The action to take, and what taking it may break.</summary>
    /// <remarks>
    /// <b>This never says the finding is then resolved.</b> That is a claim about every route to the
    /// object, which the judgement half must prove rather than assert - so the copy states an action
    /// and its cost, and <c>RuleGuidanceTests</c> fails the build on wording that goes further.
    /// </remarks>
    public string WhatToDo => Guidance?.WhatToDo
        ?? "Nothing is recorded for this rule in this build.";

    /// <summary>
    /// The family this belongs to, such as <c>Kerberos</c>, or an empty string where none is known.
    /// </summary>
    public string Category => Guidance?.Category ?? string.Empty;

    /// <summary>The Microsoft page the reasoning rests on, or null where none is recorded.</summary>
    public string? MicrosoftReference => Guidance?.MicrosoftReference;

    /// <summary>Whether a Microsoft source can be offered for this finding's reasoning.</summary>
    public bool HasMicrosoftReference => Guidance?.MicrosoftReference is not null;
}
