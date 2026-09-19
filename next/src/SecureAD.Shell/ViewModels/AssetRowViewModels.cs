using System.Globalization;
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

    public bool HasMembershipEvidence => _finding.Evidence is KerberoastableAccountEvidence;

    public string MembershipCompleteness => _finding.Evidence is KerberoastableAccountEvidence evidence
        ? evidence.MembershipRoutes.CompletenessDescription : string.Empty;

    public string MembershipDetails
    {
        get
        {
            if (_finding.Evidence is not KerberoastableAccountEvidence evidence)
                return string.Empty;
            var blocks = new List<string>();
            if (evidence.DirectProtectionName is { } direct)
                blocks.Add($"Direct protection basis: {direct} (catalogue entry {evidence.DirectProtectionCatalogueEntryId}, version {evidence.ProtectionCatalogueVersion}). Membership changes do not remove this basis.");
            foreach (var membership in evidence.MembershipRoutes.Memberships)
            {
                var lines = new List<string> { "Initial membership: " + MembershipPrincipal(membership.InitialMembership) };
                foreach (var route in membership.Routes)
                {
                    var authorization = route.Authorization switch
                    {
                        MembershipRouteAuthorization.SecurityEnabled => "Security-enabled membership chain; this is not an effective-access calculation.",
                        MembershipRouteAuthorization.DistributionGroup => "Contains a distribution group: this chain does not confer membership-based authorization.",
                        _ => "Group type was not captured: membership-based authorization is unknown.",
                    };
                    var protection = route.EstablishesProtection ? "Protection is established by this chain."
                        : route.Steps.Any(s => s.IsPrimaryGroup)
                            ? "Protection through primary-group membership is not established."
                            : "Protection propagation from this root is not established or is excluded by the forest.";
                    var chain = string.Join("", route.Steps.Select((step, index) =>
                        (index == 0 ? string.Empty : step.IsPrimaryGroup ? " --primary group--> " : " --member of--> ")
                        + MembershipPrincipal(step.Principal)));
                    lines.Add($"Root: {route.RootName} (catalogue entry {route.CatalogueEntryId})");
                    lines.Add(chain);
                    lines.Add(authorization + " " + protection);
                }
                blocks.Add(string.Join(Environment.NewLine, lines));
            }
            blocks.Add("Supporting chains are grouped by initial membership, not every possible path. They are not a minimum set of removals. Changing a shared group may affect other accounts; removing these memberships does not establish that every other form of privilege is gone.");
            return string.Join(Environment.NewLine + Environment.NewLine, blocks);
        }
    }

    private static string MembershipPrincipal(MembershipRoutePrincipal principal) =>
        (principal.DistinguishedName is { } dn ? dn + " [" + principal.Sid + "]" : principal.Sid)
        + (principal.Scope is { } scope ? " (" + scope + ")" : string.Empty);

    private bool EvidenceIsComplete => _finding.Coverage == EvidenceCompleteness.Complete
        && (_finding.Evidence is not KerberoastableAccountEvidence evidence || evidence.MembershipRoutes.IsComplete);

    /// <summary>
    /// Whether the evidence this rests on was complete, in words.
    /// </summary>
    /// <remarks>
    /// <b>Said rather than left blank.</b> An empty cell beside a finding reads as though the
    /// question was not worth asking, and the answer here changes what the finding is worth.
    /// </remarks>
    public string Coverage => EvidenceIsComplete
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
    public FactState State => EvidenceIsComplete
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

    /// <summary>What the rule looks for, and what it does not.</summary>
    /// <remarks>
    /// <b>Shown beside the finding because there is nowhere else yet.</b> It is a statement about
    /// the rule rather than about this object, so an operator reading a rule that reported nothing
    /// still cannot see it - which is the half of <c>P-118</c> that a findings panel cannot close.
    /// The other half, repeating it once per object, this does close: it is read from the catalogue
    /// rather than written into each finding's text.
    /// </remarks>
    public string About => Guidance?.About
        ?? $"No description is recorded for {_finding.RuleId} in this build.";

    /// <summary>
    /// The family this belongs to, such as <c>Kerberos</c>, or an empty string where none is known.
    /// </summary>
    public string Category => Guidance?.Category ?? string.Empty;

    /// <summary>The Microsoft page the reasoning rests on, or null where none is recorded.</summary>
    public string? MicrosoftReference => Guidance?.MicrosoftReference;

    /// <summary>Whether a Microsoft source can be offered for this finding's reasoning.</summary>
    public bool HasMicrosoftReference => Guidance?.MicrosoftReference is not null;
}

/// <summary>
/// One computer, as the LAPS inventory shows it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every column comes off the stored computer, and every judgement off the shared types.</b>
/// The row asks <see cref="LapsComputer"/> rather than deciding anything itself, so the grid cannot
/// call a machine capable while <c>SEC-094</c> calls it legacy-only.
/// </para>
/// <para>
/// <b>Both timestamps are shown, not the one that suits the machine's tier.</b> The predecessor
/// showed whichever matched the tier it had assigned, so a migrated machine looked like a modern
/// one and the legacy value it still carried was invisible.
/// </para>
/// </remarks>
internal sealed class LapsComputerViewModel
{
    private readonly LapsComputer _computer;

    /// <summary>Creates a screen's view of one computer.</summary>
    /// <param name="computer">The computer as the evidence holds it.</param>
    public LapsComputerViewModel(LapsComputer computer)
    {
        ArgumentNullException.ThrowIfNull(computer);

        _computer = computer;
    }

    /// <summary>The machine's name.</summary>
    public string Name => _computer.Name;

    /// <summary>Where it sits, so two machines of one name in two domains are told apart.</summary>
    public string Domain => _computer.DomainFqdn ?? string.Empty;

    /// <summary>The full name, for an operator who needs to find the object.</summary>
    public string DistinguishedName => _computer.DistinguishedName;

    /// <summary>What the directory shows about its password management.</summary>
    public string Management => _computer.Management switch
    {
        LapsManagement.WindowsLaps => "Windows LAPS",
        LapsManagement.LegacyLaps => "Legacy LAPS",
        LapsManagement.Migrated => "Migrated",
        LapsManagement.Unexpected => "Unexpected",
        _ => "Not managed",
    };

    /// <summary>
    /// How that reads as a state a view can colour.
    /// </summary>
    /// <remarks>
    /// <b>Unexpected is not established-bad.</b> The machine is managed and there is no exposure -
    /// what is wrong is that Microsoft says the combination cannot occur, which is a fact about the
    /// forest rather than a risk. <see cref="FactState.NotEstablished"/> is the honest mark: the
    /// product cannot say what is going on.
    /// </remarks>
    public FactState State => _computer.Management switch
    {
        LapsManagement.WindowsLaps or LapsManagement.Migrated => FactState.EstablishedGood,
        LapsManagement.NotManaged => FactState.EstablishedBad,
        _ => FactState.NotEstablished,
    };

    /// <summary>The operating system, or a statement that none was captured.</summary>
    public string OperatingSystem => _computer.OperatingSystem ?? "Not captured";

    /// <summary>What the machine could run, in the words of the classification.</summary>
    public string Capability => _computer.Capability.Kind switch
    {
        LapsCapabilityKind.WindowsLapsCapable => "Windows LAPS capable",
        LapsCapabilityKind.LegacyLapsOnly => "Legacy LAPS only",
        _ => "Unknown",
    };

    /// <summary>
    /// Whether the capability rests on the build number, the operating system name, or nothing.
    /// </summary>
    /// <remarks>
    /// <b>Shown, because the two are not equally good.</b> A bundle sealed before the build number
    /// was captured can only be classified from a name, and an operator reading the grid is
    /// entitled to know which answer he is looking at.
    /// </remarks>
    public string CapabilityBasis => _computer.Capability.Basis switch
    {
        LapsCapabilityBasis.OperatingSystemVersion => "build number",
        LapsCapabilityBasis.OperatingSystemName => "operating system name",
        _ => "nothing to read",
    };

    /// <summary>When Windows LAPS next expects to rotate, or why there is no date.</summary>
    public string WindowsLapsExpiry => Expiry(_computer.WindowsLaps);

    /// <summary>When legacy LAPS next expected to rotate, or why there is no date.</summary>
    public string LegacyLapsExpiry => Expiry(_computer.LegacyLaps);

    /// <summary>Whether this is a domain controller, which both LAPS rules leave alone.</summary>
    public bool IsDomainController => _computer.DomainController.IsDomainController;

    /// <summary>Whether the account is disabled, which both LAPS rules leave alone.</summary>
    public bool IsDisabled => _computer.IsDisabled;

    /// <summary>
    /// Why the rules say nothing about this machine, or an empty string where they do.
    /// </summary>
    /// <remarks>
    /// <b>This column is the reason the grid lists what the rules exclude.</b> An operator who
    /// cannot see a machine has no way to tell one the product deliberately ignored from one it
    /// never captured, and the first <c>ad.lab</c> run turned two excluded machines into findings
    /// precisely because there was nowhere else for them to appear.
    /// </remarks>
    public string NotJudgedBecause =>
        _computer.AccountState is LapsAttributes.AccountState.Unknown
            ? LapsInventoryText.Get(IsDomainController ? "ControllerAccountUnknown" : "AccountUnknown")
        : IsDomainController && IsDisabled ? "Domain controller, disabled"
        : IsDomainController ? "Domain controller"
        : IsDisabled ? "Disabled"
        : string.Empty;

    /// <summary>Whether either rule is in scope for this machine.</summary>
    public bool IsJudged => _computer.IsJudged;

    /// <summary>
    /// Reads one timestamp for showing, keeping absent and unreadable apart.
    /// </summary>
    /// <remarks>
    /// <b>An unreadable value is not shown as an absent one.</b> A machine whose timestamp is
    /// present but undecodable is managed, and a blank cell would say the opposite.
    /// </remarks>
    private static string Expiry(StoredLapsTimestamp timestamp) => timestamp.Reading switch
    {
        LapsTimestampReading.Present =>
            timestamp.ExpiresUtc!.Value.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
        LapsTimestampReading.Unreadable => "Present, unreadable",
        _ => string.Empty,
    };
}

/// <summary>
/// How many computers are in one LAPS state, across the whole listing.
/// </summary>
/// <remarks>
/// <b>A row per state, including the states at zero.</b> A count list that omits what it did not
/// find reads as a shorter question than the one that was asked: an operator who cannot see
/// <i>Not managed 0</i> has to work out whether it was measured at all.
/// </remarks>
internal sealed class LapsCountViewModel
{
    /// <summary>Creates one count.</summary>
    /// <param name="state">The state being counted.</param>
    /// <param name="count">How many computers are in it.</param>
    public LapsCountViewModel(LapsManagement state, int count)
    {
        State = state;
        Count = count;
    }

    /// <summary>The state being counted.</summary>
    public LapsManagement State { get; }

    /// <summary>How many computers are in it.</summary>
    public int Count { get; }

    /// <summary>The state in the words an operator reads.</summary>
    public string Label => State switch
    {
        LapsManagement.WindowsLaps => "Windows LAPS",
        LapsManagement.LegacyLaps => "Legacy LAPS",
        LapsManagement.Migrated => "Migrated",
        LapsManagement.Unexpected => "Unexpected",
        _ => "Not managed",
    };
}

/// <summary>
/// One rule, what it looks for, and what it did to this run.
/// </summary>
/// <remarks>
/// <para>
/// <b>Built from the catalogue outward, not from the judgement.</b> The rules this build ships are
/// the list; a judgement only says what became of each of them. Reading it the other way round
/// would silently drop any rule the run never scheduled, which is the one case an operator most
/// needs to see - a rule missing from a screen of rules reads as a rule that does not exist.
/// </para>
/// <para>
/// <b>An execution naming a rule this build no longer ships is kept too.</b> A judgement outlives
/// the build that wrote it, and dropping such a row would quietly shrink the account of what was
/// actually done to the bundle.
/// </para>
/// </remarks>
internal sealed class RuleRowViewModel
{
    private readonly RuleDefinition? _definition;
    private readonly StoredRuleExecution? _execution;

    /// <summary>Creates a screen's view of one rule.</summary>
    /// <param name="ruleId">The rule, which is present whether or not either half below is.</param>
    /// <param name="definition">What this build declares about it, or null if it no longer ships.</param>
    /// <param name="execution">What became of it on this run, or null if it was never scheduled.</param>
    public RuleRowViewModel(
        string ruleId, RuleDefinition? definition, StoredRuleExecution? execution)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleId);

        Rule = ruleId;
        _definition = definition;
        _execution = execution;
    }

    /// <summary>The rule, such as <c>SEC-011</c>.</summary>
    public string Rule { get; }

    /// <summary>What it is called, or the identifier alone where this build does not know.</summary>
    public string Name => _definition?.Name ?? Rule;

    /// <summary>The family it belongs to, such as <c>Kerberos</c>.</summary>
    public string Category => Guidance?.Category ?? string.Empty;

    /// <summary>How serious a finding from it is, in the word an operator reads.</summary>
    /// <remarks>
    /// Empty rather than a guess where the definition is absent. A severity invented for a rule
    /// this build does not ship would be this screen stating something it does not know.
    /// </remarks>
    public string Severity => _definition is null ? string.Empty : _definition.Severity.ToString();

    /// <summary>What the rule looks for, and what it does not.</summary>
    /// <remarks>
    /// <b>This is the half of <c>P-118</c> the findings panel could not close.</b> Guidance shown
    /// beside a finding is unreachable for a rule that found nothing, which is most of them on a
    /// healthy forest - so the description of what was checked was visible only where something
    /// was wrong.
    /// </remarks>
    public string About => Guidance?.About
        ?? $"No description is recorded for {Rule} in this build.";

    private RuleGuidance? Guidance => RuleGuidanceCatalogue.For(Rule);

    /// <summary>How many findings it wrote on this run.</summary>
    public int Findings => _execution?.FindingsProduced ?? 0;

    /// <summary>How many objects it reached a verdict on.</summary>
    public int Judged => _execution?.ObjectsJudged ?? 0;

    /// <summary>How many objects it was offered and could not reach a verdict on.</summary>
    public int NotJudged => _execution?.ObjectsNotJudged ?? 0;

    /// <summary>
    /// What became of the rule, in a sentence rather than a number.
    /// </summary>
    /// <remarks>
    /// <b>The whole reason for this screen is that four of these read as an empty grid.</b> A rule
    /// that judged four thousand objects and found nothing, one that could not read what it needed,
    /// one that threw, and one that never ran all produce no findings. Only the first is a
    /// statement about the forest, and the wording keeps them apart in words rather than by
    /// leaving the operator to infer it from a zero.
    /// </remarks>
    public string Outcome => _execution is null
        ? "Not run. This rule was not part of this judging, so nothing here has been checked "
          + "against it."
        : _execution.Outcome switch
        {
            RuleExecutionOutcome.Succeeded when _execution.FindingsProduced > 0 =>
                $"Judged {_execution.ObjectsJudged:N0} objects and reported "
                + $"{_execution.FindingsProduced:N0}.",
            RuleExecutionOutcome.Succeeded =>
                $"Judged {_execution.ObjectsJudged:N0} objects and reported nothing.",
            RuleExecutionOutcome.Indeterminate =>
                $"Could not judge {_execution.ObjectsNotJudged:N0} of the objects it was offered, "
                + $"because {MissingNamed} was not captured. What it reports is a floor, not a "
                + "total.",
            RuleExecutionOutcome.Error =>
                "This rule failed while running, so nothing has been established either way. "
                + (_execution.Error ?? "No reason was recorded."),
            _ => "Scheduled and never executed, so nothing has been checked against it.",
        };

    /// <summary>
    /// What this run established by running the rule, as the mark beside the row.
    /// </summary>
    /// <remarks>
    /// <b>A rule that found something is not a fault.</b> It did its job; the forest is what is
    /// wrong, so it reads as established rather than as broken. <see cref="FactState.Fault"/> is
    /// reserved for the rule failing, which is a defect in the product.
    /// </remarks>
    public FactState State => _execution?.Outcome switch
    {
        RuleExecutionOutcome.Succeeded when _execution.FindingsProduced > 0 =>
            FactState.EstablishedBad,
        RuleExecutionOutcome.Succeeded => FactState.EstablishedGood,
        RuleExecutionOutcome.Error => FactState.Fault,
        _ => FactState.NotEstablished,
    };

    /// <summary>The attributes it could not read, or a phrase saying none was named.</summary>
    private string MissingNamed => _execution is { MissingInputs.Count: > 0 }
        ? string.Join(", ", _execution.MissingInputs.Select(m => m.Attribute).Distinct())
        : "an input it declared";
}
