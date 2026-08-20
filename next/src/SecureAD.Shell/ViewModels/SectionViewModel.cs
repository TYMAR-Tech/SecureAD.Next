using CommunityToolkit.Mvvm.ComponentModel;

namespace SecureAD.Shell.ViewModels;

/// <summary>
/// One view within a section - the second row of tabs.
/// </summary>
/// <remarks>
/// <para>
/// <b>Two tiers rather than one row of everything.</b> The first row says where you are in the
/// product; this says which view of that thing you are looking at. They are different questions,
/// and the predecessor asked the second one in exactly this place: its Assets screen carried
/// <i>Findings, Escalation Paths, Groups, LAPS Status, Objects</i> across the top, all scoped by
/// the container selected in the tree.
/// </para>
/// <para>
/// <b><see cref="IsBuilt"/> is what keeps a tab from lying.</b> A view that is not built shows a
/// panel saying so. It must never render an empty list of findings, because an administrator reads
/// that as <i>my directory is clean</i> rather than as <i>nothing has looked</i>.
/// </para>
/// </remarks>
internal sealed partial class SectionView : ObservableObject
{
    private SectionView(string name, bool isBuilt, string? absent)
    {
        Name = name;
        IsBuilt = isBuilt;
        Absent = absent;
    }

    /// <summary>Whether this is the view showing.</summary>
    [ObservableProperty]
    private bool _isSelected;

    /// <summary>What the tab reads.</summary>
    public string Name { get; }

    /// <summary>Whether there is anything behind it yet.</summary>
    public bool IsBuilt { get; }

    /// <summary>
    /// What is missing, in terms the owner can act on, when <see cref="IsBuilt"/> is false. Null
    /// when the view is built.
    /// </summary>
    public string? Absent { get; }

    /// <summary>A view that works.</summary>
    /// <param name="name">What the tab reads.</param>
    public static SectionView Built(string name) => new(name, isBuilt: true, absent: null);

    /// <summary>A view that does not exist yet, and says so.</summary>
    /// <param name="name">What the tab reads.</param>
    /// <param name="absent">What is missing, and what it waits on.</param>
    public static SectionView NotBuilt(string name, string absent) =>
        new(name, isBuilt: false, absent);
}
