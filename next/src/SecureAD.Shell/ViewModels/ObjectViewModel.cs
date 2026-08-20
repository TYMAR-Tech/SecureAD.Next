using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using SecureAD.Evidence;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Shell.ViewModels;

/// <summary>
/// One object opened from the listing: a header, and the sections its class has.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is a host, not a screen.</b> It holds an ordered list of sections and which one is being
/// read, and nothing else. The predecessor's equivalent is one 1,311-line window holding sixteen
/// sections and their logic together, which is why adding to it is expensive; here a section is a
/// type and a control, and the seventeenth costs what the first did.
/// </para>
/// <para>
/// <b>Which sections exist is decided by the object's class</b>, in
/// <see cref="ObjectSectionCatalog"/> and for the reasons recorded there. A section this build
/// cannot yet fill is present and says so, rather than being left out - an object missing a section
/// looks completely described when it is not.
/// </para>
/// <para>
/// <b>This is a reading tool and not a verdict.</b> The owner's framing, 2026-08-18: the findings
/// are the point of the product, and since the permissions were captured anyway it is a good
/// secondary use of the tool to help an administrator understand what is on an object.
/// </para>
/// </remarks>
internal sealed partial class ObjectViewModel : ObservableObject
{
    private readonly ObjectPermissions _permissions;

    /// <summary>The section being read.</summary>
    [ObservableProperty]
    private ObjectSectionViewModel? _selected;

    /// <summary>Creates the object view's state.</summary>
    /// <param name="permissions">What the bundle holds about the object.</param>
    /// <param name="attributes">
    /// The object's captured attribute values, or null when they could not be read. Null is not
    /// nothing: a section handed null says the values were not read, where a section handed an
    /// empty value says the bundle holds none - and only the second is about the object.
    /// </param>
    /// <param name="objectType">
    /// What kind of object it is, as the listing worded it. Carried across rather than re-read, so
    /// the row and the object opened from it cannot disagree.
    /// </param>
    /// <param name="objectClass">
    /// The class as the directory spells it, which decides the sections. Null when it did not
    /// arrive, which is not a reason to show nothing.
    /// </param>
    /// <param name="vocabulary">
    /// The words and verdicts to read permissions with, built over the schema this run captured.
    /// Stated rather than defaulted: which catalogue named a right is part of what the screen is
    /// claiming, and a default would let a caller show a forest's permissions under the shipped
    /// table's names without anyone deciding to.
    /// </param>
    public ObjectViewModel(
        ObjectPermissions permissions,
        ObjectAttributes? attributes,
        string objectType,
        string? objectClass,
        PermissionVocabulary vocabulary)
    {
        ArgumentNullException.ThrowIfNull(permissions);
        ArgumentException.ThrowIfNullOrWhiteSpace(objectType);
        ArgumentNullException.ThrowIfNull(vocabulary);

        _permissions = permissions;
        ObjectType = objectType;

        foreach (var definition in ObjectSectionCatalog.For(objectClass))
            Sections.Add(Build(definition, permissions, attributes, objectType, vocabulary));

        Selected = Sections.FirstOrDefault();
    }

    /// <summary>The object's name.</summary>
    public string Name => DnHelper.ExtractFirstRdn(_permissions.DistinguishedName);

    /// <summary>Its full name, for an operator who needs to be certain which object this is.</summary>
    public string DistinguishedName => _permissions.DistinguishedName;

    /// <summary>What kind of object it is.</summary>
    public string ObjectType { get; }

    /// <summary>The sections this object's class has, in reading order.</summary>
    public ObservableCollection<ObjectSectionViewModel> Sections { get; } = [];

    /// <summary>
    /// What this run established about the object as a whole.
    /// </summary>
    /// <remarks>
    /// Never <see cref="FactState.EstablishedBad"/>. Nothing in this product judges an object yet,
    /// and a mark an administrator reads as a security verdict, set by nothing, is the worst thing
    /// this screen could do (<c>docs/decisions/0045</c>).
    /// </remarks>
    public FactState State =>
        _permissions.Availability == DescriptorAvailability.Read
        && _permissions.DaclState != DaclState.Unreadable
        && _permissions.Errors.Count == 0
            ? FactState.EstablishedGood
            : FactState.NotEstablished;

    /// <summary>
    /// The section with this key, or null when the object's class does not have one.
    /// </summary>
    /// <param name="key">The section's stable name, from <see cref="ObjectSectionCatalog"/>.</param>
    public ObjectSectionViewModel? Section(string key) =>
        Sections.FirstOrDefault(s => s.Key == key);

    /// <summary>
    /// Builds the view model for one section, or a placeholder saying it is not built.
    /// </summary>
    /// <remarks>
    /// Overview and Account are types of their own because each says something beyond its values:
    /// the overview carries who owns the object, and the account section words a bitfield. The
    /// seven built from attributes alone share one type, because they are one behaviour and seven
    /// copies of it would drift.
    /// </remarks>
    private static ObjectSectionViewModel Build(
        ObjectSectionDefinition definition,
        ObjectPermissions permissions,
        ObjectAttributes? attributes,
        string objectType,
        PermissionVocabulary vocabulary) =>
        definition.Key switch
        {
            ObjectSectionCatalog.Overview =>
                new OverviewSectionViewModel(definition, permissions, attributes, objectType),
            ObjectSectionCatalog.Account =>
                new AccountSectionViewModel(definition, attributes),
            ObjectSectionCatalog.PolicyLinks =>
                new PolicyLinksSectionViewModel(definition, attributes),
            ObjectSectionCatalog.Membership
                or ObjectSectionCatalog.Delegation
                or ObjectSectionCatalog.Group
                or ObjectSectionCatalog.Laps
                or ObjectSectionCatalog.PasswordReaders
                or ObjectSectionCatalog.Policy =>
                new AttributeSectionViewModel(definition, attributes),
            ObjectSectionCatalog.Permissions =>
                new PermissionsSectionViewModel(definition, permissions, vocabulary),
            ObjectSectionCatalog.Evidence =>
                new EvidenceSectionViewModel(definition, permissions),
            ObjectSectionCatalog.OtherValues =>
                new OtherValuesSectionViewModel(definition),
            _ => new NotBuiltSectionViewModel(definition),
        };

    /// <summary>
    /// Keeps the section list's own selection in step, so a list can bind to it and a section can
    /// be chosen from anywhere.
    /// </summary>
    partial void OnSelectedChanged(
        ObjectSectionViewModel? oldValue, ObjectSectionViewModel? newValue)
    {
        if (oldValue is not null)
            oldValue.IsSelected = false;

        if (newValue is not null)
            newValue.IsSelected = true;
    }
}
