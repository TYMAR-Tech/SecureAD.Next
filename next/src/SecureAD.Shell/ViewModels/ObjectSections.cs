using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.GroupPolicy;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Shell.ViewModels;

/// <summary>
/// One section of the object view.
/// </summary>
/// <remarks>
/// <para>
/// <b>Sections are types rather than a tab index, so a view can pick a control by data template
/// and the object view never grows a switch.</b> The predecessor's object window is 1,311 lines of
/// XAML holding sixteen sections in one file, each shown and hidden by its own visibility binding.
/// That file is the reason a seventeenth section is expensive.
/// </para>
/// <para>
/// <b>Which sections exist is <see cref="ObjectSectionCatalog"/>'s question, not this type's.</b>
/// </para>
/// </remarks>
internal abstract partial class ObjectSectionViewModel : ObservableObject
{
    /// <summary>Whether this is the section being read.</summary>
    [ObservableProperty]
    private bool _isSelected;

    /// <summary>Creates a section.</summary>
    /// <param name="definition">What the catalogue says this section is.</param>
    protected ObjectSectionViewModel(ObjectSectionDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(definition);

        Key = definition.Key;
        Title = definition.Title;
    }

    /// <summary>The section's stable name.</summary>
    public string Key { get; }

    /// <summary>What it is called on screen.</summary>
    public string Title { get; }
}

/// <summary>
/// One attribute on screen: what it is called, what it says, and what the bundle actually stored.
/// </summary>
/// <remarks>
/// <para>
/// <b>The stored form is kept because the worded one can be wrong.</b> A mistaken reading of
/// <c>userAccountControl</c> renders as a confident <i>Disabled</i>, and an operator has no way to
/// doubt it unless the value it was derived from is within reach. The reveal on the row is what
/// makes this product checkable against <c>ldp.exe</c> rather than merely believable.
/// </para>
/// <para>
/// <b>An attribute with no value says nothing about the object.</b> Active Directory omits an
/// absent attribute without saying whether the caller was refused it
/// (<c>docs/decisions/0022</c>), so the row reads as <i>not in this bundle</i> - which is a fact
/// about the evidence - and never as <i>this object has none</i>, which nobody knows.
/// </para>
/// </remarks>
internal sealed class AttributeValueViewModel
{
    /// <summary>What a row with nothing in it says. Never a statement about the object.</summary>
    /// <remarks>
    /// <b>Short, because most rows on most objects say it.</b> An organizational unit has no
    /// account name, no user principal name and no security identifier, and a full sentence
    /// repeated six times down a card drowns the values that are there. It still says
    /// <i>bundle</i> rather than <i>object</i>: the absence is a fact about the evidence, and
    /// Active Directory omits an attribute it will not disclose exactly as it omits one that is
    /// not there.
    /// </remarks>
    public const string NothingStored = "Not in this bundle";

    /// <summary>What a row says when no attribute values were read for the object at all.</summary>
    public const string NothingRead = "Not read";

    /// <summary>What a row says in place of a security descriptor's bytes.</summary>
    /// <remarks>
    /// Two attributes on an object are descriptors in their own right - who may act for a computer,
    /// and who may retrieve a managed account's password - and both decide a takeover. They are
    /// captured, and reading them is a section of its own rather than a hexadecimal dump in a field
    /// row.
    /// </remarks>
    public const string DescriptorNotRead =
        "A security descriptor is stored here. This build does not word it.";

    /// <summary>
    /// The captured attributes whose value is a security descriptor rather than data.
    /// </summary>
    private static readonly string[] Descriptors =
    [
        "nTSecurityDescriptor",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        "msDS-GroupMSAMembership",
    ];

    private readonly ObjectAttribute? _attribute;
    private readonly bool _wasRead;
    private readonly DirectoryTimeWording? _time;
    private readonly GroupTypeWording? _group;

    /// <summary>Creates a row for one attribute.</summary>
    /// <param name="ldapDisplayName">The attribute, as the directory names it.</param>
    /// <param name="attribute">What the bundle holds for it, or null when it holds nothing.</param>
    /// <param name="wasRead">
    /// Whether the object's attribute values were read. False makes every row on the section say
    /// that, because a row reading <i>no value is in this bundle</i> after a failed read would be
    /// a statement about the evidence that nobody checked.
    /// </param>
    /// <param name="capturedUtc">
    /// When the run read the object, which is what an age is measured against.
    /// </param>
    public AttributeValueViewModel(
        string ldapDisplayName,
        ObjectAttribute? attribute,
        bool wasRead,
        DateTimeOffset capturedUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ldapDisplayName);

        Attribute = ldapDisplayName;
        Label = ObjectSectionCatalog.LabelFor(ldapDisplayName);
        _attribute = attribute;
        _wasRead = wasRead;
        _time = attribute is { HasValue: true }
            ? DirectoryTime.WordTimestamp(ldapDisplayName, attribute.Values[0].Stored, capturedUtc)
            : null;
        _group = attribute is { HasValue: true }
            && string.Equals(ldapDisplayName, "groupType", StringComparison.OrdinalIgnoreCase)
            ? GroupTypeWording.Of(attribute.Values[0].Stored)
            : null;
        IsDescriptor = Descriptors.Contains(ldapDisplayName, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Whether this attribute's value is a security descriptor.</summary>
    public bool IsDescriptor { get; }

    /// <summary>What the attribute is called on screen.</summary>
    public string Label { get; }

    /// <summary>The attribute's own name, for an operator checking this against the directory.</summary>
    public string Attribute { get; }

    /// <summary>Whether the bundle holds anything for this attribute.</summary>
    public bool HasValue => _attribute is { HasValue: true };

    /// <summary>
    /// The value in the most readable form this build can put it in, or why there is none.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The kernel wordings are asked in turn, and a value none of them claims is shown as it was
    /// stored.</b> Every one of them is reversible on screen: the stored form sits under the worded
    /// one whenever the two differ, which is what makes an answer here checkable rather than merely
    /// believable.
    /// </para>
    /// <para>
    /// A security descriptor is the one value that is not shown at all. It is hundreds of bytes,
    /// it means nothing as hexadecimal, and printing it would bury the rest of the section - so
    /// the row says what the value is and that this build does not read it here, which is a true
    /// statement rather than a wall of digits pretending to be one.
    /// </para>
    /// </remarks>
    public string Worded => _time is not null
        ? _time.Worded
        : _group is not null
            ? _group.Worded
            : IsDescriptor && HasValue
                ? DescriptorNotRead
                : _attribute is { HasValue: true }
                    ? string.Join(", ", _attribute.Values.Select(Readable))
                    : _wasRead ? NothingStored : NothingRead;

    /// <summary>
    /// What a reader must know before drawing a conclusion from this value. Null when there is
    /// nothing to add.
    /// </summary>
    /// <remarks>
    /// <c>lastLogonTimestamp</c> is designed to be days out of date, and a dormant-account
    /// judgement made without knowing that is wrong by up to a fortnight. Said on the row rather
    /// than in a manual nobody has open.
    /// </remarks>
    public string? Caveat => _time?.Caveat;

    /// <summary>Whether there is a caveat to read.</summary>
    public bool HasCaveat => Caveat is not null;

    /// <summary>The value exactly as the bundle stored it. Empty when there is none.</summary>
    /// <remarks>
    /// A security descriptor gives its size instead of its bytes. Several hundred bytes of
    /// hexadecimal tells a reader nothing they can check, and the size is the one thing about it
    /// that is legible - an unusually large one is an object with an unusually long access list.
    /// </remarks>
    public string Stored => _attribute is { HasValue: true }
        ? IsDescriptor
            ? $"{_attribute.Values.Sum(v => v.Bytes?.Length ?? 0):N0} bytes"
            : string.Join(", ", _attribute.Values.Select(v => v.Stored))
        : string.Empty;

    /// <summary>
    /// Whether the worded form differs from the stored one, and so whether there is anything for a
    /// reveal to reveal.
    /// </summary>
    public bool IsInterpreted => HasValue && Worded != Stored;

    /// <summary>
    /// A SID's bytes as a SID, and anything else as it was stored.
    /// </summary>
    /// <remarks>
    /// A SID is bytes on the wire and text everywhere a person deals with it - including in the
    /// permission list on the next section, which shows trustees as text. Leaving it as
    /// hexadecimal here would mean the same principal reads two ways on two sections of one screen.
    /// </remarks>
    private static string Readable(AttributeValue value) =>
        value.Bytes is { } bytes ? Sid.ToText(bytes) ?? value.Stored : value.Stored;
}

/// <summary>
/// Who the object is.
/// </summary>
/// <remarks>
/// <b>The first thing an operator reads, so it answers the identity questions and nothing else.</b>
/// Which object this is, what kind of thing it is, what it is called in the two spellings the rest
/// of the product uses, and who owns it - an owner being no entry at all and outranking every
/// entry, since they can rewrite the whole list.
/// </remarks>
internal sealed class OverviewSectionViewModel : ObjectSectionViewModel
{
    private readonly ObjectPermissions _permissions;

    /// <summary>Creates the overview.</summary>
    /// <param name="definition">What the catalogue says this section is.</param>
    /// <param name="permissions">What the bundle holds about the object.</param>
    /// <param name="attributes">The object's attribute values, or null when none were read.</param>
    /// <param name="objectType">The class, as the listing worded it.</param>
    public OverviewSectionViewModel(
        ObjectSectionDefinition definition,
        ObjectPermissions permissions,
        ObjectAttributes? attributes,
        string objectType)
        : base(definition)
    {
        ArgumentNullException.ThrowIfNull(definition);
        ArgumentNullException.ThrowIfNull(permissions);

        _permissions = permissions;
        ObjectType = objectType;
        Values = definition.Rows(attributes);
    }

    /// <summary>What kind of object it is.</summary>
    public string ObjectType { get; }

    /// <summary>Its full name.</summary>
    public string DistinguishedName => _permissions.DistinguishedName;

    /// <summary>
    /// Who owns the object - not an entry, and outranking every entry: an owner can rewrite the
    /// whole list.
    /// </summary>
    public string Owner => _permissions.Owner is { } owner
        ? owner.Name ?? owner.Sid
        : "not recorded";

    /// <summary>
    /// What qualifies the owner's ordinary control, or null when nothing does.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Without this the name alone said the wrong thing.</b> The card named the owner and
    /// stopped, so an object deliberately hardened with an <c>OWNER RIGHTS</c> entry read exactly
    /// like one that was not - and the product's Modify Owner wording separately told the reader
    /// that an owner can rewrite permissions. An administrator who had done the right thing was
    /// shown no sign of it.
    /// </para>
    /// <para>
    /// <b>It states a fact and withholds the conclusion.</b> Microsoft documents that Read
    /// Permissions and Modify Permissions are suppressed and says nothing about Modify Owner, so
    /// this reports that the entry is present rather than that the owner is powerless. Whether the
    /// product should judge ownership is still an open question, recorded as <c>P-70</c> in
    /// <c>docs/PUNCH-LIST.md</c>, and this does not settle it.
    /// </para>
    /// </remarks>
    public string? OwnerQualification => _permissions.OwnerRightsEntryIsPresent
        ? "An OWNER RIGHTS entry on this object removes the owner's implicit Read Permissions "
          + "and Modify Permissions."
        : null;

    /// <summary>
    /// Whether <see cref="OwnerQualification"/> has anything to say.
    /// </summary>
    /// <remarks>
    /// A separate boolean because that is how every other conditional row in this product decides
    /// whether to appear - <c>Visibility="{Binding Has…, Converter={StaticResource Shown}}"</c>.
    /// The first attempt used a style trigger comparing the string against <c>x:Null</c>, which is
    /// a second way of asking one question, and the row did not appear in the lab. Copying the
    /// established pattern is the fix and the lesson.
    /// </remarks>
    public bool HasOwnerQualification => OwnerQualification is not null;

    /// <summary>How many entries the object's permission list holds.</summary>
    public int EntryCount => _permissions.Entries.Count;

    /// <summary>The identity attributes this section is responsible for.</summary>
    public IReadOnlyList<AttributeValueViewModel> Values { get; }
}

/// <summary>
/// What kind of account this is and what state it is in.
/// </summary>
/// <remarks>
/// <para>
/// <b>This section exists for one attribute.</b> <c>userAccountControl</c> is a bitfield that
/// decides whether an account can log on at all, whether its password ever expires, whether it can
/// be attacked without pre-authentication, and whether a service running as it can impersonate
/// anyone who calls. An operator reading <c>66048</c> learns nothing;
/// <see cref="SecureAD.Kernel.Security.UserAccountControlWording"/> is where it becomes sentences,
/// and it is the only place in this product that turns one of these bits into a word.
/// </para>
/// <para>
/// <b>The number stays on screen beside the sentences.</b> A wrong bit is invisible - it renders as
/// a confident statement about an account - so the value it was read from is always within reach,
/// and <see cref="UnwordedBits"/> says when a bit was set that this build had no word for rather
/// than letting the list look complete.
/// </para>
/// </remarks>
internal sealed class AccountSectionViewModel : ObjectSectionViewModel
{
    private readonly UserAccountControlWording? _control;
    private readonly AttributeValueViewModel _stored;
    private readonly bool _wasRead;

    /// <summary>Creates the account section.</summary>
    /// <param name="definition">What the catalogue says this section is.</param>
    /// <param name="attributes">The object's attribute values, or null when none were read.</param>
    public AccountSectionViewModel(
        ObjectSectionDefinition definition, ObjectAttributes? attributes)
        : base(definition)
    {
        ArgumentNullException.ThrowIfNull(definition);

        _wasRead = attributes is not null;
        Values = definition.Rows(attributes);
        _stored = Values.FirstOrDefault(v =>
            string.Equals(v.Attribute, "userAccountControl", StringComparison.OrdinalIgnoreCase))
            ?? new AttributeValueViewModel(
                "userAccountControl", null, _wasRead, DateTimeOffset.MinValue);
        _control = _stored.HasValue ? UserAccountControlWording.Of(_stored.Stored) : null;
    }

    /// <summary>Every attribute this section is responsible for, worded and stored.</summary>
    public IReadOnlyList<AttributeValueViewModel> Values { get; }

    /// <summary>What the account's state flags say, one sentence each.</summary>
    public IReadOnlyList<string> Flags =>
        _control is null ? [] : [.. _control.Flags.Select(f => f.Wording)];

    /// <summary>Whether there are flags to read.</summary>
    public bool HasFlags => Flags.Count > 0;

    /// <summary>
    /// Why there are no flags to read, or null when there are some.
    /// </summary>
    /// <remarks>
    /// Four silences and only one of them is a fact about the account: the values were never read,
    /// the attribute was not in the bundle, the value was not a number this build can read, or the
    /// account genuinely sets nothing. An empty list would render all four the same way.
    /// </remarks>
    public Notice? Emptiness => (HasFlags, _wasRead, _stored.HasValue, _control) switch
    {
        (true, _, _, _) => null,
        (_, false, _, _) => new Notice(
            "The account state was not read",
            "This object's attribute values were not read, so nothing here is known either way."),
        (_, _, false, _) => new Notice(
            "The account state was not captured",
            "userAccountControl is not in this bundle for this object. That means the object had "
            + "no value or this run was refused it - the directory does not tell the two apart."),
        (_, _, _, null) => new Notice(
            "The account state could not be read",
            $"userAccountControl was captured as '{_stored.Stored}', which is not a value this "
            + "build can read. It is shown as stored rather than worded into something it may "
            + "not mean."),
        _ => new Notice(
            "This account sets no state flags",
            "userAccountControl was captured and is zero. Nothing is disabled, expired or "
            + "delegated by it."),
    };

    /// <summary>Whether there is a silence to explain.</summary>
    public bool HasEmptiness => Emptiness is not null;

    /// <summary>
    /// The bits that were set and that this build has no word for, or null when there were none.
    /// </summary>
    public string? UnwordedBits => _control is null || _control.FlagsAreComplete
        ? null
        : $"0x{_control.UnwordedBits:X8}";

    /// <summary>Whether some bit was set that this build could not word.</summary>
    public bool HasUnwordedBits => UnwordedBits is not null;
}

/// <summary>
/// Who can do what to the object.
/// </summary>
/// <remarks>
/// <b>Nothing renders as an empty table.</b> A null list grants everyone everything, an empty one
/// grants nobody anything, an unreadable one is unknown, and a run that never asked is a fourth
/// thing. All four produce no entries and one of them is the most open object in the forest.
/// <see cref="Emptiness"/> is where they are told apart.
/// </remarks>
internal sealed partial class PermissionsSectionViewModel : ObjectSectionViewModel
{
    private readonly ObjectPermissions _permissions;
    private readonly PermissionVocabulary _vocabulary;

    /// <summary>
    /// The principal whose entries are showing.
    /// </summary>
    /// <remarks>
    /// <b>Never null while there is a principal to select.</b> Arriving with nothing selected shows
    /// an empty entry table beside a full list of principals, which reads as though the first
    /// principal holds nothing.
    /// </remarks>
    [ObservableProperty]
    private PrincipalGroupViewModel? _selectedPrincipal;

    /// <summary>
    /// Whether the operator has asked the classifier for its opinion of these permissions.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Off by default, and that is the whole point of it.</b> A colour an administrator reads as
    /// a security verdict, set by nothing, is the worst thing this screen can do. Until this is
    /// turned on nothing on the screen is a judgement, and the counters that would need one say so
    /// rather than showing a number.
    /// </para>
    /// <para>
    /// <b>It marks and it never filters.</b> A list narrowed to the marked entries lets a reader
    /// conclude the marked few are all there is, and the entries this build cannot classify would
    /// be the ones it hid. Every entry stays on screen and some of them gain a mark.
    /// </para>
    /// <para>
    /// <b>The label admits it is an opinion.</b> The owner is not certain the predecessor was right
    /// to classify at all, so this is offered as a view and not as a result.
    /// </para>
    /// </remarks>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Counters))]
    private bool _highlightRiskyPermissions;

    /// <summary>Creates the permissions section.</summary>
    /// <param name="definition">What the catalogue says this section is.</param>
    /// <param name="permissions">What the bundle holds about the object.</param>
    /// <param name="vocabulary">
    /// The words and verdicts to read the entries with, built over the schema this run captured.
    /// </param>
    public PermissionsSectionViewModel(
        ObjectSectionDefinition definition,
        ObjectPermissions permissions,
        PermissionVocabulary vocabulary)
        : base(definition)
    {
        ArgumentNullException.ThrowIfNull(permissions);
        ArgumentNullException.ThrowIfNull(vocabulary);

        _permissions = permissions;
        _vocabulary = vocabulary;

        foreach (var group in permissions.Entries
                     .GroupBy(e => e.Trustee.Sid, StringComparer.Ordinal)
                     .Select(g => new PrincipalGroupViewModel(g.First().Trustee, [.. g], vocabulary)))
        {
            Principals.Add(group);
        }

        SelectedPrincipal = Principals.FirstOrDefault();
    }

    /// <summary>Each principal named by the list, and that principal's entries.</summary>
    /// <remarks>
    /// Grouped by principal because that is the question being asked: who can do what to this
    /// object. Not re-sorted by name - canonical order puts denials first, and a principal denied
    /// something is the first thing worth seeing.
    /// </remarks>
    public ObservableCollection<PrincipalGroupViewModel> Principals { get; } = [];

    /// <summary>Whether there is a principal list to read at all.</summary>
    public bool HasPrincipals => Principals.Count > 0;

    /// <summary>What went wrong reading the descriptor. Empty when nothing did.</summary>
    public IReadOnlyList<string> Errors => _permissions.Errors;

    /// <summary>Whether anything went wrong reading the descriptor.</summary>
    public bool HasErrors => _permissions.Errors.Count > 0;

    /// <summary>Why there are no entries, when there are none. Null while there are.</summary>
    public Notice? Emptiness => Emptied();

    /// <summary>Whether the permissions are showing as a silence rather than a table.</summary>
    public bool IsEmpty => Emptiness is not null;

    /// <summary>
    /// What is true of the list as a whole and would otherwise go unsaid: that it refuses
    /// inheritance, that it was truncated, that the directory holds it in another order. Every one
    /// is a reason the list reads shorter or safer than the object is.
    /// </summary>
    public IReadOnlyList<Notice> Statements => Stated();

    /// <summary>Whether there is anything to state about the list as a whole.</summary>
    public bool HasStatements => Statements.Count > 0;

    /// <summary>
    /// The strip of counts above the two panes, each either computed or explicitly not.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Nothing here renders a zero where nothing has looked.</b> This is the failure
    /// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> exists to prevent: a
    /// <i>Dangerous 0</i> on an object nobody classified is indistinguishable from a clean one, and
    /// it is the more reassuring of the two readings that an operator will take. A counter with
    /// nothing behind it carries <see cref="PermissionCounter.NotComputed"/> and says why.
    /// </para>
    /// <para>
    /// <b>Two of these can never be computed by this build, and they are shown anyway.</b>
    /// <i>Control</i> counted the predecessor's escalation control edges and <i>Findings</i> counted
    /// rule results; the derivation and rule layers are both unbuilt. Leaving them off the strip
    /// would make the object look fully assessed, which is the same lie in the other direction.
    /// </para>
    /// </remarks>
    public IReadOnlyList<PermissionCounter> Counters => Counted();

    private List<PermissionCounter> Counted()
    {
        var entryCount = _permissions.Entries.Count;

        var counters = new List<PermissionCounter>
        {
            PermissionCounter.Computed(
                "Entries",
                entryCount,
                "How many access control entries this run read on the object."),
        };

        if (HighlightRiskyPermissions)
        {
            counters.Add(PermissionCounter.Computed(
                "Dangerous",
                Principals.Sum(p => p.DangerousCount),
                "Entries that hand somebody control of this object, or of the account, policy or "
                + "credential the right they name controls."));

            counters.Add(PermissionCounter.Computed(
                "In combination",
                Principals.Sum(p => p.DangerousInCombinationCount),
                "Entries that are not a takeover on their own and become one in the presence of "
                + "something this object cannot show: either other rights the same principal "
                + "holds, or which container the entry is written on. Creating objects of one "
                + "class is an ordinary delegation on a departmental container and domain "
                + "controller injection on the Domain Controllers OU. Both questions are asked "
                + "of a principal or a container rather than of an entry, and nothing in this "
                + "build asks them yet."));
        }
        else
        {
            counters.Add(PermissionCounter.NotComputed(
                "Dangerous",
                "Nothing has classified these permissions. Turn on Highlight risky permissions to "
                + "ask."));

            counters.Add(PermissionCounter.NotComputed(
                "In combination",
                "Nothing has classified these permissions. Turn on Highlight risky permissions to "
                + "ask."));
        }

        counters.Add(PermissionCounter.NotComputed(
            "Control",
            "A control edge is a route from one principal to another, derived across the whole "
            + "forest rather than read off this object. Nothing in this build derives them."));

        counters.Add(PermissionCounter.NotComputed(
            "Findings",
            "A finding is a rule's verdict. No rule has been run against this bundle, so this is "
            + "not zero findings - it is no answer."));

        return counters;
    }

    /// <summary>
    /// Shows or hides the classifier's opinion on every entry of every principal.
    /// </summary>
    /// <remarks>
    /// The classification itself is not recomputed: each entry was classified when it was read, so
    /// the toggle changes what is shown and never what is true.
    /// </remarks>
    partial void OnHighlightRiskyPermissionsChanged(bool value)
    {
        foreach (var principal in Principals)
            principal.SetClassified(value);
    }

    private Notice? Emptied()
    {
        if (_permissions.Entries.Count > 0)
            return null;

        return _permissions.Availability switch
        {
            DescriptorAvailability.NotAttempted => new Notice(
                "The permissions on this object were not read",
                "This run recorded no permissions for this object and no failure to read them. "
                + "Nothing is known about what it grants."),

            DescriptorAvailability.Unreadable => new Notice(
                "The permissions on this object could not be read",
                _permissions.UnreadableReason
                + " What this object grants is unknown, which is not the same as its granting "
                + "nothing."),

            _ => _permissions.DaclState switch
            {
                DaclState.Null => new Notice(
                    "This object has no permission list at all",
                    "A null permission list grants everyone full control of this object. It is "
                    + "not an empty list, and it is the opposite of one."),

                DaclState.Empty => new Notice(
                    "This object's permission list is empty",
                    "An empty list grants nobody anything. Only the object's owner can reach it."),

                DaclState.Unreadable => new Notice(
                    "This object's permission list could not be read",
                    "The list declared entries and none of them could be read, so what this "
                    + "object grants is unknown."),

                _ => new Notice(
                    "This object's permission list holds no entries",
                    "The list was read and it names nobody."),
            },
        };
    }

    private List<Notice> Stated()
    {
        var statements = new List<Notice>();

        if (_permissions.IsDaclProtected)
        {
            statements.Add(new Notice(
                "This object refuses inheritance",
                "Permissions set on the containers above this object do not reach it. That is why "
                + "this list may be shorter than the ones around it."));
        }

        if (!_permissions.DaclWasCanonical)
        {
            statements.Add(new Notice(
                "The directory holds these entries in a different order",
                "The directory works through the whole list and will not deny a right it has "
                + "already granted earlier in the list. These are shown in the standard order, so "
                + "a denial listed here may be one the directory never applies."));
        }

        if (_permissions.DaclCompleteness != DaclCompleteness.Complete)
        {
            statements.Add(new Notice(
                "This list is not everything",
                "The permission list declared more entries than could be read, so this object "
                + "grants at least what is shown here and possibly more."));
        }

        return statements;
    }
}

/// <summary>
/// How this run came by the object, and what it could not read.
/// </summary>
internal sealed class EvidenceSectionViewModel : ObjectSectionViewModel
{
    private readonly ObjectPermissions _permissions;

    /// <summary>Creates the evidence section.</summary>
    /// <param name="definition">What the catalogue says this section is.</param>
    /// <param name="permissions">What the bundle holds about the object.</param>
    public EvidenceSectionViewModel(
        ObjectSectionDefinition definition, ObjectPermissions permissions)
        : base(definition)
    {
        ArgumentNullException.ThrowIfNull(permissions);

        _permissions = permissions;
    }

    /// <summary>Whether this run holds the object's security descriptor at all, in words.</summary>
    public string DescriptorState => _permissions.Availability switch
    {
        DescriptorAvailability.Read => "The security descriptor was read.",
        DescriptorAvailability.Unreadable =>
            "The object has a security descriptor and this run could not read it. "
            + _permissions.UnreadableReason,
        _ => "No security descriptor was read for this object, and no failure to read one was "
             + "recorded.",
    };
}

/// <summary>
/// What the rules concluded about this object.
/// </summary>
/// <remarks>
/// <para>
/// <b>Four silences are kept apart here, and only one of them is about the object.</b> A bundle
/// nobody judged, a judgement that would not open, a judging where the rules ran and found nothing
/// about this object, and findings that exist — an empty list renders identically for the first
/// three, and only the third is a statement an operator may act on. <c>docs/decisions/0002</c> is
/// the rule; <see cref="Verdict"/> is where it is obeyed.
/// </para>
/// <para>
/// <b>The section is never hidden.</b> Unlike the LAPS section on a user, which is absent because a
/// user is not a thing LAPS applies to, absence here would say <i>nothing was found</i> about an
/// object nobody had looked at.
/// </para>
/// </remarks>
internal sealed class FindingsSectionViewModel : ObjectSectionViewModel
{
    /// <summary>What the section says when the rules ran and this object was not among what they found.</summary>
    public const string NothingFound =
        "The rules ran over this object and none of them found anything.";

    /// <summary>What the section says when nobody has judged the bundle.</summary>
    /// <remarks>
    /// <b>Not <i>nothing was found</i>.</b> Nothing has looked, which is a fact about the run and
    /// not about the object, and the remedy is to judge the bundle rather than to relax.
    /// </remarks>
    public const string NobodyLooked =
        "No rule has been run over this bundle, so nothing is known about this object. What is "
        + "shown here is silence rather than a clean result.";

    /// <summary>
    /// Creates the findings section.
    /// </summary>
    /// <param name="definition">What the catalogue says this section is.</param>
    /// <param name="findings">
    /// What was found about this object, or null when the judgement could not be read at all.
    /// </param>
    /// <param name="refusal">
    /// Why the judgement could not be read, or null when it was. Carried in the layer below's own
    /// words rather than reworded, because a second account of one failure drifts from the first.
    /// </param>
    public FindingsSectionViewModel(
        ObjectSectionDefinition definition,
        FindingsPage? findings,
        string? refusal)
        : base(definition)
    {
        Refusal = refusal;

        Findings = findings is null
            ? []
            : [.. findings.Findings.Select(f => new FindingRowViewModel(f))];

        NobodyHasLooked = findings?.DidNotRun ?? false;
    }

    /// <summary>What the rules found about this object.</summary>
    public IReadOnlyList<FindingRowViewModel> Findings { get; }

    /// <summary>Why the judgement could not be read, or null when it was.</summary>
    public string? Refusal { get; }

    /// <summary>Whether no rule has been run over the bundle this object came from.</summary>
    public bool NobodyHasLooked { get; }

    /// <summary>Whether there is anything to list.</summary>
    public bool HasFindings => Findings.Count > 0;

    /// <summary>
    /// What the section says in place of a list, or null when there is a list to show.
    /// </summary>
    /// <remarks>
    /// <b>One property, so a view cannot show two of these at once</b> and cannot forget one. The
    /// order is deliberate: a refusal outranks silence, because a judgement that would not open
    /// tells you nothing about whether anybody judged it.
    /// </remarks>
    public string? Verdict
    {
        get
        {
            if (Refusal is { } refused)
                return refused;

            if (NobodyHasLooked)
                return NobodyLooked;

            return HasFindings ? null : NothingFound;
        }
    }

    /// <summary>Whether the section is saying something in place of a list.</summary>
    public bool HasVerdict => Verdict is not null;
}

/// <summary>
/// Values this object carries that no section for its class claims.
/// </summary>
/// <remarks>
/// <b>The safety valve on a class-driven section list.</b> Capture asks every object for every
/// attribute whatever its class, so an object can hold a value its class does not justify. Without
/// somewhere for those to land, curation would silently drop a value the bundle holds - and a value
/// this product captured and cannot show is worse than one it never captured, because the customer
/// paid for it and nobody can prove it exists. Shown only when there are some, so it never appears
/// as an empty section on the wrong class.
/// </remarks>
internal sealed class OtherValuesSectionViewModel : ObjectSectionViewModel
{
    /// <summary>Creates the overflow section.</summary>
    /// <param name="definition">What the catalogue says this section is.</param>
    public OtherValuesSectionViewModel(ObjectSectionDefinition definition)
        : base(definition)
    {
    }
}

/// <summary>
/// A section that is its attributes: every value the catalogue says this section is answerable for,
/// and a plain statement when the bundle holds none of them.
/// </summary>
/// <remarks>
/// <para>
/// <b>Seven sections share this because they are the same shape.</b> Membership, Delegation, Group,
/// LAPS, Password readers, Linked policies and Policy each show the attributes their section
/// claims and nothing else. Giving each its own type would be seven copies of one behaviour, and
/// the seventh copy is where the emptiness handling stops matching the other six.
/// </para>
/// <para>
/// <b>A section with nothing in it still appears.</b> Which sections exist is decided by the
/// object's class and never by whether a value arrived - hiding an empty Delegation section would
/// hide <i>we were refused this</i> behind <i>there is nothing here</i>, and Active Directory does
/// not let a reader tell those apart. <see cref="Emptiness"/> is where the section says which of
/// the two it cannot distinguish.
/// </para>
/// </remarks>
internal sealed class AttributeSectionViewModel : ObjectSectionViewModel
{
    private readonly bool _wasRead;

    /// <summary>Creates a section built from attribute values.</summary>
    /// <param name="definition">What the catalogue says this section is.</param>
    /// <param name="attributes">The object's attribute values, or null when none were read.</param>
    public AttributeSectionViewModel(
        ObjectSectionDefinition definition, ObjectAttributes? attributes)
        : base(definition)
    {
        ArgumentNullException.ThrowIfNull(definition);

        _wasRead = attributes is not null;
        Values = definition.Rows(attributes);
    }

    /// <summary>Every attribute this section is responsible for, worded and stored.</summary>
    public IReadOnlyList<AttributeValueViewModel> Values { get; }

    /// <summary>Whether the bundle holds a value for anything this section shows.</summary>
    public bool HasAnyValue => Values.Any(v => v.HasValue);

    /// <summary>
    /// Why the section shows nothing, or null when it shows something.
    /// </summary>
    /// <remarks>
    /// The wording is careful: <i>this bundle holds no value</i>, never <i>this object has none</i>.
    /// The directory omits an attribute it will not disclose exactly as it omits one that is not
    /// there, so the second sentence would be a claim nobody can support (<c>docs/decisions/0022</c>).
    /// </remarks>
    public Notice? Emptiness => (HasAnyValue, _wasRead) switch
    {
        (true, _) => null,
        (_, false) => new Notice(
            "These values were not read",
            "This object's attribute values were not read, so nothing here is known either way."),
        _ => new Notice(
            "This bundle holds none of these values",
            "Every attribute this section shows is absent from the bundle for this object. That "
            + "means the object had no value or this run was refused it - the directory does not "
            + "tell the two apart."),
    };

    /// <summary>Whether there is a silence to explain.</summary>
    public bool HasEmptiness => Emptiness is not null;
}

/// <summary>
/// The policies linked to a container, in the order they take effect.
/// </summary>
/// <remarks>
/// <b>A section of its own because the value is a list pretending to be a string.</b> A container's
/// <c>gPLink</c> holds every link concatenated into one line, so the generic field row shows it as
/// a single unreadable value however wide the window is. More importantly the order it is stored in
/// is the reverse of the order it takes effect in, and a reader left to assume otherwise gets the
/// answer backwards on exactly the containers where two policies disagree.
/// </remarks>
internal sealed class PolicyLinksSectionViewModel : ObjectSectionViewModel
{
    private readonly bool _wasRead;

    /// <summary>Creates the linked policies section.</summary>
    /// <param name="definition">What the catalogue says this section is.</param>
    /// <param name="attributes">The object's attribute values, or null when none were read.</param>
    public PolicyLinksSectionViewModel(
        ObjectSectionDefinition definition, ObjectAttributes? attributes)
        : base(definition)
    {
        ArgumentNullException.ThrowIfNull(definition);

        _wasRead = attributes is not null;
        Values = definition.Rows(attributes);

        var stored = attributes?.Find("gPLink")?.OnlyValue?.Stored;
        var parsed = PolicyLinkList.Of(stored);

        Links = [.. parsed.Links.OrderBy(l => l.Precedence)];
        Errors = parsed.Errors;
    }

    /// <summary>The attributes this section is responsible for, worded and stored.</summary>
    public IReadOnlyList<AttributeValueViewModel> Values { get; }

    /// <summary>
    /// The linked policies, strongest first.
    /// </summary>
    /// <remarks>
    /// Sorted by precedence rather than shown in stored order, because precedence is the question
    /// being asked. The stored order is on each row, so an operator comparing this against the
    /// attribute itself can still follow it.
    /// </remarks>
    public IReadOnlyList<PolicyLink> Links { get; }

    /// <summary>Whether there are links to read.</summary>
    public bool HasLinks => Links.Count > 0;

    /// <summary>What could not be read out of the value. Empty when nothing failed.</summary>
    public IReadOnlyList<string> Errors { get; }

    /// <summary>Whether anything failed to read.</summary>
    public bool HasErrors => Errors.Count > 0;

    /// <summary>
    /// Why there are no links, or null when there are some.
    /// </summary>
    /// <remarks>
    /// A container with no policies linked to it is an ordinary container and not a fault, so this
    /// says that plainly - but it says it about the bundle, since an attribute the run was refused
    /// arrives the same way as one that was never set.
    /// </remarks>
    public Notice? Emptiness => (HasLinks, _wasRead, HasErrors) switch
    {
        (true, _, _) => null,
        (_, false, _) => new Notice(
            "These values were not read",
            "This object's attribute values were not read, so nothing here is known either way."),
        (_, _, true) => new Notice(
            "The links could not be read",
            "This container names policies in a form this build does not understand. The value is "
            + "shown as stored, and nothing is claimed about which policies apply."),
        _ => new Notice(
            "No policies are linked here",
            "This bundle holds no gPLink for this object. That means no policy is linked to this "
            + "container or this run was refused the value - the directory does not tell the two "
            + "apart. Policies linked further up still apply to what is inside it."),
    };

    /// <summary>Whether there is a silence to explain.</summary>
    public bool HasEmptiness => Emptiness is not null;
}

/// <summary>
/// A section this product intends to show and cannot yet.
/// </summary>
/// <remarks>
/// <b>Present and honest rather than absent.</b> Leaving an unbuilt section out of the list would
/// make an object look completely described when it is not, and the operator would have no way to
/// tell a class that has no delegation from a build that cannot read it. This says which it is. It
/// is the same choice <c>NotBuiltView</c> already makes for a whole screen.
/// </remarks>
internal sealed class NotBuiltSectionViewModel : ObjectSectionViewModel
{
    /// <summary>Creates a placeholder for a section that is not built.</summary>
    /// <param name="definition">What the catalogue says this section is.</param>
    public NotBuiltSectionViewModel(ObjectSectionDefinition definition)
        : base(definition)
    {
        Detail =
            $"This build does not yet read what the {definition.Title} section shows. Nothing is "
            + "claimed about this object either way.";
    }

    /// <summary>What is not built, said plainly.</summary>
    public string Detail { get; }
}

/// <summary>
/// One principal named by an object's permission list, and everything that list says about them.
/// </summary>
/// <remarks>
/// <b>The header is what a collapsed group has to be readable from.</b> Groups arrive collapsed, so
/// the principal, where they come from, roughly what they hold and how many entries say so all have
/// to be on the one line an operator is scanning.
/// </remarks>
internal sealed class PrincipalGroupViewModel
{
    private readonly PermissionTrustee _trustee;

    /// <summary>Creates a screen's view of one principal's permissions.</summary>
    /// <param name="trustee">The principal.</param>
    /// <param name="entries">Their entries, in the list's canonical order.</param>
    /// <param name="vocabulary">The words and verdicts to read the entries with.</param>
    public PrincipalGroupViewModel(
        PermissionTrustee trustee,
        IReadOnlyList<PermissionEntry> entries,
        PermissionVocabulary vocabulary)
    {
        ArgumentNullException.ThrowIfNull(trustee);
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(vocabulary);

        _trustee = trustee;
        Entries = [.. entries.Select(e => new PermissionEntryViewModel(e, vocabulary))];
    }

    /// <summary>
    /// The principal's name, or their identifier when this run captured no object holding it.
    /// </summary>
    /// <remarks>
    /// The predecessor's screen showed a bare <c>S-1-5-21-…-25601</c> holding Full Control with no
    /// explanation; it was an orphaned identifier. It is shown, and <see cref="Unresolved"/> says
    /// why it has no name.
    /// </remarks>
    public string Principal => _trustee.Name ?? _trustee.Sid;

    /// <summary>Where the principal was captured from, or empty when nothing captured them.</summary>
    public string Domain => _trustee.DomainFqdn ?? string.Empty;

    /// <summary>Why this principal has no name, in words. Null when they have one.</summary>
    public string? Unresolved => _trustee.UnresolvedReason switch
    {
        UnresolvedReferenceReason.DomainNotCaptured =>
            "This identifier belongs to a domain this run did not capture.",
        UnresolvedReferenceReason.AnotherForest =>
            "This identifier belongs to another forest, reached across a trust.",
        UnresolvedReferenceReason.OrphanedIdentifier =>
            "This identifier names something that no longer exists.",
        UnresolvedReferenceReason.Unreadable =>
            "This identifier is in a captured partition that could not be read.",
        _ => _trustee.Name is null && _trustee.DistinguishedName is null
            ? "Nothing this run captured holds this identifier."
            : null,
    };

    /// <summary>Whether there is something to say about why the principal has no name.</summary>
    public bool IsUnresolved => Unresolved is not null;

    /// <summary>The principal's entries, in the list's canonical order.</summary>
    public IReadOnlyList<PermissionEntryViewModel> Entries { get; }

    /// <summary>How many entries name this principal.</summary>
    public string EntryCount => Entries.Count == 1 ? "1 entry" : $"{Entries.Count} entries";

    /// <summary>
    /// Roughly what this principal holds, for the one line a collapsed group shows.
    /// </summary>
    /// <remarks>
    /// <b>It says when it is a summary.</b> Naming three of eleven rights and stopping would let a
    /// reader conclude those three are all there is, so what is left out is counted.
    /// </remarks>
    public string RightsSummary
    {
        get
        {
            var rights = Entries
                .SelectMany(e => e.Rights)
                .Select(r => r.Name)
                .Distinct(StringComparer.Ordinal)
                .ToList();

            if (rights.Contains("Full control", StringComparer.Ordinal))
                return "Full control";

            if (rights.Count == 0)
                return "No rights";

            return rights.Count <= 3
                ? string.Join(", ", rights)
                : string.Join(", ", rights.Take(3)) + $", and {rights.Count - 3} more";
        }
    }

    /// <summary>Whether any of this principal's entries is a denial.</summary>
    public bool HasDenials => Entries.Any(e => e.IsDenial);

    /// <summary>
    /// How many of this principal's entries the classifier calls a takeover on its own.
    /// </summary>
    /// <remarks>
    /// The classifier's answer, not the screen's. It is the same number whether or not the operator
    /// has asked to see marks; whether it is <i>shown</i> is the section's business.
    /// </remarks>
    public int DangerousCount => Entries.Count(e => e.Risk == PermissionRisk.Dangerous);

    /// <summary>
    /// How many of this principal's entries are a takeover only alongside evidence the entry does
    /// not carry - other rights the principal holds, or the container the entry sits on.
    /// </summary>
    public int DangerousInCombinationCount =>
        Entries.Count(e => e.Risk == PermissionRisk.DangerousInCombination);

    /// <summary>
    /// Shows or hides the classifier's opinion on every one of this principal's entries.
    /// </summary>
    /// <param name="isClassified">Whether the operator has asked for it.</param>
    /// <remarks>
    /// <b>Pushed down rather than pulled up.</b> One toggle governs the whole object, and a row
    /// that reached up the visual tree for it could not be tested without a window.
    /// </remarks>
    public void SetClassified(bool isClassified)
    {
        foreach (var entry in Entries)
            entry.IsClassified = isClassified;
    }
}

/// <summary>
/// One figure on the strip above the permission list, or an explicit statement that there is no
/// figure.
/// </summary>
/// <remarks>
/// <para>
/// <b>A counter carries whether it was computed, because a number cannot.</b> Printing <c>0</c> for
/// something nobody measured is the defect
/// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> exists to prevent, and it is a
/// dangerous one here specifically: of the two ways to read a zero, the wrong one is the reassuring
/// one, and an auditor who reads <i>Dangerous 0</i> off an unclassified object stops looking.
/// </para>
/// <para>
/// <b>The explanation is not a tooltip nicety.</b> When a counter is not computed the explanation is
/// the entire content of the counter, and it has to say which of the reasons applies: nobody asked
/// yet, or this build cannot answer at all.
/// </para>
/// </remarks>
/// <param name="Label">What is being counted, in one word where possible.</param>
/// <param name="Value">The figure, or null when there is none.</param>
/// <param name="Explanation">What the figure means, or why there is not one.</param>
internal sealed record PermissionCounter(string Label, int? Value, string Explanation)
{
    /// <summary>A figure something actually computed.</summary>
    /// <param name="label">What is being counted.</param>
    /// <param name="value">The figure.</param>
    /// <param name="explanation">What the figure means.</param>
    public static PermissionCounter Computed(string label, int value, string explanation) =>
        new(label, value, explanation);

    /// <summary>A counter nothing has computed, which is never rendered as a zero.</summary>
    /// <param name="label">What would be counted.</param>
    /// <param name="explanation">Why there is no figure.</param>
    public static PermissionCounter NotComputed(string label, string explanation) =>
        new(label, null, explanation);

    /// <summary>Whether there is a figure to show.</summary>
    public bool IsComputed => Value is not null;

    /// <summary>
    /// Whether this counter is standing in for an answer nobody produced.
    /// </summary>
    /// <remarks>
    /// Published rather than inverted in the view: the shell has one boolean-to-visibility
    /// converter and no inverting one, and adding a second converter to express <i>not</i> puts a
    /// decision about what an operator sees somewhere no test reads.
    /// </remarks>
    public bool IsNotComputed => Value is null;

    /// <summary>
    /// The figure as the strip shows it, or an em dash standing in for the absence of one.
    /// </summary>
    /// <remarks>
    /// A dash rather than a blank: a blank cell reads as a rendering fault, and an operator who
    /// thinks the screen is broken will guess at what belongs there.
    /// </remarks>
    public string Display => Value?.ToString(System.Globalization.CultureInfo.CurrentCulture) ?? "\u2014";
}

/// <summary>
/// The words and verdicts a permission list is read with, built once from one schema catalogue.
/// </summary>
/// <remarks>
/// <para>
/// <b>It exists because the catalogue stopped being a constant.</b> The three readers used to hold
/// <see cref="SchemaGuidCatalog.Embedded"/> in static fields, which made the shipped table a
/// compile-time fact three layers below anything that knew which bundle was open - and that is
/// exactly why a forest's own schema never reached the screen.
/// </para>
/// <para>
/// <b>Built once per bundle, not once per entry.</b> A large object has hundreds of access control
/// entries and each of the three readers indexes the whole catalogue on construction. Rebuilding
/// them per row would index a forest's entire schema hundreds of times to render one screen.
/// </para>
/// </remarks>
internal sealed class PermissionVocabulary
{
    /// <summary>Reads a vocabulary over the given catalogue.</summary>
    /// <param name="catalog">What a GUID means, forest first and shipped behind it.</param>
    public PermissionVocabulary(SchemaGuidCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(catalog);

        Catalog = catalog;
        Words = new PermissionWordingWriter(catalog);
        Scopes = new PermissionScopeWriter(catalog);
        Risks = new DangerousPermissionClassifier(catalog);
    }

    /// <summary>
    /// The vocabulary available without a bundle: the shipped table and nothing else.
    /// </summary>
    /// <remarks>
    /// For a caller that has no run open. It resolves what Microsoft publishes and nothing a
    /// forest added, and <see cref="SchemaGuidCatalog.HasCapturedEntries"/> says so.
    /// </remarks>
    public static PermissionVocabulary Shipped { get; } = new(SchemaGuidCatalog.Embedded);

    /// <summary>What a GUID means.</summary>
    public SchemaGuidCatalog Catalog { get; }

    /// <summary>An entry's access mask in words.</summary>
    public PermissionWordingWriter Words { get; }

    /// <summary>How far an entry reaches, in words.</summary>
    public PermissionScopeWriter Scopes { get; }

    /// <summary>Whether an entry hands somebody control.</summary>
    public DangerousPermissionClassifier Risks { get; }
}

/// <summary>
/// How loudly a classified entry is marked, when the operator has asked for classification.
/// </summary>
/// <remarks>
/// <para>
/// <b>Three members for four verdicts, and that is the point.</b>
/// <see cref="PermissionVerdict.NotDangerous"/> and <see cref="PermissionVerdict.CannotClassify"/>
/// both arrive here as <see cref="None"/>, by the owner's decision of 2026-08-18. Marking every
/// examined-and-ordinary entry would put a reassurance on most rows of most objects, and a screen
/// that reassures on a hundred rows is one an operator stops reading. Marking every unclassifiable
/// entry would do the opposite and mark the schema catalogue's gaps as though they were the
/// forest's.
/// </para>
/// <para>
/// <b>This is a statement about the entry, not about how it looks.</b> A view model may not hold a
/// brush, and <c>ShellMvvmGateTests</c> fails the build for one that does. Which colour a mark
/// wears is the template's business.
/// </para>
/// </remarks>
internal enum PermissionRisk
{
    /// <summary>
    /// Not marked. Either nothing has classified this entry, or the classifier examined it and did
    /// not call it a takeover, or it could not classify it at all.
    /// </summary>
    /// <remarks>
    /// First deliberately, so an entry nobody classified is unmarked rather than accused.
    /// </remarks>
    None = 0,

    /// <summary>
    /// The entry hands somebody control of this object, or of the account, policy or credential
    /// the right it names controls.
    /// </summary>
    Dangerous,

    /// <summary>
    /// The right becomes a takeover in the presence of evidence the entry does not carry - other
    /// rights the same principal holds, or the container the entry is written on. Marked more
    /// quietly than <see cref="Dangerous"/> because on its own it is not one.
    /// </summary>
    /// <remarks>
    /// The container half arrives with <c>S-57</c> finding <c>#8</c>: a right to create children of
    /// one class is a delegation wizard's ordinary output in most places and
    /// <c>docs/rules/SEC-121.md</c>'s Critical domain controller injection in one. This mirrors
    /// <see cref="PermissionVerdict.DangerousInCombination"/>, which carries the same widening -
    /// the screen must not describe the bucket more narrowly than the classifier fills it.
    /// </remarks>
    DangerousInCombination,
}

/// <summary>
/// One right an access control entry grants, with the classifier's opinion of that right alone.
/// </summary>
/// <remarks>
/// <para>
/// <b>The mark belongs here and not on the row, because a row is one entry and an entry is not one
/// right.</b> An <c>ACCESS_MASK</c> is a set of bits Windows evaluates independently, and
/// <see cref="DangerousPermissionClassifier"/> judges them differently by construction. A row
/// reading <i>Write userAccountControl, Read userAccountControl</i> under a single <i>Takeover</i>
/// mark states something true of the entry and useless about the rights: an administrator deciding
/// what to remove cannot tell which half earned it. This is structural rather than statistical -
/// it follows from what a mask is - and it is why no measurement of how often it happens was worth
/// taking.
/// </para>
/// <para>
/// <b>The row stays one entry all the same.</b> An access control entry is what the directory
/// holds, what canonical order applies to and what an administrator removes; splitting rows per
/// right would show a list that does not exist in the object and cannot be acted on. Only the mark
/// moved.
/// </para>
/// </remarks>
internal sealed partial class PermissionRightViewModel : ObservableObject
{
    private readonly PermissionAssessment _assessment;

    /// <summary>
    /// Whether the operator has asked for the classifier's opinion.
    /// </summary>
    /// <remarks>
    /// Pushed down from the entry, which has it from the section. One toggle governs the object,
    /// and a right that reached up the visual tree for it could not be tested without a window.
    /// </remarks>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Mark))]
    [NotifyPropertyChangedFor(nameof(IsMarked))]
    [NotifyPropertyChangedFor(nameof(RiskReason))]
    private bool _isClassified;

    /// <summary>Creates a screen's view of one right.</summary>
    /// <param name="name">What the right is called, in Microsoft's words.</param>
    /// <param name="isNamed">Whether this build has a word for what the right grants.</param>
    /// <param name="assessment">What the classifier says about this right on its own.</param>
    public PermissionRightViewModel(string name, bool isNamed, PermissionAssessment assessment)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(assessment);

        Name = name;
        IsNamed = isNamed;
        _assessment = assessment;
    }

    /// <summary>What the right is called.</summary>
    public string Name { get; }

    /// <summary>
    /// What this run established about the right: whether this build has a word for what it
    /// grants.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Separate from <see cref="Mark"/> deliberately, and this is why it sits on the right
    /// rather than the row.</b> A right can be completely understood and be a takeover, or be
    /// unworded and harmless. It used to be a statement about the whole entry, which meant one
    /// unnamed bit rendered every right beside it as not established - including rights the
    /// classifier had just called a takeover, so the same line said both <i>we could not read
    /// this</i> and <i>this hands over the object</i>.
    /// </para>
    /// <para>
    /// It is <see cref="FactState.NotEstablished"/> and never <see cref="FactState.EstablishedBad"/>:
    /// this is about whether the right was read, and it is not a verdict on the access.
    /// </para>
    /// </remarks>
    public FactState State => IsNamed ? FactState.EstablishedGood : FactState.NotEstablished;

    /// <summary>Whether this build has a word for what the right grants.</summary>
    public bool IsNamed { get; }

    /// <summary>
    /// What the classifier says about this right, whether or not anybody asked.
    /// </summary>
    public PermissionRisk Risk => _assessment.Verdict switch
    {
        PermissionVerdict.Dangerous => PermissionRisk.Dangerous,
        PermissionVerdict.DangerousInCombination => PermissionRisk.DangerousInCombination,
        _ => PermissionRisk.None,
    };

    /// <summary>
    /// The mark this right wears: the classifier's opinion when the operator asked for it, and
    /// nothing at all when they did not.
    /// </summary>
    public PermissionRisk Mark => IsClassified ? Risk : PermissionRisk.None;

    /// <summary>Whether this right is currently wearing a mark.</summary>
    public bool IsMarked => Mark != PermissionRisk.None;

    /// <summary>Why the classifier reached its verdict, or null when this right is not marked.</summary>
    public string? RiskReason => IsMarked ? _assessment.Reason : null;
}

/// <summary>
/// One access control entry, in the four columns the predecessor showed and an administrator reads.
/// </summary>
internal sealed partial class PermissionEntryViewModel : ObservableObject
{
    private readonly PermissionEntry _entry;
    private readonly PermissionWording _wording;
    private readonly PermissionScope _scope;

    /// <summary>
    /// Whether the operator has asked for the classifier's opinion.
    /// </summary>
    /// <remarks>
    /// <b>Set by the section, never by this entry.</b> One toggle governs the whole object, so the
    /// state is pushed down rather than each row reaching up for it - a row that walked the visual
    /// tree to find the toggle would be a row that cannot be tested without a window.
    /// </remarks>
    [ObservableProperty]
    private bool _isClassified;

    /// <summary>Creates a screen's view of one entry.</summary>
    /// <param name="entry">The entry as the evidence holds it.</param>
    /// <param name="vocabulary">The words and verdicts to read the entry with.</param>
    public PermissionEntryViewModel(PermissionEntry entry, PermissionVocabulary vocabulary)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(vocabulary);

        _entry = entry;

        // NOT EXPANDED HERE, DELIBERATELY. This used to translate Windows' shorthand bits into the
        // specific rights they stand for before wording them, as a safety net. That net reported a
        // permission the domain controller may not honour as though it were an ordinary one:
        // Microsoft states the access check does not translate a shorthand bit found in an entry
        // already attached to an object.
        //
        // The fear that removing it would cost a warning does not hold. It would, if the shorthand
        // fell through to 'other rights', because an unnamed right is refused classification. The
        // wording now names those bits instead, so the classifier is still asked about them and
        // still expands them itself when judging severity. Naming the doubt is not the same as
        // ignoring the danger. See docs/next/S-56 R2.
        var mask = entry.AccessMask;

        _wording = vocabulary.Words.Describe(mask, entry.ObjectTypeGuid);
        _scope = vocabulary.Scopes.Describe(
            entry.InheritanceFlags,
            entry.PropagationFlags,
            entry.IsInherited,
            entry.InheritedObjectTypeGuid);
        Rights = [.. _wording.Rights.Select(r => new PermissionRightViewModel(
            r.Name, r.IsNamed, Assess(entry, r, vocabulary.Risks)))];
    }

    /// <summary>
    /// Pushes the operator's request down to every right on this entry.
    /// </summary>
    /// <remarks>
    /// The generated setter cannot do this, so it is done here. A right left unclassified while
    /// the toggle is on would read as examined and ordinary.
    /// </remarks>
    /// <param name="value">Whether the operator has asked for the classifier's opinion.</param>
    partial void OnIsClassifiedChanged(bool value)
    {
        foreach (var right in Rights)
            right.IsClassified = value;
    }

    /// <summary>
    /// Runs the classifier against one right of the entry, once, when the entry is read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The stored ACE type is a string and the classifier takes an enum.</b> A type this build
    /// does not know cannot be handed over as an undefined enum value and cannot be folded into an
    /// allow - either would have the classifier judge an entry whose meaning is unknown. It is
    /// refused here instead, with the same wording the classifier uses for the case it does catch.
    /// </para>
    /// <para>
    /// <b>A right this build has no word for is refused rather than asked about.</b> The mask can
    /// carry bits nothing here names, and the classifier's unscoped arm would answer
    /// <see cref="PermissionVerdict.NotDangerous"/> to them - reporting access nobody examined as
    /// safe. It is not assessed, and it is not reported as safe either.
    /// </para>
    /// <para>
    /// <b>The entry's reach is passed, not just its mask.</b> An <c>INHERIT_ONLY_ACE</c> does not
    /// control access to the object it is attached to, so a reason claiming it hands somebody
    /// control of <i>this</i> object is false. The flags were already being read two lines above
    /// for the Scope column and were not reaching the classifier, which is how a row came to show
    /// <i>All descendant objects</i> beside a mark asserting a grant here. See <c>S-56</c> R13.
    /// </para>
    /// </remarks>
    private static PermissionAssessment Assess(
        PermissionEntry entry, PermissionRight right, DangerousPermissionClassifier classifier)
    {
        if (!right.IsNamed)
        {
            return PermissionAssessment.CannotClassify(
                "The access mask carries bits this build has no word for, so what they grant has "
                + "not been assessed. They are not being reported as safe.");
        }

        if (!Enum.TryParse<AceType>(entry.AceType, ignoreCase: false, out var aceType))
        {
            return PermissionAssessment.CannotClassify(
                "The entry carries an ACE type this product does not model, so what it grants is "
                + "unknown.");
        }

        return classifier.Classify(
            aceType,
            right.Bits,
            entry.ObjectTypeGuid,
            EntryReachReader.FromPropagationFlags(entry.PropagationFlags));
    }

    /// <summary>What the entry grants or denies, in one line.</summary>
    public string Right => _wording.Summary;

    /// <summary>
    /// Each right the entry names, each carrying its own verdict and its own mark.
    /// </summary>
    public IReadOnlyList<PermissionRightViewModel> Rights { get; }

    /// <summary>
    /// Whether every bit of the access mask was named. False means one of <see cref="Rights"/>
    /// stands for bits this build has no word for, and that right says so itself.
    /// </summary>
    public bool RightsAreComplete => _wording.RightsAreComplete;

    /// <summary>
    /// Whether the entry grants or denies. A type this build does not know is shown as it was
    /// stored rather than folded into <i>Allow</i>, which would state the opposite of a denial.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A callback entry says so.</b> Its applicability is decided by a condition evaluated
    /// during the access check, so rendering it as a plain <i>Allow</i> tells an operator the
    /// entry grants when it may grant nothing at all - <c>S-57</c> finding <c>#6</c>. The word is
    /// kept because the entry really is an allow or a deny, and qualified because whether it takes
    /// effect is not something this product read. Same treatment, and the same reason, as
    /// <c>PermissionWording</c>'s <i>shorthand - may not be enforced</i>.
    /// </para>
    /// <para>
    /// It says <i>conditional</i> rather than naming the condition, because the bytes carrying it
    /// are dropped before the bundle and never reach this screen. See <c>F-S58-10</c>.
    /// </para>
    /// </remarks>
    public string Type => _entry.AceType switch
    {
        nameof(AceType.AccessAllowed) or nameof(AceType.AccessAllowedObject) => "Allow",
        nameof(AceType.AccessAllowedCallback)
            or nameof(AceType.AccessAllowedCallbackObject) => "Allow (conditional)",
        nameof(AceType.AccessDenied) or nameof(AceType.AccessDeniedObject) => "Deny",
        nameof(AceType.AccessDeniedCallback)
            or nameof(AceType.AccessDeniedCallbackObject) => "Deny (conditional)",
        nameof(AceType.SystemAudit) or nameof(AceType.SystemAuditObject) => "Audit",
        _ => _entry.AceType,
    };

    /// <summary>Whether this entry denies rather than grants.</summary>
    /// <remarks>
    /// Tested by prefix so a conditional denial is still a denial. Comparing the whole string
    /// against <c>"Deny"</c> stopped being correct the moment <see cref="Type"/> could qualify
    /// itself, and a denial that stopped counting as one would read as a grant.
    /// </remarks>
    public bool IsDenial => Type.StartsWith("Deny", StringComparison.Ordinal);

    /// <summary>How far the entry reaches.</summary>
    public string Scope => _scope.AppliesTo;

    /// <summary>Whether the entry was set here or came down from a container above.</summary>
    public string Inheritance => _scope.Inheritance;

    /// <summary>
    /// What this run established about the entry: whether every bit of its mask was worded. Never
    /// <see cref="FactState.EstablishedBad"/> - this is not a verdict on the access.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Separate from the classifier's opinion deliberately.</b> An entry can be completely
    /// understood and be a takeover, or be half-worded and be harmless. Folded into one column, an
    /// unworded access mask bit and a granted takeover would reach the screen as the same mark.
    /// </para>
    /// <para>
    /// <b>Nothing renders this, and <see cref="PermissionRightViewModel.State"/> does.</b> The row
    /// is not what is or is not established - one right of it is - and greying an entire entry
    /// because one bit was unworded put <i>we could not read this</i> on rights the classifier had
    /// just called a takeover. This survives as the entry-level statement of the same fact.
    /// </para>
    /// </remarks>
    public FactState State =>
        RightsAreComplete ? FactState.EstablishedGood : FactState.NotEstablished;

    /// <summary>
    /// What the classifier says about the entry, whether or not anybody asked: the loudest thing
    /// said about any one of its rights.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Derived from the rights and never computed a second time.</b> Asking the classifier
    /// about the whole mask as well would put two answers about one entry in the product, and six
    /// places disagreeing about what is dangerous is the defect
    /// <see cref="DangerousPermissionClassifier"/> exists to end. The entry is as dangerous as the
    /// worst thing in it, which is also how an administrator reads it.
    /// </para>
    /// <para>
    /// <b>Nothing renders this.</b> The row carries no mark - the mark is beside the right that
    /// earned it. This survives because the counters ask how many entries are a takeover, and an
    /// entry is what a counter of entries counts.
    /// </para>
    /// </remarks>
    public PermissionRisk Risk => Rights.Any(r => r.Risk == PermissionRisk.Dangerous)
        ? PermissionRisk.Dangerous
        : Rights.Any(r => r.Risk == PermissionRisk.DangerousInCombination)
            ? PermissionRisk.DangerousInCombination
            : PermissionRisk.None;
}
