using SecureAD.Kernel.Schema;

namespace SecureAD.Kernel.Security;

/// <summary>
/// The product's single answer to "does this access control entry hand somebody control".
/// </summary>
/// <remarks>
/// <para>
/// <b>What it replaces.</b> The previous product answered this question in six places and the
/// six disagreed. A bitmask classifier that never used the extended-rights constant it declared,
/// so a DCSync grant was not dangerous by it. A per-GUID flag on a lookup table, which never saw
/// an access mask. A user-interface aggregation service that unioned the two, which was the right
/// answer computed in the wrong layer. And two effective-access panels that matched on rendered
/// display strings, disagreed with each other about <c>gPLink</c>, <c>scriptPath</c> and
/// <c>userAccountControl</c>, and are the two screens a user is meant to read side by side. A
/// sixth list lived in the rule SQL.
/// </para>
/// <para>
/// <b>What it decides, and what it does not.</b> This classifies <i>one entry</i>. Whether a
/// principal is dangerous because of the <i>set</i> of rights it holds - the replication pair that
/// makes DCSync - is a different question against different evidence, and it is not answered here.
/// An entry that is only half of such a pair returns
/// <see cref="PermissionVerdict.DangerousInCombination"/> rather than a verdict it is not entitled
/// to. See <c>docs/decisions/0016-the-filtered-set-replication-route-is-a-product-judgement.md</c>.
/// </para>
/// <para>
/// <b>Where the assertions come from.</b> Mask bit values are Microsoft's
/// <c>ADS_RIGHTS_ENUM</c>. Which rights count as takeover-class is taken from the rule
/// specifications in <c>docs/rules/</c>, which are source of truth for their own rules per
/// <c>docs/decisions/0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md</c>, and not from
/// the previous implementation. The names are looked up in the schema catalogue; no GUID is
/// written down here.
/// </para>
/// </remarks>
public sealed class DangerousPermissionClassifier
{
    // Access mask bits, from ADS_RIGHTS_ENUM (iads.h). Named as Microsoft names them.
    private const int CreateChild = 0x00000001;      // ACTRL_DS_CREATE_CHILD
    private const int DeleteChild = 0x00000002;      // ACTRL_DS_DELETE_CHILD
    private const int Self = 0x00000008;             // ADS_RIGHT_DS_SELF, validated writes
    private const int ReadProperty = 0x00000010;     // ADS_RIGHT_DS_READ_PROP
    private const int WriteProperty = 0x00000020;    // ADS_RIGHT_DS_WRITE_PROP
    private const int ControlAccess = 0x00000100;    // ADS_RIGHT_DS_CONTROL_ACCESS, extended rights
    private const int WriteDac = 0x00040000;         // ADS_RIGHT_WRITE_DAC
    private const int WriteOwner = 0x00080000;       // ADS_RIGHT_WRITE_OWNER

    /// <summary>
    /// Extended rights that hand over an account on their own. Sourced to the rule that detects
    /// each: <c>User-Force-Change-Password</c> to <c>docs/rules/SEC-003.md</c>.
    /// </summary>
    private static readonly HashSet<string> DangerousExtendedRights =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "User-Force-Change-Password",
        };

    /// <summary>
    /// The replication family. Each is a component of a combination and none is a takeover alone -
    /// which is precisely why no per-GUID boolean could ever have been right about them.
    /// </summary>
    private static readonly HashSet<string> ReplicationRights =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "DS-Replication-Get-Changes",
            "DS-Replication-Get-Changes-All",
            "DS-Replication-Get-Changes-In-Filtered-Set",
        };

    /// <summary>
    /// Validated writes that hand over a group or an account. <c>Self-Membership</c> is the
    /// membership vector <c>docs/rules/SEC-006.md</c> detects; <c>Validated-SPN</c> is the write
    /// that makes an account Kerberoastable, detected by <c>docs/rules/SEC-024.md</c>.
    /// </summary>
    private static readonly HashSet<string> DangerousValidatedWrites =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "Self-Membership",
            "Validated-SPN",
        };

    /// <summary>
    /// Attributes whose value decides who an account is, what it may impersonate, or what code
    /// runs. Each is named by a rule specification: <c>member</c> by SEC-006,
    /// <c>msDS-KeyCredentialLink</c> by SEC-025, <c>msDS-AllowedToActOnBehalfOfOtherIdentity</c>
    /// by SEC-014 and SEC-122, <c>servicePrincipalName</c> by SEC-024, <c>sIDHistory</c> by
    /// SEC-123, and <c>userAccountControl</c> by SEC-022, SEC-023 and SEC-067, each of which turns
    /// on a bit of it.
    ///
    /// <para>
    /// <c>gPLink</c> and <c>scriptPath</c> are here by the owner's decision of 2026-08-10, recorded
    /// in <c>docs/next/S-4-dangerous-permission-classification.md</c>. They were dangerous to the
    /// live effective-access panel and not to the stored one, and this settles that disagreement in
    /// favour of the wider reading: writing either runs code across everything in scope, and
    /// unlinking a hardening policy through <c>gPLink</c> needs no other privilege at all.
    /// </para>
    /// </summary>
    private static readonly HashSet<string> DangerousAttributeWrites =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "member",
            "userAccountControl",
            "unicodePwd",
                        "servicePrincipalName",
            "sIDHistory",
            "msDS-KeyCredentialLink",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
            "gPLink",
            "scriptPath",
        };

    /// <summary>
    /// Attributes whose <i>value</i> is a credential, so reading is the whole attack.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>ms-Mcs-AdmPwd</c> is legacy LAPS and <c>msLAPS-Password</c> is its Windows LAPS
    /// replacement; both hold a local administrator password in clear text, and both are what
    /// <c>docs/rules/SEC-090.md</c> detects read access to.
    /// </para>
    /// <para>
    /// <b>The encrypted attributes are here too, and deliberately at the same weight.</b> Windows
    /// LAPS only encrypts when the domain functional level is 2016 or later and encryption has been
    /// turned on; below that, Microsoft states passwords can be stored only in clear text. The
    /// schema is extended either way, so the presence of these attributes proves nothing about
    /// whether what they hold is encrypted. Judging them as a lesser thing would rest on an
    /// assumption about a forest's configuration that this component cannot check, and would be
    /// wrong in exactly the environments least likely to have hardened anything else.
    /// </para>
    /// <para>
    /// They reach an access control entry through the
    /// <c>ms-LAPS-Encrypted-Password-Attributes</c> property set rather than singly - Microsoft
    /// publishes it with <c>Valid accesses: 48</c>, which is a property set - so the property-set
    /// path is where this list usually gets consulted. <c>msLAPS-Password</c> by contrast has no
    /// <c>attributeSecurityGUID</c> and is only ever reachable directly.
    /// <see href="https://learn.microsoft.com/windows-server/identity/laps/laps-technical-reference">Windows
    /// LAPS schema extensions reference</see>.
    /// </para>
    /// </remarks>
    private static readonly HashSet<string> SecretAttributeReads =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "ms-Mcs-AdmPwd",
            "msLAPS-Password",
            "msLAPS-EncryptedPassword",
            "msLAPS-EncryptedPasswordHistory",
            "msLAPS-EncryptedDSRMPassword",
            "msLAPS-EncryptedDSRMPasswordHistory",
        };

    private readonly SchemaGuidCatalog _catalog;

    /// <summary>
    /// Creates a classifier that reads the given schema catalogue.
    /// </summary>
    /// <param name="catalog">
    /// The table that says what a GUID means. Stated rather than defaulted: the catalogue a forest
    /// captured and the one shipped with the product are different tables, and which was used is
    /// part of what an audit claims.
    /// </param>
    public DangerousPermissionClassifier(SchemaGuidCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(catalog);

        _catalog = catalog;
    }

    /// <summary>
    /// Says what the product is prepared to claim about one access control entry.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>It may be asked about one bit rather than a whole entry, and that is the intended
    /// use.</b> An <c>ACCESS_MASK</c> is a set of bits Windows evaluates independently -
    /// <c>AccessCheck</c> tests each right and accumulates across entries - and the arms below
    /// judge them differently by construction. So an entry granting several rights has several
    /// answers, and the one this returns for the whole mask is whichever the arms reach first.
    /// That is a fair verdict about the entry and a useless one about a right: it cannot say which
    /// right earned it.
    /// </para>
    /// <para>
    /// A caller wanting per-right answers passes one right's bits at a time, taken from
    /// <see cref="PermissionRight.Bits"/>. Nothing here changes for that case - the arms already
    /// test single bits - which is why per-right marking needed no second opinion about what is
    /// dangerous. <b>A caller must not pass bits this build has no word for</b>: the unscoped arm
    /// would answer <see cref="PermissionVerdict.NotDangerous"/>, and reporting an unexamined bit
    /// as safe is the failure <see cref="PermissionAssessment"/> exists to prevent.
    /// <see cref="PermissionRight.IsNamed"/> is how a caller tells.
    /// </para>
    /// </remarks>
    /// <param name="aceType">
    /// Whether the entry allows, denies or audits. An entry type Windows does not define is
    /// <see cref="PermissionVerdict.CannotClassify"/>, because an unrecognised type may grant in a
    /// way this code does not model.
    /// </param>
    /// <param name="accessMask">
    /// The raw mask, or one right's bits out of it. Generic rights are expanded before anything is
    /// read from it, so <c>GENERIC_ALL</c> and the specific mask it stands for reach the same
    /// verdict.
    /// </param>
    /// <param name="objectTypeGuid">
    /// The GUID the entry is scoped to, or <c>null</c> when it applies to the whole object.
    /// A GUID the catalogue does not know is <see cref="PermissionVerdict.CannotClassify"/>, never
    /// <see cref="PermissionVerdict.NotDangerous"/>.
    /// </param>
    /// <returns>The verdict and the reason for it. Never <c>null</c>.</returns>
    public PermissionAssessment Classify(AceType aceType, int accessMask, string? objectTypeGuid) =>
        Classify(aceType, accessMask, objectTypeGuid, EntryReach.ThisObject);

    /// <inheritdoc cref="Classify(AceType, int, string?)"/>
    /// <param name="aceType">Whether the entry allows, denies or audits.</param>
    /// <param name="accessMask">The raw mask, or one right's bits out of it.</param>
    /// <param name="objectTypeGuid">The GUID the entry is scoped to, or <c>null</c>.</param>
    /// <param name="reach">
    /// What the entry governs. <see cref="EntryReach.DescendantsOnly"/> does not change the
    /// verdict - an inherit-only grant of Modify Permissions is exactly as dangerous, to the
    /// objects it reaches - but it does change what the reason is allowed to claim, per
    /// <c>S-56</c> R13. The three-argument overload asserts <see cref="EntryReach.ThisObject"/>,
    /// which is what an entry means unless <c>INHERIT_ONLY_ACE</c> says otherwise.
    /// </param>
    public PermissionAssessment Classify(
        AceType aceType, int accessMask, string? objectTypeGuid, EntryReach reach)
    {
        var assessment = ClassifyGrant(aceType, accessMask, objectTypeGuid);

        if (reach == EntryReach.DescendantsOnly)
            assessment = WhereItLands(assessment);

        return IsCallback(aceType) ? WhetherItApplies(assessment) : assessment;
    }

    /// <summary>
    /// Corrects a verdict's reason for a callback entry, whose applicability is decided by a
    /// condition this product does not evaluate.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The defect this fixes.</b> A conditional ACE is a callback ACE whose application data
    /// carries a condition evaluated during the access check; a false condition makes the entry
    /// inapplicable. Until <c>S-57</c> finding <c>#6</c>, the two allow-callback types missed
    /// <see cref="IsDeny"/> and <see cref="IsAudit"/> and fell into the ordinary mask arms, so
    /// <i>grants Modify Permissions</i> was said of an entry that may grant nothing at all.
    /// </para>
    /// <para>
    /// <b>Why the verdict is qualified rather than withdrawn, which is the decision to overturn if
    /// any is.</b> <c>S-56</c> v4 R1 says callback types must be reported as unsupported or
    /// unclassified and not interpreted through the ordinary ACE model, and read literally that
    /// makes this <see cref="PermissionVerdict.CannotClassify"/>. It is not, by the owner's
    /// decision recorded in <c>S-58</c>: a conditional entry granting full control is a real
    /// takeover to anybody who satisfies the condition, and answering <c>CannotClassify</c> would
    /// take its mark off the screen and its row out of the Dangerous count - trading a false
    /// positive for a false negative, which is <c>F-S54-2</c>. R1 is satisfied by reporting the
    /// entry as unsupported in the sentence an operator reads, rather than by declining to judge a
    /// mask that is dangerous whenever it applies.
    /// </para>
    /// <para>
    /// <b>This is <see cref="WhereItLands"/>'s shape exactly</b>, and follows its rules: only a
    /// claim of danger is rewritten, because <c>NotDangerous</c> and <c>CannotClassify</c> assert
    /// nothing a condition can falsify; and the original sentence is kept whole, because the
    /// correction is about <i>whether</i> the grant applies, not <i>what</i> it grants. The two
    /// compose - an inherit-only conditional entry earns both sentences - which is why this runs
    /// after the reach qualifier rather than instead of it.
    /// </para>
    /// <para>
    /// <b>It cannot say whether a condition is actually present.</b> The bytes that would say so
    /// are read by the parser and dropped before the bundle, so only the ACE type reaches here.
    /// The wording therefore names the callback rather than claiming a condition exists. See
    /// <c>F-S58-10</c>.
    /// </para>
    /// </remarks>
    private static PermissionAssessment WhetherItApplies(PermissionAssessment assessment)
    {
        if (assessment.Verdict is not (PermissionVerdict.Dangerous
            or PermissionVerdict.DangerousInCombination))
        {
            return assessment;
        }

        return assessment with
        {
            Reason = "This entry is a callback entry, so whether it applies at all is decided by a "
                + "condition evaluated during the access check that this product does not read. "
                + "When it does apply: " + Uncapitalised(assessment.Reason),
        };
    }

    /// <summary>
    /// Lowers the first letter of a reason being folded into the middle of a longer sentence.
    /// </summary>
    /// <remarks>
    /// Only the first character, and only when the second is not also upper case - so
    /// <c>Grants Modify Permissions</c> becomes <c>grants Modify Permissions</c> while a reason
    /// opening on an acronym is left alone.
    /// </remarks>
    private static string Uncapitalised(string reason) =>
        reason.Length >= 2 && char.IsUpper(reason[0]) && !char.IsUpper(reason[1])
            ? char.ToLowerInvariant(reason[0]) + reason[1..]
            : reason;

    /// <summary>
    /// Whether the entry is one of the callback types, whose applicability is decided outside the
    /// ordinary ACE model.
    /// </summary>
    /// <remarks>
    /// The deny-callback types are included and reach <see cref="WhetherItApplies"/> without
    /// effect, because a deny entry answers <see cref="PermissionVerdict.NotDangerous"/> and
    /// <i>a deny entry grants no access</i> stays true whether or not its condition fires. They are
    /// named here rather than excluded so that the set means <i>callback</i> and not
    /// <i>callback we happen to rewrite</i>.
    /// </remarks>
    private static bool IsCallback(AceType aceType) =>
        aceType is AceType.AccessAllowedCallback
            or AceType.AccessAllowedCallbackObject
            or AceType.AccessDeniedCallback
            or AceType.AccessDeniedCallbackObject;


    /// <summary>
    /// Corrects a verdict's reason for an entry that does not govern the object it sits on.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Only a claim of danger is rewritten.</b> The reasons for
    /// <see cref="PermissionVerdict.Dangerous"/> and
    /// <see cref="PermissionVerdict.DangerousInCombination"/> say what the entry hands somebody on
    /// this object, and that is the sentence <c>INHERIT_ONLY_ACE</c> falsifies.
    /// <see cref="PermissionVerdict.NotDangerous"/> and
    /// <see cref="PermissionVerdict.CannotClassify"/> make no such claim - "grants no write over
    /// the object" and "has not been assessed" are both still true of an inherit-only entry - so
    /// they are left exactly as they were rather than decorated.
    /// </para>
    /// <para>
    /// <b>The original sentence is kept whole.</b> It is prefixed rather than reworded, because it
    /// is still the accurate description of what the grant does - the correction is about
    /// <i>where</i>, not <i>what</i>.
    /// </para>
    /// </remarks>
    private static PermissionAssessment WhereItLands(PermissionAssessment assessment)
    {
        if (assessment.Verdict is not (PermissionVerdict.Dangerous
            or PermissionVerdict.DangerousInCombination))
        {
            return assessment;
        }

        return assessment with
        {
            Reason = "This entry is inherit-only, so it grants nothing on this object and "
                + "everything below applies to the objects beneath it. "
                + assessment.Reason,
        };
    }

    private PermissionAssessment ClassifyGrant(
        AceType aceType, int accessMask, string? objectTypeGuid)
    {
        if (!Enum.IsDefined(aceType))
        {
            return PermissionAssessment.CannotClassify(
                "The entry carries an ACE type this product does not model, so what it grants is "
                + "unknown.");
        }

        if (IsDeny(aceType))
        {
            return PermissionAssessment.NotDangerous(
                "A deny entry grants no access.", null);
        }

        if (IsAudit(aceType))
        {
            return PermissionAssessment.NotDangerous(
                "An audit entry is not part of discretionary access control and grants nothing "
                + "wherever it appears.", null);
        }

        var mask = GenericRightsExpander.Expand(accessMask);

        var objectIndependent = ClassifyObjectIndependentBits(mask);
        if (objectIndependent is not null)
            return objectIndependent;

        return string.IsNullOrWhiteSpace(objectTypeGuid)
            ? ClassifyUnscoped(mask)
            : ClassifyScoped(mask, objectTypeGuid);
    }

    /// <summary>
    /// The bits that mean the same thing whether or not the entry names an object type. Writing
    /// the DACL of an object is writing the DACL of that object; naming an attribute alongside it
    /// does not narrow it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b><c>CreateChild</c> and <c>DeleteChild</c> used to be judged here, and that was wrong.</b>
    /// For those two bits Microsoft states that <c>ObjectType</c> "identifies a type of child
    /// object" and that the entry "controls the trustee's right to create this type of child
    /// object", so the GUID narrows the grant rather than decorating it - which is exactly what
    /// this method is for bits that do <i>not</i> do. Judging them here returned before the GUID
    /// was ever read, so <i>create user objects here</i> and <i>create any child object here</i>
    /// reached the same verdict by the same words. They now live in
    /// <see cref="ClassifyUnscoped"/> and <see cref="ClassifyScoped"/>, which is
    /// <c>S-56</c> R3: kind is a function of <c>(GUID, mask bit)</c>. Moved per <c>S-57</c>
    /// finding <c>#8</c>.
    /// </para>
    /// <para>
    /// <c>WriteDac</c> and <c>WriteOwner</c> are still judged first and still ignore the GUID, so
    /// an entry carrying one of them alongside a class-scoped child right stays
    /// <see cref="PermissionVerdict.Dangerous"/> on their account and never reaches the class arm.
    /// </para>
    /// </remarks>
    private static PermissionAssessment? ClassifyObjectIndependentBits(int mask)
    {
        if ((mask & WriteDac) != 0)
        {
            return PermissionAssessment.Dangerous(
                "Grants Modify Permissions, so the holder can rewrite the object's permissions and "
                + "grant itself anything else.", null);
        }

        if ((mask & WriteOwner) != 0)
        {
            return PermissionAssessment.Dangerous(
                "Grants Modify Owner. An object's owner has the implicit right to modify its "
                + "permissions, so this reaches the same place as Modify Permissions.", null);
        }

        return null;
    }

    /// <summary>
    /// An entry with no object type applies to everything on the object, so a write bit here is a
    /// grant over every attribute, every validated write, or every extended right - which includes
    /// Reset Password and the replication family.
    /// </summary>
    /// <remarks>
    /// The same reading governs the child rights: with no <c>ObjectType</c> the grant is every
    /// class the schema permits under the container, so it is the takeover
    /// <c>docs/rules/SEC-060.md</c> describes. These two arms are first so that the verdict and
    /// the wording an unscoped entry receives are unchanged by the move out of
    /// <see cref="ClassifyObjectIndependentBits"/>.
    /// </remarks>
    private static PermissionAssessment ClassifyUnscoped(int mask)
    {
        if ((mask & CreateChild) != 0)
        {
            return PermissionAssessment.Dangerous(
                "Grants Create Child Objects of any class, which is takeover-class write access "
                + "to the container per docs/rules/SEC-060.md.", null);
        }

        if ((mask & DeleteChild) != 0)
        {
            return PermissionAssessment.Dangerous(
                "Grants Delete Child Objects of any class, which is takeover-class write access "
                + "to the container per docs/rules/SEC-060.md.", null);
        }

        if ((mask & ControlAccess) != 0)
        {
            return PermissionAssessment.Dangerous(
                "Grants All Extended Rights, which includes Reset Password and the replication "
                + "rights behind DCSync.", null);
        }

        if ((mask & WriteProperty) != 0)
        {
            return PermissionAssessment.Dangerous(
                "Grants Write All Properties, which includes every attribute that decides who an "
                + "account is and what it may impersonate.", null);
        }

        if ((mask & Self) != 0)
        {
            return PermissionAssessment.Dangerous(
                "Grants All Validated Writes, which includes adding the holder to a group and "
                + "setting a service principal name.", null);
        }

        return PermissionAssessment.NotDangerous(
            "The entry grants no write, no extended right and no validated write over the object.",
            null);
    }

    /// <summary>
    /// An entry that names an object type. The mask bit says which kind of thing the GUID is being
    /// used as - Active Directory reuses one GUID across a validated write and the attribute it
    /// validates, and the entry's mask is the only thing that says which is meant.
    /// </summary>
    private PermissionAssessment ClassifyScoped(int mask, string objectTypeGuid)
    {
        if (!Guid.TryParse(objectTypeGuid, out var parsed))
        {
            return PermissionAssessment.CannotClassify(
                "The entry's object type is not a GUID, so what the permission is scoped to cannot "
                + "be determined.");
        }

        var entries = _catalog.FindByGuid(parsed.ToString("D"));

        if (entries.Count == 0)
        {
            return PermissionAssessment.CannotClassify(
                "The object type is not in the schema catalogue, so this permission has not been "
                + "assessed. It is not being reported as safe.");
        }

        if ((mask & (CreateChild | DeleteChild)) != 0
            && Named(entries, SchemaGuidKind.ObjectClass) is { } childClass)
        {
            return ClassifyChildClassRight(mask, childClass);
        }

        if ((mask & ControlAccess) != 0 && Named(entries, SchemaGuidKind.ExtendedRight) is { } right)
            return ClassifyExtendedRight(right);

        if ((mask & Self) != 0 && Named(entries, SchemaGuidKind.ValidatedWrite) is { } validated)
            return ClassifyValidatedWrite(validated);

        if ((mask & WriteProperty) != 0)
        {
            if (Named(entries, SchemaGuidKind.Attribute) is { } attribute)
                return ClassifyAttributeWrite(attribute);

            if (Named(entries, SchemaGuidKind.PropertySet) is { } set)
                return ClassifyPropertySetWrite(set, parsed.ToString("D"));
        }

        if ((mask & ReadProperty) != 0)
        {
            if (Named(entries, SchemaGuidKind.Attribute) is { } read)
                return ClassifyAttributeRead(read);

            if (Named(entries, SchemaGuidKind.PropertySet) is { } readSet)
                return ClassifyPropertySetRead(readSet, parsed.ToString("D"));
        }

        // Said before the mask-mismatch answer below, because the two are different failures and
        // an operator acts on them differently: this one is the forest's validAccesses being
        // absent or unreadable, and it is the only reason the catalogue holds a name at all.
        if (Named(entries, SchemaGuidKind.Unclassified) is { } unclassified)
        {
            return PermissionAssessment.CannotClassify(
                $"The object type is {unclassified}, which the forest publishes without a "
                + "readable validAccesses, so which kind of right it is cannot be determined and "
                + "this permission has not been assessed. It is not being reported as safe.");
        }

        return PermissionAssessment.CannotClassify(
            "The access mask names no kind of right that matches what this object type is, so the "
            + "permission has not been assessed.");
    }

    /// <summary>
    /// A right to create or delete children of one named class, rather than of anything the schema
    /// allows under the container.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why this is not <see cref="PermissionVerdict.Dangerous"/>.</b> Microsoft's own words for
    /// <c>ADS_RIGHT_DS_CREATE_CHILD</c> are that the GUID "identifies a type of child object" and
    /// the entry "controls the trustee's right to create this type of child object". A grant of
    /// one class is what a delegation wizard produces and is not, on its own, the takeover of the
    /// container that <c>docs/rules/SEC-060.md</c> describes - that rule's set is unscoped.
    /// </para>
    /// <para>
    /// <b>Why it is not <see cref="PermissionVerdict.NotDangerous"/> either, which matters more.</b>
    /// Whether one class is a takeover depends on the class and on the container, and this method
    /// is handed neither the container's identity nor its place in the directory.
    /// <c>docs/rules/SEC-121.md</c> is the case in point: <c>CreateChild</c> scoped to the
    /// <c>computer</c> class is <i>Critical</i> on the Domain Controllers OU, because it is rogue
    /// domain controller injection, and unremarkable on a departmental OU. Answering
    /// <c>NotDangerous</c> here would put this component's word against a shipped rule
    /// specification on the same ACE - which is the disagreement between six classifiers that this
    /// component exists to have ended, re-created inside it.
    /// </para>
    /// <para>
    /// So the entry is recorded rather than answered, and the layer that can see the container
    /// decides. This is the reading of <see cref="PermissionVerdict.DangerousInCombination"/>
    /// widened from "which other rights the principal holds" to "what else the entry sits on",
    /// which is the same shape: evidence this component is not given. That widening is stated on
    /// the enumeration member.
    /// </para>
    /// </remarks>
    private static PermissionAssessment ClassifyChildClassRight(int mask, string className)
    {
        var verb = (mask & CreateChild) != 0 ? "create" : "delete";

        return PermissionAssessment.DangerousInCombination(
            $"Grants the right to {verb} {className} objects, and only that class, rather than "
            + "any child object. Whether that is a takeover depends on which container the entry "
            + "is written on - creating computer objects is rogue domain controller injection on "
            + "the Domain Controllers OU per docs/rules/SEC-121.md - and one entry cannot say "
            + "where it sits; the per-container assessment decides.",
            className);
    }

    private static PermissionAssessment ClassifyExtendedRight(string name)
    {
        if (DangerousExtendedRights.Contains(name))
        {
            return PermissionAssessment.Dangerous(
                $"Grants the {name} extended right, which hands over the target account without "
                + "needing its current password.", name);
        }

        if (ReplicationRights.Contains(name))
        {
            return PermissionAssessment.DangerousInCombination(
                $"Grants {name}. Replication rights are dangerous as a set rather than singly, and "
                + "one entry cannot say what else the principal holds; the per-principal "
                + "assessment decides.", name);
        }

        return PermissionAssessment.NotDangerous(
            $"Grants the {name} extended right, which is not a takeover of the object.", name);
    }

    private static PermissionAssessment ClassifyValidatedWrite(string name) =>
        DangerousValidatedWrites.Contains(name)
            ? PermissionAssessment.Dangerous(
                $"Grants the {name} validated write, which changes who a group contains or how an "
                + "account can be attacked.", name)
            : PermissionAssessment.NotDangerous(
                $"Grants the {name} validated write, which the directory value-checks and which "
                + "does not hand over the object.", name);

    private static PermissionAssessment ClassifyAttributeWrite(string name) =>
        DangerousAttributeWrites.Contains(name)
            ? PermissionAssessment.Dangerous(
                $"Grants write access to {name}, whose value decides who an account is, what it "
                + "may impersonate, or what code runs.", name)
            : PermissionAssessment.NotDangerous(
                $"Grants write access to {name}, which does not confer control of the object.",
                name);

    /// <summary>
    /// A property set is exactly as dangerous as what a forest has actually put in it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This used to answer <see cref="PermissionVerdict.Dangerous"/> for every property set.</b>
    /// The reasoning was that a set is wider than it reads, which is true and is not the same as a
    /// takeover: <c>Personal-Information</c> is addresses, telephone numbers and photographs, and
    /// Active Directory grants <c>SELF</c> write access to it on every user and computer out of the
    /// box. Marking that as a takeover put the product's loudest signal on a default ACE in every
    /// forest, which is how a mark stops being read at all.
    /// </para>
    /// <para>
    /// <b>The answer is derived rather than opinionated.</b> A set is dangerous when it contains an
    /// attribute already judged dangerous by <see cref="DangerousAttributeWrites"/>, which is
    /// sourced to the rule specifications. Nothing here is a second judgement that could drift from
    /// the first - and drift between six places that each judged this separately is the defect this
    /// component was built to end. <c>User-Account-Restrictions</c> comes out dangerous because it
    /// holds <c>userAccountControl</c> and <c>msDS-AllowedToActOnBehalfOfOtherIdentity</c>;
    /// <c>Personal-Information</c> comes out not, because it holds neither.
    /// </para>
    /// <para>
    /// <b>Membership is the forest's, so this cannot be answered offline.</b> A property set names
    /// none of its members - each attribute points back at the set through
    /// <c>attributeSecurityGUID</c> - so a customer can put their own attribute into a
    /// Microsoft-defined set. A run that did not read the schema cannot know, and says so rather
    /// than guessing either way.
    /// </para>
    /// </remarks>
    private PermissionAssessment ClassifyPropertySetWrite(string name, string guid)
    {
        var members = _catalog.MembersOfPropertySet(guid);

        if (members is null)
        {
            return PermissionAssessment.CannotClassify(
                $"Grants write access to the {name} property set, and this run did not read the "
                + "schema that says which attributes are in it, so what the grant reaches is "
                + "unknown. It is not being reported as safe.");
        }

        var dangerous = members
            .Where(DangerousAttributeWrites.Contains)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (dangerous.Count == 0)
        {
            return PermissionAssessment.NotDangerous(
                $"Grants write access to the {name} property set. It is wider than one attribute, "
                + $"and none of the {members.Count} attributes this forest puts in it confers "
                + "control of the object.", name);
        }

        return PermissionAssessment.Dangerous(
            $"Grants write access to the {name} property set, which in this forest includes "
            + $"{string.Join(", ", dangerous)} - whose value decides who an account is, what it "
            + "may impersonate, or what code runs.", name);
    }

    /// <summary>
    /// Reading a property set is a takeover when the set holds a credential.
    /// </summary>
    /// <remarks>
    /// <b>Nothing judged this before.</b> A property-set read fell through to
    /// <see cref="PermissionVerdict.CannotClassify"/>, so an entry granting read of a set holding a
    /// local administrator password was never marked. LAPS keeps its password attributes in a set
    /// for exactly the reason that makes this matter: one grant reaches all of them.
    /// </remarks>
    private PermissionAssessment ClassifyPropertySetRead(string name, string guid)
    {
        var members = _catalog.MembersOfPropertySet(guid);

        if (members is null)
        {
            return PermissionAssessment.CannotClassify(
                $"Grants read access to the {name} property set, and this run did not read the "
                + "schema that says which attributes are in it, so what the grant reaches is "
                + "unknown. It is not being reported as safe.");
        }

        var secrets = members
            .Where(SecretAttributeReads.Contains)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return secrets.Count == 0
            ? PermissionAssessment.NotDangerous(
                $"Grants read access to the {name} property set, and none of the {members.Count} "
                + "attributes this forest puts in it is a credential.", name)
            : PermissionAssessment.Dangerous(
                $"Grants read access to the {name} property set, which in this forest includes "
                + $"{string.Join(", ", secrets)} - held in clear text, so reading is the whole "
                + "attack.", name);
    }

    private static PermissionAssessment ClassifyAttributeRead(string name) =>
        SecretAttributeReads.Contains(name)
            ? PermissionAssessment.Dangerous(
                $"Grants read access to {name}, which holds a local administrator password in "
                + "clear text, so reading it is the whole attack.", name)
            : PermissionAssessment.NotDangerous(
                $"Grants read access to {name}, which is not a credential.", name);

    private static string? Named(IReadOnlyList<SchemaGuidEntry> entries, SchemaGuidKind kind)
    {
        foreach (var entry in entries)
        {
            if (entry.Kind == kind)
                return entry.LdapName;
        }

        return null;
    }

    private static bool IsDeny(AceType aceType) =>
        aceType is AceType.AccessDenied
            or AceType.AccessDeniedObject
            or AceType.AccessDeniedCallback
            or AceType.AccessDeniedCallbackObject;

    /// <summary>
    /// Whether the entry is an audit entry, which since
    /// <c>docs/decisions/0036-capture-never-requests-the-sacl.md</c> can only ever reach this
    /// classifier from inside a DACL.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Capture never reads a SACL, so an audit entry here is a malformed descriptor</b> - and it
    /// is still correctly <see cref="PermissionVerdict.NotDangerous"/>. <c>[MS-DTYP]</c> §2.5.3.2
    /// evaluates a DACL over allow, deny and their object and callback forms; audit types take no
    /// part in it, and every Microsoft description of <c>SYSTEM_AUDIT_ACE</c> places it in a SACL.
    /// It grants nothing wherever it sits.
    /// </para>
    /// <para>
    /// <b>The verdict is right and the anomaly is not this component's to report.</b> Something
    /// wrote a descriptor that should not exist, which is a fact about the customer's forest rather
    /// than a permission, and it is already findable - <c>ace.ace_type</c> stores
    /// <c>SystemAudit</c> by name. Owed to inventory row <c>E1</c> as <c>F-S21-7</c>.
    /// </para>
    /// <para>
    /// <b>Do not generalise from §2.5.3.2 that any unhandled type is harmless.</b> Its case list
    /// omits the deny-callback and callback-object types, which certainly do grant and deny, so the
    /// list is illustrative rather than exhaustive. That is why an unrecognised type still fails
    /// closed to <see cref="PermissionVerdict.CannotClassify"/> at the top of
    /// <see cref="Classify"/>, and audit types do not.
    /// </para>
    /// </remarks>
    private static bool IsAudit(AceType aceType) =>
        aceType is AceType.SystemAudit or AceType.SystemAuditObject;
}
