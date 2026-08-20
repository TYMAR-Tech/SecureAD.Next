namespace SecureAD.Kernel.Schema;

/// <summary>
/// What a schema GUID names.
/// </summary>
/// <remarks>
/// Active Directory reuses a GUID across kinds. <c>bf9679c0-0de6-11d0-a285-00aa003049e2</c> is both
/// the <c>Self-Membership</c> validated write and the <c>member</c> attribute, and which one an ACE
/// means is decided by the ACE's type, not by the GUID. The kind is therefore a property of an
/// entry rather than of a GUID, and the same GUID may appear under more than one.
/// </remarks>
public enum SchemaGuidKind
{
    /// <summary>A control access right, such as <c>User-Force-Change-Password</c>.</summary>
    ExtendedRight,

    /// <summary>A validated write, such as <c>Self-Membership</c>.</summary>
    ValidatedWrite,

    /// <summary>A property set: one name covering a group of attributes.</summary>
    PropertySet,

    /// <summary>A single schema attribute, such as <c>userAccountControl</c>.</summary>
    Attribute,

    /// <summary>A schema object class, such as <c>user</c>.</summary>
    ObjectClass,

    /// <summary>
    /// A control access right whose kind this build could not determine, because the forest
    /// published no <c>validAccesses</c> for it or published a value this build does not recognise.
    /// Never treated as any of the three kinds it might be.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is "could not compute", not "found nothing".</b> The alternative - and what the
    /// product did until <c>S-58</c> finding <c>#13</c> - was to call an unrecognised right an
    /// <see cref="ExtendedRight"/>, on the grounds that it is the reading that grants most. That
    /// reasoning is sound for a severity judgement and wrong here: <c>validAccesses</c> decides
    /// what kind of thing a GUID is, and per <c>S-56</c> R3 and R4 that is a factual
    /// classification. A wrong kind does not make the product louder, it makes it answer a
    /// different question - in
    /// <c>DangerousPermissionClassifier.ClassifyScoped</c> the kind selects the branch, so a
    /// property set called an extended right is judged by the extended-right rule and never
    /// reaches the property-set one. <c>S-53</c> carries the amendment.
    /// </para>
    /// <para>
    /// <b>Only captured evidence produces this.</b> The shipped table classifies every entry it
    /// ships, so a member of this kind always means the forest said something this build could not
    /// read - which is a fact about that forest worth surfacing, not a gap to paper over.
    /// </para>
    /// </remarks>
    Unclassified,
}
