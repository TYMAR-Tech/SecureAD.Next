using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// Normalising parsed ACEs into a canonical, comparable form: generic rights expanded, GUIDs
/// lowercased, a deterministic hash per ACE, canonical ordering, and duplicates removed.
/// </summary>
public sealed class AceNormalizerTests
{
    private static readonly Guid ObjectGuid = Guid.Parse("aaaaaaaa-1111-2222-3333-444444444444");

    // --- Canonical ordering ---
    //
    // Deny sorts before allow because that is the order the directory evaluates them in. A DACL
    // arriving out of that order is not an error; it must still normalise.

    [Fact]
    public void WhenAllowPrecedesDenyOnTheWire_ThenDenySortsFirst()
    {
        var sd = Aces.Sd(
            Aces.Allow("S-1-5-32-544", 0x000F01FF),
            Aces.Deny("S-1-1-0", 0x00000004));

        var result = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.Equal(AceType.AccessDenied, result.Aces[0].AceType);
        Assert.Equal(AceType.AccessAllowed, result.Aces[1].AceType);
    }

    [Fact]
    public void WhenBothExplicitAndInherited_ThenExplicitSortsFirst()
    {
        var sd = Aces.Sd(
            Aces.Allow("S-1-5-32-544", 0x000F01FF, inherited: true),
            Aces.Allow("S-1-5-32-544", 0x000F01FF, inherited: false));

        var result = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.False(result.Aces[0].IsInherited);
        Assert.True(result.Aces[1].IsInherited);
    }

    /// <summary>
    /// The four ordering categories in full: explicit deny, explicit allow, inherited deny,
    /// inherited allow. Fed in reverse so the assertion is about the sort rather than the input.
    /// </summary>
    [Fact]
    public void WhenAllFourCategoriesArePresent_ThenTheyOrderDenyBeforeAllowAndExplicitBeforeInherited()
    {
        var sd = Aces.Sd(
            Aces.Allow("S-1-5-18", 0x000F01FF, inherited: true),
            Aces.Deny("S-1-1-0", 0x00000004, inherited: true),
            Aces.Allow("S-1-5-32-544", 0x000F01FF),
            Aces.Deny("S-1-5-11", 0x00000004));

        var result = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.Collection(
            result.Aces,
            a => AssertCategory(a, AceType.AccessDenied, inherited: false),
            a => AssertCategory(a, AceType.AccessAllowed, inherited: false),
            a => AssertCategory(a, AceType.AccessDenied, inherited: true),
            a => AssertCategory(a, AceType.AccessAllowed, inherited: true));
    }

    [Fact]
    public void WhenTwoAcesShareACategory_ThenTheySortByTrusteeSid()
    {
        var sd = Aces.Sd(
            Aces.Allow("S-1-5-32-544", 0x000F01FF),
            Aces.Allow("S-1-1-0", 0x000F01FF));

        var result = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.Equal("S-1-1-0", result.Aces[0].TrusteeSid);
        Assert.Equal("S-1-5-32-544", result.Aces[1].TrusteeSid);
    }

    [Fact]
    public void WhenTwoAcesShareATrustee_ThenTheySortByAccessMask()
    {
        var sd = Aces.Sd(
            Aces.Allow("S-1-5-32-544", 0x000F01FF),
            Aces.Allow("S-1-5-32-544", 0x00000010));

        var result = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.Equal(0x00000010, result.Aces[0].AccessMask);
        Assert.Equal(0x000F01FF, result.Aces[1].AccessMask);
    }

    // --- The hash ---

    [Fact]
    public void WhenTheSameDescriptorIsNormalizedTwice_ThenTheHashesMatch()
    {
        var sd = Aces.Sd(Aces.Allow("S-1-5-32-544", 0x000F01FF));

        var first = AceNormalizer.Normalize(ObjectGuid, sd);
        var second = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.Equal(first.Aces[0].AceHash, second.Aces[0].AceHash);
    }

    [Fact]
    public void WhenAHashIsComputed_ThenItIsSixtyFourLowercaseHexCharacters()
    {
        var result = AceNormalizer.Normalize(
            ObjectGuid, Aces.Sd(Aces.Allow("S-1-5-32-544", 0x000F01FF)));

        var hash = result.Aces[0].AceHash;

        Assert.Equal(64, hash.Length);
        Assert.All(hash, c => Assert.Contains(c, "0123456789abcdef"));
    }

    [Fact]
    public void WhenTheTrusteeDiffers_ThenTheHashDiffers()
    {
        AssertHashesDiffer(
            Aces.Sd(Aces.Allow("S-1-5-32-544", 0x000F01FF)),
            Aces.Sd(Aces.Allow("S-1-5-18", 0x000F01FF)));
    }

    [Fact]
    public void WhenTheAccessMaskDiffers_ThenTheHashDiffers()
    {
        AssertHashesDiffer(
            Aces.Sd(Aces.Allow("S-1-5-32-544", 0x000F01FF)),
            Aces.Sd(Aces.Allow("S-1-5-32-544", 0x00000010)));
    }

    [Fact]
    public void WhenTheAceTypeDiffers_ThenTheHashDiffers()
    {
        AssertHashesDiffer(
            Aces.Sd(Aces.Allow("S-1-5-11", 0x00000020)),
            Aces.Sd(Aces.Deny("S-1-5-11", 0x00000020)));
    }

    [Fact]
    public void WhenInheritanceDiffers_ThenTheHashDiffers()
    {
        AssertHashesDiffer(
            Aces.Sd(Aces.Allow("S-1-5-32-544", 0x000F01FF, inherited: false)),
            Aces.Sd(Aces.Allow("S-1-5-32-544", 0x000F01FF, inherited: true)));
    }

    /// <summary>
    /// The same grant found on two objects is one fact, and the hash says so. This is the property
    /// the whole of <c>P-272</c> rests on: until canonicalization version 4 the hash covered the
    /// object the entry was found on, so an entry inherited by a hundred thousand descendants was a
    /// hundred thousand different values and had to be stored a hundred thousand times. The
    /// production capture of 2026-09-23 measured 294 copies of each distinct entry in a 51.08 GB
    /// file.
    /// </summary>
    /// <remarks>
    /// The assertion here used to be <c>NotEqual</c>, under the name
    /// <c>WhenTheObjectDiffers_ThenTheHashDiffers</c>. It was not failing and it was not wrong; it
    /// pinned a decision that was later measured and reversed, which is what a test is supposed to
    /// do. The object a descriptor belongs to is still carried - on the descriptor, where
    /// <see cref="AceNormalizationResult.ObjectGuid"/> holds it and the writer refuses a descriptor
    /// attributed to the wrong object.
    /// </remarks>
    [Fact]
    public void WhenTheObjectDiffers_ThenTheHashIsTheSame()
    {
        var sd = Aces.Sd(Aces.Allow("S-1-5-32-544", 0x000F01FF));

        var first = AceNormalizer.Normalize(Guid.Parse("aaaaaaaa-0000-0000-0000-000000000001"), sd);
        var second = AceNormalizer.Normalize(Guid.Parse("bbbbbbbb-0000-0000-0000-000000000002"), sd);

        Assert.Equal(first.Aces[0].AceHash, second.Aces[0].AceHash);
        Assert.Equal(Guid.Parse("aaaaaaaa-0000-0000-0000-000000000001"), first.ObjectGuid);
        Assert.Equal(Guid.Parse("bbbbbbbb-0000-0000-0000-000000000002"), second.ObjectGuid);
    }

    // --- Deduplication ---

    [Fact]
    public void WhenTwoAcesAreIdentical_ThenOneSurvives()
    {
        var sd = Aces.Sd(
            Aces.Allow("S-1-5-32-544", 0x000F01FF),
            Aces.Allow("S-1-5-32-544", 0x000F01FF));

        var result = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.Single(result.Aces);
    }

    [Fact]
    public void WhenTwoAcesDifferOnlyByInheritance_ThenBothSurvive()
    {
        var sd = Aces.Sd(
            Aces.Allow("S-1-5-32-544", 0x000F01FF, inherited: false),
            Aces.Allow("S-1-5-32-544", 0x000F01FF, inherited: true));

        var result = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.Equal(2, result.Aces.Count);
    }

    // --- Two ACEs that differ only by type are two ACEs (F-S1-2) ---
    //
    // Windows defines an ACE by four things: the trustee, the access mask, the type, and the
    // inheritance flags. Until canonicalization version 2 the hash covered three of them, so the
    // pairs below collided and deduplication discarded one of each silently.

    [Fact]
    public void WhenADenyAndAnAllowDifferOnlyByType_ThenBothSurvive()
    {
        var sd = Aces.Sd(
            Aces.Deny("S-1-5-11", 0x00000020),
            Aces.Allow("S-1-5-11", 0x00000020));

        var result = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.Equal(2, result.Aces.Count);
        Assert.Contains(result.Aces, a => a.AceType == AceType.AccessDenied);
        Assert.Contains(result.Aces, a => a.AceType == AceType.AccessAllowed);
    }

    /// <summary>
    /// An object ACE may legitimately carry neither GUID — the object-ACE flags field defines 0 as
    /// meaning neither is present. Every other field is then identical to a plain ACE, so this is
    /// the likelier of the two collisions.
    /// </summary>
    [Fact]
    public void WhenAPlainAceAndAnObjectAceWithNoGuidsAreBothPresent_ThenBothSurvive()
    {
        var sd = Aces.Sd(PlainAllow(), ObjectAllowWithNoGuids());

        var result = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.Equal(2, result.Aces.Count);
        Assert.Contains(result.Aces, a => a.AceType == AceType.AccessAllowed);
        Assert.Contains(result.Aces, a => a.AceType == AceType.AccessAllowedObject);
    }

    /// <summary>
    /// The canonical form must not depend on the order the ACEs arrived in. Those two ACEs tie on
    /// every other comparison key, and the sort is not stable, so before version 2 the survivor —
    /// and therefore the stored record — was decided by wire order.
    /// </summary>
    [Fact]
    public void WhenTheSameAcesArriveInEitherOrder_ThenTheCanonicalFormIsIdentical()
    {
        var forwards = AceNormalizer.Normalize(
            ObjectGuid, Aces.Sd(PlainAllow(), ObjectAllowWithNoGuids()));
        var backwards = AceNormalizer.Normalize(
            ObjectGuid, Aces.Sd(ObjectAllowWithNoGuids(), PlainAllow()));

        Assert.Equal(forwards.Aces, backwards.Aces);
    }

    private static ParsedAce PlainAllow() =>
        new(AceType.AccessAllowed, 0x00, 0x00000020, "S-1-5-11", null, null, false, 0, 0,
            Ordinal: 0, ObjectFlags: 0, ApplicationData: []);

    private static ParsedAce ObjectAllowWithNoGuids() =>
        new(AceType.AccessAllowedObject, 0x00, 0x00000020, "S-1-5-11", null, null, false, 0, 0,
            Ordinal: 0, ObjectFlags: 0, ApplicationData: []);

    // --- Two ACEs that differ only by condition are two ACEs (F-S58-11) ---
    //
    // The same failure as F-S1-2, one level down. A conditional ACE is defined by its condition,
    // and until canonicalization version 3 the hash covered every field except that one - so the
    // pairs below collided and deduplication discarded one of each before it was ever written.
    // This is evidence loss in the projection rather than a display gap: the descriptor's
    // raw_bytes still hold both entries, but every read path goes through the ace table.

    [Fact]
    public void WhenTwoConditionalAcesDifferOnlyByTheirCondition_ThenBothSurvive()
    {
        var sd = Aces.Sd(
            Conditional([0x61, 0x72, 0x74, 0x78]),
            Conditional([0x61, 0x72, 0x74, 0x79]));

        var result = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.Equal(2, result.Aces.Count);
    }

    /// <summary>
    /// A conditional entry may not apply at all; its unconditional twin always does. Collapsing
    /// them reports the weaker grant as the stronger one, or loses the stronger one entirely,
    /// depending on which arrived first.
    /// </summary>
    [Fact]
    public void WhenAConditionalAceSitsBesideAnIdenticalUnconditionalOne_ThenBothSurvive()
    {
        var sd = Aces.Sd(
            Conditional([0x61, 0x72, 0x74, 0x78]),
            Conditional([]));

        var result = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.Equal(2, result.Aces.Count);
    }

    [Fact]
    public void WhenTheConditionDiffers_ThenTheHashDiffers()
    {
        AssertHashesDiffer(
            Aces.Sd(Conditional([0x61, 0x72, 0x74, 0x78])),
            Aces.Sd(Conditional([0x61, 0x72, 0x74, 0x79])));
    }

    /// <summary>
    /// A callback ACE carrying <paramref name="condition"/> as its application data. Every other
    /// field is fixed, so the condition is the only thing that can separate two of these.
    /// </summary>
    private static ParsedAce Conditional(byte[] condition) =>
        new(AceType.AccessAllowedCallback, 0x00, 0x00000020, "S-1-5-11", null, null, false, 0, 0,
            Ordinal: 0, ObjectFlags: 0, ApplicationData: condition);

    // --- Generic rights, through the pipeline ---

    [Fact]
    public void WhenAnAceGrantsGenericAll_ThenTheStoredMaskIsExpanded()
    {
        var sd = Aces.Sd(Aces.Allow("S-1-5-32-544", unchecked((int)0x10000000)));

        var result = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.Equal(0x000F01FF, result.Aces[0].AccessMask);
    }

    /// <summary>
    /// The reason expansion happens before hashing rather than after: an ACE written as
    /// <c>GENERIC_ALL</c> and the same permission written out in full must dedupe to one ACE, not
    /// compare as two.
    /// </summary>
    [Fact]
    public void WhenTheSamePermissionIsWrittenBothWays_ThenItDeduplicatesToOneAce()
    {
        var sd = Aces.Sd(
            Aces.Allow("S-1-5-32-544", unchecked((int)0x10000000)),
            Aces.Allow("S-1-5-32-544", 0x000F01FF));

        var result = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.Single(result.Aces);
    }

    // --- A null DACL is not an empty DACL ---

    [Fact]
    public void WhenTheDaclIsNull_ThenNormalizationSaysSoRatherThanReportingNoAces()
    {
        var sd = new ParsedSecurityDescriptor(
            "S-1-5-18", null, DaclState.Null, false, [], 0x8004, [], DaclCompleteness: DaclCompleteness.Complete, DaclWasCanonical: true);

        var result = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.Equal(DaclState.Null, result.DaclState);
        Assert.Empty(result.Aces);
    }

    [Fact]
    public void WhenTheDaclIsEmpty_ThenNormalizationSaysSoRatherThanReportingNoAces()
    {
        var sd = new ParsedSecurityDescriptor(
            "S-1-5-18", null, DaclState.Empty, false, [], 0x8004, [], DaclCompleteness: DaclCompleteness.Complete, DaclWasCanonical: true);

        var result = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.Equal(DaclState.Empty, result.DaclState);
        Assert.Empty(result.Aces);
    }

    /// <summary>
    /// Both carry no ACEs, and they mean opposite things: a null DACL grants everyone everything,
    /// an empty DACL grants nobody anything. The result must let a reader tell them apart.
    /// </summary>
    [Fact]
    public void WhenComparingANullDaclWithAnEmptyOne_ThenTheyAreDistinguishable()
    {
        var nullDacl = AceNormalizer.Normalize(
            ObjectGuid,
            new ParsedSecurityDescriptor("S-1-5-18", null, DaclState.Null, false, [], 0x8004, [], DaclCompleteness: DaclCompleteness.Complete, DaclWasCanonical: true));
        var emptyDacl = AceNormalizer.Normalize(
            ObjectGuid,
            new ParsedSecurityDescriptor("S-1-5-18", null, DaclState.Empty, false, [], 0x8004, [], DaclCompleteness: DaclCompleteness.Complete, DaclWasCanonical: true));

        Assert.Empty(nullDacl.Aces);
        Assert.Empty(emptyDacl.Aces);
        Assert.NotEqual(nullDacl.DaclState, emptyDacl.DaclState);
    }

    // --- Carried metadata ---

    [Fact]
    public void WhenNormalized_ThenOwnerGroupProtectionAndObjectAreCarriedThrough()
    {
        var sd = new ParsedSecurityDescriptor(
            "S-1-5-18", "S-1-5-32-544", DaclState.Present, true,
            [Aces.Allow("S-1-5-32-544", 0x000F01FF)], 0x9004, [], DaclCompleteness: DaclCompleteness.Complete, DaclWasCanonical: true);

        var result = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.Equal("S-1-5-18", result.OwnerSid);
        Assert.Equal("S-1-5-32-544", result.GroupSid);
        Assert.True(result.IsDaclProtected);
        Assert.Equal(ObjectGuid, result.ObjectGuid);
    }

    [Fact]
    public void WhenNormalized_ThenEachAceRecordsTheCanonicalizationVersionThatProducedIt()
    {
        var result = AceNormalizer.Normalize(
            ObjectGuid, Aces.Sd(Aces.Allow("S-1-5-32-544", 0x000F01FF)));

        Assert.Equal(AceCanonicalization.Version, result.Aces[0].CanonicalizationVersion);
    }

    [Fact]
    public void WhenAnObjectAceCarriesGuids_ThenTheySurviveNormalization()
    {
        var ace = new ParsedAce(
            AceType.AccessAllowedObject, 0x00, 0x00000010, "S-1-5-32-544",
            "bf967aba-0de6-11d0-a285-00aa003049e2",
            "bf967a86-0de6-11d0-a285-00aa003049e2",
            false, 0, 0,
            Ordinal: 0, ObjectFlags: 0x03, ApplicationData: []);

        var result = AceNormalizer.Normalize(ObjectGuid, Aces.Sd(ace));

        Assert.Equal("bf967aba-0de6-11d0-a285-00aa003049e2", result.Aces[0].ObjectTypeGuid);
        Assert.Equal("bf967a86-0de6-11d0-a285-00aa003049e2", result.Aces[0].InheritedObjectTypeGuid);
    }

    // --- Errors ---

    [Fact]
    public void WhenParsingReportedDamage_ThenNormalizationCarriesItForward()
    {
        var sd = new ParsedSecurityDescriptor(
            "S-1-5-18", null, DaclState.Present, false,
            [Aces.Allow("S-1-5-32-544", 0x000F01FF)], 0x8004, ["Some prior error"], DaclCompleteness: DaclCompleteness.Complete, DaclWasCanonical: true);

        var result = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.Contains("Some prior error", result.Errors);
    }

    [Fact]
    public void WhenParsingReportedNoDamage_ThenNormalizationInventsNone()
    {
        var result = AceNormalizer.Normalize(
            ObjectGuid, Aces.Sd(Aces.Allow("S-1-5-32-544", 0x000F01FF)));

        Assert.Empty(result.Errors);
    }

    [Fact]
    public void WhenTheDaclIsNull_ThenParseErrorsAreStillCarriedForward()
    {
        var sd = new ParsedSecurityDescriptor(
            null, null, DaclState.Null, false, [], 0, ["Security descriptor too short"], DaclCompleteness: DaclCompleteness.Complete, DaclWasCanonical: true);

        var result = AceNormalizer.Normalize(ObjectGuid, sd);

        Assert.Contains("Security descriptor too short", result.Errors);
    }

    [Fact]
    public void WhenTheDescriptorIsNull_ThenNormalizationRefusesIt()
    {
        Assert.Throws<ArgumentNullException>(
            () => AceNormalizer.Normalize(ObjectGuid, null!));
    }

    private static void AssertCategory(CanonicalAce ace, AceType type, bool inherited)
    {
        Assert.Equal(type, ace.AceType);
        Assert.Equal(inherited, ace.IsInherited);
    }

    private static void AssertHashesDiffer(
        ParsedSecurityDescriptor first, ParsedSecurityDescriptor second)
    {
        Assert.NotEqual(
            AceNormalizer.Normalize(ObjectGuid, first).Aces[0].AceHash,
            AceNormalizer.Normalize(ObjectGuid, second).Aces[0].AceHash);
    }
}
