using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// The oracle: the exact output of the parse-and-normalise pipeline, pinned.
///
/// <para>
/// <b>These are version 3 values, and their provenance differs from version 1's.</b> The version 1
/// constants were copied byte for byte from the previous implementation's oracle, and they passed
/// unedited — that is what proved the port changed nothing, and it is recorded in commit
/// <c>9ce95cf9</c>. Fixing F-S1-2 added <c>ace_type</c> to the hash, so every one of those values
/// necessarily moved. Fixing F-S58-11 added <c>application_data</c>, so they moved again.
/// </para>
/// <para>
/// The replacements were <b>not</b> read out of the new code, at either step. They were computed by
/// a separate implementation of the written recipe — the fields joined by <c>|</c>, encoded UTF-8,
/// hashed SHA-256, rendered lowercase hex — which was first shown to reproduce all eight known
/// constants of the preceding version from that version's recipe. Reproducing known-correct values
/// is what makes that calculator evidence rather than a second guess; the new values follow from
/// the same arithmetic. So these assertions check the implementation against the specification, not
/// against itself.
/// </para>
/// <para>
/// Every ACE below carries empty <c>ApplicationData</c>, so the version 3 field these were computed
/// with is the empty string and each input is its version 2 input plus a trailing <c>|</c>. The
/// entries that field exists for are pinned separately, in <c>AceNormalizerTests</c>.
/// </para>
/// <para>
/// The rule is unchanged and now applies to these: <b>a golden value that needs editing is a
/// finding, not a fix.</b> If one of these stops matching, either the pipeline changed or the
/// specification did. Stop, work out which, and decide deliberately.
/// </para>
/// </summary>
public sealed class GoldenAceHashTests
{
    /// <summary>The object GUID every golden hash below was computed against.</summary>
    private static readonly Guid GoldenObjectGuid =
        Guid.Parse("12345678-abcd-ef01-2345-6789abcdef01");

    /// <summary>Explicit allow, Administrators, full control (<c>0x000F01FF</c>).</summary>
    private const string AdministratorsFullControl =
        "2904f49b84f9dc12463b7cde4cdfe08289e124487638110f3796b122be0f25a6";

    [Fact]
    public void DenyAndAllow()
    {
        var result = Normalize(
            Ace(AceType.AccessAllowed, "S-1-5-32-544", 0x000F01FF),
            Ace(AceType.AccessDenied, "S-1-1-0", 0x00000004));

        Assert.Equal(2, result.Aces.Count);
        Assert.Empty(result.Errors);

        Assert.Equal(AceType.AccessDenied, result.Aces[0].AceType);
        Assert.Equal("S-1-1-0", result.Aces[0].TrusteeSid);
        Assert.Equal(0x00000004, result.Aces[0].AccessMask);
        Assert.Equal(
            "d7cf9b8a608d62ab8ceab7bdb565f3c445a52eed696e860b10de13ef213d0363",
            result.Aces[0].AceHash);

        Assert.Equal(AceType.AccessAllowed, result.Aces[1].AceType);
        Assert.Equal("S-1-5-32-544", result.Aces[1].TrusteeSid);
        Assert.Equal(0x000F01FF, result.Aces[1].AccessMask);
        Assert.Equal(AdministratorsFullControl, result.Aces[1].AceHash);
    }

    [Fact]
    public void ObjectAceWithBothGuids()
    {
        var result = Normalize(new ParsedAce(
            AceType.AccessAllowedObject, 0x00, 0x00000010, "S-1-5-32-544",
            "bf967aba-0de6-11d0-a285-00aa003049e2",
            "bf967a86-0de6-11d0-a285-00aa003049e2",
            false, 0, 0,
            Ordinal: 0,
            ObjectFlags: ObjectTypePresent | InheritedObjectTypePresent,
            ApplicationData: []));

        var ace = Assert.Single(result.Aces);
        Assert.Empty(result.Errors);
        Assert.Equal(AceType.AccessAllowedObject, ace.AceType);
        Assert.Equal("S-1-5-32-544", ace.TrusteeSid);
        Assert.Equal(0x00000010, ace.AccessMask);
        Assert.Equal("bf967aba-0de6-11d0-a285-00aa003049e2", ace.ObjectTypeGuid);
        Assert.Equal("bf967a86-0de6-11d0-a285-00aa003049e2", ace.InheritedObjectTypeGuid);
        Assert.False(ace.IsInherited);
        Assert.Equal(
            "51c23024caad2407395a49ddc9446fe24dd4be8219f892b76fb5e633be1e1297",
            ace.AceHash);
    }

    [Fact]
    public void AllFourOrderingCategories()
    {
        var result = Normalize(
            Ace(AceType.AccessAllowed, "S-1-5-18", 0x000F01FF, inherited: true),
            Ace(AceType.AccessDenied, "S-1-1-0", 0x00000004, inherited: true),
            Ace(AceType.AccessAllowed, "S-1-5-32-544", 0x000F01FF),
            Ace(AceType.AccessDenied, "S-1-5-11", 0x00000004));

        Assert.Equal(4, result.Aces.Count);
        Assert.Empty(result.Errors);

        Assert.Equal(AceType.AccessDenied, result.Aces[0].AceType);
        Assert.False(result.Aces[0].IsInherited);
        Assert.Equal("S-1-5-11", result.Aces[0].TrusteeSid);
        Assert.Equal(
            "f9676b1d5b903189684958a068c97572d94a210623a11865a5f6a9f5d96a354c",
            result.Aces[0].AceHash);

        Assert.Equal(AceType.AccessAllowed, result.Aces[1].AceType);
        Assert.False(result.Aces[1].IsInherited);
        Assert.Equal("S-1-5-32-544", result.Aces[1].TrusteeSid);
        Assert.Equal(AdministratorsFullControl, result.Aces[1].AceHash);

        Assert.Equal(AceType.AccessDenied, result.Aces[2].AceType);
        Assert.True(result.Aces[2].IsInherited);
        Assert.Equal("S-1-1-0", result.Aces[2].TrusteeSid);
        Assert.Equal(
            "acaeaea85d070b9a485c3c91e7590286b46c6de11b0f2f8a61c12165961603e6",
            result.Aces[2].AceHash);

        Assert.Equal(AceType.AccessAllowed, result.Aces[3].AceType);
        Assert.True(result.Aces[3].IsInherited);
        Assert.Equal("S-1-5-18", result.Aces[3].TrusteeSid);
        Assert.Equal(
            "7db79477bbb20340a7d51dc770bd6e3cabba8410e8baa905f1c26ee2bbdd2614",
            result.Aces[3].AceHash);
    }

    /// <summary>
    /// <c>GENERIC_ALL</c> expands to exactly the mask an explicit full-control ACE carries, so the
    /// two hash the same. That equality is the whole reason the expander exists.
    /// </summary>
    [Fact]
    public void GenericAllHashesAsItsExpansion()
    {
        var result = Normalize(
            Ace(AceType.AccessAllowed, "S-1-5-32-544", unchecked((int)0x10000000)));

        var ace = Assert.Single(result.Aces);
        Assert.Equal(0x000F01FF, ace.AccessMask);
        Assert.Equal(0, ace.AccessMask & unchecked((int)0x10000000));
        Assert.Equal(AdministratorsFullControl, ace.AceHash);
    }

    [Fact]
    public void DuplicatesCollapseToOne()
    {
        var ace = Ace(AceType.AccessAllowed, "S-1-5-32-544", 0x000F01FF);

        var result = Normalize(ace, ace);

        Assert.Equal(AdministratorsFullControl, Assert.Single(result.Aces).AceHash);
    }

    [Fact]
    public void DomainSidTrustee()
    {
        var result = Normalize(
            Ace(AceType.AccessAllowed, "S-1-5-21-1234567890-987654321-111222333-512", 0x000F01FF));

        var ace = Assert.Single(result.Aces);
        Assert.Equal("S-1-5-21-1234567890-987654321-111222333-512", ace.TrusteeSid);
        Assert.Equal(
            "7c3263696953205af78696c3567f33716a0847cc62f304eb817a238b7eaf8b6d",
            ace.AceHash);
    }

    [Fact]
    public void InheritedAceWithContainerInherit()
    {
        // INHERITED_ACE (0x10) | CONTAINER_INHERIT_ACE (0x02)
        var result = Normalize(new ParsedAce(
            AceType.AccessAllowed, 0x12, 0x000F01FF, "S-1-5-32-544",
            null, null, true, 0x02, 0x00,
            Ordinal: 0, ObjectFlags: 0, ApplicationData: []));

        var ace = Assert.Single(result.Aces);
        Assert.True(ace.IsInherited);
        Assert.Equal(0x02, ace.InheritanceFlags);
        Assert.Equal(0x00, ace.PropagationFlags);
        Assert.Equal(
            "d5b8cac3f73ce93c9231269db40c64d303f149a062b581d80df0e299cd40cb17",
            ace.AceHash);
    }

    [Fact]
    public void NullDacl()
    {
        var result = AceNormalizer.Normalize(
            GoldenObjectGuid,
            new ParsedSecurityDescriptor(
                "S-1-5-18", "S-1-5-32-544", DaclState.Null, false, [], 0x8000, [], DaclCompleteness: DaclCompleteness.Complete, DaclWasCanonical: true));

        Assert.Equal(DaclState.Null, result.DaclState);
        Assert.Empty(result.Aces);
        Assert.False(result.IsDaclProtected);
        Assert.Equal("S-1-5-18", result.OwnerSid);
        Assert.Equal("S-1-5-32-544", result.GroupSid);
        Assert.Equal(GoldenObjectGuid, result.ObjectGuid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void ProtectedDacl()
    {
        var result = AceNormalizer.Normalize(
            GoldenObjectGuid,
            new ParsedSecurityDescriptor(
                "S-1-5-18", null, DaclState.Present, true,
                [Ace(AceType.AccessAllowed, "S-1-5-32-544", 0x000F01FF)],
                0x9004, [], DaclCompleteness: DaclCompleteness.Complete, DaclWasCanonical: true));

        Assert.True(result.IsDaclProtected);
        Assert.Equal(AdministratorsFullControl, Assert.Single(result.Aces).AceHash);
    }

    [Fact]
    public void TheWholePipelineIsDeterministic()
    {
        var sd = Sd(
            Ace(AceType.AccessAllowed, "S-1-5-18", 0x000F01FF, inherited: true),
            Ace(AceType.AccessDenied, "S-1-1-0", 0x00000004, inherited: true),
            Ace(AceType.AccessAllowed, "S-1-5-32-544", 0x000F01FF),
            Ace(AceType.AccessDenied, "S-1-5-11", 0x00000004),
            new ParsedAce(AceType.AccessAllowedObject, 0x00, 0x00000010, "S-1-5-32-544",
                "bf967aba-0de6-11d0-a285-00aa003049e2", null, false, 0, 0,
                Ordinal: 4, ObjectFlags: ObjectTypePresent, ApplicationData: []));

        var first = AceNormalizer.Normalize(GoldenObjectGuid, sd);
        var second = AceNormalizer.Normalize(GoldenObjectGuid, sd);

        Assert.Equal(first.Aces, second.Aces);
    }

    [Fact]
    public void EveryGoldenAceRecordsCanonicalizationVersionThree()
    {
        var result = Normalize(
            Ace(AceType.AccessDenied, "S-1-1-0", 0x00000004),
            Ace(AceType.AccessAllowed, "S-1-5-32-544", 0x000F01FF),
            Ace(AceType.AccessAllowed, "S-1-5-18", 0x000F01FF, inherited: true));

        Assert.All(result.Aces, ace =>
        {
            Assert.Equal(AceCanonicalization.Version, ace.CanonicalizationVersion);
            Assert.Equal(3, ace.CanonicalizationVersion);
        });
    }

    [Fact]
    public void GenericAllOnAnObjectAceStillExpands()
    {
        var generic = Normalize(new ParsedAce(
            AceType.AccessAllowedObject, 0x00, unchecked((int)0x10000000), "S-1-5-32-544",
            "bf967aba-0de6-11d0-a285-00aa003049e2", null, false, 0, 0,
            Ordinal: 0, ObjectFlags: ObjectTypePresent, ApplicationData: []));
        var explicitRights = Normalize(new ParsedAce(
            AceType.AccessAllowedObject, 0x00, 0x00000010, "S-1-5-32-544",
            "bf967aba-0de6-11d0-a285-00aa003049e2", null, false, 0, 0,
            Ordinal: 0, ObjectFlags: ObjectTypePresent, ApplicationData: []));

        Assert.NotEqual(0x00000010, generic.Aces[0].AccessMask);
        Assert.NotEqual(generic.Aces[0].AceHash, explicitRights.Aces[0].AceHash);
    }

    /// <summary>ACE_OBJECT_TYPE_PRESENT, so a fixture states presence the way the wire does.</summary>
    private const int ObjectTypePresent = 0x01;

    /// <summary>ACE_INHERITED_OBJECT_TYPE_PRESENT.</summary>
    private const int InheritedObjectTypePresent = 0x02;

    private static ParsedAce Ace(AceType type, string sid, int mask, bool inherited = false) =>
        new(type, inherited ? (byte)0x10 : (byte)0x00, mask, sid, null, null, inherited, 0, 0,
            Ordinal: 0, ObjectFlags: 0, ApplicationData: []);

    private static ParsedSecurityDescriptor Sd(params ParsedAce[] aces)
    {
        var stored = aces.Select((ace, index) => ace with { Ordinal = index }).ToArray();

        return new(
            "S-1-5-18", "S-1-5-32-544", DaclState.Present, false, stored, 0x8004, [],
            DaclCompleteness: DaclCompleteness.Complete,
            DaclWasCanonical: AceCanonicalization.IsCanonicalOrder(stored));
    }

    private static AceNormalizationResult Normalize(params ParsedAce[] aces) =>
        AceNormalizer.Normalize(GoldenObjectGuid, Sd(aces));
}
