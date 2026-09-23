using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// The oracle: the exact output of the parse-and-normalise pipeline, pinned.
///
/// <para>
/// <b>These are version 4 values, and their provenance differs from version 1's.</b> The version 1
/// constants were copied byte for byte from the previous implementation's oracle, and they passed
/// unedited — that is what proved the port changed nothing, and it is recorded in commit
/// <c>9ce95cf9</c>. Fixing F-S1-2 added <c>ace_type</c> to the hash, so every one of those values
/// necessarily moved. Fixing F-S58-11 added <c>application_data</c>, so they moved again. P-272
/// removed the object's own GUID, so they have moved a third time.
/// </para>
/// <para>
/// The replacements were <b>not</b> read out of the new code, at any step. They were computed by a
/// separate implementation of the written recipe — the fields joined by <c>|</c>, encoded UTF-8,
/// hashed SHA-256, rendered lowercase hex — which was first shown to reproduce all eight known
/// constants of the preceding version from that version's recipe. Reproducing known-correct values
/// is what makes that calculator evidence rather than a second guess; the new values follow from
/// the same arithmetic. So these assertions check the implementation against the specification, not
/// against itself. The calculator used for this move is <c>next/tools/ace-hash-v4.ps1</c>, and it
/// prints the reproduction before it prints an answer.
/// </para>
/// <para>
/// <b>The version 3 values are recorded here because editing one is a finding.</b> They were not
/// wrong; they answered a recipe this product no longer implements, which is a different thing, and
/// keeping them is what lets somebody check by hand that only the leading <c>{object_guid}|</c>
/// came off. Every ACE below carries empty <c>ApplicationData</c>, so each version 4 input is its
/// version 3 input with that prefix removed and nothing else.
/// </para>
/// <list type="table">
/// <listheader><term>Entry</term><description>version 3 hash</description></listheader>
/// <item><term>Administrators, full control</term><description><c>2904f49b84f9dc12463b7cde4cdfe08289e124487638110f3796b122be0f25a6</c></description></item>
/// <item><term>Deny Everyone, explicit</term><description><c>d7cf9b8a608d62ab8ceab7bdb565f3c445a52eed696e860b10de13ef213d0363</c></description></item>
/// <item><term>Object ACE, both GUIDs</term><description><c>51c23024caad2407395a49ddc9446fe24dd4be8219f892b76fb5e633be1e1297</c></description></item>
/// <item><term>Deny Authenticated Users</term><description><c>f9676b1d5b903189684958a068c97572d94a210623a11865a5f6a9f5d96a354c</c></description></item>
/// <item><term>Deny Everyone, inherited</term><description><c>acaeaea85d070b9a485c3c91e7590286b46c6de11b0f2f8a61c12165961603e6</c></description></item>
/// <item><term>Allow SYSTEM, inherited</term><description><c>7db79477bbb20340a7d51dc770bd6e3cabba8410e8baa905f1c26ee2bbdd2614</c></description></item>
/// <item><term>Domain SID trustee</term><description><c>7c3263696953205af78696c3567f33716a0847cc62f304eb817a238b7eaf8b6d</c></description></item>
/// <item><term>Inherited, container inherit</term><description><c>d5b8cac3f73ce93c9231269db40c64d303f149a062b581d80df0e299cd40cb17</c></description></item>
/// </list>
/// <para>
/// The entries <c>application_data</c> exists for are pinned separately, in
/// <c>AceNormalizerTests</c>.
/// </para>
/// <para>
/// The rule is unchanged and now applies to these: <b>a golden value that needs editing is a
/// finding, not a fix.</b> If one of these stops matching, either the pipeline changed or the
/// specification did. Stop, work out which, and decide deliberately.
/// </para>
/// </summary>
public sealed class GoldenAceHashTests
{
    /// <summary>
    /// The object GUID the golden hashes below are computed <i>against nothing</i>: it is the object
    /// the descriptor is normalised for, and since version 4 it reaches no entry hash at all. It is
    /// still passed in, and <see cref="NullDacl"/> still checks it comes back, because the
    /// descriptor does belong to an object even though its entries do not.
    /// </summary>
    private static readonly Guid GoldenObjectGuid =
        Guid.Parse("12345678-abcd-ef01-2345-6789abcdef01");

    /// <summary>Explicit allow, Administrators, full control (<c>0x000F01FF</c>).</summary>
    private const string AdministratorsFullControl =
        "7fc5e517ec60fb64d00a821bb33332f202e80da1cdb35deeae429c81e12dfafa";

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
            "25c45cddb92ccd3d12dea096cf3a7bb4d0315f77b6724a29658ba17e485d491a",
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
            "3c7e605dc065d4b592070e757df0861b4f6844dba33003b6814a24ccd0ff82ec",
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
            "91966f9bb156651a137eedb05dbb3bdbd57294aefc9776b4ff78a5b092bae30e",
            result.Aces[0].AceHash);

        Assert.Equal(AceType.AccessAllowed, result.Aces[1].AceType);
        Assert.False(result.Aces[1].IsInherited);
        Assert.Equal("S-1-5-32-544", result.Aces[1].TrusteeSid);
        Assert.Equal(AdministratorsFullControl, result.Aces[1].AceHash);

        Assert.Equal(AceType.AccessDenied, result.Aces[2].AceType);
        Assert.True(result.Aces[2].IsInherited);
        Assert.Equal("S-1-1-0", result.Aces[2].TrusteeSid);
        Assert.Equal(
            "69defd910cee289e5436e1b563550af3855a5061c7bf7dd864632c3cd29c9ab9",
            result.Aces[2].AceHash);

        Assert.Equal(AceType.AccessAllowed, result.Aces[3].AceType);
        Assert.True(result.Aces[3].IsInherited);
        Assert.Equal("S-1-5-18", result.Aces[3].TrusteeSid);
        Assert.Equal(
            "7ea8672f54d70b78702aa52d45b43c3bd3eb098e164531ac19a29dfda2445b93",
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
            "d0a010b5e1c048f36841bf7eb0d4e32b59930241e609f852e358f4b929a636e1",
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
            "b3632bf50a47e03a025914fb046adfa743d471bf1fa4f4f37bf62936eaf89d3e",
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
    public void EveryGoldenAceRecordsCanonicalizationVersionFour()
    {
        var result = Normalize(
            Ace(AceType.AccessDenied, "S-1-1-0", 0x00000004),
            Ace(AceType.AccessAllowed, "S-1-5-32-544", 0x000F01FF),
            Ace(AceType.AccessAllowed, "S-1-5-18", 0x000F01FF, inherited: true));

        Assert.All(result.Aces, ace =>
        {
            Assert.Equal(AceCanonicalization.Version, ace.CanonicalizationVersion);
            Assert.Equal(4, ace.CanonicalizationVersion);
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
