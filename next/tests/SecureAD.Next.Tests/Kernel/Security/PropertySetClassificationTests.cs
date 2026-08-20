using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// A property set is exactly as dangerous as what a forest has actually put in it.
/// </summary>
/// <remarks>
/// <para>
/// <b>These did not exist, which is how the defect survived.</b> Nothing in
/// <c>DangerousPermissionClassifierTests</c> covered a property-set permission at all, so the
/// classifier answered <see cref="PermissionVerdict.Dangerous"/> for every one of them, unexamined
/// and untested, until an operator saw <c>Write Personal-Information</c> marked as a takeover on a
/// default <c>SELF</c> entry.
/// </para>
/// <para>
/// <b>Why the answer has to come from the forest.</b> A property set names none of its members;
/// each attribute points back at the set through <c>attributeSecurityGUID</c>. A customer can put
/// their own attribute into a Microsoft-defined set, so no table shipped with a product can say
/// what a set grants in a particular directory.
/// </para>
/// </remarks>
public sealed class PropertySetClassificationTests
{
    private const int ReadProperty = 0x00000010;
    private const int WriteProperty = 0x00000020;

    /// <summary>Personal-Information. Addresses and telephone numbers, per Microsoft's schema.</summary>
    private const string PersonalInformation = "77b5b886-944a-11d1-aebd-0000f80367c1";

    /// <summary>
    /// User-Account-Restrictions, which Microsoft documents as holding <c>userAccountControl</c>
    /// and <c>msDS-AllowedToActOnBehalfOfOtherIdentity</c>.
    /// </summary>
    private const string UserAccountRestrictions = "4c164200-20c0-11d0-a768-00aa006e0529";

    /// <summary>A set holding LAPS passwords, which is a credential rather than a property.</summary>
    private const string LapsPasswordAttributes = "aaaaaaaa-1111-2222-3333-444444444444";

    /// <summary>
    /// <c>ms-LAPS-Encrypted-Password-Attributes</c>, as Microsoft publishes it: a real property
    /// set, with <c>Valid accesses: 48</c>.
    /// </summary>
    private const string WindowsLapsEncryptedAttributes = "f3531ec6-6330-4f8e-8d39-7a671fbac605";

    // -------------------------------------------------------------------------------------------
    // Writing.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The defect this session fixed. Active Directory grants <c>SELF</c> write access to
    /// Personal-Information on every user and computer out of the box, so marking it a takeover put
    /// the loudest signal the product has on a default entry in every forest.
    /// </summary>
    [Fact]
    public void WritingASetOfAddressesAndTelephoneNumbersIsNotATakeover()
    {
        var result = Classifier(PersonalInformation, "streetAddress", "telephoneNumber")
            .Classify(AceType.AccessAllowedObject, WriteProperty, PersonalInformation);

        Assert.Equal(PermissionVerdict.NotDangerous, result.Verdict);
    }

    /// <summary>
    /// And the same set is a takeover the moment a forest puts something dangerous in it, which a
    /// shipped list could never have noticed.
    /// </summary>
    [Fact]
    public void WritingTheSameSetIsATakeoverWhenTheForestAddedADangerousAttributeToIt()
    {
        var result = Classifier(PersonalInformation, "streetAddress", "servicePrincipalName")
            .Classify(AceType.AccessAllowedObject, WriteProperty, PersonalInformation);

        Assert.Equal(PermissionVerdict.Dangerous, result.Verdict);
    }

    [Fact]
    public void WritingAccountRestrictionsIsATakeoverBecauseOfWhatMicrosoftPutsInIt()
    {
        var result = Classifier(
                UserAccountRestrictions,
                "accountExpires",
                "pwdLastSet",
                "userAccountControl",
                "msDS-AllowedToActOnBehalfOfOtherIdentity")
            .Classify(AceType.AccessAllowedObject, WriteProperty, UserAccountRestrictions);

        Assert.Equal(PermissionVerdict.Dangerous, result.Verdict);
    }

    /// <summary>
    /// The reason names the attribute that earned the verdict, because "dangerous" on its own is
    /// not something an administrator can act on or argue with.
    /// </summary>
    [Fact]
    public void TheReasonNamesWhichAttributeMadeTheSetDangerous()
    {
        var result = Classifier(
                UserAccountRestrictions, "accountExpires", "userAccountControl")
            .Classify(AceType.AccessAllowedObject, WriteProperty, UserAccountRestrictions);

        Assert.Contains("userAccountControl", result.Reason, StringComparison.Ordinal);
    }

    // -------------------------------------------------------------------------------------------
    // Reading.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// Nothing judged a property-set read before this: it fell through to
    /// <see cref="PermissionVerdict.CannotClassify"/>, so a grant reaching a local administrator
    /// password through a set was never marked.
    /// </summary>
    [Fact]
    public void ReadingASetHoldingALapsPasswordIsATakeover()
    {
        var result = Classifier(LapsPasswordAttributes, "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime")
            .Classify(AceType.AccessAllowedObject, ReadProperty, LapsPasswordAttributes);

        Assert.Equal(PermissionVerdict.Dangerous, result.Verdict);
    }

    /// <summary>
    /// The regression that judging a property set by its contents nearly introduced.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>ms-LAPS-Encrypted-Password-Attributes</c> is the real property set Microsoft publishes for
    /// Windows LAPS, and it holds none of the two attributes this product used to call a credential.
    /// Under the old blanket rule it was marked dangerous by accident; under a rule that reads the
    /// contents it went quiet - which is the worse direction to be wrong in, and is how a screen
    /// stops reporting a local administrator password being readable.
    /// </para>
    /// <para>
    /// It stays dangerous because the schema is extended whether or not a forest encrypts anything:
    /// Microsoft states that below a 2016 domain functional level passwords can be stored only in
    /// clear text, so these attribute names prove nothing about what they actually hold.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("msLAPS-EncryptedPassword")]
    [InlineData("msLAPS-EncryptedPasswordHistory")]
    [InlineData("msLAPS-EncryptedDSRMPassword")]
    [InlineData("msLAPS-EncryptedDSRMPasswordHistory")]
    public void ReadingTheWindowsLapsEncryptedPasswordSetIsATakeover(string member)
    {
        var result = Classifier(
                WindowsLapsEncryptedAttributes, member, "msLAPS-CurrentPasswordVersion")
            .Classify(AceType.AccessAllowedObject, ReadProperty, WindowsLapsEncryptedAttributes);

        Assert.Equal(PermissionVerdict.Dangerous, result.Verdict);
    }

    [Fact]
    public void ReadingASetOfOrdinaryAttributesIsNotATakeover()
    {
        var result = Classifier(PersonalInformation, "streetAddress", "telephoneNumber")
            .Classify(AceType.AccessAllowedObject, ReadProperty, PersonalInformation);

        Assert.Equal(PermissionVerdict.NotDangerous, result.Verdict);
    }

    // -------------------------------------------------------------------------------------------
    // When the forest was never read.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// A run that did not read the schema cannot know what a set contains, and an unassessed
    /// permission is never reported as safe.
    /// </summary>
    [Theory]
    [InlineData(WriteProperty)]
    [InlineData(ReadProperty)]
    public void WithoutTheForestSchemaAPropertySetIsNotAssessedRatherThanCleared(int mask)
    {
        var result = new DangerousPermissionClassifier(SchemaGuidCatalog.Embedded)
            .Classify(AceType.AccessAllowedObject, mask, PersonalInformation);

        Assert.NotEqual(PermissionVerdict.NotDangerous, result.Verdict);
    }

    [Fact]
    public void WithoutTheForestSchemaTheReasonSaysTheSchemaWasNotRead()
    {
        var result = new DangerousPermissionClassifier(SchemaGuidCatalog.Embedded)
            .Classify(AceType.AccessAllowedObject, WriteProperty, PersonalInformation);

        Assert.Equal(PermissionVerdict.CannotClassify, result.Verdict);
        Assert.Contains("did not read the schema", result.Reason, StringComparison.Ordinal);
    }

    // -------------------------------------------------------------------------------------------

    /// <summary>A classifier over a forest that defined one property set with the given members.</summary>
    private static DangerousPermissionClassifier Classifier(
        string propertySetGuid, params string[] members)
    {
        var name = "Set-" + propertySetGuid[..8];

        var entries = new List<SchemaGuidEntry>
        {
            new(propertySetGuid, name, SchemaGuidKind.PropertySet, SchemaGuidSource.Captured),
        };

        entries.AddRange(members.Select((m, i) => new SchemaGuidEntry(
            $"00000000-0000-0000-0000-{i:D12}", m, SchemaGuidKind.Attribute,
            SchemaGuidSource.Captured)));

        var membership = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
        {
            [propertySetGuid] = members,
        };

        return new DangerousPermissionClassifier(
            SchemaGuidCatalog.CapturedOver(entries, SchemaGuidCatalog.Embedded, membership));
    }
}
