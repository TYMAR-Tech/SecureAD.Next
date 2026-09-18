using SecureAD.Judgement;
using SecureAD.Kernel.Schema;
using Xunit;
using static SecureAD.Next.Tests.Judgement.ControlEdgeDeriverTests;
using static SecureAD.Next.Tests.Judgement.GroupMembershipControlTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class MemberSchemaCorrectionTests
{
    private const string OtherGuid = "77777777-1111-2222-3333-444444444444";
    private const string MemberId = "bf9679c0-0de6-11d0-a285-00aa003049e2";

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 0)]
    public void CorrectionCatalogueRetainsNameAmbiguityInEitherOrder(int first, int second)
    {
        SchemaGuidEntry[] definitions =
        [
            new(MemberId, "member", SchemaGuidKind.Attribute, SchemaGuidSource.Captured),
            new(OtherGuid, "MEMBER", SchemaGuidKind.ExtendedRight, SchemaGuidSource.Captured),
        ];
        var catalogue = SchemaGuidCatalog.CapturedOver([definitions[first], definitions[second]], SchemaGuidCatalog.Embedded,
            new Dictionary<string, IReadOnlyList<string>>());

        Assert.Null(catalogue.FindUnambiguousByLdapName("member"));
    }

    [Fact]
    public void CorrectionCatalogueKeepsAnUnambiguousCapturedAttribute()
    {
        var definition = new SchemaGuidEntry(MemberId, "member", SchemaGuidKind.Attribute, SchemaGuidSource.Captured);
        var catalogue = SchemaGuidCatalog.CapturedOver([definition, definition], SchemaGuidCatalog.Embedded,
            new Dictionary<string, IReadOnlyList<string>>());

        Assert.Equal(definition, catalogue.FindUnambiguousByLdapName("MEMBER"));
    }

    [Theory]
    [InlineData(SchemaGuidKind.ExtendedRight, MemberId)]
    [InlineData(SchemaGuidKind.Attribute, OtherGuid)]
    [InlineData(SchemaGuidKind.ExtendedRight, OtherGuid)]
    public void CorrectionMemberScopeRequiresBothAttributeKindAndFixedIdentity(SchemaGuidKind kind, string guid)
    {
        var catalogue = new SchemaGuidCatalog([new(guid, "member", kind, SchemaGuidSource.Captured)]);
        var result = Membership(Permissions(Scoped(0, 0x20, guid)), catalogue);

        Assert.Equal(ControlEvaluationState.Unknown, Assert.Single(result.Edges).EvaluationState);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 0)]
    public void CorrectionHolderMembershipPermissionKeepsNameConflictsUnknown(int first, int second)
    {
        SchemaGuidEntry[] definitions =
        [
            new(MemberId, "member", SchemaGuidKind.Attribute, SchemaGuidSource.Captured),
            new(OtherGuid, "member", SchemaGuidKind.ExtendedRight, SchemaGuidSource.Captured),
        ];
        var catalogue = SchemaGuidCatalog.CapturedOver([definitions[first], definitions[second]], SchemaGuidCatalog.Embedded,
            new Dictionary<string, IReadOnlyList<string>>());
        var result = Membership(Permissions(Scoped(0, 0x20, MemberId)), catalogue);

        Assert.Equal(ControlEvaluationState.Unknown, Assert.Single(result.Edges).EvaluationState);
    }

    [Fact]
    public void CorrectionMemberClassScopeCannotSubstituteAnotherClassIdentity()
    {
        var catalogue = new SchemaGuidCatalog(
        [
            new(MemberId, "member", SchemaGuidKind.Attribute, SchemaGuidSource.Captured),
            new(OtherGuid, "group", SchemaGuidKind.ObjectClass, SchemaGuidSource.Captured),
        ]);
        var result = Membership(Permissions(Scoped(0, 0x20, OtherGuid)), catalogue);

        Assert.Equal(ControlEvaluationState.Unknown, Assert.Single(result.Edges).EvaluationState);
    }
}
