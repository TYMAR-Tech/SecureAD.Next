using System.Text.Json;
using SecureAD.Judgement;
using SecureAD.Kernel.Schema;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class SchemaPayloadReuseTests
{
    [Fact]
    public void AlternatingSchemaRecordsReuseTheirSerializedStrings()
    {
        var session = new PermissionWriteSession();
        var first = Support("first");
        var json = session.SerializeSchema(first);
        session.SerializeSchema(Support("second"));

        Assert.Same(json, session.SerializeSchema(first));
    }

    [Fact]
    public void DistinctEquivalentRecordsReuseTheSamePayload()
    {
        var session = new PermissionWriteSession();
        var json = session.SerializeSchema(Support("first"));

        Assert.Same(json, session.SerializeSchema(Support("first")));
    }

    [Theory]
    [InlineData("definitions")]
    [InlineData("members")]
    [InlineData("ambiguous")]
    public void MutatedListsDoNotReuseTheOldPayload(string changed)
    {
        var definitions = new[] { new SchemaGuidEntry("first", "original", SchemaGuidKind.Attribute, SchemaGuidSource.Captured) };
        var members = new[] { "member" };
        var ambiguous = new[] { "name" };
        var support = new PermissionSchemaSupport("first", definitions, members, ambiguous);
        var session = new PermissionWriteSession();
        var before = session.SerializeSchema(support);
        switch (changed)
        {
            case "definitions": definitions[0] = definitions[0] with { LdapName = "changed" }; break;
            case "members": members[0] = "changed"; break;
            case "ambiguous": ambiguous[0] = "changed"; break;
        }

        var after = session.SerializeSchema(support);

        Assert.Equal((false, JsonSerializer.Serialize(support)), (before == after, after));
    }

    [Fact]
    public void UnknownAndEmptyPropertySetsRemainDifferent()
    {
        var session = new PermissionWriteSession();
        var support = Support("first") with { PropertySetMembers = null };
        var unknown = session.SerializeSchema(support);

        var empty = session.SerializeSchema(support with { PropertySetMembers = [] });

        Assert.NotEqual(unknown, empty);
    }

    [Fact]
    public void PayloadReuseDoesNotAdoptARolledBackSchemaRow()
    {
        var session = new PermissionWriteSession();
        var support = Support("first");
        var json = session.SerializeSchema(support);
        session.AddSchema(support.Guid, json);
        session.Discard();
        session.SerializeSchema(support);

        Assert.False(session.TryGetSchema(support.Guid, out _));
    }

    private static PermissionSchemaSupport Support(string guid) => new(guid,
        [new(guid, "attribute", SchemaGuidKind.Attribute, SchemaGuidSource.Captured)], ["member"], []);
}
