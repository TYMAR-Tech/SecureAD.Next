using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class GroupMembershipStorageTests
{
    private static readonly Guid Generation = Guid.NewGuid();
    private static readonly JudgementDescription Description = new(new string('a', 64), Generation, null,
        JudgementRunState.Completed, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
    private static readonly GroupInventoryQuery All = new(null, ListingScope.Subtree, "",
        GroupInventoryScope.All, GroupInventoryKind.All, false, GroupInventorySort.Name);

    [Theory]
    [InlineData("known_total")]
    [InlineData("unresolved_members")]
    [InlineData("unreadable_members")]
    [InlineData("membership_limitations")]
    public void SavedTotalsRefusePublicationWhenAFieldWasNotSaved(string column)
    {
        using var connection = Saved();
        Execute(connection, $"UPDATE group_inventory SET {column}=NULL");
        Assert.Throws<InvalidDataException>(() => GroupInventoryStorage.RequirePublishable(connection, null));
    }

    [Theory]
    [InlineData("known_total")]
    [InlineData("unresolved_members")]
    [InlineData("unreadable_members")]
    [InlineData("membership_limitations")]
    public void SavedTotalsRefuseReadbackWhenAFieldWasNotSaved(string column)
    {
        using var connection = Saved();
        Execute(connection, $"UPDATE group_inventory SET {column}=NULL");
        Assert.Throws<InvalidDataException>(() => GroupInventoryStorage.Read(connection, Description, All, null, CancellationToken.None));
    }

    [Theory]
    [InlineData("membership_limitations=1")]
    [InlineData("membership_limitations=2")]
    [InlineData("membership_limitations=4")]
    [InlineData("unresolved_members=1")]
    [InlineData("unreadable_members=1")]
    public void SavedTotalsRejectCountsWhoseLimitationsDisagree(string change)
    {
        using var connection = Saved();
        Execute(connection, $"UPDATE group_inventory SET {change}");
        Assert.Throws<InvalidDataException>(() => GroupInventoryStorage.Read(connection, Description, All, null, CancellationToken.None));
    }

    [Fact]
    public void SavedTotalsRetainCaptureShortfallAndCountsIndependently()
    {
        using var connection = Saved();
        Execute(connection, "UPDATE group_inventory_product SET capture_complete=0; UPDATE group_inventory SET membership_limitations=7,unresolved_members=2,unreadable_members=3");
        var page = GroupInventoryStorage.Read(connection, Description, All, null, CancellationToken.None);
        Assert.False(page.Coverage.IsComplete);
        Assert.Equal(new(17, 2, 3, GroupMembershipLimitations.CaptureIncomplete | GroupMembershipLimitations.UnresolvedReferences
            | GroupMembershipLimitations.UnreadableReferences), Assert.Single(page.Groups).MembershipTotal);
    }

    private static SqliteConnection Saved()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        JudgementSchema.CreateTables(connection);
        GroupInventoryStorage.Start(connection, Generation, true);
        Execute(connection, """
            UPDATE group_inventory_product SET completed=1;
            INSERT INTO group_inventory VALUES('CN=Group,DC=example',NULL,'Group',NULL,'example',2,4,0,NULL,'DC=example','DC=example,CN=Group',17,0,0,0);
            """);
        return connection;
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }
}
