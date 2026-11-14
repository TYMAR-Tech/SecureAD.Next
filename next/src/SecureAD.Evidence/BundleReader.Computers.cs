namespace SecureAD.Evidence;

public sealed partial class BundleReader
{
    internal IEnumerable<CapturedObjectIdentity> StreamComputerIdentities(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (_navigation) throw new InvalidOperationException("Computer calculation scope requires original evidence.");
        using var command = Connection.CreateCommand();
        command.CommandText = """
            SELECT o.object_id,o.object_guid,o.distinguished_name,o.domain_fqdn,
                (SELECT c.value FROM objectclass_value c WHERE c.object_id=o.object_id ORDER BY c.ordinal DESC LIMIT 1) AS class
            FROM captured_object o
            WHERE class='computer' COLLATE NOCASE
            ORDER BY o.object_id
            """;
        using var rows = command.ExecuteReader();
        while (rows.Read())
        {
            token.ThrowIfCancellationRequested();
            yield return new(rows.GetString(2), rows.IsDBNull(1) ? null : Guid.Parse(rows.GetString(1)),
                rows.GetString(4), rows.IsDBNull(3) ? null : rows.GetString(3), null)
            {
                ObjectId = rows.GetInt64(0),
                CaptureGenerationId = Description.CaptureGenerationId,
            };
        }
    }
}
