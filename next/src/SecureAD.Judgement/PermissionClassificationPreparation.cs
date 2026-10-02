using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Kernel.Schema;

namespace SecureAD.Judgement;

/// <summary>One catalogue, producer and judgement generation over one evidence stream.</summary>
internal sealed class PermissionClassificationPreparation(
    DescriptorObjectStream source, SchemaGuidCatalog catalog, Guid generation)
{
    private readonly PermissionClassificationProducer _producer = new(catalog);
    private DescriptorObjectStream.Descriptor? _descriptor;
    private PermissionClassificationStorage.Prepared? _prepared;

    internal long ClassifiedDescriptors { get; private set; }
    internal long ClassifiedEntries { get; private set; }

    internal ObjectWrite Prepare(DescriptorObjectStream.Reading reading, PermissionWriteWork work,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        reading.RequireCurrent();
        if (!ReferenceEquals(reading.Source, source))
            throw new InvalidOperationException("The classification context belongs to another evidence stream.");

        PermissionClassificationStorage.Prepared prepared;
        if (reading.Descriptor is { } descriptor)
        {
            if (!ReferenceEquals(descriptor, _descriptor))
            {
                var result = _producer.CreateObjectResult(descriptor.ClassificationInput, token);
                _prepared = PermissionClassificationStorage.Prepare(result, generation, work, token);
                _descriptor = descriptor;
                ClassifiedDescriptors++;
                ClassifiedEntries += result.Entries.Count;
            }
            prepared = _prepared!;
        }
        else
        {
            _descriptor = null;
            _prepared = null;
            prepared = PermissionClassificationStorage.Prepare(
                _producer.CreateObjectResult(reading.Permissions, token), generation, work, token);
        }
        return new(source, reading, prepared);
    }

    /// <summary>The object link carries the current evidence-row witness, not a caller-supplied ID.</summary>
    internal sealed class ObjectWrite(DescriptorObjectStream source, DescriptorObjectStream.Reading reading,
        PermissionClassificationStorage.Prepared prepared)
    {
        internal void Write(SqliteConnection connection, SqliteTransaction transaction, Guid generation,
            PermissionWriteWork work, PreparedStatements statements, PermissionWriteSession session,
            CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            reading.RequireCurrent();
            if (!ReferenceEquals(reading.Source, source))
                throw new InvalidOperationException("The object link belongs to another evidence stream.");
            prepared.Write(connection, transaction, generation, reading.Permissions, work, statements, session, token);
        }
    }
}
