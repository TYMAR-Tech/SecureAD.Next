using System.IO;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services.Export;

namespace SecureAD.Shell.Services;

internal sealed partial class OpenedRunResults
{
    internal Result<LapsExportSnapshot> ReadLapsExport(LapsQuery query, CancellationToken token)
    {
        var captured = ReadNavigation(reader =>
        {
            var scope = reader.ReadScope();
            if (!scope.IsSuccess) throw new InvalidDataException(scope.Error.Description);
            return (reader.Description, Scope: scope.Value, Coverage: reader.ReadListingCoverage(query.Container, query.Scope));
        }, token);
        if (!captured.IsSuccess) return Result<LapsExportSnapshot>.Failure(captured.Error);
        return ReadFindings(reader => new LapsExportSnapshot(captured.Value.Description, captured.Value.Scope,
            reader.ReadLapsInventorySummary(query, captured.Value.Coverage, token),
            reader.ListLapsComputers(query, null, captured.Value.Coverage, token)), token);
    }
}
