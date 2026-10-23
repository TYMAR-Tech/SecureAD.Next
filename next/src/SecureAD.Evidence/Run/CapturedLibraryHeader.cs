using SecureAD.Kernel;

namespace SecureAD.Evidence.Run;

/// <summary>A domain's saved coverage fields in the compact capture publication header.</summary>
public sealed record CapturedDomainHeader(string DomainFqdn, string Outcome, string? Reason);

/// <summary>The library's scope information, published atomically with the captured products.</summary>
public sealed record CapturedLibraryHeader(string CoverageId, IReadOnlyList<CapturedDomainHeader> Domains)
{
    [System.Text.Json.Serialization.JsonInclude]
    internal IReadOnlyList<CapturedDomainHeader> Domains { get; init; } = Domains;

    internal Result<RunScope> ReadScope(string directory)
    {
        if (string.IsNullOrWhiteSpace(CoverageId) || Domains is null || Domains.Count == 0)
            return Result<RunScope>.Failure(AuditError.Create(ErrorCategory.Evidence, "CoverageAbsent",
                ErrorSeverity.Failed, "This run records no domain at all.", directory));
        var domains = new List<DomainCoverage>();
        foreach (var row in Domains)
        {
            if (row is null) throw new InvalidDataException("A captured library domain is null.");
            var read = DomainCoverageReading.Read(row.DomainFqdn, row.Outcome, row.Reason, directory);
            if (!read.IsSuccess) return Result<RunScope>.Failure(read.Error);
            domains.Add(read.Value);
        }
        return RunScope.Of(CoverageId, domains);
    }
}
