using SecureAD.Kernel;

namespace SecureAD.Evidence.Run;

internal static class DomainCoverageReading
{
    internal static Result<DomainCoverage> Read(string domain, string outcome, string? reason, string directory) =>
        outcome switch
        {
            "Read" => Result<DomainCoverage>.Success(DomainCoverage.Read(domain)),
            "PartiallyRead" => Stated(domain, outcome, reason, directory, r => DomainCoverage.PartiallyRead(domain, r)),
            "ExcludedByChoice" => Stated(domain, outcome, reason, directory,
                r => DomainCoverage.Excluded(domain, ExclusionKind.ByChoice, r)),
            "ExcludedForWantOfCandidates" => Stated(domain, outcome, reason, directory,
                r => DomainCoverage.Excluded(domain, ExclusionKind.ForWantOfCandidates, r)),
            "NotRead" => Failure("CoverageImpossible",
                $"This run records {domain} as not read, which a sealed bundle cannot honestly "
                + "say: a domain that could not be read ends the run before its evidence is "
                + "sealed. The bundle was written by something other than this product, or it "
                + "has been altered, so what the run covered cannot be established.", directory),
            _ => Failure("CoverageUnrecognised",
                $"This run records '{outcome}' for {domain}, which this build does not "
                + "recognise. The bundle was written by a version that knew an outcome this "
                + "one does not, so what the run covered cannot be established here.", directory),
        };

    private static Result<DomainCoverage> Stated(
        string domain, string outcome, string? reason, string directory, Func<string, DomainCoverage> build) =>
        string.IsNullOrWhiteSpace(reason)
            ? Failure("CoverageUnexplained",
                $"This run records '{outcome}' for {domain} without saying why, and the writer "
                + "requires a reason. Supplying one here would present a guess as the run's own "
                + "statement.", directory)
            : Result<DomainCoverage>.Success(build(reason));

    private static Result<DomainCoverage> Failure(string code, string description, string directory) =>
        Result<DomainCoverage>.Failure(AuditError.Create(
            ErrorCategory.Evidence, code, ErrorSeverity.Failed, description, directory));
}
