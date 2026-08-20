using System.Text.Json;
using System.Text.Json.Serialization;
using SecureAD.Kernel;

namespace SecureAD.Evidence.Run;

/// <summary>
/// The two ways a run can end badly.
/// </summary>
/// <remarks>
/// A run that ended well writes no outcome file at all, so there is no member for success here.
/// The evidence file and its intact seal already say the run succeeded, and a second artefact
/// saying the same thing would be a second answer to one question.
/// </remarks>
public enum RunOutcome
{
    /// <summary>The run ended in an error.</summary>
    Failed,

    /// <summary>The operator stopped the run.</summary>
    Cancelled,
}

/// <summary>
/// The note a run leaves behind when it ends badly, so that the run library can say why rather
/// than only that.
/// </summary>
/// <remarks>
/// <para>
/// Without this file a failure, a cancellation, a reboot and a capture that is still running all
/// look identical from outside: one <c>evidence.db.partial</c> and no <c>evidence.db</c>. That is
/// a correct consequence of the rename mechanism in
/// <c>docs/decisions/0029-a-run-that-ends-badly-says-so.md</c>, and it leaves the library unable
/// to tell a dead run from a live one - so it would offer a delete button beside a capture still
/// in progress.
/// </para>
/// <para>
/// <b>This file is not evidence.</b> It sits outside the seal, and has to: a failed run has no
/// evidence file for a seal to cover. Anyone can write it or change it. Nothing that reads it may
/// present it as proof of anything, and no security conclusion rests on it - it describes a run
/// that produced no evidence at all.
/// </para>
/// <para>
/// A missing outcome file is not an error. It means the run stopped without being able to say why,
/// which is reported as <see cref="RunState.Interrupted"/>.
/// </para>
/// </remarks>
public static class RunOutcomeFile
{
    private static readonly JsonSerializerOptions Format = new() { WriteIndented = true };

    /// <summary>
    /// Records that a run ended badly.
    /// </summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    /// <param name="outcome">Which bad ending it was.</param>
    /// <param name="detail">
    /// Why, in the words the operator should see. Required even for a cancellation, so that the
    /// library always has a sentence to show rather than a blank where a cause belongs.
    /// </param>
    public static void Write(string bundleDirectory, RunOutcome outcome, string detail)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(detail);

        var contents = new RunOutcomeContents(outcome, detail.Trim(), DateTimeOffset.UtcNow);

        File.WriteAllText(
            BundleLayout.OutcomePath(bundleDirectory),
            JsonSerializer.Serialize(contents, Format));
    }

    /// <summary>
    /// Reads the outcome file, if there is one.
    /// </summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    /// <returns>
    /// The contents; a success carrying null when there is no such file, because an absent outcome
    /// is a normal observation rather than a fault; and a failure when the file is there and
    /// cannot be read, because a file that exists and cannot be parsed must not be reported as an
    /// absent one - that is the degradation <c>0020</c> forbids for the seal, for the same reason.
    /// </returns>
    public static Result<RunOutcomeContents?> Read(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        var path = BundleLayout.OutcomePath(bundleDirectory);
        if (!File.Exists(path))
        {
            return Result<RunOutcomeContents?>.Success(null);
        }

        try
        {
            var contents = JsonSerializer.Deserialize<RunOutcomeContents>(File.ReadAllText(path));

            return contents is null
                ? Failure("The run outcome file is empty.", path)
                : Result<RunOutcomeContents?>.Success(contents);
        }
        catch (JsonException e)
        {
            return Failure($"The run outcome file could not be read: {e.Message}", path);
        }
        catch (IOException e)
        {
            return Failure($"The run outcome file could not be opened: {e.Message}", path);
        }
    }

    private static Result<RunOutcomeContents?> Failure(string description, string path) =>
        Result<RunOutcomeContents?>.Failure(AuditError.Create(
            ErrorCategory.Evidence,
            "RunOutcomeUnreadable",
            ErrorSeverity.Failed,
            description,
            path));
}

/// <summary>
/// What a run recorded about its bad ending.
/// </summary>
/// <param name="Outcome">Which bad ending it was.</param>
/// <param name="Detail">Why, in the words the operator should see.</param>
/// <param name="EndedUtc">When the run ended.</param>
public sealed record RunOutcomeContents(
    [property: JsonPropertyName("outcome")] RunOutcome Outcome,
    [property: JsonPropertyName("detail")] string Detail,
    [property: JsonPropertyName("endedUtc")] DateTimeOffset EndedUtc);
