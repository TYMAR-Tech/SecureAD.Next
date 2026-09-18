using System.Text.Json;
using System.Text.Json.Serialization;
using CommunityToolkit.Mvvm.ComponentModel;
using SecureAD.Derivation;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services;

namespace SecureAD.Shell.ViewModels;

/// <summary>Presentation of a saved calculation, never an analysis request or a security-operation runner.</summary>
internal sealed partial class SavedTier0PathSectionViewModel(ObjectSectionDefinition definition) : ObjectSectionViewModel(definition)
{
    private static readonly JsonSerializerOptions EvidenceJson = new()
    { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
    private Func<Result<SavedTier0Path?>>? _read;
    private Func<CancellationToken, Task<Result<SavedTier0Path?>>>? _readAsync;
    private CancellationTokenSource? _pending;
    private long _revision;
    private string? _subjectDn;
    [ObservableProperty] private string _result = SavedPathText.Get("NotRead");
    [ObservableProperty] private string _detail = "";
    [ObservableProperty] private string _provenance = "";
    [ObservableProperty] private string _distance = "";
    [ObservableProperty] private string _destination = "";
    [ObservableProperty] private string _automaticChecks = SavedPathText.Get("NotRead");
    [ObservableProperty] private string _savedQuestions = SavedPathText.Get("NoneRecorded");
    [ObservableProperty] private IReadOnlyList<SavedPathStepViewModel> _steps = [];
    [ObservableProperty] private IReadOnlyList<string> _limitations = [];

    public string ResultHeading { get; } = SavedPathText.Get("ResultHeading");
    public string RouteHeading { get; } = SavedPathText.Get("RouteHeading");
    public string CoverageHeading { get; } = SavedPathText.Get("CoverageHeading");
    public string ChecksHeading { get; } = SavedPathText.Get("ChecksHeading");
    public string Boundary { get; } = SavedPathText.Get("Boundary");
    public string ChecksCaveat { get; } = SavedPathText.Get("ChecksCaveat");
    public string CoverageScope { get; } = SavedPathText.Get("CoverageScope");
    public string SavedQuestionsHeading { get; } = SavedPathText.Get("SavedQuestions");
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;

    /// <summary>Binds this object's original bundle callback without reading it.</summary>
    public void Configure(string subjectDn, Func<Result<SavedTier0Path?>> read)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectDn);
        ArgumentNullException.ThrowIfNull(read);
        CancelRead();
        _subjectDn = subjectDn;
        _read = read;
        _readAsync = null;
    }

    /// <summary>Binds a cancellable source without starting or retaining a result.</summary>
    public void ConfigureAsync(string subjectDn, Func<CancellationToken, Task<Result<SavedTier0Path?>>> read)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectDn);
        ArgumentNullException.ThrowIfNull(read);
        CancelRead();
        _subjectDn = subjectDn;
        _read = null;
        _readAsync = read;
    }

    /// <summary>Reads only on section selection, discarding any previously displayed result first.</summary>
    public void Read()
    {
        CancelRead();
        if (_readAsync is { } readAsync)
        {
            Result = SavedPathText.Get("Loading");
            var pending = new CancellationTokenSource();
            _pending = pending;
            ReadCompletion = LoadAsync(readAsync, pending, _revision);
        }
        else if (_read is { } read)
            Apply(read());
    }

    /// <summary>Leaving or rebinding cancels work and invalidates late completions, even if a source ignores cancellation.</summary>
    public void CancelRead()
    {
        _revision++;
        var pending = _pending;
        _pending = null;
        pending?.Cancel();
        Result = SavedPathText.Get("NotRead");
        Detail = Provenance = Distance = Destination = "";
        AutomaticChecks = SavedPathText.Get("NotRead");
        SavedQuestions = SavedPathText.Get("NotRead");
        Steps = [];
        Limitations = [];
    }

    private async Task LoadAsync(Func<CancellationToken, Task<Result<SavedTier0Path?>>> read,
        CancellationTokenSource pending, long revision)
    {
        try
        {
            var result = await read(pending.Token);
            if (revision != _revision || pending.IsCancellationRequested) return;
            Apply(result);
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (Exception error)
        {
            if (revision == _revision && !pending.IsCancellationRequested)
                Refuse(SavedPathText.Get("InvalidEvidence") + " " + error.Message);
        }
        finally
        {
            if (ReferenceEquals(_pending, pending)) _pending = null;
            pending.Dispose();
        }
    }

    private void Apply(Result<SavedTier0Path?> read)
    {
        SavedQuestions = SavedPathText.Get("NoneRecorded");
        if (!read.IsSuccess) { Refuse(read.Error.Description); return; }
        if (read.Value is not { } saved)
        {
            Result = SavedPathText.Get("Absent");
            Detail = SavedPathText.Get("AbsentDetail");
            return;
        }
        if (!saved.IsBound) { Refuse(SavedPathText.Get("GenerationChanged")); return; }
        var path = saved.Path;
        if (path.Subject is { } subject && !string.Equals(subject.DistinguishedName, _subjectDn, StringComparison.OrdinalIgnoreCase))
        { Refuse(SavedPathText.Get("SubjectChanged")); return; }
        var description = saved.Description;
        if (description.State is not (JudgementRunState.Completed or JudgementRunState.CompletedDegraded))
        { Refuse(SavedPathText.Get("Unfinished")); return; }
        Provenance = SavedPathText.Get("Generation", description.GenerationId, description.CompletedUtc,
            description.EvidenceSeal, description.DerivationGenerationId?.ToString() ?? SavedPathText.Get("NotUsed"));
        AutomaticChecks = SavedPathText.Get(saved.Requesters.Verdict.ToString());
        var limits = new List<string>();
        if (!path.Coverage.InputsComplete) limits.Add(SavedPathText.Get("CapturedIncomplete"));
        if (!path.Coverage.AnalysisComplete) limits.Add(SavedPathText.Get("Unsupported"));
        if (!path.Coverage.ProcessingComplete) limits.Add(SavedPathText.Get("UnfinishedProcessing"));
        if (description.State == JudgementRunState.CompletedDegraded) limits.Add(SavedPathText.Get("Degraded"));
        if (path.Inputs.Availability == PathInputAvailability.RequiredInputsUnavailable)
            limits.Add(SavedPathText.Get("InputsUnavailable"));
        limits.AddRange(path.Inputs.UncertaintyRegions.Select(region => SavedPathText.Get("Region",
            SavedPathText.Get("Region" + region.Cause), Json(region))));
        limits.AddRange(saved.Requesters.Limitations.Select(value => SavedPathText.Get("Selection",
            SavedPathText.Get("Selection" + value.Reason), Json(value))));
        if (saved.Requesters.Families.Any(value => value.UnresolvedResults > 0))
            limits.Add(SavedPathText.Get("UnresolvedQuestions"));
        Limitations = limits;
        if (path.RequesterAssessments.Count + path.OwnAccountAssessments.Count + path.MembershipDaclAssessments.Count > 0)
            SavedQuestions = SavedPathText.Get("OwnContext") + "\n" + Json(new
            {
                path.RequesterAssessments, path.OwnAccountAssessments, path.MembershipDaclAssessments,
            });
        if (path.Inputs.Availability == PathInputAvailability.NotProduced)
        {
            Result = SavedPathText.Get("Absent");
            Detail = SavedPathText.Get("AbsentDetail");
        }
        else if (path.Reachability == Tier0Reachability.Reachable)
        {
            var fixedTarget = path.ShortestProvenDistance == 0 && path.Subject is not null
                && path.Inputs.FixedTargets.Contains(path.Subject);
            Result = SavedPathText.Get(fixedTarget ? "FixedTarget" : "Supported");
            Distance = fixedTarget ? SavedPathText.Get("ZeroDistance")
                : (path.ShortestProvenDistance == 1 ? SavedPathText.Get("SingleStepDistance")
                    : SavedPathText.Get("Distance", path.ShortestProvenDistance)) + "\n" + SavedPathText.Get("ShorterUnknown");
            var target = fixedTarget ? path.Subject : path.Steps.Count == 0 ? null : path.Steps[^1].To;
            Destination = target is null ? "" : SavedPathText.Get("Destination", Identity(target));
            Steps = path.Steps.Select((step, index) => new SavedPathStepViewModel(
                SavedPathText.Get("Step", index + 1, SavedPathText.Get("Step" + step.Kind),
                    step.From.DistinguishedName, step.To.DistinguishedName), Evidence(step, saved))).ToArray();
        }
        else
        {
            Result = SavedPathText.Get("Unknown");
            Detail = SavedPathText.Get("UnknownDetail");
        }
    }

    private void Refuse(string reason)
    {
        Result = SavedPathText.Get("Unavailable");
        Detail = reason;
    }

    private static string Evidence(Tier0PathStep step, SavedTier0Path saved)
    {
        var evidence = new List<string> { Identity(step.From), Identity(step.To) };
        if (step.MembershipWitness is { } witness)
            evidence.Add(SavedPathText.Get("MembershipWitness", witness.Object.DistinguishedName,
                witness.Attribute, witness.Ordinal, witness.Value));
        if (step.MembershipSubject is not null)
            evidence.Add(SavedPathText.Get("MembershipSupport", step.MembershipSubject, step.MembershipSupport));
        if (step.PermissionId is { } id)
            evidence.Add(SavedPathText.Get("Permission", id,
                new ControlEdgeRowViewModel(saved.Permissions.Single(value => value.Id == id)).Evidence));
        if (step.RequesterRequest is { } requester)
            evidence.Add(SavedPathText.Get("RequesterProof", Json(saved.Path.RequesterAssessments.Single(value => value.Request == requester))));
        if (step.OwnAccountRequest is { } own)
        {
            evidence.Add(SavedPathText.Get("OwnContext"));
            var membership = step.MembershipDaclRequest is { } membershipRequest
                ? saved.Path.MembershipDaclAssessments.Single(value => value.Request == membershipRequest).Membership
                : saved.Path.OwnAccountAssessments.Single(value => value.Request == own);
            evidence.Add(SavedPathText.Get("OwnProof", SavedPathText.Get(own.PermissionKind.ToString()),
                Json(membership)));
        }
        if (step.MembershipDaclRequest is { } combined)
        {
            var proof = saved.Path.MembershipDaclAssessments.Single(value => value.Request == combined);
            evidence.Add(proof.AuthorizationContext);
            evidence.Add(SavedPathText.Get("CombinedProof", Json(proof)));
        }
        return string.Join("\n\n", evidence);
    }

    private static string Identity(Tier0Target value) => SavedPathText.Get("Identity", value.DistinguishedName,
        value.ObjectGuid, value.Sid ?? SavedPathText.Get("NoneRecorded"), value.NamingContext, value.DomainFqdn,
        value.SidScope ?? SavedPathText.Get("NotUsed"));

    private static string Json<T>(T value) => JsonSerializer.Serialize(value, EvidenceJson);
}

internal sealed record SavedPathStepViewModel(string Description, string Evidence)
{
    public string EvidenceHeading { get; } = SavedPathText.Get("EvidenceHeading");
}
