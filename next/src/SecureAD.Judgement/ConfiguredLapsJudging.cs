using System.Diagnostics;
using System.Globalization;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

internal static class ConfiguredLapsJudging
{
    internal static Result<ConfiguredLapsSchedulingSummary> Run(ConfiguredLapsPolicy policy,
        JudgingInputs inputs, JudgementWriter writer, long objectsRead,
        JudgingStatus progress, IRunLog log, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var scope = writer.StartConfiguredLapsScheduling(policy, inputs.Bundle.Description.EveryDeclaredUnitRecordedAsRead);
        long considered = 0, saved = 0, unassessed = 0;
        var calculation = new Stopwatch();
        var storage = new Stopwatch();
        if (policy == ConfiguredLapsPolicy.AllCapturedComputers)
        {
            var opened = LapsConfiguredPolicyReader.Open(inputs, token);
            if (!opened.IsSuccess)
            {
                log.Record("Judge", opened.Error, []);
                return Result<ConfiguredLapsSchedulingSummary>.Failure(opened.Error);
            }
            using var reader = opened.Value;
            foreach (var computer in inputs.Bundle.StreamComputerIdentities(token))
            {
                token.ThrowIfCancellationRequested();
                progress.BeginOperation("calculate-configured-laps");
                calculation.Start();
                Result<LapsConfiguredPolicy> result;
                try { result = reader.Read(computer, token); }
                finally { calculation.Stop(); }
                considered++;
                token.ThrowIfCancellationRequested();
                progress.BeginOperation("store-configured-laps");
                storage.Start();
                try
                {
                    if (result.IsSuccess)
                    {
                        if (result.Value.Computer.ObjectId != computer.ObjectId
                            || result.Value.Computer.ObjectGuid != computer.ObjectGuid
                            || result.Value.CaptureGenerationId != computer.CaptureGenerationId)
                            throw LapsSchedulingStorage.Invalid();
                        writer.WriteLapsConfiguredPolicy(result.Value, token);
                        saved++;
                    }
                    else
                    {
                        writer.WriteUnassessedLapsComputer(computer, result.Error);
                        log.Record("Judge", result.Error, [new("computer-row", computer.ObjectId.ToString(CultureInfo.InvariantCulture))]);
                        unassessed++;
                    }
                    writer.CompleteObject();
                }
                finally { storage.Stop(); }
                if (considered % JudgingRun.ProgressEvery == 0)
                    Report();
                token.ThrowIfCancellationRequested();
            }
        }
        var completed = scope with
        {
            State = policy == ConfiguredLapsPolicy.Disabled ? ConfiguredLapsSchedulingState.Disabled
                : unassessed == 0 ? ConfiguredLapsSchedulingState.Complete : ConfiguredLapsSchedulingState.CompleteWithUnassessed,
            QuestionsConsidered = considered,
            SavedCalculations = saved,
            UnassessedComputers = policy == ConfiguredLapsPolicy.Disabled ? scope.ObservedComputers : unassessed,
        };
        token.ThrowIfCancellationRequested();
        writer.CompleteConfiguredLapsScheduling(completed);
        log.Note("Judge", "configured-laps", [
            new("generation", writer.GenerationId.ToString("D")), new("policy", policy.ToString()),
            new("state", completed.State.ToString()), new("scope", "captured-ordinary-computers"),
            new("observed", completed.ObservedComputers.ToString(CultureInfo.InvariantCulture)),
            new("considered", considered.ToString(CultureInfo.InvariantCulture)),
            new("saved", saved.ToString(CultureInfo.InvariantCulture)),
            new("unassessed", completed.UnassessedComputers.ToString(CultureInfo.InvariantCulture)),
            new("calculation-ms", calculation.Elapsed.TotalMilliseconds.ToString("F1", CultureInfo.InvariantCulture)),
            new("storage-ms", storage.Elapsed.TotalMilliseconds.ToString("F1", CultureInfo.InvariantCulture)),
        ]);
        if (policy != ConfiguredLapsPolicy.Disabled) Report();
        token.ThrowIfCancellationRequested();
        return completed;

        void Report() => progress.Report(new JudgingRun.JudgingProgress(objectsRead)
        {
            Phase = JudgingPhase.EvaluatingObjects,
            JudgementGenerationId = writer.GenerationId,
            WorkCompleted = considered,
            WorkUnit = JudgingWorkUnit.Resources,
        });
    }
}
