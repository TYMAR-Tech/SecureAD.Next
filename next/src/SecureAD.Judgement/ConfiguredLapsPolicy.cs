namespace SecureAD.Judgement;

/// <summary>Controls automatic captured-computer LAPS calculations, separately from finding rules.</summary>
public enum ConfiguredLapsPolicy
{
    /// <summary>No automatic calculations; recorded scope remains explicitly unassessed.</summary>
    Disabled,
    /// <summary>Consider every captured ordinary-computer row, without a supplied target list.</summary>
    AllCapturedComputers,
}

internal enum ConfiguredLapsSchedulingState { Writing, Disabled, Complete, CompleteWithUnassessed }

internal sealed record ConfiguredLapsSchedulingSummary(Guid JudgementGenerationId, Guid CaptureGenerationId,
    string EvidenceSeal, Guid? DerivationGenerationId, ConfiguredLapsPolicy Policy,
    ConfiguredLapsSchedulingState State, long ObservedComputers, long QuestionsConsidered,
    long SavedCalculations, long UnassessedComputers, bool CaptureScopeComplete);
