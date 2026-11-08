namespace SecureAD.Judgement;

internal static class SavedPermissionReview
{
    internal static string Describe(string reason, string invalidDetails) => reason switch
    {
        nameof(ControlExpectednessReason.UnexpectedBroadPrincipal) => "The holder is a broadly applicable identity.",
        nameof(ControlExpectednessReason.UnexpectedNotControlPlane) =>
            "The saved assessment does not identify this holder as an expected administrator for this target.",
        nameof(ControlExpectednessReason.UnexpectedOutsideAuthorityScope) =>
            "The holder is outside its expected administrative authority for this target in the saved assessment.",
        _ => throw new InvalidDataException(invalidDetails),
    };
}
