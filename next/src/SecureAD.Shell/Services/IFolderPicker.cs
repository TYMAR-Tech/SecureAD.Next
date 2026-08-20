namespace SecureAD.Shell.Services;

/// <summary>
/// Asking the operator for a folder.
/// </summary>
/// <remarks>
/// A seam over a modal dialog, and it exists so that a view model can offer "choose a run library"
/// without being able to open a window. A view model that opened its own dialog could not be tested
/// without someone present to close it.
/// </remarks>
internal interface IFolderPicker
{
    /// <summary>
    /// Asks for a folder, starting at <paramref name="startingAt"/> where there is one.
    /// </summary>
    /// <param name="title">What the operator is being asked for.</param>
    /// <param name="startingAt">Where to open, or null to let the system decide.</param>
    /// <returns>The chosen folder, or null if the operator cancelled.</returns>
    string? Pick(string title, string? startingAt);
}
