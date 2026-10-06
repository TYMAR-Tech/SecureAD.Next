using CommunityToolkit.Mvvm.ComponentModel;

namespace SecureAD.Shell.ViewModels;

/// <summary>A display filter over the selected section's already-read evidence.</summary>
internal sealed partial class AttributeCardsViewModel(IReadOnlyList<AttributeValueViewModel> values) : ObservableObject
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(VisibleValues))]
    private bool _showMissingAttributes;

    // Microsoft's Computer class includes optional inherited userPrincipalName. Schema allowance
    // cannot tell whether a value arrived: https://learn.microsoft.com/windows/win32/adschema/c-computer
    // Read permissions can silently omit properties:
    // https://learn.microsoft.com/windows/win32/ad/access-control-and-read-operations
    // Filter only presentation; unread evidence and the section's qualifications remain visible.
    public IReadOnlyList<AttributeValueViewModel> VisibleValues => ShowMissingAttributes
        ? values : [.. values.Where(value => value.HasValue || value.IsUnread)];

    public bool HasMissingAttributes => values.Any(value => !value.HasValue && !value.IsUnread);
}
