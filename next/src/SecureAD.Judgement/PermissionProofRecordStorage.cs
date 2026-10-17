using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal static class PermissionProofRecordStorage
{
    internal static RequestedDetailIndex.RecordLayout Entry { get; } = new("permission_entry",
    [
        "id", "generation", "entry_hash", "ace_type", "sid", "name", "dn", "domain", "unresolved_reason",
        "role", "meaning", "mask", "object_type", "inherited_object_type", "inherited", "inheritance_flags",
        "propagation_flags", "has_object_type", "has_inherited_object_type", "application_data", "meaning_binding",
    ], [0]);

    internal static RequestedDetailIndex.RecordLayout Edge { get; } = new("control_edge",
    [
        "id", "target", "target_guid", "target_class", "holder_sid", "holder_name", "holder_scope",
        "capability", "edge_class", "evaluation", "uncertainty", "expectedness", "expectedness_reason",
        "catalogue_version", "generation", "derivation_generation", "counted", "ace_count", "precondition_count",
    ], [0]);

    internal static RequestedDetailIndex.RecordLayout Ace { get; } = new("control_ace",
        ["edge_id", "ordinal", "entry_id", "fingerprint"], [0, 1]);

    internal static RequestedDetailIndex.RecordLayout Precondition { get; } = new("control_precondition",
        ["edge_id", "ordinal", "name", "state", "evidence"], [0, 1]);

    internal static RequestedDetailIndex.RecordLayout FullSource { get; } = new("full_control_source",
        ["target", "ace_count", "fingerprint"], [0]);

    internal static RequestedDetailIndex.RecordLayout FullSourceEntry { get; } = new("full_control_source_entry",
        ["target", "position", "ordinal", "entry_id", "fingerprint"], [0, 1]);

    internal static RequestedDetailIndex.RecordLayout FullAssessment { get; } = new("full_control_assessment",
    [
        "id", "target", "holder_sid", "holder_scope", "evaluation", "expectedness", "generation",
        "derivation_generation", "support_count", "proof", "route_value_id", "route_fingerprint",
    ], [0]);

    internal static IReadOnlyList<RequestedDetailIndex.RecordLayout> All { get; } =
        [Entry, Edge, Ace, Precondition, FullSource, FullSourceEntry, FullAssessment];
}
