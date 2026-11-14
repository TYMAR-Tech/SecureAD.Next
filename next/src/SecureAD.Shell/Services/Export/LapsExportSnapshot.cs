using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;

namespace SecureAD.Shell.Services.Export;

internal sealed record LapsExportSnapshot(
    BundleDescription Capture, RunScope CaptureScope, LapsInventorySummary Inventory, LapsPage FirstPage);
