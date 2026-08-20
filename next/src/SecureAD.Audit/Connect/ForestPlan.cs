using SecureAD.Audit.Capture;

namespace SecureAD.Audit.Connect;

/// <summary>
/// Everything one discovery pass established: what will be read, from which controller, and the
/// evidence behind that choice.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why the plan is not enough on its own.</b> <see cref="CapturePlan"/> carries one controller
/// per domain and nothing about why it was chosen. That was sufficient while each domain was read
/// from its own DNS name, because there was no choice being made. It is not sufficient now:
/// <c>docs/decisions/0040-a-failed-domain-is-read-again-from-another-controller.md</c> needs the
/// ranked alternatives when a read fails, and
/// <c>docs/decisions/0055-the-pdc-emulator-is-established-at-preflight.md</c> needs the topology and
/// the roles again at preflight, to re-rank a domain whose pinned controller turns out to be its PDC
/// emulator.
/// </para>
/// <para>
/// <b>The bootstrap controller is not here.</b> It answered one question and is never pinned, per
/// <c>docs/decisions/0053-the-tool-finds-its-own-forest.md</c>. Which controller each domain is read
/// from is <see cref="ControllerSelection"/>'s answer alone.
/// </para>
/// </remarks>
/// <param name="Capture">What will be read, with each domain's pinned controller already applied.</param>
/// <param name="Topology">Every candidate controller and the forest's subnets, from one read.</param>
/// <param name="Roles">
/// The operations master roles. Every domain's PDC emulator is
/// <see cref="PdcEmulatorKnowledge.NotYetEstablished"/> here, by design.
/// </param>
/// <param name="Selection">Each domain's pinned controller and its ordered failover list.</param>
public sealed record ForestPlan(
    CapturePlan Capture,
    ForestTopology Topology,
    ForestRoles Roles,
    ControllerSelection Selection);
