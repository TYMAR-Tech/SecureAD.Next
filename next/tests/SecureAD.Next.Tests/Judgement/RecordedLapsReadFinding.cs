using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Schema;

namespace SecureAD.Next.Tests.Judgement;

internal static class RecordedLapsReadFinding
{
    internal static LapsPasswordReaderEvidence Evidence(string trustee, string? trusteeName,
        string broad, string? broadName, IReadOnlyList<PathStep> path, string attribute,
        LapsReadRights rights, LapsGrantReach reach, string? inheritedClassGuid, bool complete)
    {
        var attributeGuid = attribute switch
        {
            "msLAPS-Password" => "53c5be7e-5403-4013-a04b-b22e05d0e3c1",
            "msLAPS-EncryptedPassword" => "f3531ec6-6330-4f8e-8d39-7a671fbac605",
            "ms-Mcs-AdmPwd" => "2e0e4a88-f5fa-11df-b3af-001fc000a000",
            _ => throw new ArgumentOutOfRangeException(nameof(attribute)),
        };
        var entry = new PermissionEntry(0, "AccessAllowedObject",
            new(trustee, trusteeName, null, null, null, null, null), 0x110,
            reach == LapsGrantReach.ThisAttributeOnly ? attributeGuid : null, inheritedClassGuid,
            inheritedClassGuid is not null, 0, 0, reach == LapsGrantReach.ThisAttributeOnly,
            inheritedClassGuid is not null, []);
        var exposure = new LapsReadExposure("Fixture target; explicitly bound before writing", Guid.Empty, null,
            trustee, trusteeName, null, attribute, attributeGuid, "computer", null, 128, 0,
            LapsConfidentiality.Confidential, LapsReadState.Established, rights, reach,
            inheritedClassGuid is not null, inheritedClassGuid is null ? [] : [inheritedClassGuid], path, complete,
            new(0x10, LapsReadState.Established, [0], [], []),
            new(0x100, LapsReadState.Established, [0], [], []),
            [0], [new(entry, LapsReadState.Established, "Recorded synthetic grant.",
                [new(attributeGuid, attribute, SchemaGuidKind.Attribute, SchemaGuidSource.Captured)], null)]);
        return new(trustee, trusteeName, broad, broadName, path, attribute, rights, reach, inheritedClassGuid, complete)
        {
            IsInherited = inheritedClassGuid is not null,
            Assessment = new(1, 1, true, true, complete, true, complete ? [] : ["MembershipIncomplete"]),
            SupportingExposures = [exposure],
        };
    }

    internal static Finding Bind(Finding finding)
    {
        if (finding.Evidence is not LapsPasswordReaderEvidence evidence) return finding;
        var exposures = evidence.SupportingExposures
            ?? throw new InvalidOperationException("The fixture must provide its actual supporting values.");
        return finding with
        {
            Evidence = evidence with
            {
                SupportingExposures = exposures.Select(value => value with
                {
                    Target = finding.DistinguishedName,
                    TargetGuid = finding.ObjectGuid,
                    ResourceDomain = finding.DomainFqdn,
                }).ToArray(),
            },
        };
    }
}
