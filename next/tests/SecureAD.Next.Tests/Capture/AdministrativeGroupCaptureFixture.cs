using System.Globalization;
using SecureAD.Next.Tests.Kernel.Security;

namespace SecureAD.Next.Tests.Capture;

internal static class AdministrativeGroupCaptureFixture
{
    private const string Domain = "DC=example,DC=com";
    private const string Administrator = "CN=Fixture administrator," + Domain;
    private static readonly uint[] DomainAuthority = [21, 1111111111, 2222222222, 3333333333];

    internal static void AddTo(ControllerModel controller)
    {
        controller.AddObject(Domain, ("objectClass", ["top", "domainDNS"]),
            ("objectGUID", [Guid.NewGuid().ToByteArray()]), ("objectSid", [SdBytes.Sid(1, 5, DomainAuthority)]));
        controller.AddObject(Administrator, ("objectClass", ["top", "person", "organizationalPerson", "user"]),
            ("objectGUID", [Guid.NewGuid().ToByteArray()]), ("objectSid", [SdBytes.Sid(1, 5, [.. DomainAuthority, 500])]),
            ("sAMAccountName", ["fixture-administrator"]), ("userAccountControl", ["512"]), ("primaryGroupID", ["513"]));
        foreach (var (name, rid, builtin, type) in new[]
        {
            ("Fixture domain administrators", 512u, false, -2147483646L),
            ("Fixture enterprise administrators", 519u, false, -2147483640L),
            ("Fixture schema administrators", 518u, false, -2147483640L),
            ("Fixture administrators", 544u, true, -2147483643L),
            ("Fixture legacy access", 554u, true, -2147483643L),
            ("Fixture domain users", 513u, false, -2147483646L),
        })
        {
            var dn = "CN=" + name + "," + (builtin ? "CN=Builtin," : "") + Domain;
            controller.AddObject(dn, ("objectClass", ["top", "group"]), ("objectGUID", [Guid.NewGuid().ToByteArray()]),
                ("objectSid", [SdBytes.Sid(1, 5, builtin ? [32, rid] : [.. DomainAuthority, rid])]),
                ("groupType", [type.ToString(CultureInfo.InvariantCulture)]), ("member", [Administrator]));
        }
    }
}
