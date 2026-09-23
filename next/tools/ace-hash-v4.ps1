# An independent implementation of the written ace_hash recipe, used to move the golden values from
# canonicalization version 3 to version 4 (P-272). It is shown to reproduce all eight version 3
# constants from the version 3 recipe before its version 4 answers are trusted - which is what makes
# it evidence rather than a second guess. It reads nothing from the product.
#
# Recipe, version 3: {object_guid}|{sid}|{mask}|{object_type}|{inherited_object_type}|{inherited}|
#                    {inheritance_flags}|{propagation_flags}|{ace_type}|{application_data}
# Recipe, version 4: the same with the leading {object_guid}| removed.
# UTF-8, SHA-256, lowercase hex.

$guid = '12345678-abcd-ef01-2345-6789abcdef01'
$sha  = [System.Security.Cryptography.SHA256]::Create()

function Hash([string]$text) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
}

$cases = @(
    @{ Name='AdministratorsFullControl'; Sid='S-1-5-32-544'; Mask=983551; Ot=''; Iot=''; Inh=0; If_=0; Pf=0; Type=0; V3='2904f49b84f9dc12463b7cde4cdfe08289e124487638110f3796b122be0f25a6' }
    @{ Name='DenyEveryoneExplicit';      Sid='S-1-1-0';      Mask=4;      Ot=''; Iot=''; Inh=0; If_=0; Pf=0; Type=1; V3='d7cf9b8a608d62ab8ceab7bdb565f3c445a52eed696e860b10de13ef213d0363' }
    @{ Name='ObjectAceWithBothGuids';    Sid='S-1-5-32-544'; Mask=16;     Ot='bf967aba-0de6-11d0-a285-00aa003049e2'; Iot='bf967a86-0de6-11d0-a285-00aa003049e2'; Inh=0; If_=0; Pf=0; Type=5; V3='51c23024caad2407395a49ddc9446fe24dd4be8219f892b76fb5e633be1e1297' }
    @{ Name='DenyAuthenticatedUsers';    Sid='S-1-5-11';     Mask=4;      Ot=''; Iot=''; Inh=0; If_=0; Pf=0; Type=1; V3='f9676b1d5b903189684958a068c97572d94a210623a11865a5f6a9f5d96a354c' }
    @{ Name='DenyEveryoneInherited';     Sid='S-1-1-0';      Mask=4;      Ot=''; Iot=''; Inh=1; If_=0; Pf=0; Type=1; V3='acaeaea85d070b9a485c3c91e7590286b46c6de11b0f2f8a61c12165961603e6' }
    @{ Name='AllowSystemInherited';      Sid='S-1-5-18';     Mask=983551; Ot=''; Iot=''; Inh=1; If_=0; Pf=0; Type=0; V3='7db79477bbb20340a7d51dc770bd6e3cabba8410e8baa905f1c26ee2bbdd2614' }
    @{ Name='DomainSidTrustee';          Sid='S-1-5-21-1234567890-987654321-111222333-512'; Mask=983551; Ot=''; Iot=''; Inh=0; If_=0; Pf=0; Type=0; V3='7c3263696953205af78696c3567f33716a0847cc62f304eb817a238b7eaf8b6d' }
    @{ Name='InheritedWithContainerInherit'; Sid='S-1-5-32-544'; Mask=983551; Ot=''; Iot=''; Inh=1; If_=2; Pf=0; Type=0; V3='d5b8cac3f73ce93c9231269db40c64d303f149a062b581d80df0e299cd40cb17' }
)

$failed = 0
foreach ($c in $cases) {
    $tail = "$($c.Sid)|$($c.Mask)|$($c.Ot)|$($c.Iot)|$($c.Inh)|$($c.If_)|$($c.Pf)|$($c.Type)|"
    $v3 = Hash "$guid|$tail"
    $v4 = Hash $tail
    $ok = $v3 -eq $c.V3
    if (-not $ok) { $failed++ }
    '{0,-30} v3 {1} {2}   v4 {3}' -f $c.Name, $v3, $(if ($ok) { 'REPRODUCED' } else { 'MISMATCH  ' }), $v4
}

''
if ($failed -eq 0) {
    'All eight version 3 constants reproduced. The version 4 column is the same arithmetic.'
} else {
    "$failed of $($cases.Count) version 3 constants did NOT reproduce - the version 4 column is not trustworthy."
    exit 1
}
