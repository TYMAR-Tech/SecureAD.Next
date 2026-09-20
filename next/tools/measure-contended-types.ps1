$root = 'C:\Users\jistrand\source\repos\SecureAD.Next'

$contended = @{
    'SecurityDescriptorParser'            = @('kernel/permission-classification.md','kernel/permission-requirements.md','kernel/security-descriptors.md')
    'CapturedAttributeCatalog'            = @('audit/the-attribute-catalogue.md','audit/the-search-capture-issues.md','evidence/what-a-bundle-holds.md','kernel/permission-requirements.md')
    'CapturedAttribute'                   = @('audit/how-a-controller-is-read.md','audit/the-attribute-catalogue.md')
    'CaptureSearchRequestFactory'         = @('audit/how-a-controller-is-read.md','audit/the-search-capture-issues.md','connect/how-a-connection-is-opened.md')
    'ParsedAce'                           = @('kernel/permission-classification.md','kernel/security-descriptors.md')
    'AceType'                             = @('evidence/what-a-bundle-holds.md','kernel/security-descriptors.md')
    'ContinuationReferenceReconciliation' = @('audit/how-a-controller-is-read.md','audit/the-search-capture-issues.md')
}

foreach ($type in $contended.Keys | Sort-Object) {
    ''
    "########## $type"
    foreach ($page in $contended[$type]) {
        $path = Join-Path $root ("docs\layers\" + $page.Replace('/','\'))
        $lines = [System.IO.File]::ReadAllLines($path)

        $hits = @()
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $parts = $lines[$i].Split('`')
            for ($j = 1; $j -lt $parts.Length; $j += 2) {
                foreach ($half in $parts[$j].Split('.')) {
                    if ($half -ceq $type) { $hits += $i }
                }
            }
        }

        $hits = $hits | Sort-Object -Unique
        ''
        "--- $page   mentions on $($hits.Count) line(s)"
        # is the type named in the Code: header, i.e. the page is the description of its file?
        $header = ($lines[0..6] -join ' ')
        if ($header -match [regex]::Escape($type)) { "    HEADER: named in the Code: header" }
        foreach ($h in $hits) { '    {0,4}: {1}' -f $h, $lines[$h] }
    }
}
