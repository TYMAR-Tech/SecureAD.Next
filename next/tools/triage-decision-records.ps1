$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# For each decision record: its status, whether the product's code or tests cite it, and how
# many other documents link to it. A record nothing cites is not thereby dead - but it is the
# pile worth reading, because nothing anchors it to the product.
#
# Decision file names carry a unique four-digit prefix, so matching on the file name is safe
# here. It is not safe generally: docs/README.md and docs/next/README.md share a leaf name and
# matching on it inflated one file's reference count from 1 to 69 earlier in this work.
"{0,-6} {1,-11} {2,5} {3,5}  {4}" -f 'REC', 'STATUS', 'CODE', 'DOCS', 'TITLE'
foreach ($f in (git ls-files 'docs/decisions/0*.md')) {
    $leaf = Split-Path $f -Leaf
    $id = $leaf.Substring(0, 4)
    $head = Get-Content $f -TotalCount 6
    $status = (($head | Select-String '^Status:\s*(\S+)').Matches.Groups[1].Value)
    $title = ($head[0] -replace '^#\s*\d+\s*-\s*', '')
    $code = (git grep -l -F $leaf -- 'next/src' 'next/tests' | Measure-Object).Count
    $docs = (git grep -l -F $leaf -- 'docs' | Where-Object { $_ -ne $f } | Measure-Object).Count
    "{0,-6} {1,-11} {2,5} {3,5}  {4}" -f $id, $status, $code, $docs, $title
}
