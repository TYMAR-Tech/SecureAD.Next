$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Traceability for the twenty requirements of the archived permissions specification. For each,
# the concrete thing the code would have to contain if it were implemented. A hit is evidence to
# go and read, not proof; a miss is a strong signal that nothing implements it.
$checks = [ordered]@{
    'R1  unsupported ACE kept raw'          = 'RawBytes|UnsupportedAce|UnknownAceType|raw bytes'
    'R2  raw mask kept, generic mapped'     = 'GenericRightsExpander'
    'R3  GUID meaning per mask bit'         = 'ClassifyExtendedRight|ClassifyProperty|SchemaGuidKind'
    'R4  validAccesses + attributeSecurityGUID' = 'validAccesses|attributeSecurityGUID'
    'R5  stored ordinal and canonicality'   = 'AceCanonicalization|StoredOrdinal|Ordinal'
    'R6  NULL DACL evidence'                = 'NullDacl|DaclPresent|DaclUnreadable'
    'R7  property scope over attributes'    = 'PermissionScope'
    'R8  confidential needs two bits'       = 'Confidential'
    'R9  searchFlags and systemFlags'       = 'searchFlags|systemFlags'
    'R10 accumulate across entries'         = 'Accumulat|Aggregate.*Ace|union of'
    'R11 owner-SID implicit rights'         = 'implicit right|implicitly|owner can rewrite'
    'R11b OWNER RIGHTS SID qualification'   = 'S-1-3-4|OwnerRightsSid'
    'R12 LIST_OBJECT visibility'            = 'ListObject|LIST_OBJECT|fDoListObject'
    'R13 INHERIT_ONLY suppresses grant'     = 'InheritOnly|INHERIT_ONLY'
    'R14 InheritedObjectType most-specific' = 'InheritedObjectType'
    'R15 new-object DACL construction'      = 'DefaultSecurityDescriptor|defaultSecurityDescriptor|NewObjectDacl'
    'R16 transitive membership'             = 'Transitive|transitive'
    'R17 adminCount history, SE_DACL_PROTECTED' = 'SE_DACL_PROTECTED|DaclProtected'
    'R18 trustee SID semantics'             = 'S-1-3-0|S-1-5-10|CreatorOwner|PrincipalSelf|placeholder SID'
    'R19 never entry-level as effective'    = 'EntryReach|effective access'
    'R20 access-check family'               = 'AccessCheckFamily|AccessCheck'
}

"{0,-42} {1,6} {2}" -f 'REQUIREMENT', 'HITS', 'WHERE'
foreach ($k in $checks.Keys) {
    $files = @(git grep -lEi $checks[$k] -- 'next/src')
    $where = if ($files.Count) { ($files | ForEach-Object { Split-Path $_ -Leaf } | Select-Object -First 3) -join ', ' } else { '-' }
    "{0,-42} {1,6} {2}" -f $k, $files.Count, $where
}
