& "$PSScriptRoot\Edit-File.ps1" -Path "$PSScriptRoot\..\..\docs\layers\judgement\what-a-finding-is.md" -OldText @'
| `PathStep` | One principal on a membership path, carrying both its identifier and its name — the identifier survives a rename, the name is the part an operator can act on |

<!-- TYPES:END -->
'@ -NewText @'
| `PathStep` | One principal on a membership path, carrying both its identifier and its name — the identifier survives a rename, the name is the part an operator can act on |
| `LapsDecryptorBroadPrincipal` | SEC-093: a Group Policy Object whose authorized Windows LAPS password decryptor is, or contains through nesting, a principal broad in every organisation |
| `LapsDecryptorEvidence` | The configured decryptor value, the principal it resolved to, the broad principal that can decrypt and the route that reached it |
| `LapsDecryptorForm` | Which of the three forms Microsoft accepts the value was written in, which decides what an unresolved value means |

<!-- TYPES:END -->
'@
