# SecureAD

**Active Directory security assessment and delegation auditing for Windows.**

SecureAD reads a forest over LDAP, captures what it finds into a sealed evidence bundle on disk,
and lets an operator read that bundle back offline. It runs as a standard domain user; no
administrative privileges are required.

The product is being rebuilt. **[`docs/next/README.md`](docs/next/README.md) is the authority** for
this repository: what is built and what is not, what counts as documentation here, the gates every
change is held to, and how to continue the work.

```powershell
dotnet build next/SecureAD.Next.sln
dotnet test next/SecureAD.Next.sln
```

This file is a signpost. Nothing here states the product's position; only a record in
[`docs/decisions/`](docs/decisions/) with `Status: Accepted` does that.
