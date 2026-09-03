# 0094 - A WMI filter is captured and named, never evaluated

Date: 2026-09-03
Status: Accepted.

Settles how SecureAD states which machines a Group Policy Object reaches, for every rule that
reasons about policy scope. Sits beside [`0002`](0002-absent-view-means-degraded-run.md) and
[`0086`](0086-a-qualified-statement-beats-silence.md), and adds four attributes to the captured
attribute catalogue at version 7.

## Context

A Group Policy Object is linked to a site, domain or organizational unit, and that link is a
directory fact SecureAD already captures as `gPLink`. A **WMI filter** narrows it further: the
policy applies only to machines where a WQL query returns a result. Microsoft describes the
`ms-WMI-Som` class as refining *"a Group Policy Object's Scope of Management"*, adding *"a list of
rules, expressed as WQL queries that are executed on the target computer. All queries must return
results for this SOM to be applicable to the target."*

The filter is not hidden. Three attributes hold it, all replicated:

| Attribute | Class | Holds |
|---|---|---|
| `gPCWQLFilter` | `groupPolicyContainer` | The filter's GUID and namespace path - the link from policy to filter |
| `msWMI-Name` | `msWMI-Som` | The name an administrator knows the filter by |
| `msWMI-Parm2` | `msWMI-Som` | The WQL query text |

**The queries execute on the machine, against live WMI.** They can ask about free disk space,
installed hotfixes, registry values, hardware model or the current time - facts no domain controller
has ever held. Some ask only about the operating system, which SecureAD does capture.

The lab forest carries four filters, splitting servers at the Server 2019 build boundary
(`Version >= '10.0.17763' AND ProductType = '3'`), and two are attached to the LAPS policies that
SEC-091 and SEC-092 judge. This is not a corner case in an estate we can see.

## Decision

**Capture the three attributes. Never evaluate the query.**

**A rule may use linked scope to raise a finding, and never to suppress one.** Where the absence of
a finding would depend on a policy having reached a machine, the rule reports that it could not
determine coverage rather than staying silent.

**A finding whose subject is reached by a filtered policy names the filter and shows its query**,
and says SecureAD did not evaluate it.

## Why

**Evaluating means writing a partial WQL interpreter, and a partial interpreter is worse than none.**
It would handle a recognised subset and misread the rest, producing a scoping answer that reads as
authoritative and is wrong. `0086` reserves silence for completeness precisely because a wrong
confident answer makes someone stop looking.

**The asymmetry decides the suppression rule.** A WMI filter can only ever make a policy apply to
*fewer* machines than it is linked to, never more. So using linked scope to raise a finding
over-reports at worst - the operator investigates and finds the filter. Using it to conclude a
machine is covered can say *safe* about a machine the policy never reached, silently. Those are not
equally acceptable errors.

**Naming the filter is what makes the warning survive contact with an operator.** A footer on every
GPO finding saying WMI might be involved is boilerplate, and boilerplate gets skipped. *"This policy
carries the filter '2019 and above' - `SELECT * FROM Win32_OperatingSystem WHERE (Version >=
'10.0.17763' AND ProductType = '3')` - which SecureAD does not evaluate"* is a fact an operator acts
on in seconds.

**It also converts an omission into a stated gap**, which is `0002`. Without these attributes the
product cannot distinguish *this policy has no filter* from *we never looked*.

## What this does not decide

Which container-to-machine scoping model the derivation uses, and whether scoping is computed per
container or per machine. That work is unstarted. This record constrains what any such model may
claim, not how it is built.

Site-linked policies remain outside what a bundle answers, for an unrelated reason: site links live
in the configuration naming context and resolving a machine to a site needs its IP address at boot,
which the directory does not hold.

## Consequences

- Catalogue version 6 to 7. A bundle stamped 6 cannot say whether a policy was filtered; a rule
  reading one reports that, rather than treating absence as *no filter*.
- `msWMI-Som` becomes a captured class. The objects are few - one per filter, tens in a large
  estate - so the capture cost is negligible.
- Every GPO-scoped rule card must state which direction it uses linked scope in. A card that would
  suppress a finding on linked scope needs rewriting before it is built.
