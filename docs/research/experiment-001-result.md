# Experiment 001: Target-Only Observation Gap

Date: 2026-10-21
Project: Kalpang Effect-Boundary Probe
Status: PASS — controlled demonstration

## Research question

Can the declared fields of a target object match while a separate effect exists elsewhere in the same service?

## Setup

- Service: GitHub Issues
- Target issue: #1
- Secondary issue: #2
- Target checks: title, body, and open state
- Broader check: repository issue inventory

## Observed results

- Target-only observer: MATCH
- Repository inventory: DEVIATION_FOUND
- Secondary issue: #2
- Overall probe verdict: PASS

Run:
https://github.com/gokuljayprakash8/kalpang-effect-boundary-probe/actions/runs/39575418914

## Interpretation

The target object's declared fields matched while a separate issue existed elsewhere in the repository. Target-only read-back is therefore insufficient to establish the absence of other effects within the broader issue boundary.

## Limitations

The workflow deliberately created the secondary issue. Both observations rely on GitHub and the same repository. The inventory covers issues, not every possible downstream effect.

This result does not establish an independent trust domain, complete effect coverage, a novel mechanism, or a vulnerability.

## Next experiment

Add controls to distinguish the target's expected effect from an additional effect. Test a normal execution, a deliberately injected additional effect, and a target-mismatch case. Record expected and observed results separately.
