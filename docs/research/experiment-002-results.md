# Experiment 002: Controlled Effect-Boundary Checks

Date: 2026-10-21
Project: Kalpang
Status: Three controlled scenarios passed

## Objective

Test whether the workflow distinguishes a normal target, a target with an additional marked issue, and a target mismatch.

## Results

### Test A — Normal
- Run ID: EB002-20261021-N1
- Target issue: #3
- Target observer: MATCH
- Marked side-effect count: 0
- Verdict: PASS
- Run: https://github.com/gokuljayaprakash8/kalpang-effect-boundary-probe/actions/runs/39582620026

### Test B — Additional effect

Initial attempt:
- Run ID: EB002-20261021-E1
- Target issue: #4
- Target observer: MATCH
- Marked side-effect count: 0 (expected 1)
- Verdict: FAIL

Rerun after adding a retry loop:
- Run ID: EB002-20261021-E2
- Target issue: #6
- Target observer: MATCH
- Marked side-effect count: 1
- Verdict: PASS
- Run: https://github.com/gokuljayaprakash8/kalpang-effect-boundary-probe/actions/runs/39584242891

The retry fixed the observed failure in the subsequent run. The precise cause of the initial miss has not been independently established.

### Test C — Target mismatch
- Run ID: EB002-20261021-M1
- Target issue: #8
- Target observer: NONMATCH
- Marked side-effect count: 0
- Verdict: PASS
- Run: https://github.com/gokuljayaprakash8/kalpang-effect-boundary-probe/actions/runs/39584473277

## Interpretation

The workflow distinguished the three configured scenarios. The target-only observation matched the target's declared fields in Tests A and B, while the inventory detected the deliberately created additional issue in the successful Test B rerun.

## Limitations

The additional issue was deliberately created by the workflow. Both observations rely on GitHub within the same repository. The marker inventory does not cover every possible side effect and is not an independent trust domain.

These results validate a controlled demonstration, not a production security boundary, complete effect coverage, or research novelty.

## Next research question

Can a controlled REST service demonstrate an additional state change that the executor's target-only read-back misses, while a separately implemented observer detects it?