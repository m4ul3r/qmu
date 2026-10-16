# Evidence and handoff contract

Companion to `skill://qmu` (the main `SKILL.md`). Read this before promoting a
matched marker, a green `qmu run`, or a reachable SSH port into a claim about
the system under test, and before handing an emulation milestone to another
agent. The concrete isolation rules (unique names, `--no-replace`, explicit
`--vm`, private `QMU_TEMP_DIR`) are summarized in the main skill under
*Working with other agents on one host*; this file is the full operating
contract.

Infrastructure health is not application convergence. At intake, name the benign
completion operation and its required environment. For firmware convergence,
SSH or a manually started original binary is an intermediate milestone, not
completion of the relevant vendor init/service environment.

- Identify the kernel, kernel config, resolved boot recipe, rootfs, init, inputs,
  and helpers by immutable revision or content digest, with discoverable paths.
  A path alone is not artifact identity. Declare substitutions and limits before
  interpreting results; separate **observations**, **explanations**, and
  **applicability**. Emulation without original-system ground truth does not
  independently establish hardware equivalence.
- Concurrent workers need unique VM names, `--no-replace`, explicit `--vm`
  selection, and private writable images, build outputs, scripts, and receipts.
  Only identified read-only inputs may be shared. Use config-based boot recipes,
  not a parallel launcher; agree ownership before editing shared artifacts.
  Filesystem isolation does not isolate a shared retained interpreter. Run
  independent verifier preparation in separate processes; do not let workers
  overwrite each other's Eval globals. If setup collides, invalidate that
  attempt and recreate/re-identify private inputs before accepting evidence.
  Use an ordinary private runtime directory, for example
  `QMU_TEMP_DIR=<private-root>/run`, consistently for launch, exec and transfers.
  qmu budgets the expanded SSH control socket name including OpenSSH's temporary
  suffix, and omits its multiplex options when that name cannot fit. Do not pad
  directory names to force a fallback or require multiplexing to be disabled:
  safe short paths retain it. Keep cache/VM names short enough for QMP sockets.
- Missing exercise evidence, stale artifacts, VM collisions, or failed observation
  channels make a run **invalid/inconclusive**, not negative. Follow the marker
  and epoch limits in the main skill's *boot-and-check iterate loop*.
  `qmu wait --pattern` exit 0 proves a pattern matched, not the semantic truth
  of its text. Without `--pattern`, exit 0 establishes recorded QEMU process
  termination only, not exercise evidence.
- Before another attempt, name the unresolved hypothesis, changed variable, and
  distinguishing observation. Stop the blocked lane when none is available,
  rather than imposing a fixed time limit or repeating unchanged attempts.
  A passed isolated experiment does not unblock a different main goal.
- Repair routine setup autonomously. Interrupt only for changes to the proof
  question or relevant original behavior, destructive/shared-state actions, or
  prerequisites only the user can provide. Hardware-facing models stay in
  isolated experiments until explicitly approved for the baseline; that approval
  authorizes an adaptation, not equivalence to unobserved hardware.
- Keep a current recipe and linked receipts sufficient for a fresh agent on the
  same host to discover, identify, and reproduce the environment without chat
  history. Include offline changes and redeployment of ephemeral guest files.
  Before an emulation milestone or handoff is complete, a **fresh independent
  agent** reviews the exact scope/evidence and reproduces the named benign
  operation from a **clean VM**, not just warm state. This gate is per milestone
  or handoff, not per edit. Until then, report awaiting independent verification.
  Preserve limits and corrections; changed claim scope or bound evidence
  invalidates prior approval and requires renewed review/reproduction. When Stet
  is used, follow its revision-bound observation/explanation/applicability
  discipline; bookkeeping currentness alone does not prove a claim.

Report one compact current row per milestone: **milestone | current state |
strongest observation | substitutions/limits | receipt link | next distinguishing
check or blocker**. Keep detailed history in the receipts, not an expanding
status narrative. This is an operating contract, not a new qmu output schema.
