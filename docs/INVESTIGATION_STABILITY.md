# Investigation Stability

This document records known stability and reliability investigations that are intentionally deferred because they do not currently represent a demonstrated product-correctness defect or a prerequisite for continued feature development.

Entries in this document are **not** permission to weaken tests, suppress failures, or treat unexplained behavior as acceptable indefinitely. Each entry should preserve the evidence already gathered, rejected hypotheses, current impact, deferral rationale, and explicit conditions for reopening the investigation.

---

# Frontend

## E22/E22-B Chromium renderer wedge

### Status

**DEFERRED — non-blocking**

This investigation does not currently block continued ATI feature development.

### Affected tests

```text
frontend/e2e/zz-pivots.spec.ts

E22
E22-B
```

The affected scenarios exercise PR 24D cross-resource pivot and provenance behavior through the real-stack browser harness.

### Observed behavior

On a constrained two-core host, Chromium can become unresponsive while Playwright interacts with controls inside ATI's pivot/detail overlay stack.

Observed characteristics:

- the page is responsive immediately before the triggering interaction;
- the Playwright interaction is dispatched or attempted;
- the Chromium renderer/main thread becomes unresponsive;
- subsequent Playwright/evaluate operations stall;
- the test eventually terminates through its timeout;
- no corresponding browser-console or `pageerror` failure has been observed before the stall;
- the exact interaction at which the wedge occurs is not deterministic.

The issue has reproduced in both E22 and E22-B.

### Known reproduction mechanisms

The wedge has reproduced through all of the following interaction mechanisms:

1. normal Playwright locator-based pointer interaction;
2. raw `page.mouse.click(...)` interaction;
3. explicit focus followed by keyboard `Enter`.

Therefore the issue must **not** be described as a pointer-dispatch-only problem.

### Important negative findings

The investigation has established the following:

- The wedge is **not specific to raw pointer dispatch**.
- Replacing mouse interaction with keyboard interaction does not resolve it.
- The wedge is **not specific to `PivotWorkspace.push()`** or URL-driven pivot-step replacement.
- E22-B can wedge while opening the non-modal `ActionMenu` Portal, before a pivot URL transition or step-swap unmount occurs.
- The exact wedge point can vary between attempts.
- The affected production controls are keyboard-accessible.
- Component-level keyboard behavior for `PivotMenu` works deterministically.
- No current evidence identifies a functional error in ATI's pivot, provenance, breadcrumb, or URL-state semantics.
- No current evidence establishes that the problem occurs during normal interactive product use outside the constrained automated-browser environment.

### PR 24F-1 experiment

A narrowly scoped stabilization experiment was performed after PR 24F.

The experiment:

- removed the E22/E22-B `clickForce` raw-pointer helper;
- replaced affected overlay interactions with explicit keyboard activation;
- waited for the intended control to be visible and enabled;
- explicitly focused the control;
- verified focus ownership;
- activated the control with `page.keyboard.press("Enter")`;
- added component-level keyboard-contract coverage;
- did not use pointer fallback, force-click, DOM `.click()`, synthetic events, increased retries, increased timeouts, browser flags, changed fake data, or weakened assertions.

The real-stack harness reproduced the Chromium wedge in **4 of 4 attempts**.

Observed examples included:

```text
E22
  relationship drawer
    -> "Observations for this relationship"
    -> focus succeeds
    -> Enter attempted
    -> Chromium wedges

E22 retry
  Evidence workspace
    -> "Pivot actions"
    -> focus succeeds
    -> Enter attempted
    -> Chromium wedges

E22-B
  Evidence drawer
    -> "Pivot actions"
    -> focus succeeds
    -> Enter attempted
    -> Chromium wedges
```

The E22-B result is particularly important because opening `Pivot actions` at that point only opens the non-modal `ActionMenu` Portal and transfers focus. It does not yet perform a pivot URL mutation.

The experimental changes were reverted and were not merged.

### PR 25B E2E run record (06/2026)

A PR 25B real-stack run on this constrained host reproduced the same
wedge without any interaction-mechanism change: E22 wedged after the
``relationship drawer open`` step during the raw-pointer click on
``Observations for this relationship``; the retry wedged earlier, inside
the Evidence pivot workspace; E22-B wedged after ``dead: evidence drawer
open`` on both attempts. All four stalls were pure test timeouts with no
browser console/page errors, matching the documented characteristics
above. No PR 25B code path (the Map module, tab, or route) was involved
in any stale point, and the feature's own spec (E24) exercised the real
stack to the honest empty-state data STOP without a stall.

A second, unrelated suite-isolation observation from the same run: E10's
flaky first attempt (cold-start ``Verdict: Malicious`` wait) is retried
as a fresh test that creates a **second** Investigation with the exact
same objective, so E11's ``appears once in the real list`` assertion then
resolves two rows of the same objective and fails strictly. This is a
pre-existing E2E suite-isolation gap (retry re-runs the whole create
flow), not a product defect; it is recorded here rather than patched
inside PR 25B (which touches neither flow).

### Current assessment

The available evidence is more consistent with an environment/browser/rendering interaction involving some combination of:

```text
Chromium
MUI Portal/focus management
fixed-position overlay composition
DetailDrawer
PivotWorkspace
ActionMenu
constrained host resources
```

than with a deterministic ATI product-logic defect.

This remains a hypothesis, not an established root cause.

Production Modal/Portal/focus architecture must not be changed solely on this hypothesis.

### Current handling

For now:

- retain E22 and E22-B;
- retain their substantive assertions;
- retain the normal repository/CI E2E gate;
- retain the existing CI retry policy unless separately justified;
- do not skip or mark the tests as permanently ignored;
- do not fake interactions or results to make the tests green;
- do not increase retries or timeouts merely to conceal the wedge;
- do not change production frontend architecture without stronger root-cause evidence.

The existing retry policy is **not** considered the root-cause fix.

### Why the investigation is deferred

The investigation is currently non-blocking because:

1. no product-correctness defect has been demonstrated;
2. the relevant pivot/menu behavior has deterministic component-level coverage;
3. the existing real-stack E2E scenarios remain valuable;
4. the failure has been associated with a constrained Chromium execution environment;
5. the attempted pointer-free workaround falsified the previous pointer-specific hypothesis rather than identifying a reliable replacement;
6. no certain product-level fix or browser-level workaround is currently known;
7. speculative changes to MUI Modal/Portal/focus architecture would carry greater regression risk than continuing feature development;
8. subsequent ATI functionality does not structurally depend on resolving this browser reliability investigation.

The PR 24 feature series may therefore be treated as functionally closed while this investigation remains deferred.

### Future investigation plan

When this issue is reopened, begin with diagnosis rather than another interaction workaround.

#### 1. Build minimal browser-level reproductions

Progressively isolate the relevant frontend structures.

At minimum test:

```text
A. DetailDrawer + simple Button

B. DetailDrawer + ActionMenu Portal

C. PivotWorkspace + ActionMenu Portal
   without DetailDrawer

D. PivotWorkspace + DetailDrawer
   without ActionMenu

E. PivotWorkspace + DetailDrawer + ActionMenu Portal
```

Keep each reproduction as small as possible while preserving the same MUI/Portal/focus structure.

The objective is to identify the minimum structure that reproduces the wedge.

#### 2. Separate event mechanism from resulting UI transition

For each minimal case, test independently:

```text
pointer activation
keyboard activation
focus transfer without activation
menu Portal creation
menu focus transfer
drawer opening/closing
pivot workspace state replacement
```

Do not assume the event mechanism itself is causal.

#### 3. Capture Chromium renderer diagnostics

Capture a DevTools/Chromium performance or CPU trace covering:

```text
immediately before interaction
interaction dispatch
onset of the wedge
renderer spin
```

Determine whether the blocked renderer is spending time primarily in:

```text
JavaScript execution
React/MUI event handling
focus processing
accessibility-tree processing
style recalculation
layout
paint/compositing
Portal/Modal management
Chromium internal renderer work
```

If possible, capture browser-process and renderer-process diagnostics separately.

#### 4. Compare environments

Run the minimal reproduction against:

```text
the constrained two-core host
normal CI environment
a representative developer workstation
```

Record:

```text
Chromium version
Playwright version
OS/container environment
CPU allocation
memory allocation
GPU/headless configuration
reproduction rate
```

Do not attribute the problem to CPU count unless comparative evidence supports that conclusion.

#### 5. Test dependency-level hypotheses only after isolation

If the minimum reproduction implicates MUI Portal/Modal/focus behavior, test the relevant structure independently of ATI application logic.

Do not begin by restructuring the production application.

#### 6. Consider production changes only after root-cause evidence

A product-level change to:

```text
Modal/Portal ownership
focus management
drawer composition
ActionMenu rendering
overlay structure
```

requires evidence that the production structure itself causes or materially contributes to the wedge.

Any such change should receive its own architecture review and regression plan.

### Reopen criteria

Reopen this investigation when any of the following occurs:

1. E22/E22-B begin failing materially or repeatedly in the normal CI environment.
2. The configured CI retry no longer provides a reliable E2E gate.
3. Another ATI frontend E2E test reproduces the same renderer wedge.
4. The same behavior is observed during normal interactive product use.
5. The issue begins blocking feature-development E2E coverage.
6. A Chromium, Playwright, MUI, or related dependency change materially changes the reproduction.
7. Frontend Modal/Portal/focus architecture is being revised for another justified reason.
8. Sufficient engineering time is explicitly allocated for browser-level root-cause analysis.

### Exit criteria

This investigation may be closed only when one of the following is established with repeatable evidence:

#### Root cause and fix

A specific root cause is identified and a fix passes:

```text
E22 repeated runs
E22-B repeated runs
full frontend E2E suite
normal CI
constrained-host reproduction
```

without weakened assertions, artificial retries, synthetic interactions, or test skips.

#### Upstream resolution

A specific Chromium, Playwright, MUI, or other upstream change eliminates the reproduction across the relevant environments and repeated runs demonstrate stability.

#### Proven obsolete

The affected frontend architecture is legitimately replaced for independent product reasons and the replacement architecture passes equivalent real-stack coverage without reproducing the issue.

### Guardrails for future coding agents

Do not restart from the already-falsified assumption that this is a pointer-only problem.

Do not propose, without new evidence:

```text
page.mouse instead of locator.click
keyboard Enter instead of page.mouse
keyboard Space instead of Enter
force-click
DOM element.click()
dispatchEvent("click")
higher retry counts
larger timeouts
test skipping
```

as a root-cause solution.

A future investigation should first isolate the minimum reproducing browser/UI structure and collect renderer-level evidence.

---

# Maintenance

When adding another investigation:

1. place it under the appropriate subsystem section;
2. state whether it is blocking or non-blocking;
3. describe the observed behavior without asserting an unproven cause;
4. preserve important negative findings and failed experiments;
5. define the current handling;
6. explain why deferral is safe, if deferred;
7. provide explicit reopen criteria;
8. provide measurable exit criteria.

Resolved investigations should remain in this document with their status changed to `RESOLVED` and a concise description of the verified root cause and resolution.
