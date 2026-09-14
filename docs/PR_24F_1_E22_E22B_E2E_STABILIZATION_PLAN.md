# PR 24F-1 — Stabilize E22/E22-B with Pointer-Free Keyboard Interaction

## Purpose

PR 24F-1 is a narrowly scoped E2E hardening change for `frontend/e2e/zz-pivots.spec.ts`.

Its sole purpose is to eliminate the Chromium/Playwright pointer-dispatch wedge observed while E22/E22-B interact with ATI's nested fixed-position pivot/detail overlay stack.

The fix is to stop using pointer input for those overlay interactions and instead use the production UI's existing keyboard-accessible path.

This is a valid deterministic workaround because current production code already guarantees that the affected controls are keyboard-operable:

- Pivot triggers are MUI `Button` elements.
- Multi-target `PivotMenu` explicitly handles `Enter`, `Space`, `ArrowDown`, and `ArrowUp`.
- `ActionMenu` renders actions as `role="menuitem"` MUI buttons.
- The menu moves focus to its first action when opened.
- The pivot `push()` path explicitly blurs the active element before the URL-driven step swap, avoiding Chromium's focused-node removal race.
- Relationship/detail actions, breadcrumbs, and the pivot close control are buttons.

The test therefore does not need mouse hit-testing or raw mouse dispatch to validate E22/E22-B.

---

## 1. Problem statement

Current E22/E22-B use `clickForce()`:

```ts
async function clickForce(page: Page, target: Locator): Promise<void> {
  await expect(target).toBeVisible({ timeout: 30_000 });
  const box = await target.boundingBox();
  ...
  await page.mouse.click(
    box.x + box.width / 2,
    box.y + box.height / 2,
    { delay: 40 },
  );
}
```

This helper was introduced because Playwright locator hit-testing could wedge Chromium while a fixed-position detail drawer was open.

The latest constrained-host run demonstrated that raw `page.mouse.click(...)` can also wedge Chromium at the same point:

```text
page responsive before click
raw page.mouse click begins
Chromium main thread wedges
driver/evaluate operations subsequently stall
console remains clean
```

Therefore the current mitigation is not reliable.

The remediation must avoid pointer dispatch entirely.

---

## 2. Binding remediation

Inside the nested pivot/detail overlay interaction sequence:

> **Use focus + keyboard Enter on the actual accessible production control.**

Do not replace `page.mouse` with another pointer-based mechanism.

Do not use synthetic DOM click events.

Do not weaken assertions.

---

## 3. Why this workaround is technically sound

### 3.1 Pivot trigger

Current `PivotMenu` explicitly handles keyboard activation:

```ts
if (
  event.key === "ArrowDown" ||
  event.key === "ArrowUp" ||
  event.key === "Enter" ||
  event.key === " "
) {
  event.preventDefault();
  setOpen(true);
}
```

Therefore focusing the pivot button and pressing Enter follows a supported production interaction path.

### 3.2 Menu action

Each action is a MUI button with:

```text
role="menuitem"
onClick={() => onSelect(action)}
```

Native Enter activation invokes the same React `onClick` handler as a mouse click.

Therefore:

```text
focus menuitem
 -> Enter
 -> onClick
 -> onSelect
 -> same PivotStep
 -> same URL update
```

### 3.3 Focus-safe pivot navigation

Before replacing the active pivot step, production code already does:

```ts
(document.activeElement as HTMLElement | null)?.blur();
```

That specifically avoids the Chromium focused-node-removal race during URL-driven unmount.

This makes keyboard activation compatible with the existing step-swap design.

### 3.4 Other E22/E22-B interactions

The affected controls are buttons:

```text
View ...
Observations for this relationship
Evidence
breadcrumb Return to ...
Close pivot workspace
```

They are keyboard activatable without product changes.

---

## 4. Scope

Expected changes:

```text
frontend/e2e/zz-pivots.spec.ts
docs/TESTING.md
```

Optional:

```text
frontend/src/pivots/PivotMenu.test.tsx
```

only if current unit/component tests do not already demonstrate keyboard activation.

No production implementation file should normally change.

---

## 5. Explicitly out of scope

Do not:

- change `PivotWorkspace`;
- change `PivotMenu`;
- change detail drawer architecture;
- change z-index values;
- upgrade MUI or Playwright;
- change browser launch flags;
- increase retry count;
- increase timeout as a workaround;
- skip E22/E22-B;
- mark tests flaky;
- use `force: true`;
- use `locator.dispatchEvent("click")`;
- use DOM `element.click()`;
- use JavaScript event synthesis;
- use raw CDP mouse events;
- change fake-world fixtures;
- remove or weaken E22/E22-B assertions;
- alter pivot URL semantics.

---

## 6. Delete `clickForce`

Remove the raw-pointer helper completely.

After this change, `zz-pivots.spec.ts` must not use:

```text
page.mouse
clickForce
boundingBox for click coordinates
```

for E22/E22-B interactions.

Do not leave a pointer fallback.

---

## 7. Add `activateByKeyboard`

Add a single narrow helper:

```ts
async function activateByKeyboard(
  page: Page,
  target: Locator,
): Promise<void> {
  await expect(target).toBeVisible({ timeout: 30_000 });
  await expect(target).toBeEnabled();
  await target.focus();
  await expect(target).toBeFocused();
  await page.keyboard.press("Enter");
}
```

The explicit focus assertion is required.

It proves that the subsequent Enter targets the intended production control rather than whichever element happened to retain focus.

Do not implement the helper using:

```text
target.click()
page.mouse
dispatchEvent
evaluate(el => el.click())
```

---

## 8. Prefer `focus()` + `page.keyboard.press()` over `locator.press()`

`locator.press("Enter")` is also keyboard-based, but the plan requires the more explicit form:

```text
target.focus()
assert target focused
page.keyboard.press("Enter")
```

Reasons:

1. focus ownership becomes independently testable;
2. diagnostics can distinguish focus failure from activation failure;
3. Portal/menu transitions are easier to debug;
4. the test documents the actual accessibility contract being exercised.

---

## 9. E22 conversion steps

### 9.1 Evidence subject -> Relationships

Replace:

```text
clickForce(Pivot actions)
clickForce(Relationships where source)
```

with:

```ts
await activateByKeyboard(
  page,
  evidenceDrawer.getByRole("button", { name: "Pivot actions" }),
);

const sourceRelationshipAction = page.getByRole("menuitem", {
  name: "Relationships where source",
});
await expect(sourceRelationshipAction).toBeVisible({ timeout: 30_000 });
await activateByKeyboard(page, sourceRelationshipAction);
```

Keep the existing postconditions:

```text
Relationships pivot workspace visible
Source entity ID exact filter populated
Relationships table visible
```

### 9.2 Open Relationship detail

Replace the raw click on:

```text
View ...
```

with keyboard activation of the exact button locator.

Keep:

```text
Relationships detail drawer visible
```

### 9.3 Relationship -> observations

Replace raw click on:

```text
Observations for this relationship
```

with keyboard activation.

This may be a single-target `PivotMenu` rendered directly as a button.

Do not require a menu if production renders only the direct action.

Keep:

```text
Relationship observations pivot workspace visible
Observed at visible
```

### 9.4 Observation -> Evidence

Replace:

```text
raw click Evidence
raw click Open evidence
```

with focus + Enter for the Evidence trigger and the exact `Open evidence` menuitem.

Keep all exact-Evidence/breadcrumb assertions.

### 9.5 Breadcrumb truncation

Replace raw click on:

```text
Return to update-package.test
```

with keyboard activation of the breadcrumb button.

Keep:

```text
Relationships workspace restored
```

### 9.6 Close workspace

Replace raw click on:

```text
Close pivot workspace
```

with keyboard activation.

Keep all current close/base-route assertions.

---

## 10. E22-B conversion steps

### 10.1 Evidence detail -> Pivot actions

Use keyboard activation for the drawer's `Pivot actions` button.

### 10.2 Research action

Focus the exact:

```text
role=menuitem
name="Research for this entity"
```

and press Enter.

Keep:

```text
Research pivot workspace visible
Subject entity ID exact filter set
honest filtered-empty state visible
```

### 10.3 Close

Keyboard-activate `Close pivot workspace`.

Keep base Evidence route, FAKE DATA, breadcrumb-removal, and console assertions unchanged.

---

## 11. Do not rely on menu order

Do not navigate to actions by repeated Tab presses or by assuming the first menu item is the desired one.

Always select the intended action by:

```text
role
accessible name
```

Then focus it explicitly and press Enter.

This keeps the E2E independent of benign menu-order changes.

---

## 12. Keep non-overlay clicks unchanged

The following ordinary interactions may remain normal Playwright locator clicks because they occur before the problematic nested overlay pointer path:

```text
New Investigation
Submit
Open evidence support on Overview
Evidence tab
initial base-page View action
```

Do not convert the entire suite unnecessarily.

The narrow rule is:

> **Once interaction occurs inside the pivot/detail overlay stack, use keyboard activation.**

Using keyboard activation for more of E22/E22-B is acceptable if simpler, but is not required.

---

## 13. No fallback path

Do not implement:

```ts
try {
  await activateByKeyboard(...);
} catch {
  await page.mouse.click(...);
}
```

or the inverse.

A main-thread wedge does not reliably reject and permit fallback.

A fallback would also make the test nondeterministic and conceal whether this remediation works.

Keyboard activation must be the sole interaction path for the affected controls.

---

## 14. Update `zz-pivots.spec.ts` documentation

Remove the current assertion that raw pointer input is unaffected.

Replace it with comments equivalent to:

```text
Interaction notes:
- Chromium/Playwright can wedge during pointer dispatch while the pivot
  workspace and nested fixed-position detail drawer are active.
- The wedge has reproduced through both Playwright locator hit-testing
  and raw page.mouse input on constrained hosts.
- The affected ATI controls are first-class keyboard-accessible buttons
  and menuitems, so E22/E22-B focus the exact control and activate it
  with Enter inside the overlay stack.
- This exercises the same production React handlers without entering
  the problematic Chromium pointer-dispatch path.
- Pivot navigation already blurs active focus before URL-driven step
  replacement, preventing the known focused-node unmount race.
```

Do not claim ATI fixes Chromium.

---

## 15. Update `docs/TESTING.md`

Replace the current paragraph saying raw events are the workaround.

Document:

```text
E22/E22-B use pointer-free keyboard activation inside the nested
pivot/detail overlay stack. Chromium pointer dispatch has reproduced
environment-specific main-thread wedges on constrained hosts through
both locator hit-testing and raw page.mouse input.

The tests focus the real accessible production button/menuitem, assert
focus ownership, and activate it with Enter. No force-click, DOM click,
synthetic event, test-only navigation path, or skipped assertion is used.
```

If Playwright still has one global retry in CI, do not describe the retry as the mitigation.

The keyboard path is the mitigation.

---

## 16. Product code must remain unchanged

Expected:

```text
no change to PivotMenu.tsx
no change to PivotWorkspace.tsx
no change to DetailDrawer
```

If keyboard activation cannot operate the current production controls, that indicates a real accessibility/product defect.

In that case STOP instead of altering production code under this narrow test-hardening change.

---

## 17. Validation — targeted E22

Run E22 using the repository's real production-path E2E harness.

Required observations:

```text
evidence workspace open
relationships workspace open
relationship drawer open
observations workspace open
nested evidence step open
Back/Forward restored
truncation restored relationships
close restored base route
```

The existing step markers should all be reached.

Required result:

```text
no Chromium pointer wedge
no interaction timeout
all assertions pass
clean console
```

---

## 18. Validation — targeted E22-B

Run E22-B alone through the same real-stack harness.

Required:

```text
F01 completes
Evidence drawer opens
Research pivot opens
exact subject filter visible
empty/dead-end state shown
breadcrumb preserved
Close succeeds
FAKE DATA visible
clean console
```

---

## 19. Repetition on the constrained host

The previous pointer path failed 4/4 attempts on the constrained host.

Validation of this workaround must therefore include repeated execution on that host, if available:

```text
E22: at least 4 consecutive runs
E22-B: at least 4 consecutive runs
```

Acceptance:

```text
0 Chromium main-thread wedges
0 pointer-dispatch stalls
0 timeout recovered only by retry
```

A single successful retry is not sufficient validation.

---

## 20. Full E2E validation

Run:

```bash
cd frontend
npm run test:e2e
```

using the normal repository harness.

Required:

```text
whole suite passes
E22 passes
E22-B passes
no skipped test
no test faked green
```

Do not change worker count, retries, or global timeout in the same change.

---

## 21. Other quality gates

Run:

```bash
npm run typecheck
npm run lint
npm test
npm run build
```

No backend test rerun is required solely for this test-only change unless repository policy requires the complete QA suite.

If normal repository QA is required, run it unchanged.

---

## 22. Diagnostic STOP cases

### A. Focus failure

If:

```text
target.focus() fails
or
toBeFocused() fails
```

STOP.

Record:

```text
step
role/name
visibility
enabled state
focus result
current dialogs
```

Do not fall back to pointer interaction.

This would expose a production accessibility problem.

### B. Enter does not activate

If:

```text
focus succeeds
Enter is sent
page remains responsive
expected UI transition does not occur
```

STOP.

For a native/MUI button this means keyboard behavior is broken or the target locator is wrong.

Do not use synthetic click.

### C. Keyboard dispatch also wedges Chromium

If:

```text
focus succeeds
Enter is dispatched
page/main thread wedges
```

STOP.

That would disprove the pointer-specific diagnosis and require deeper analysis of focus/unmount behavior.

Do not improvise another workaround in this PR.

---

## 23. Static verification

Before finishing, run a source search such as:

```bash
grep -nE 'clickForce|page\.mouse|boundingBox\('   frontend/e2e/zz-pivots.spec.ts
```

Expected for E22/E22-B:

```text
no raw-pointer helper/use remains
```

If a searched term is used elsewhere for unrelated non-pointer purposes, inspect manually.

---

## 24. Expected files changed

Expected:

```text
frontend/e2e/zz-pivots.spec.ts
docs/TESTING.md
```

Optional only if necessary for already-required keyboard contract coverage:

```text
frontend/src/pivots/PivotMenu.test.tsx
```

No backend, schema, generated API, dependency, or fake-world changes.

---

## 25. Acceptance criteria

This hardening change is complete only when:

1. `clickForce` is removed.
2. E22/E22-B no longer use `page.mouse` in the overlay stack.
3. no force-click is introduced.
4. no DOM `.click()` is introduced.
5. no synthetic click event is introduced.
6. no retry/timeout increase is used as the fix.
7. helper waits for visibility.
8. helper verifies enabled state.
9. helper explicitly focuses the target.
10. helper asserts target focus.
11. helper sends Enter through keyboard input.
12. Pivot actions open through the production keyboard handler.
13. menu actions activate the exact production React handler.
14. action lookup uses role/name rather than positional Tab order.
15. Evidence -> Relationships path remains unchanged semantically.
16. Relationship detail opens.
17. Relationship -> observations works.
18. Observation -> Evidence works.
19. Back/Forward assertions remain.
20. breadcrumb truncation remains.
21. refresh restoration remains.
22. Close restoration remains.
23. E22-B Research dead-end path remains.
24. exact subject filter assertion remains.
25. honest empty-state assertions remain.
26. no-fallback/no-inference assertions remain.
27. FAKE DATA assertions remain.
28. clean-console assertions remain.
29. no application code is changed.
30. no fake-world data is changed.
31. constrained-host E22 passes repeated runs without wedge.
32. constrained-host E22-B passes repeated runs without wedge.
33. full E2E suite passes.
34. typecheck passes.
35. lint passes.
36. frontend unit tests pass.
37. frontend build passes.
38. source comments no longer claim raw pointer input is reliably safe.
39. TESTING.md documents keyboard interaction as the workaround.
40. CI continues to execute E22/E22-B normally.

---

## 26. STOP conditions

STOP rather than improvising if:

1. an affected control is not focusable;
2. Enter does not activate a focused affected control;
3. keyboard activation reproduces the Chromium wedge;
4. production code must change to make keyboard activation work;
5. only a synthetic click can make the test pass;
6. assertions need weakening;
7. fake-world fixtures need alteration;
8. browser flags need alteration;
9. retries/timeouts need increasing;
10. failure reproduces independently of pointer dispatch.

STOP report:

```text
exact E22/E22-B step
target role/name
visibility/enabled state
whether focus succeeded
whether Enter was dispatched
last reached step marker
whether page remained responsive
console/pageerror state
```

---

## 27. Implementation sequence

1. Delete `clickForce`.
2. Add `activateByKeyboard`.
3. Convert only the first known failing interaction:
   `Evidence drawer -> Pivot actions -> Relationships where source`.
4. Run E22 and verify it passes the former wedge point.
5. Convert all remaining E22 overlay raw-pointer interactions.
6. Run E22 fully.
7. Convert E22-B overlay interactions.
8. Run E22-B fully.
9. Repeat E22/E22-B on the constrained host.
10. Update comments and `TESTING.md`.
11. Run full E2E.
12. Run frontend quality gates.

Do not update the documentation until the keyboard path has actually passed.

---

## 28. Suggested PR description

### Stabilize E22/E22-B with pointer-free keyboard interaction

Replaces the E22/E22-B raw `page.mouse` workaround with ATI's first-class keyboard-accessible interaction path.

Chromium/Playwright has reproduced a main-thread wedge during pointer dispatch inside the nested fixed-position pivot/detail overlay stack through both locator hit-testing and raw mouse input on constrained hosts. The affected production controls are accessible buttons/menuitems with explicit keyboard behavior, and pivot navigation already blurs active focus before URL-driven unmount.

The tests now focus the exact accessible production control, assert focus ownership, and activate it with Enter. This invokes the same React handlers and preserves all existing navigation/assertions without entering Chromium's pointer-dispatch path.

No product behavior, pivot semantics, retries, fake data, assertions, dependencies, or backend code are changed.
