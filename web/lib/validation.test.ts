// N4: silent-clean findings are distinguishable in the UI.
// Run: node --test --experimental-strip-types lib/*.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { isRecallUnvalidated } from "./validation.ts";

test("a silent-clean finding is labelled", () => {
  assert.equal(isRecallUnvalidated({ metadata: { validation: "silent-clean", recall_unvalidated: true } }), true);
  assert.equal(isRecallUnvalidated({ metadata: { recall_unvalidated: true } }), true);
});

test("a proven finding is not", () => {
  assert.equal(isRecallUnvalidated({ metadata: { ruleset: "aegis-custom" } }), false);
  assert.equal(isRecallUnvalidated({ metadata: null }), false);
  assert.equal(isRecallUnvalidated({}), false);
  assert.equal(isRecallUnvalidated({ metadata: { recall_unvalidated: "yes" } }), false);
});
