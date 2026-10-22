// N4 three-tier rule validation. A finding from a SILENT-CLEAN rule is real, but the
// rule has never been seen to fire on real code (it is API-shaped and ran on the
// measured corpus with zero false positives, without a single hit), so its recall is
// unvalidated. It is shown -- never hidden -- with a label, and it is never counted
// as coverage. The scanner sets `metadata.recall_unvalidated` / `metadata.validation`.

export interface ValidatedFinding {
  metadata?: Record<string, unknown> | null;
}

export const isRecallUnvalidated = (f: ValidatedFinding): boolean =>
  f.metadata?.recall_unvalidated === true || f.metadata?.validation === "silent-clean";

export const RECALL_UNVALIDATED_LABEL = "recall unvalidated";

export const RECALL_UNVALIDATED_EXPLANATION =
  "This rule detects the weakness from the API it uses, and it produced no false " +
  "positives on the real repositories Aegis measured it on -- but it had not yet " +
  "fired on any of them, so how much it misses is unknown. It does not count " +
  "toward the coverage shown for this language.";
