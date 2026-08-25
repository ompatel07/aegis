function branchesSingle(flag) {
  // ruleid: aegis-bug-identical-if-else-branches
  if (flag) doThing(1);
  else doThing(1);
  // ok: aegis-bug-identical-if-else-branches
  if (flag) doThing(1);
  else doThing(2);
}

function branchesMulti(flag) {
  // ruleid: aegis-bug-identical-if-else-branches
  if (flag) { a(); b(); }
  else { a(); b(); }
  // ok: aegis-bug-identical-if-else-branches
  if (flag) { a(); b(); }
  else { a(); c(); }
  // ruleid: aegis-bug-identical-if-else-branches
  if (flag) { a(); b(); c(); }
  else { a(); b(); c(); }
}

function retFinally() {
  try {
    risky();
  } finally {
    cleanup();
    // ruleid: aegis-bug-return-in-finally
    return 1;
  }
}

function okNestedArrow() {
  try { risky(); }
  // ok: aegis-bug-return-in-finally
  finally { cleanup(() => { return 1; }); }
}

function okNestedFunctionExpr() {
  try { risky(); }
  // ok: aegis-bug-return-in-finally
  finally { arr.forEach(function () { return 2; }); }
}

function okForEachArrow() {
  try { risky(); }
  // ok: aegis-bug-return-in-finally
  finally { arr.forEach((x) => { return x; }); }
}

function okFinally() {
  let r = 0;
  // ok: aegis-bug-return-in-finally
  try { r = risky(); } finally { cleanup(); }
  return r;
}

function lengthCheck(a) {
  // ruleid: aegis-bug-js-length-lt-zero
  if (a.length < 0) return true;
  // ok: aegis-bug-js-length-lt-zero
  if (a.length === 0) return false;
  return null;
}

function typeofCheck(x) {
  // ruleid: aegis-bug-js-typeof-invalid-comparison
  if (typeof x === "array") return 1;
  // ok: aegis-bug-js-typeof-invalid-comparison
  if (typeof x === "string") return 2;
  return 0;
}
