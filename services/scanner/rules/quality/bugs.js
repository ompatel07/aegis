function branches(flag) {
  // ruleid: aegis-bug-identical-if-else-branches
  if (flag) doThing(1);
  else doThing(1);

  // ok: aegis-bug-identical-if-else-branches
  if (flag) doThing(1);
  else doThing(2);
}

function retFinally() {
  // ruleid: aegis-bug-return-in-finally
  try {
    risky();
  } finally {
    cleanup();
    return 1;
  }
}

function okFinally() {
  let r = 0;
  try {
    r = risky();
    // ok: aegis-bug-return-in-finally
  } finally {
    cleanup();
  }
  return r;
}
