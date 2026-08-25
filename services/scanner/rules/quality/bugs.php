<?php
function br($flag) {
  // ruleid: aegis-bug-identical-if-else-branches
  if ($flag) doThing(1);
  else doThing(1);
  // ok: aegis-bug-identical-if-else-branches
  if ($flag) doThing(1);
  else doThing(2);
}
