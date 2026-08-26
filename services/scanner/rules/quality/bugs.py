def branches(c):
    # ruleid: aegis-bug-identical-if-else-branches-py
    if c:
        a()
    else:
        a()
    # ok: aegis-bug-identical-if-else-branches-py
    if c:
        a()
    else:
        b()

def branches_multi(c):
    # ruleid: aegis-bug-identical-if-else-branches-py
    if c:
        a()
        b()
    else:
        a()
        b()




def assert_tuple(cond):
    # ruleid: aegis-bug-py-assert-on-tuple
    assert (cond, "must be true")
    # ok: aegis-bug-py-assert-on-tuple
    assert cond, "must be true"
