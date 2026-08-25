# ruleid: aegis-bug-mutable-default-arg
def bad_list(a, items=[]):
    items.append(a)
    return items

# ruleid: aegis-bug-mutable-default-arg
def bad_dict(a, cache={}):
    return cache

# ok: aegis-bug-mutable-default-arg
def good(a, items=None):
    items = items or []
    return items

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


def is_literal(x):
    # ruleid: aegis-bug-py-is-literal-comparison
    if x is "admin":
        return 1
    # ok: aegis-bug-py-is-literal-comparison
    if x == "admin":
        return 2
    return 0


def assert_tuple(cond):
    # ruleid: aegis-bug-py-assert-on-tuple
    assert (cond, "must be true")
    # ok: aegis-bug-py-assert-on-tuple
    assert cond, "must be true"
