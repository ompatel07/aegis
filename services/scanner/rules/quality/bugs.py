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

