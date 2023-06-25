from tonsdk.boc import begin_cell


def filter_dict(d: dict, *keys):
    nd = {}
    for k, v in d.items():
        if k not in keys:
            nd[k] = v
    return nd


def bytes_to_number(x: bytes, bitlen: int):
    s = begin_cell()
    s.store_bytes(x)
    return s.end_cell().begin_parse().read_uint(bitlen)


def hash_to_number(x: bytes):
    s = begin_cell()
    s.store_bytes(x)
    s2 = s.end_cell().begin_parse()
    h1 = s2.read_uint(256)
    h2 = s2.read_uint(256)
    return h1, h2
