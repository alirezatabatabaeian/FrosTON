from binascii import hexlify
import frost
from hashlib import sha256
from frost_node import FrostUser
from util import bytes_to_number, hash_to_number, filter_dict

n = 3
t = 2
id_list = [1, 2, 3]

nodes = {id: FrostUser(id, n, t) for id in id_list}

# Round 1 of DKG: Construct Secret Shares
for id, n in nodes.items():
    n_d = filter_dict(nodes, id)
    n_d = {k: p.encode() for k, p in n_d.items()}
    n.round1(list(n_d.values()))

# Round 2 of DKG: Construct Secret Key + Group Key
for id, n in nodes.items():
    n_d = filter_dict(nodes, id)
    my_shares = [n.user_their_secret_shares for n in n_d.values()]
    n.round2(my_shares)

# Make sure we reached a single group key
g_keys = set()
g_key = None
for n in nodes.values():
    g_key = n.user_group_key
    h = sha256(bytes(g_key)).hexdigest()
    g_keys.add(h)

assert len(set(g_keys)) == 1

print("Group Key is verified and Ready")
print(f"A = {bytes_to_number(g_key, 256)};")

# END OF KEY GEN

# Generate Commitments and Proceed to Signing

for n in nodes.values():
    n.generate_commitments()


context = b"CONTEXT STRING SAMPLE"
message = b"This is just a test message from FrosTON"

msg_hash = bytes(frost.compute_message_hash(context, message))
h1, h2 = hash_to_number(msg_hash)
print("Message Hash Ready")
print(f"H1 = {h1};")
print(f"H2 = {h2};")
# Signature aggregation
signers_id = [1, 2]

nx = nodes[list(nodes.keys())[0]]
aggregator = frost.SignatureAggregatorInitial(nx.params, nx.user_group_key, context, message)

for id, n in nodes.items():
    if n.will_sign() and id in signers_id:
        aggregator.include_signer(n.id, n.user_public_comshares[0], n.user_public_key)

signers = aggregator.get_signers()

partials = []
for id, n in nodes.items():
    if n.will_sign() and id in signers_id:
        partial = n.sign(msg_hash, signers)
        partials.append(partial)

for partial in partials:
    aggregator.include_partial_signature(partial)

aggregator = aggregator.finalize()
threshold_sig = aggregator.aggregate()

threshold_sig_hex = hexlify(bytes(threshold_sig[0] + threshold_sig[1])) # R,z
print("Schnorr Threshold Signature is Ready")
print(f"R = {bytes_to_number(threshold_sig[0], 256)};")
print(f"Z = {bytes_to_number(threshold_sig[1], 256)};")

print("Checking signature to ensure correctness")
if frost.verify(threshold_sig, nx.user_group_key, msg_hash) == 0:
    print("Signature invalid!")
else:
    print("Signature valid :)")
