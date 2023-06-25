import frost


class FrostUser:
    def __init__(self, id: int, n: int, t: int):  # n --> users , t --> threshold
        self.id = id
        self.t = t
        self.params = frost.Parameters(n, t)
        self.user = frost.Participant(self.params, self.id)
        self.user.verify_proof_of_secret_key()

    def round1(self, parties_list: list[bytes]):
        self.other_participants = [
            frost.Participant.load(p, self.t) for p in parties_list
        ]
        self.user_state = frost.DistributedKeyGenerationR1(
            self.params, self.user, self.other_participants
        )
        self.user_their_secret_shares = self.user_state.their_secret_shares()

    def round2(self, their_secret_shares: list[list[int]]):
        self.user_my_secret_shares = [
            bytes(dict(secret_shares)[self.id]) for secret_shares in their_secret_shares
        ]
        self.user_state = self.user_state.to_round_two(
            self.id, self.user_my_secret_shares
        )
        (
            self.user_group_key,
            self.user_secret_key,
            self.user_public_key,
        ) = self.user_state.finish(self.user)

    def generate_commitments(
        self,
    ):
        (
            self.user_public_comshares,
            self.user_secret_comshares,
        ) = frost.generate_commitment_share_lists(self.id, 1)

    def will_sign(
        self,
    ):
        return True

    def sign(self, msg_hash, signers):
        self.user_partial = frost.sign(
            self.id,
            self.user_secret_key,
            msg_hash,
            self.user_group_key,
            self.user_secret_comshares,
            0,
            signers,
        )
        return self.user_partial

    def encode(self):
        return bytes(self.user.encode(self.t))

