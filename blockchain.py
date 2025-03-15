import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, cast
from datetime import datetime
import random
import hashlib
import json
import time

# used for validator signatures
from ecdsa import SigningKey, VerifyingKey, SECP256k1


class Validator:
    address: str
    staked_amount: int
    # copy of the chain
    chain: List["Block"]
    current_proposed_block: Optional["Block"]
    current_proposed_block_is_valid: bool
    # validator keys
    public_key: str
    private_key: SigningKey
    is_bad_actor: bool

    def __init__(
        self, chain: List["Block"], address: str, staked_amount: int, bad_actor: bool
    ):
        self.address = address
        self.staked_amount = staked_amount
        self.chain = chain
        self.current_proposed_block = None
        self.current_proposed_block_is_valid = False
        # init keys for the validator
        self.private_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.private_key.get_verifying_key().to_string().hex()
        self.is_bad_actor = bad_actor

    def set_proposed_block(self, block: "Block") -> None:
        self.current_proposed_block = block

    def validate_new_block(self, block: "Block", validator_signature: str) -> bool:
        latest_block = self.chain[-1]
        if not block.verify_signature(validator_signature):
            return False
        if (
            latest_block.index != (block.index - 1)
            or block.previous_hash != latest_block.calculate_hash()
        ):
            return False
        self.current_proposed_block_is_valid = True
        return self.current_proposed_block_is_valid

    def vote(self) -> bool:
        # bad actor always votes
        if self.is_bad_actor:
            return True
        return self.current_proposed_block_is_valid

    def epoch(self) -> None:
        self.current_proposed_block = None
        self.current_proposed_block_is_valid = False

    def get_public_key(self) -> str:
        return self.public_key

    # propose a new block
    def generate_block(self) -> "Block":
        new_block = Block(self.chain[-1])
        new_block.validator = self.address
        if self.is_bad_actor:
            # tamper block index
            new_block.index += 10
        # sign the block
        signature = self.private_key.sign(new_block.calculate_hash().encode())
        new_block.signature = signature.hex()
        return new_block


@dataclass
class Block:
    index: Optional[int] = None
    timestamp: Optional[str] = None
    previous_hash: str = ""
    hash: str = ""
    # signature of the validator
    signature: str = ""
    # address of the validator
    validator: str = ""
    transactions: List[Dict[str, Any]] = field(default_factory=list)

    def __init__(self, previous_block: Optional["Block"]):
        self.timestamp = f"{datetime.now():%Y-%m-%d %H:%M:%S%z}"
        self.transactions = []
        if previous_block:
            self.index = previous_block.index + 1
            self.previous_hash = previous_block.calculate_hash()
        else:
            # genesis
            self.index = 0
            self.signature = ""
            self.validator = ""
            self.hash = ""

    def calculate_hash(self) -> str:
        return hashlib.sha256(self.get_data_as_string()).hexdigest()

    # verify validator's signature
    def verify_signature(self, public_key_hex: str) -> bool:
        public_key_bytes = bytes.fromhex(public_key_hex)
        verifying_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
        signature_bytes = bytes.fromhex(self.signature)
        return verifying_key.verify(signature_bytes, self.calculate_hash().encode())

    def get_hash(self) -> str:
        return self.hash

    def get_data(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "validator": self.validator,
        }

    def get_data_as_string(self) -> bytes:
        return json.dumps(self.get_data(), sort_keys=True).encode()


class Blockchain:
    logger: logging.Logger
    validators: List[Validator]
    chain: List[Block]
    votes: int

    def __init__(self, logger: logging.Logger) -> None:
        self.validators = []
        self.chain = []
        self.votes = 0
        self.logger = logger

    def genesis(self) -> None:
        new_block = Block(None)
        self.chain.append(new_block)

    def add_block(self, block: Block) -> None:
        self.chain.append(block)

    def get_chain(self) -> List[Block]:
        return self.chain

    def validate_chain(self) -> Tuple[bool, float]:
        start_time = time.time()
        for i in range(1, len(self.chain)):
            block = self.chain[i]
            # check block index and hash
            if (
                block.index != i
                or block.previous_hash != self.chain[i - 1].calculate_hash()
            ):
                return False, 0
            # check validator's signature
            validator = next(
                (v for v in self.validators if v.address == block.validator), None
            )
            if not validator:
                return False, 0
            if not block.verify_signature(validator.get_public_key()):
                return False, 0
        elapsed_time = time.time() - start_time
        self.logger.info(f"Time taken to validate: {elapsed_time:.6f} seconds")
        return True, elapsed_time

    def add_validator(self, new_validator: Validator) -> None:
        self.validators.append(new_validator)

    def pick_validator(self) -> Validator:
        # retrieve the address of the previous block's validator
        previous_validator_address = self.chain[-1].get_data()["validator"]
        # previous validator is excluded
        available_validators = [
            v for v in self.validators if v.address != previous_validator_address
        ]
        if not available_validators:
            # if we cannot pick anyone else, return the only available validator
            self.logger.info(
                "All remaining validators are the same as previous; using fallback."
            )
            return self.validators[0]
        # map the stake (weights) of the validators to the available validators
        # more staked amount = higher chance to be selected
        weights = list(map(self.get_validator_weight, available_validators))
        # randomly select a validator weighted by their stake
        selected_validator = random.choices(available_validators, weights=weights)[0]
        return cast(Validator, selected_validator)

    def broadcast_block_to_validators(self, block: Block) -> None:
        for validator in self.validators:
            validator.set_proposed_block(block)

    def receive_vote(self, agree: bool) -> None:
        if agree:
            self.votes += 1

    def epoch(self) -> None:
        self.votes = 0
        for validator in self.validators:
            validator.epoch()

    def is_consensus_on_adding_new_block(self) -> bool:
        self.logger.info(
            "Add a new block voting result: %d/%d", self.votes, len(self.validators)
        )
        # majority of validators must agree
        return self.votes >= (len(self.validators) * 2 // 3)

    def get_validators(self) -> List[Validator]:
        return self.validators

    def get_validator_weight(self, v: Validator) -> int:
        return v.staked_amount
