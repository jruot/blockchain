import logging
import time

from blockchain import Blockchain, Validator


def setup_logger(name="blockchain"):
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


if __name__ == "__main__":
    logger = setup_logger()

    blockchain = Blockchain(logger)
    # genesis
    blockchain.genesis()

    # add some validators to a committee
    blockchain.add_validator(Validator(blockchain.get_chain(), "shrimp", 1, False))
    blockchain.add_validator(Validator(blockchain.get_chain(), "1", 10, False))
    blockchain.add_validator(Validator(blockchain.get_chain(), "2", 20, False))
    blockchain.add_validator(Validator(blockchain.get_chain(), "3", 30, False))
    # bad actor
    blockchain.add_validator(Validator(blockchain.get_chain(), "4", 40, True))
    blockchain.add_validator(Validator(blockchain.get_chain(), "5", 50, False))
    blockchain.add_validator(Validator(blockchain.get_chain(), "whale", 100, False))

    # add 25 blocks for demo
    for i in range(0, 25):
        blockchain.epoch()
        # 1. randomly pick a validator from the committee to propose a blocks
        winning_validator = blockchain.pick_validator()
        logger.info("Winning validator: %s", winning_validator.address)
        # 2. selected validator proposes a new block
        proposed_block = winning_validator.generate_block()
        # 3. proposed block is broadcasted to the validators
        blockchain.broadcast_block_to_validators(proposed_block)
        for validator in blockchain.get_validators():
            # 4. each validator validates the proposed block
            validator.validate_new_block(
                proposed_block, winning_validator.get_public_key()
            )
            # 5. each validator sends a vote
            blockchain.receive_vote(validator.vote())
        # 6. block is added to the chain if there is a consensus
        if blockchain.is_consensus_on_adding_new_block():
            blockchain.add_block(proposed_block)
            logger.info(
                "New block added to the chain: %s", proposed_block.calculate_hash()
            )
        else:
            logger.info("Block was rejected: %s", proposed_block.calculate_hash())
        # for demo purposes a new block is added every 1 second
        time.sleep(1)

    # is the chain valid at the end
    is_valid, _ = blockchain.validate_chain()
    if is_valid:
        logger.info("Chain is in valid state")
    else:
        logger.info("Chain is in invalid state")
