from Transaction import User, Transaction
import pytest
from cryptography.exceptions import InvalidSignature
###############################################################################################
###############################################################################################
############################             TEST SECTION              ############################
###############################################################################################
###############################################################################################


def testTransaction():
    """
    Test to verify that when creating a transaction the verification works correctly.
    """
    Bob = User('Bob', 1500)
    Alice = User('Alice', 1000)
    tx = User.createTransaction(Bob, Alice, 100, Bob.nonce, 1)
    assert tx.verify(Bob.balance, Bob.nonce - 2) == True


def testValidTransaction():
    """
    Test to verify that if any of the fields of the transaction is changed once it is created, this will give an
    Assertion Error of the validate() method. 
    """
    Bob = User('Bob', 1500)
    Alice = User('Alice', 1000)
    tx = User.createTransaction(Bob, Alice, 100, Bob.nonce, 1)
    assert tx.verify(Bob.balance, Bob.nonce - 2) == True

    # Change amount
    txAmount = tx
    txAmount.amount = txAmount.amount + 10
    with pytest.raises(AssertionError):
        txAmount.verify(Bob.balance, Bob.nonce - 2)

    # Change nonce
    txNonce = tx
    txNonce.amount = txNonce.nonce + 1
    with pytest.raises(AssertionError):
        txNonce.verify(Bob.balance, Bob.nonce - 2)

    # Change sender_hash
    txSender = tx
    txSender.sender_hash = User.hashSHA1('test'.encode('ascii'))
    with pytest.raises(AssertionError):
        txNonce.verify(Bob.balance, Bob.nonce - 2)


def testInvalidSignature():
    """
    Generate a valid transaction, change the amount field, regenerate the txid so it is valid
    again. Check that transaction.verify raises an exception due to an invalid signature.
    """
    Bob = User('Bob', 1500)
    Alice = User('Alice', 1000)
    tx = User.createTransaction(Bob, Alice, 100, Bob.nonce, 1)
    tx.verify(Bob.balance, Bob.nonce - 2)
    tx.amount = 200
    tx.txid = Transaction.txid(tx.sender_public_bytes, tx.sender_hash,
                               tx.recipient_hash, Transaction.littleEndian(
                                   tx.amount),
                               Transaction.littleEndian(tx.fee), Transaction.littleEndian(tx.nonce), tx.signature)
    with pytest.raises(InvalidSignature):
        tx.verify(Bob.balance, Bob.nonce - 2)


def testNotEnoughBalance():
    Bob = User('Bob', 1500)
    Alice = User('Alice', 1000)
    tx = User.createTransaction(Bob, Alice, 10000, Bob.nonce + 2, 1)
    with pytest.raises(AssertionError):
        tx.verify(Bob.balance, Bob.nonce - 2)


def testTwoPrivateKeys():
    """
    Changing the signature makes the new txid different, and therefore an assertion error is given
    when comparing these two txid's.
    """
    Bob = User('Bob', 1500)
    Alice = User('Alice', 1500)
    Chris = User('Chris', 1000)
    tx = User.createTransaction(Bob, Chris, 100, Bob.nonce, 10)
    tx.verify(Bob.balance, Bob.nonce - 2)
    tx.signature = User.sign_transaction(
        Alice.private_key, Transaction.sig_ready(tx.recipient_hash, tx.amount, tx.fee, tx.nonce))

    with pytest.raises(AssertionError):
        tx.verify(Bob.balance, Bob.nonce - 2)


def testZimmerTransaction():
    tx = Transaction(
        bytes.fromhex("3df8f04b3c159fdc6631c4b8b0874940344d173d"),
        bytes.fromhex("5c1499a0484ace2f731b0afb83241e15f0e168ca"),
        bytes.fromhex("3056301006072a8648ce3d020106052b8104000a" +
                      "03420004886ed03cb7ffd4cbd95579ea2e202f1d" +
                      "b29afc3bf5d7c2c34a34701bbb0685a7b535f1e6" +
                      "31373afe8d1c860a9ac47d8e2659b74d437435b0" +
                      "5f2c55bf3f033ac1"),
        10,
        2,
        5,
        bytes.fromhex("3046022100f9c076a72a2341a1b8cb68520713e1" +
                      "2f173378cf78cf79c7978a2337fbad141d022100" +
                      "ec27704d4d604f839f99e62c02e65bf60cc93ae1"
                      "735c1ccf29fd31bd3c5a40ed"),
        bytes.fromhex("ca388e0890b71bd1775460d478f26af3776c9b4f" +
                      "6c2b936e1e788c5c87657bc3"))
    sender_balance = 20
    sender_previous_nonce = 4
    assert tx.verify(sender_balance, sender_previous_nonce) == True

###############################################################################################
###############################################################################################
