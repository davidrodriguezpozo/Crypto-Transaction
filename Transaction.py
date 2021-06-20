from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_der_private_key
from cryptography.hazmat.primitives.asymmetric import utils
import json
import hashlib
import datetime
import collections
import base64


class User():
    """
    Fields:
    private_key
    public_key
    address: hash of the public key
    balance: number of Zimcoins
    """

    def __init__(self, name, balance):
        self.private_key = ec.generate_private_key(
            ec.SECP256K1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.balance = balance
        self.nonce = 1

    @property
    def address(self):
        """
        Return the public key SHA256 hash.
        """
        return User.hashSHA1(self.public_keyDER)

    def incr(self, amount: int):
        self.balance = self.balance + amount

    def decr(self, amount: int):
        self.balance = self.balance - amount

    @property
    def public_keyDER(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

    @property
    def public_keyPEM(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

    @property
    def private_keyDER(self):
        return self.public_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b'password')).decode()

    @property
    def private_keyPEM(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b'password')).decode()

    @staticmethod
    def sign_transaction(private_key: ec.EllipticCurvePrivateKey, data: bytes):
        signature = private_key.sign(
            data, ec.ECDSA(hashes.SHA256()))
        return signature

    @staticmethod
    def hashSHA1(obj: bytes):
        digest = hashes.Hash(hashes.SHA1())
        digest.update(obj)
        return digest.finalize()

    @staticmethod
    def hashSHA256(obj: bytes):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(obj)
        return digest.finalize()

    @staticmethod
    def createTransaction(sender: 'User', recipient: 'User', amount: int, nonce: int, fee: int):
        transaction = Transaction.create_signed_transaction(
            sender_private_key=sender.private_key, recipient_hash=recipient.address, amount=amount, fee=fee, nonce=nonce)
        transaction.verifySignature()
        transaction.change_balance(sender, recipient)
        print(f"""
                Created transaction between \n {sender.public_keyPEM} and \n {recipient.public_keyPEM}. \n

                Total amount transfered: {amount}

                Signature of the transaction: {transaction.signature}

                Nonce is: {nonce}

                And fee is: {fee}

                Transaction verified: {transaction.isVerified}

        """)
        return transaction


class Transaction():
    def __init__(self, sender_hash: bytes, recipient_hash: bytes, sender_public_key: bytes, amount: int, fee: int, nonce: int, signature: bytes, txid: bytes):
        self.sender_hash: bytes = sender_hash
        self.recipient_hash: bytes = recipient_hash
        self.sender_public_bytes: bytes = sender_public_key
        self.amount: int = amount
        self.signature: bytes = signature
        self.fee: int = fee
        self.nonce: int = nonce
        self.__verified: bool = False
        self.txid: bytes = txid
        self.sender_public_key: ec.EllipticCurvePublicKey = load_der_public_key(
            sender_public_key, default_backend())

    def __str__(self):
        text = f"""
        Transaction between {self.sender_public_bytes} and {self.recipient_hash} \n
        Amount of transaction is {self.amount}
        The signature is {self.signature}
        """
        return text

    def change_balance(self, sender: User, recipient: User):
        sender.decr(self.amount)
        recipient.incr(self.amount)
        sender.nonce = sender.nonce + 1

    def verify(self, sender_balance, sender_previous_nonce):
        assert len(self.sender_hash) == 20
        assert len(self.recipient_hash) == 20
        assert User.hashSHA1(self.sender_public_bytes) == self.sender_hash
        assert sender_balance - self.amount >= 0
        assert self.amount > 0 and self.amount <= 2**(64-1)
        assert self.fee > 0 and self.fee <= self.amount
        assert self.nonce == sender_previous_nonce + 1
        assert self.txid == Transaction.txid(
            self.sender_public_bytes, self.sender_hash, self.recipient_hash, Transaction.littleEndian(self.amount), Transaction.littleEndian(self.fee), Transaction.littleEndian(self.nonce), self.signature)
        self.__verified = True
        self.verifySignature()
        return True

    @ property
    def isVerified(self):
        return self.__verified

    def verifySignature(self):
        pk = self.sender_public_key
        pk.verify(self.signature, Transaction.sig_ready(self.recipient_hash,
                                                        Transaction.littleEndian(self.amount), Transaction.littleEndian(self.fee), Transaction.littleEndian(self.nonce)), ec.ECDSA(hashes.SHA256()))

    @ staticmethod
    def sig_ready(recipient_hash: bytes, amount: int, fee: int, nonce: int):
        msg = collections.OrderedDict(
            {'recipient_hash': recipient_hash, 'amount': amount, 'fee': fee, 'nonce': nonce})
        msg = str(msg)
        msg = msg.encode('ascii')
        output_byte = base64.b64encode(msg)
        return output_byte

    @ staticmethod
    def create_signed_transaction(sender_private_key: ec.EllipticCurvePrivateKey, recipient_hash: bytes, amount: int, fee: int = 1, nonce: int = 1) -> 'Transaction':

        sender_public_key = sender_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        sender_hash = User.hashSHA1(sender_public_key)

        # the signature contains recipient hash, amount, fee and nonce.
        signature = User.sign_transaction(
            sender_private_key, Transaction.sig_ready(recipient_hash, Transaction.littleEndian(amount), Transaction.littleEndian(fee), Transaction.littleEndian(nonce)))

        txid = Transaction.txid(
            sender_public_key, sender_hash, recipient_hash, Transaction.littleEndian(amount), Transaction.littleEndian(fee), Transaction.littleEndian(nonce), signature)

        tx = Transaction(sender_hash=sender_hash, recipient_hash=recipient_hash, sender_public_key=sender_public_key,
                         amount=amount, fee=fee, nonce=nonce, txid=txid, signature=signature)
        return tx

    @ staticmethod
    def txid(sender_public_key, sender_hash, recipient_hash, amount, fee, nonce, signature):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(sender_hash)
        digest.update(recipient_hash)
        digest.update(sender_public_key)
        digest.update(amount)
        digest.update(fee)
        digest.update(nonce)
        digest.update(signature)
        return digest.finalize()

    @ staticmethod
    def littleEndian(number: int):
        return number.to_bytes(8, byteorder='little', signed=False)

    @ staticmethod
    def to_dict(txid, sender_name, recipient_name, sender_public_key, recipient_public_key, signature, amount, time):
        return collections.OrderedDict({
            'txid': txid,
            'sender_name': sender_name,
            'recipient_name': recipient_name,
            'sender_public_key': sender_public_key,
            'recipient_public_key': recipient_public_key,
            'signature': signature,
            'amount': amount,
            'time': time
        })


if __name__ == '__main__':

    sender_hash = bytes.fromhex("3df8f04b3c159fdc6631c4b8b0874940344d173d")
    recipient_hash = bytes.fromhex("5c1499a0484ace2f731b0afb83241e15f0e168ca")
    pk_bytes = bytes.fromhex("3056301006072a8648ce3d020106052b8104000a" +
                             "03420004886ed03cb7ffd4cbd95579ea2e202f1d" +
                             "b29afc3bf5d7c2c34a34701bbb0685a7b535f1e6" +
                             "31373afe8d1c860a9ac47d8e2659b74d437435b0" +
                             "5f2c55bf3f033ac1")

    sender_public_key: bytes = load_der_public_key(
        pk_bytes, default_backend()).public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    sender_hash = User.hashSHA1(sender_public_key)

    signature = bytes.fromhex("3046022100f9c076a72a2341a1b8cb68520713e1" +
                              "2f173378cf78cf79c7978a2337fbad141d022100" +
                              "ec27704d4d604f839f99e62c02e65bf60cc93ae1"
                              "735c1ccf29fd31bd3c5a40ed")

    amount = 10
    fee = 2
    nonce = 5
    tx = Transaction(
        sender_hash,
        recipient_hash,
        sender_public_key,
        amount,
        fee,
        nonce,
        signature,
        bytes.fromhex("ca388e0890b71bd1775460d478f26af3776c9b4f" +
                      "6c2b936e1e788c5c87657bc3"))

    tx.verify(20, 4)
