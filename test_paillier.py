from pailler_cryptosystem import paillier as pal
from gmpy2 import mpz

m1 = mpz(10)
m2 = mpz(1)
m3 = mpz(0)
m4 = mpz(2000)
m5 = mpz(4000)
m6 = mpz(999)
key_pair = pal.keygen()
c1 = pal.encrypt(m1, key_pair.public_key)
c2 = pal.encrypt(m2, key_pair.public_key)
c3 = pal.encrypt(m3, key_pair.public_key)
c4 = pal.encrypt(m4, key_pair.public_key)
c5 = pal.encrypt(m5, key_pair.public_key)
c6 = pal.encrypt(m6, key_pair.public_key)


def test_additive():
    assert pal.decrypt(c1 + c2, key_pair.private_key) == 11
    assert pal.decrypt(c1 + c2 + c1, key_pair.private_key) == 21
    assert pal.decrypt(c1 + c2 + c1 + c2, key_pair.private_key) == 22
    assert pal.decrypt(c6 + c2, key_pair.private_key) == 1000
    assert pal.decrypt(c5 + c6 + c5, key_pair.private_key) == 8999
    assert pal.decrypt(c3 + c3 + c3 + c3 + c3, key_pair.private_key) == 0


def test_sub():
    assert pal.decrypt(c2 - c3, key_pair.private_key) == 1
    assert pal.decrypt(c2 - c3 - c3 - c3, key_pair.private_key) == 1
    assert pal.decrypt(c5 - c4 - c2, key_pair.private_key) == 1999
    assert pal.decrypt(c2 + c3 + c2 - c3 - c2, key_pair.private_key) == 1


def test_mul():
    assert pal.decrypt(c1 * m2, key_pair.private_key) == 10
    assert pal.decrypt(c1 * m1, key_pair.private_key) == 100
    assert pal.decrypt(c1 * m1 * m1 * m1 * m2, key_pair.private_key) == 10000
    assert pal.decrypt(c5 * m3, key_pair.private_key) == 0


def toy_example():
    key_pair = pal.keygen(48)
    message_1 = 1221
    message_2 = 1234
    cipher_1 = pal.encrypt(message_1, key_pair.public_key)
    cipher_2 = pal.encrypt(message_2, key_pair.public_key)
    assert pal.decrypt(cipher_1 + cipher_2, key_pair.private_key) == 2455


def work_example():
    key_pair = pal.keygen(2048)
    message_1 = 1221
    message_2 = 1234
    cipher_1 = pal.encrypt(message_1, key_pair.public_key)
    cipher_2 = pal.encrypt(message_2, key_pair.public_key)
    assert pal.decrypt(cipher_1 + cipher_2, key_pair.private_key) == 2455


def main():
    test_additive()
    test_sub()
    test_mul()
    toy_example()
    work_example()


if __name__ == '__main__':
    main()
