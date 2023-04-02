from cracker.password import AbstractPasswordCracker
from cracker.policy import PasswordProperty


def test_password_property():
    AbstractPasswordCracker.get_password_property(b"hello") == PasswordProperty(
        0, 4, 0, 0
    )
    AbstractPasswordCracker.get_password_property(b"HellO") == PasswordProperty(
        2, 2, 0, 0
    )
    AbstractPasswordCracker.get_password_property(b"H3ll0") == PasswordProperty(
        1, 2, 2, 0
    )
    AbstractPasswordCracker.get_password_property(b"H3ll0?!") == PasswordProperty(
        1, 2, 2, 2
    )
