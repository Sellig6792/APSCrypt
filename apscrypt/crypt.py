def _spl_two(string: str):
    return [string[i:i + 2] for i in range(0, len(string), 2)]


def bad_crypt(string: str, password: str) -> str:
    string_ords = [ord(char) for char in string]
    password_ords = [ord(char) for char in password]

    for char in string:
        string_ords.append(ord(char))
    for char in password:
        password_ords.append(ord(char))
    while len(password_ords) < len(string_ords):
        for char in password:
            password_ords.append(ord(char))
    while len(password_ords) > len(string_ords):
        password_ords.pop(-1)

    return ''.join([chr(ord_) for ord_ in [os - op for os, op in zip(string_ords, password_ords)]])


def bad_decrypt(string: str, password: str) -> str:
    string_ords = [ord(char) for char in string]
    password_ords = [ord(char) for char in password]
    chars = ""
    while len(password_ords) < len(string_ords):
        for char in password:
            password_ords.append(ord(char))
    while len(password_ords) > len(string_ords):
        password_ords.pop(-1)

    for ord_ in [os - op for os, op in zip(string_ords, password_ords)]:
        try:
            chars += chr(ord_)
        except ValueError:
            break
    return chars


def crypt(string: str, password: str) -> str:
    return bad_crypt(
        bad_crypt(
            bad_crypt(
                bad_crypt(
                    string, password
                ), password[::-1]
            ), ''.join(_spl_two(password)[::-1])
        ), password
    )


def decrypt(string: str, password: str) -> str:
    return bad_decrypt(
        bad_decrypt(
            bad_decrypt(
                bad_decrypt(
                    string, password
                ), password[::-1]
            ), ''.join(_spl_two(password)[::-1])
        ), password
    )


class Crypter:
    def __init__(self, password):
        self.password = password

    def crypt(self, string: str) -> str:
        return crypt(string=string, password=self.password)

    def decrypt(self, string: str) -> str:
        return decrypt(string=string, password=self.password)


class BadCrypter:
    def __init__(self, password):
        self.password = password

    def crypt(self, string: str) -> str:
        return bad_crypt(string=string, password=self.password)

    def decrypt(self, string: str) -> str:
        return bad_decrypt(string=string, password=self.password)
