def _spl_two(string: str):
    return [string[i:i + 2] for i in range(0, len(string), 2)]


def bad_crypt(data: str, password: str) -> str:
    string_ords = [ord(char) for char in data]
    password_ords = [ord(char) for char in password]

    for char in data:
        string_ords.append(ord(char))
    for char in password:
        password_ords.append(ord(char))
    while len(password_ords) < len(string_ords):
        for char in password:
            password_ords.append(ord(char))
    while len(password_ords) > len(string_ords):
        password_ords.pop(-1)
    return ''.join([chr(ord_) for ord_ in [os + op for os, op in zip(string_ords, password_ords)]])


def bad_decrypt(encrypted_data: str, password: str) -> str:
    string_ords = [ord(char) for char in encrypted_data]
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


def crypt(data: str, password: str) -> str:
    return bad_crypt(
        bad_crypt(
            bad_crypt(
                bad_crypt(
                    data, password
                ), password[::-1]
            ), ''.join(_spl_two(password)[::-1])
        ), password
    )


def decrypt(encrypted_data: str, password: str) -> str:
    return bad_decrypt(
        bad_decrypt(
            bad_decrypt(
                bad_decrypt(
                    encrypted_data, password
                ), password[::-1]
            ), ''.join(_spl_two(password)[::-1])
        ), password
    )


class Crypter:
    def __init__(self, password):
        self.password = password

    def crypt(self, data: str) -> str:
        return crypt(data=data, password=self.password)

    def decrypt(self, encrypted_Data: str) -> str:
        return decrypt(encrypted_data=encrypted_Data, password=self.password)


class BadCrypter:
    def __init__(self, password):
        self.password = password

    def crypt(self, data: str) -> str:
        return bad_crypt(data=data, password=self.password)

    def decrypt(self, encrypted_data: str) -> str:
        return bad_decrypt(encrypted_data=encrypted_data, password=self.password)
