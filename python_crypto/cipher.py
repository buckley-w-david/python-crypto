class Cipher:
    """
    Base class defining a standard API to interact with
    a cipher
    """

    def __init__(self) -> None:
        raise NotImplementedError("Must use a subclass of generic `Cipher`")

    def encrypt_text(self, text: str) -> str:
        """
        Returns text encrypted by cipher

        :param text str: string to encypt
        :returns: encrypted version of text
        :rtype: str
        """
        return self.encrypt(text.encode()).decode()

    def decrypt_text(self, text: str) -> str:
        """
        Returns text decrypted by cipher

        :param text str: string to encypt
        :returns: encrypted version of text
        :rtype: str
        """
        return self.decrypt(text.encode()).decode()

    def encrypt(self, data: bytes) -> bytes:
        """
        Returns data encrypted by cipher

        :param text bytes: data to encypt
        :returns: encrypted version of data
        :rtype: bytes
        """
        raise NotImplementedError("Must use a subclass of generic `Cipher`")

    def decrypt(self, data: bytes) -> bytes:
        """
        Returns data decrypted by cipher

        :param text bytes: data to decrypt
        :returns: encrypted version of data
        :rtype: bytes
        """
        raise NotImplementedError("Must use a subclass of generic `Cipher`")
