"""Password Validators"""
from abc import ABC, abstractmethod
from hashlib import sha1
from requests import get

class ValidationError(Exception):
    """Exception for validation error"""

class ValidatorInterface(ABC):
    """Interface for validators"""
    @abstractmethod
    def __init__(self, text) -> None:
        """Forcing to implement __init__ method"""
    @abstractmethod
    def validate(self):
        """Forcing to implement validate method"""

class LenValidator(ValidatorInterface):
    """Length validator for text"""
    def __init__(self, text, min_len = 8):
        self.text = text
        self.min_len = min_len

    def validate(self):
        """Checks if text is valid

        Raises:
            ValidationError: text is not valid because its to short

        Returns:
            bool: the length of the text is correct
        """
        if len(self.text) >= self.min_len:
            return True

        raise ValidationError('Password must contain at least 8 characters!')

class HasNumValidator(ValidatorInterface):
    """Validator checking if text contains number"""
    def __init__(self, text):
        self.text = text

    def validate(self):
        """Checks if text is valid

        Raises:
            ValidationError: text is not valid because do not contain number

        Returns:
            bool: text contains a number
        """
        if any(char in [str(number) for number in range(0, 10)] for char in self.text):
            return True

        raise ValidationError('Password must contain at least 1 number!')


class HasSpecialCharValidator(ValidatorInterface):
    """Validator checking if text contains special character"""
    def __init__(self, text):
        self.text = text

    def validate(self):
        """Checks if text is valid

        Raises:
            ValidationError: text is not valid because do not contain special character

        Returns:
            bool: text contains a special character
        """
        if any(not char.isalnum() for char in self.text):
            return True

        raise ValidationError('Password must contain at least 1 special character!')


class HasUpperCharValidator(ValidatorInterface):
    """Validator checking if text contains upper letter"""
    def __init__(self, text):
        self.text = text

    def validate(self):
        """Checks if text is valid

        Raises:
            ValidationError: text is not valid because do not contain upper letter in text

        Returns:
            bool: text contains a upper letter
        """
        if any(char.isupper() for char in self.text):
            return True

        raise ValidationError('Password must contain at least 1 Upper letter!')


class HasLowerCharValidator(ValidatorInterface):
    """Validator checking if text contains lower letter"""
    def __init__(self, text):
        self.text = text

    def validate(self):
        """Checks if text is valid

        Raises:
            ValidationError: text is not valid because do not contain lower letter in text

        Returns:
            bool: text contains a lower letter
        """
        if any(char.islower() for char in self.text):
            return True

        raise ValidationError('Password must contain at least 1 Lower letter!')

class DidPasswordLeakValidator(ValidatorInterface):
    """Validator checking if password leaked before"""
    def __init__(self, password):
        self.password = password

    def validate(self):
        """Checks if password leaked before

        Raises:
            ValidationError: password is not valid because it leaked before

        Returns:
            bool: password never leaked before
        """
        hashed_password = sha1(self.password.encode('utf-8')).hexdigest().upper()
        response = get('https://api.pwnedpasswords.com/range/' + hashed_password[:5])
        if hashed_password[5:] not in [line.split(':')[0] for line in response.text.splitlines()]:
            return True

        raise ValidationError('This password leaked before!')

class PasswordValidator(ValidatorInterface):
    """Validator checking if password is valid"""
    def __init__(self, password) -> None:
        self.password = password
        self.validators = [
            LenValidator,
            HasNumValidator,
            HasSpecialCharValidator,
            HasUpperCharValidator,
            HasLowerCharValidator,
            DidPasswordLeakValidator,
            ]

    def validate(self):
        """Checks if password is valid

        Returns:
            bool: returns true if password passed all validations
        """
        for class_name in self.validators:
            validator = class_name(self.password)
            if validator.validate() is False:
                return False
        return True
