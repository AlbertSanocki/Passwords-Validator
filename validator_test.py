"""Tests of Password Validators"""
import pytest

from validator import (
    LenValidator,
    HasNumValidator,
    HasSpecialCharValidator,
    HasUpperCharValidator,
    HasLowerCharValidator,
    DidPasswordLeakValidator,
    ValidationError,
    PasswordValidator
)

def test_len_validator_positive():
    """Positive tests of length validator"""
    validator = LenValidator('12345678')
    assert validator.validate() is True

    validator = LenValidator('123456789')
    assert validator.validate() is True

    validator = LenValidator('12345', 5)
    assert validator.validate() is True

def test_len_validator_negative():
    """Negative tests of length validator"""
    validator = LenValidator('1234567')
    with pytest.raises(ValidationError) as error:
        validator.validate()
    assert 'Password must contain at least 8 characters!' in str(error.value)

    validator = LenValidator('123', 5)
    with pytest.raises(ValidationError) as error:
        validator.validate()
    assert 'Password must contain at least 8 characters!' in str(error.value)

def test_if_has_number_validator_positive():
    """Positive tests of HasNumValidator validator"""
    validator = HasNumValidator('a9bc')
    assert validator.validate() is True

def test_if_has_number_validator_nagetive():
    """Negative tests of HasNumValidator validator"""
    validator = HasNumValidator('abcd')
    with pytest.raises(ValidationError) as error:
        validator.validate()
    assert 'Password must contain at least 1 number!' in str(error.value)

def test_if_has_special_char_validator_positive():
    """Positive tests of HasSpecialCharValidator validator"""
    validator = HasSpecialCharValidator('a#bc')
    assert validator.validate() is True

def test_if_has_special_char_validator_negative():
    """Negative tests of HasSpecialCharValidator validator"""
    validator = HasSpecialCharValidator('abcd')
    with pytest.raises(ValidationError) as error:
        validator.validate()
    assert 'Password must contain at least 1 special character!' in str(error.value)

def test_if_has_upper_char_validator_positive():
    """Positive tests of HasUpperCharValidator validator"""
    validator = HasUpperCharValidator('aBcD')
    assert validator.validate() is True

def test_if_has_upper_char_validator_negative():
    """Negative tests of HasUpperCharValidator validator"""
    validator = HasUpperCharValidator('abcd')
    with pytest.raises(ValidationError) as error:
        validator.validate()
    assert 'Password must contain at least 1 Upper letter!' in str(error.value)

def test_if_has_lower_char_validator_positive():
    """Positive tests of HasLowerCharValidator validator"""
    validator = HasLowerCharValidator('AbcD')
    assert validator.validate() is True

def test_if_has_lower_char_validator_negative():
    """Negative tests of HasLowerCharValidator validator"""
    validator = HasLowerCharValidator('ABCD')
    with pytest.raises(ValidationError) as error:
        validator.validate()
    assert 'Password must contain at least 1 Lower letter!' in str(error.value)

def test_did_password_leak_validator_positive(requests_mock):
    """Positive tests of DidPasswordLeakValidator validator"""
    data = '00173F1B8083E73D5CA6E6750E3B15F94E5:1\r\n0122AD80005AA533B11EEC7730CAAF620AA:2'
    requests_mock.get('https://api.pwnedpasswords.com/range/12284', text = data)
    validator = DidPasswordLeakValidator('Albert1!')
    assert validator.validate() is True

def test_did_password_leak_validator_negative(requests_mock):
    """Negative tests of DidPasswordLeakValidator validator"""
    data = '00173F1B8083E73D5CA6E6750E3B15F94E5:1\r\n49FA14AFB7A97DF31BC7872CC023CC5ABF7:2'
    requests_mock.get('https://api.pwnedpasswords.com/range/12284', text = data)
    validator = DidPasswordLeakValidator('Albert1!')
    with pytest.raises(ValidationError) as error:
        validator.validate()
    assert 'This password leaked before!' in str(error.value)

def test_password_validator_positive():
    """Positive tests of PasswordValidator validator"""
    validator = PasswordValidator('Albertronix4#!@!!')
    assert validator.validate() is True

def test_password_validator_negative():
    """Negative tests of PasswordValidator validator"""
    validator = PasswordValidator('Ala')
    with pytest.raises(ValidationError) as error:
        validator.validate()
    assert 'Password must contain at least 8 characters!' in str(error.value)
