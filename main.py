"""Paswwords Validator"""
from validator import PasswordValidator, ValidationError

with open('passwords.txt', mode='r',encoding='utf-8') as input_file,\
    open('safe_passwords.txt', mode='a', encoding='utf-8') as output_file:
    for password in input_file:
        try:
            PasswordValidator(password.strip()).validate()
            output_file.write(password)
        except ValidationError as error:
            print(password, error)
