import random
from string import ascii_letters, digits


def create_exec_id():
    return ''.join([random.choice(ascii_letters + digits) for n in range(8)])
