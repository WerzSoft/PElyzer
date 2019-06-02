import os
import yara
import hashlib
from colorama import init,Fore, Back, Style


def merge_dicts(x, y):
    return {**x, **y}


def valores_dict_to_float(dic):
    return dict((clave, float(valor)) for clave, valor in dic.items())


def tupla_a_str(tupla):
    str = '-'.join(tupla)
    return str


def cargar_yara(archivo_yara):
    return yara.load(archivo_yara)


def compilar_yara():
    for regla in os.listdir("pelyzer/recursos/yara/reglas"):
        regla_compilada = yara.compile("pelyzer/recursos/yara/reglas/" + regla)
        regla_compilada.save("pelyzer/recursos/yara/compiladas/" + regla)


def hash_sha256(archivo):
    sha256 = hashlib.sha256()
    with open(archivo, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256.update(byte_block)

    f.close()
    return sha256.hexdigest()


def mostrar_mensaje(color, mensaje):
    colores = {"verde": Fore.GREEN, "rojo": Fore.RED}
    print(colores[color] + "\n{}".format(mensaje))
    print(Style.RESET_ALL)
