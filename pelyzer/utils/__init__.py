#conjunto de funciones que son empleadas a lo largo de toda la aplicación

import os
import yara
import hashlib
from colorama import init,Fore, Back, Style
from multiprocessing import cpu_count
import pymongo
import pelyzer.utils.config as config


def num_procs():
    return cpu_count()//2


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
    n_reglas = 0
    for regla in os.listdir("pelyzer/recursos/yara/reglas"):
        regla_compilada = yara.compile("pelyzer/recursos/yara/reglas/" + regla)
        regla_compilada.save("pelyzer/recursos/yara/compiladas/" + regla)
        n_reglas += 1

    return n_reglas


def hash_sha256(archivo):
    sha256 = hashlib.sha256()
    with open(archivo, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256.update(byte_block)

    f.close()
    return sha256.hexdigest()

def conectar_db():
    if config.USE_DB_AUTH:
        return pymongo.MongoClient(config.MONGO_SERVER, 27017, serverSelectionTimeoutMS=10,
                                      username=config.MONGO_USERNAME, password=config.MONGO_PASSWORD,
                                      authSource="admin")
    else:
        return pymongo.MongoClient(config.MONGO_SERVER, 27017, serverSelectionTimeoutMS=10)


def comprobar_db():
    try:
        cliente = conectar_db()
        cliente.server_info()
        return True
    except pymongo.errors.ServerSelectionTimeoutError as err:
       return False


def db_vacia():
    cliente = conectar_db()
    db = cliente[config.MONGO_DB]
    coleccion = db[config.MONGO_COLLECTION]
    if coleccion.count() == 0:
        return True
    else:
        return False


def mostrar_mensaje(color, mensaje):
    colores = {"verde": Fore.GREEN, "rojo": Fore.RED}
    print(colores[color] + "\n{}".format(mensaje))
    print(Style.RESET_ALL)