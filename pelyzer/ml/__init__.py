#modulo encargado de obtener las características de las muestras desde la base de datos, preprocesarlas y transformarlas
#de modo que puedan ser empleadas por el algoritmo de machine learning. Además se encarga de mostrar los resultados de
#los análisis efectuados sobre los archivos.


import os
from sklearn.feature_extraction import FeatureHasher

from utils import merge_dicts
from ml.analizar import analizar_pe
from ml.entrenar import entrenar_XGBoost
import utils as utils


def procesar_sections(sections):
    tmp = dict()
    #calculos sobre las secciones

    secciones = sections['sections']

    #se utilizará el hashing-trick con cada valor extraido de las secciones junto a su nombre (para darle mayor significacion)
    #el resto de características se dejará igual
    n_t_secciones_tmp = [(seccion['name'], seccion['s_size']) for seccion in secciones]
    n_t_secciones = FeatureHasher(50, input_type="pair").transform([n_t_secciones_tmp]).toarray()[0]

    n_vsize_secciones_tmp = [(seccion['name'], seccion['s_vsize']) for seccion in secciones]
    n_vsize_secciones = FeatureHasher(50, input_type="pair").transform([n_vsize_secciones_tmp]).toarray()[0]

    n_entropy_secciones_tmp = [(seccion['name'], seccion['s_entropy']) for seccion in secciones]
    n_entropy_secciones = FeatureHasher(50, input_type="pair").transform([n_entropy_secciones_tmp]).toarray()[0]

    for i, elemento in enumerate(n_t_secciones):
        tmp['n_vsize_secciones_%d' % i] = elemento

    for i, elemento in enumerate(n_vsize_secciones):
        tmp['n_t_secciones_%d' % i] = elemento

    for i, elemento in enumerate(n_entropy_secciones):
        tmp['n_entropy_secciones_%d' % i] = elemento

    tmp['n_std_sec'] = sections['n_std_sec']
    tmp['n_susp_sec'] = sections['n_susp_sec']

    return tmp


def procesar_imports(imports):
    tmp = dict()
    #calculos sobre las librerias importadas

    #obtenemos los nombres de las librerias(recordar que por usar mongo se cambio el . por _)
    #al ser cadenas se usará el hasing-trick para transformarlas de valor categórico a valor numérico
    dlls_tmp = list(set([dll.lower() for dll in imports.keys()]))
    dlls = FeatureHasher(200, input_type="string").transform([dlls_tmp]).toarray()[0]

    for i, elemento in enumerate(dlls):
        tmp['dlls_%d' % i] = elemento

    #se realiza el mismo proceso con el nombre de las funciones. Al tratarse de cadenas y no de numeros
    #se crea una cadena del tipo dll_funcion para realizar el hashing-trick sobre ella. De este modo se guarda
    #la informacion de que función se importa por cada dll
    funciones_tmp = [dll.lower() + ':' + funcion for dll, funciones in imports.items() for funcion in funciones]
    funciones = FeatureHasher(1000, input_type="string").transform([funciones_tmp]).toarray()[0]

    for i, elemento in enumerate(funciones):
        tmp['funciones_%d' % i] = elemento

    return tmp


def procesar_exports(exports):
    tmp = dict()
    #calculos sobre las funciones exportadas

    #al tratarse de una lista de cadenas, es decir, datos categóricos, se empela el hashing-trick para pasarlos a
    #valor numérico. Como normalmente se exportan pocas funciones (excepto en el caso de dlls, se usa un valor reducido
    funciones_exportadas = FeatureHasher(50, input_type="string").transform([exports]).toarray()[0]

    for i, elemento in enumerate(funciones_exportadas):
        tmp['funciones_%d' % i] = elemento

    return tmp


def procesar_pe_header(pe_header):
    tmp = dict()
    tmp = merge_dicts(tmp, pe_header['dos_nt_header'])
    tmp = merge_dicts(tmp, pe_header['file_header'])
    tmp = merge_dicts(tmp, pe_header['optional_header'])
    tmp = merge_dicts(tmp, procesar_sections(pe_header['sections']))
    tmp = merge_dicts(tmp, procesar_imports(pe_header['imports']))
    tmp = merge_dicts(tmp, procesar_exports(pe_header['exports']))

    return tmp


def procesar_opcodes(opcodes):
    tmp = dict()
    opcodes_tmp = FeatureHasher(1500).transform([opcodes]).toarray()[0]

    for i, elemento in enumerate(opcodes_tmp):
        tmp['opcodes_%d' % i] = elemento

    return tmp


def procesar_yara(yara):
    tmp = dict()

    for clave, valor in yara.items():
        tmp['yara_%s' % clave] = valor

    return tmp


def vector_caracteristicas(datos_raw, is_training=False):
    datos_pe = dict()

    sha = datos_raw['sha256']
    is_exe = datos_raw['is_exe']
    is_dll = datos_raw['is_dll']
    is_driver = datos_raw['is_driver']
    pe_header = datos_raw['pe_header']
    opcodes = datos_raw['opcodes']
    unk_opcodes = datos_raw['unk_opcodes']
    yara = datos_raw['yara']
    checksum_invalido = datos_raw['checksum_invalido']
    firmado = datos_raw['firmado']

    datos_pe['sha256'] = sha
    datos_pe['is_exe'] = 1 if is_exe else 0
    datos_pe['is_dll'] = 1 if is_dll else 0
    datos_pe['is_driver'] = 1 if is_driver else 0
    datos_pe = merge_dicts(datos_pe, procesar_pe_header(pe_header))
    datos_pe = merge_dicts(datos_pe, procesar_opcodes(opcodes))
    datos_pe['unk_opcodes'] = unk_opcodes
    datos_pe = merge_dicts(datos_pe, procesar_yara(yara))
    datos_pe['checksum_invalido'] = 1 if checksum_invalido else 0
    datos_pe['firmado'] = 1 if firmado else 0
    if is_training:
        malware = datos_raw['malware']
        datos_pe['malware'] = malware


    return datos_pe

def analizar_archivo(ruta):
    resultado, proba = analizar_pe(os.path.join(ruta, ruta))
    if resultado is None:
        print("[*]El archivo tiene un formato no válido")
    elif resultado == 1:
        utils.mostrar_mensaje("rojo", "### ALERTA => Malware Detectado ###")
        print("Probablilidad: {:.2f}%\n".format(proba*100))
    else:
        utils.mostrar_mensaje("verde", "### PASS => Archivo limpio")
        print("Probablilidad: {:.2f}%\n".format(proba*100))


def analizar_directorio(ruta):
    resultados = {"clean": 0, "malware": 0, "malware_files":[]}
    print("[+]Listando archivos")
    for r, d, f in os.walk(ruta):
        for archivo in f:
            resultado, proba = analizar_pe(os.path.join(r, archivo))
            if resultado is None:
                #no es un archivo con formato PE
                print("[*]El archivo tiene un formato no válido")
            elif resultado == 1:
                #si es malware se muestra mensaje en rojo
                resultados["malware"] += 1
                resultados["malware_files"].append(os.path.join(r, archivo))
                utils.mostrar_mensaje("rojo", "### ALERTA => Malware Detectado ###")
                print("Probablilidad: {:.2f}%\n".format(proba * 100))
            else:
                #si es goodware se muestra mensaje en verde
                resultados["clean"] += 1
                utils.mostrar_mensaje("verde", "### PASS => Archivo limpio")
                print("Probablilidad: {:.2f}%\n".format(proba * 100))

    print("[*]RESULTADOS: {} archivos infectados y {} archivos limpios".format(resultados["malware"], resultados["clean"]))
    if resultados["malware"] > 0:
        print("[*]Archivos infectados: ")
        for archivo in resultados["malware_files"]:
            print("\t[-]{}".format(archivo))
