#modulo encargado de la extraccion de características de los samples.


import os
from tqdm import tqdm
import pymongo
import pefile
from functools import partial
from multiprocessing import Pool
import utils
import utils.config as config
import pe as pe


#lista todos los samples existentes en la ruta pasada por parámetro
def get_samples(directorio):
    samples = []
    for ruta in os.listdir(directorio):
        #en entornos mac se excluye este directorio para evitar errores
        if ".DS" not in ruta:
            samples.append(os.path.join(directorio, ruta))
    return samples

#recupera las características extraídas y, si esta habilitado el almacenamiento, las guarda en la base de datos
#mongo db definida en la configuración
def extraer_y_almacenar(tipo, muestra):
    datos_muestra = extraer_caracteristicas_pe(muestra)
    if bool(datos_muestra):
        datos_muestra['malware'] = tipo
        #añadimos los datos de la muestra a la base de datos mongodb
        if config.USE_DB:
            cliente = utils.conectar_db()
            db = cliente[config.MONGO_DB]
            coleccion = db[config.MONGO_COLLECTION]
            coleccion.insert_one(datos_muestra)
            #cerramos la conexión para evitar errores al crear nuevos procesos
            cliente.close()
        else:
            pass
        # borramos la variable datos_muestra para ahorrar espacio en memoria
        del datos_muestra

#llama a los distintios modulos encargados de extraer las características de un sample. Así mismo, comprueba que se
#trate de un archivo con formato PE
def extraer_caracteristicas_pe(archivo_pe):
    caracteristicas = dict()

    try:
        datos_pe = pefile.PE(archivo_pe, fast_load=False)
    except OSError as e:
        print(e)
    except pefile.PEFormatError as e:
        pass
        #logger
        #print("[-] PEFormatError: %s" % e.value)
    else:
        caracteristicas['sha256'] = utils.hash_sha256(archivo_pe)
        caracteristicas["is_dll"] = datos_pe.is_dll()
        caracteristicas["is_exe"] = datos_pe.is_exe()
        caracteristicas["is_driver"] = datos_pe.is_driver()
        caracteristicas['pe_header'] = pe.extraer_cabecera(datos_pe)
        opcodes, unk_opcodes = pe.extraer_opcodes(datos_pe)
        caracteristicas['opcodes'] = opcodes
        caracteristicas['unk_opcodes'] = unk_opcodes
        caracteristicas['yara'] = pe.extraer_yara(archivo_pe)
        caracteristicas['checksum_invalido'] = pe.check_checksum(datos_pe)
        caracteristicas['firmado'] = pe.check_firma(datos_pe)

    return caracteristicas


#procesamiento de los directorios de muestras. Se efectúa en paralelo para optimizar la utilización de los recursos
#hardware así como para reducir el tiempo de extracción
def extraer_caracteristicas_dirs(malwareDir, goodwareDir):
    print("[+]Compilando reglas yara...")
    utils.compilar_yara()
    print("[+]Listando Malwares....")
    muestras_malware = get_samples(malwareDir)
    print("[+]Listando archivos benignos...")
    muestras_goodware = get_samples(goodwareDir)

    total_malware = len(muestras_malware)
    total_benignos = len(muestras_goodware)

    print("[+]Analizando {} samples de malware y {} samples benignos...".format(total_malware, total_benignos))

    sub_malware = partial(extraer_y_almacenar, 1)
    sub_goodware = partial(extraer_y_almacenar, 0)

    print("[*]Usando {} Cores".format(utils.num_procs()))

    pool = Pool(utils.num_procs())
    with tqdm(total=total_malware, desc='[*]Analizando malware', position=0) as pbar:
        for i, _ in tqdm(enumerate(pool.imap_unordered(sub_malware, muestras_malware))):
            pbar.update()
        mal_pool.close()
        mal_pool.join()

    with tqdm(total=total_benignos, desc='[*]Analizando goodware', position=1) as pbar:
        for i, _ in tqdm(enumerate(pool.imap_unordered(sub_goodware, muestras_goodware))):
            pbar.update()
        good_pool.close()
        good_pool.join()