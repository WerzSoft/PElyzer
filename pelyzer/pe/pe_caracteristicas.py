import os
import ntpath
from tqdm import tqdm
import pymongo
from functools import partial
from multiprocessing import Pool, cpu_count
from pelyzer.utils import compilar_yara
from .pe_header import extraer_cabecera
from .pe_opcodes import extraer_opcodes
from .pe_cadenas import extraer_cadenas
from .pe_packer import extraer_packer

USE_DB = True
MONGO_SERVER = "127.0.0.1"
NUM_PROCS = cpu_count()

def get_samples(directorio):
    samples = []
    for ruta in os.listdir(directorio):
        if ".DS" not in ruta:
            samples.append(os.path.join(directorio, ruta))
    return samples

def extraer_y_almacenar(tipo, muestra):
    if USE_DB:
        cliente = pymongo.MongoClient(MONGO_SERVER, 27017)
        db = cliente['tfg']
        coleccion = db['samples_data']

    datos_muestra = extraer_caracteristicas_pe(muestra)
    if datos_muestra is not None:
        datos_muestra['malware'] = tipo
        #añadimos los datos de la muestra a la base de datos mongodb
        if USE_DB:
            coleccion.insert_one(datos_muestra)
        else:
            pass
        # borramos la variable datos_muestra para ahorrar espacio en memoria
        del datos_muestra

def extraer_caracteristicas_pe(pefile):
    caracteristicas = dict()
    pefile_bin = open(pefile, "rb")
    caracteristicas['sha256'] = ntpath.basename(pefile)
    caracteristicas['pe_header'] = extraer_cabecera(pefile_bin)
    opcodes, unk_opcodes = extraer_opcodes(pefile_bin, caracteristicas['pe_header']['optional_header']['AddressOfEntryPoint'],
                                                    caracteristicas['pe_header']['optional_header']['ImageBase']
                                                 )
    caracteristicas['opcodes'] = opcodes
    caracteristicas['unk_opcodes'] = unk_opcodes
    caracteristicas['cadenas'] = extraer_cadenas(pefile_bin)
    caracteristicas['packers'] = extraer_packer(pefile_bin)

    return caracteristicas


def extraer_caracteristicas_dirs(malwareDir, goodwareDir):
    print("[+]Compilando reglas yara...")
    compilar_yara()
    print("[+]Listando Malwares....")
    muestras_malware = get_samples(malwareDir)
    print("[+]Listando archivos benignos...")
    muestras_goodware = get_samples(goodwareDir)

    total_malware = len(muestras_malware)
    total_benignos = len(muestras_goodware)

    print("[+]Analizando {} samples de malware y {} samples benignos...".format(total_malware, total_benignos))

    sub_malware = partial(extraer_y_almacenar, 1)
    sub_goodware = partial(extraer_y_almacenar, 0)

    print("Usando {} Cores".format(NUM_PROCS))


    with Pool(processes=NUM_PROCS) as p:
        with tqdm(total=total_malware, desc='[+]Analizando malware', position=0) as pbar:
            for i, _ in tqdm(enumerate(p.imap_unordered(sub_malware, muestras_malware))):
                pbar.update()

    with Pool(processes=NUM_PROCS) as p:
        with tqdm(total=total_benignos, desc='[+]Analizando goodware', position=1) as pbar:
            for i, _ in tqdm(enumerate(p.imap_unordered(sub_goodware, muestras_goodware))):
                pbar.update()