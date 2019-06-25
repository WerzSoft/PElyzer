#Este modulo carga las funciones y características del paquete que son usadas en otras partes de la aplicación. Además
#es el encargado de iniciar el procesamiento de los samples para la extracción de características.

import time

from pelyzer.pe.pe_caracteristicas import extraer_caracteristicas_dirs
from pelyzer.pe.pe_caracteristicas import extraer_caracteristicas_pe
from pelyzer.pe.pe_header import extraer_cabecera
from pelyzer.pe.pe_opcodes import extraer_opcodes
from pelyzer.pe.pe_yara import extraer_yara
from pelyzer.pe.pe_extras import check_checksum, check_firma


def procesar_samples(malwareDir, goodwareDir):
    t0 = time.time()
    print("[+]Iniciando extracción de características")
    extraer_caracteristicas_dirs(malwareDir, goodwareDir)
    t1 = time.time()
    print("\n\n[+]Proceso finalizado en {} segundos".format(t1-t0))
    print("\n**Puede lanzar el comando entrenar para crear el modelo de predicción**")