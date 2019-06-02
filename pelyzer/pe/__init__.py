import os
import time

from pelyzer.pe.pe_caracteristicas import extraer_caracteristicas_dirs
from pelyzer.pe.pe_caracteristicas import extraer_caracteristicas_pe
from pelyzer.pe.pe_header import extraer_cabecera
from pelyzer.pe.pe_opcodes import extraer_opcodes
from pelyzer.pe.pe_cadenas import extraer_cadenas
from pelyzer.pe.pe_packer import extraer_packer

def procesar_samples(malwareDir, goodwareDir):
    t0 = time.time()
    print("[+]Iniciando extracción de características")
    extraer_caracteristicas_dirs(malwareDir, goodwareDir)
    t1 = time.time()
    print("\n\n[+]Proceso finalizado en {} segundos".format(t1-t0))
    print("\n**Puede lanzar el comando entrenar para crear el modelo de predicción**")