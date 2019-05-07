from .pe_caracteristicas import extraer_caracteristicas_dirs
from .pe_caracteristicas import extraer_caracteristicas_pe

def entrenar_algoritmo(malwareDir, goodwareDir):
    extraer_caracteristicas_dirs(malwareDir, goodwareDir)

def analizar_archivo():
    pass