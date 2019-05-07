#este modulo se iba a construir sobre la utilidad para analizar packers provista por los peutils de peid,
#pero al dar problemas con ciertos archivos (malware mal codificados a propósito) se ha decidido emplear reglas yara

import yara
from pelyzer.utils import cargar_yara

PEID_YARA = "pelyzer/recursos/yara/compiladas/peid.yar"

def extraer_packer(archivo_pe):
    packers = []

    datos_bin = archivo_pe.read()

    packer_match = cargar_yara(PEID_YARA).match(data=datos_bin)
    # hay mas de una regla en el archivo yara
    if packer_match:
        for match in packer_match:
            for packer in match.strings:
                packers.append(packer[2])

    return len(packers)