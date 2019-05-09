import peutils
import pefile
import mmap

USER_DB = "pelyzer/recursos/UserDB.TXT"

def extraer_packer(datos_pe):
    packers = []

    with open(USER_DB, 'rt', encoding = "ISO-8859-1") as f:
        archivo_firmas = f.read()

    firmas = peutils.SignatureDatabase(data=archivo_firmas)
    packer_match = firmas.match_all(datos_pe, ep_only = True)
    if packer_match:
        for match in packer_match:
            packers.append(match)

    return len(packers)