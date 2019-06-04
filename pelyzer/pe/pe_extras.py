import pefile

def check_checksum(datos_pe):
    sospechoso = False
    informado = hex(datos_pe.OPTIONAL_HEADER.CheckSum)
    actual = hex(datos_pe.generate_checksum())

    if actual != informado:
        sospechoso = True

    return sospechoso

def check_firma(datos_pe):
    try:
        address = datos_pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    except:
        return False

    if address == 0:
        return False

    signature = datos_pe.write()[address + 8:]

    if signature:
        return True
    else:
        return False