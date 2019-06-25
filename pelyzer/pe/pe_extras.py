#modulo encargado de extraer características adicionales de las muestras

import pefile

#comprueba que el checksum registrado en la cabecera de los archivos PE coincide con el checksum calculado
def check_checksum(datos_pe):
    sospechoso = False
    informado = hex(datos_pe.OPTIONAL_HEADER.CheckSum)
    actual = hex(datos_pe.generate_checksum())

    if actual != informado:
        sospechoso = True

    return sospechoso


#comprueba si el archivo PE está firmado
def check_firma(datos_pe):
    try:
        direccion_firma = datos_pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    except:
        return False

    if direccion_firma == 0:
        return False

    firma = datos_pe.write()[direccion_firma + 8:]

    if firma:
        return True
    else:
        return False