##reglas yara obtenidas de https://github.com/Yara-Rules
from pelyzer.utils import cargar_yara

CADENAS_YARA = "pelyzer/recursos/yara/compiladas/cadenas_sospechosas.yar"
URLS_YARA = "pelyzer/recursos/yara/compiladas/urls.yar"
IPS_YARA = "pelyzer/recursos/yara/compiladas/ips.yar"
CAPACIDADES_YARA = "pelyzer/recursos/yara/compiladas/capacidades.yar"

def extraer_cadenas(archivo_pe):
    tmp = {}
    sospechosas = []
    urls = []
    ips = []
    capacidades = []

    pefile_bin = open(archivo_pe, "rb")
    datos_bin = pefile_bin.read()

    cadenas_match = cargar_yara(CADENAS_YARA).match(data=datos_bin)
    # hay mas de una regla en el archivo yara
    if cadenas_match:
        for match in cadenas_match:
            for cadena in match.strings:
                sospechosas.append(cadena[2])

    urls_match = cargar_yara(URLS_YARA).match(data=datos_bin)
    if urls_match:
        for url in urls_match[0].strings:
            urls.append(url[2])

    ips_match = cargar_yara(IPS_YARA).match(data=datos_bin)
    if ips_match:
        for ip in ips_match[0].strings:
            ips.append(ip[2])

    capacidades_match = cargar_yara(CAPACIDADES_YARA).match(data=datos_bin)
    #hay mas de una regla en el archivo yara
    if capacidades_match:
        for match in capacidades_match:
            for capacidad in match.strings:
                capacidades.append(capacidad[2])

    tmp['sospechosas'] = len(sospechosas)
    tmp['URLs'] = len(urls)
    tmp['IPs'] = len(ips)
    tmp['capacidades'] = len(capacidades)

    return tmp
