##reglas yara obtenidas de https://github.com/Yara-Rules
from pelyzer.utils import cargar_yara

CADENAS_YARA = "pelyzer/recursos/yara/compiladas/cadenas_sospechosas.yar"
URLS_YARA = "pelyzer/recursos/yara/compiladas/urls.yar"
IPS_YARA = "pelyzer/recursos/yara/compiladas/ips.yar"
CAPACIDADES_YARA = "pelyzer/recursos/yara/compiladas/capacidades.yar"
ANTIDEBUG_ANTIVM = "pelyzer/recursos/yara/compiladas/antidebug_antivm.yar"
PEID = "pelyzer/recursos/yara/compiladas/peid.yar"

def extraer_yara(archivo_pe):
    tmp = {}
    sospechosas = []
    urls = []
    ips = []
    capacidades = []
    antidebug_antivm = []
    packers = []

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

    antidebug_antivm_match = cargar_yara(ANTIDEBUG_ANTIVM).match(data=datos_bin)
    # hay mas de una regla en el archivo yara
    if antidebug_antivm_match:
        for match in antidebug_antivm_match:
            for tecnica in match.strings:
                antidebug_antivm.append(tecnica[2])

    # se produce el error porque hay demasiados matches en ciertos archivos al ser un conjunto de reglas muy grande
    #se controla el error y se manda un valor elevado si este se produce
    packers_len = 0
    try:
        packers_match = cargar_yara(PEID).match(data=datos_bin)
        # hay mas de una regla en el archivo yara
        if packers_match:
            for match in packers_match:
                for packer in match.strings:
                    packers.append(packer[2])
        packers_len = len(packers)
    except Exception as e:
        if "internal error: 30" in str(e):
            raise
    else:
        packers_len = 9999


    tmp['cadenas_sospechosas'] = len(sospechosas)
    tmp['URLs'] = len(urls)
    tmp['IPs'] = len(ips)
    tmp['capacidades'] = len(capacidades)
    tmp['antidebug_antivm'] = len(antidebug_antivm)
    tmp['packers'] = packers_len

    return tmp
