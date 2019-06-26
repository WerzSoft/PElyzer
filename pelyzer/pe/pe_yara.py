#modulo encargado de extraer características a través de la búsqueda de patrones mediante reglas YARA pre-compiladas


#reglas yara obtenidas de https://github.com/Yara-Rules
from utils import cargar_yara

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
    packers_len = 0

    #pefile_bin = open(archivo_pe, "rb")
    #datos_bin = pefile_bin.read()

    for cadenas_match in cargar_yara(CADENAS_YARA).match(archivo_pe):
        if type(cadenas_match) is list:
            sospechosas.append(cadenas_match[0])
        else:
            sospechosas.append(cadenas_match)

    for urls_match in cargar_yara(URLS_YARA).match(archivo_pe):
        if type(urls_match) is list:
            urls.append(urls_match[0])
        else:
            urls.append(urls_match)

    for ips_match in cargar_yara(IPS_YARA).match(archivo_pe):
        if type(ips_match) is list:
            ips.append(ips_match[0])
        else:
            ips.append(ips_match)

    for capacidades_match in cargar_yara(CAPACIDADES_YARA).match(archivo_pe):
        if type(capacidades_match) is list:
            capacidades.append(capacidades_match[0])
        else:
            capacidades.append(capacidades_match)

    for antidebug_antivm_match in cargar_yara(ANTIDEBUG_ANTIVM).match(archivo_pe):
        if type(antidebug_antivm_match) is list:
            antidebug_antivm.append(antidebug_antivm_match[0])
        else:
            antidebug_antivm.append(antidebug_antivm_match)

    #estas reglas producen muchos matches en algunos archivos, por lo que se ha de crear un manejador de errores
    try:
        for packers_match in cargar_yara(PEID).match(archivo_pe):
            if type(packers_match) is list:
                packers.append(packers_match[0])
            else:
                packers.append(packers_match)
        packers_len = len(packers)
    except Exception as e:
        #el error en cuestión produce el mensaje internal error: 30
        if str(e) != "internal error: 30":
            raise
        else:
            #introducir log en versiones futuras
            #si se produce un error se introduce un numero de packers elevado para subsanar el error
            packers_len = 99



    tmp['cadenas_sospechosas'] = len(sospechosas)
    tmp['URLs'] = len(urls)
    tmp['IPs'] = len(ips)
    tmp['capacidades'] = len(capacidades)
    tmp['antidebug_antivm'] = len(antidebug_antivm)
    tmp['packers'] = packers_len

    return tmp
