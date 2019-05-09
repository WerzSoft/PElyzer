import os
import yara

def valores_dict_to_float(dic):
    return dict((clave, float(valor)) for clave, valor in dic.items())

def tupla_a_str(tupla):
    str = '-'.join(tupla)
    return str

def cargar_yara(archivo_yara):
    return yara.load(archivo_yara)

def compilar_yara():
    for regla in os.listdir("pelyzer/recursos/yara/reglas"):
        regla_compilada = yara.compile("pelyzer/recursos/yara/reglas/" + regla)
        regla_compilada.save("pelyzer/recursos/yara/compiladas/" + regla)