import ntpath
import os
import pandas as pd
from sklearn.externals import joblib

import pelyzer.pe as pe
import pelyzer.ml as ml
import pelyzer.utils as utils

import warnings
warnings.filterwarnings("ignore")

def analizar_pe(archivo):
    print("[+]Compilando reglas yara...")
    utils.compilar_yara()
    print("[+]Analizando {}".format(ntpath.basename(archivo)))

    #extraer caracteristicas
    caracteristicas = pe.extraer_caracteristicas_pe(archivo)
    if bool(caracteristicas):
        caracteristicas = ml.vector_caracteristicas(caracteristicas, False)
        caracteristicas = pd.DataFrame.from_dict([caracteristicas], orient='columns')
        caracteristicas = caracteristicas.drop('sha256', axis=1).values
    else:
        return None

    clf = joblib.load(os.path.join(os.path.dirname(os.path.realpath(__file__)),'modelos/modelo_prediccion6.pkl'))
    resultado = clf.predict(caracteristicas)[0]

    return resultado