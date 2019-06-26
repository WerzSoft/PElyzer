#modulo encargado de realizar el análisis sobre archivos y procesar los resultados en base al modelo de predicción
#previamente entrenado


import ntpath
import os
import pandas as pd
from sklearn.externals import joblib

import pe as pe
import ml as ml


def analizar_pe(archivo):
    print("[+]Analizando {}".format(ntpath.basename(archivo)))

    #extraer caracteristicas
    caracteristicas = pe.extraer_caracteristicas_pe(archivo)
    if bool(caracteristicas):
        caracteristicas = ml.vector_caracteristicas(caracteristicas, False)
        caracteristicas = pd.DataFrame.from_dict([caracteristicas], orient='columns')
        caracteristicas = caracteristicas.drop('sha256', axis=1).values
    else:
        return None, None

    clf = joblib.load(os.path.join(os.path.dirname(os.path.realpath(__file__)),'modelos\\modelo_xgboost.pkl'))
    resultado = clf.predict(caracteristicas)[0]

    if resultado == 1:
        proba = clf.predict_proba(caracteristicas)[:,1][0]
    else:
        proba = clf.predict_proba(caracteristicas)[:, 0][0]

    return resultado, proba