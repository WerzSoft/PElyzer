#modulo encargado de entrenar el modelo de predicción empelando como algoritmo XGBoosting
#una vez entrenado, se muestra el scoring resulante y se guarda en formato pickle (propio de sklearn)
#el modelo resultante


import os
import pandas as pd
from pymongo import MongoClient

from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
from sklearn.externals import joblib
import xgboost as xgb

import ml as ml
import utils as utils
import utils.config as config

def entrenar_XGBoost():
    print("[+]Leyendo base de datos")
    cliente = utils.conectar_db()
    db = cliente[config.MONGO_DB]
    coleccion = db[config.MONGO_COLLECTION]

    df = pd.DataFrame(list(coleccion.find()))

    print("[+]Pre-procesando datos")

    matriz_caracteristicas = []
    for indice, fila in df.iterrows():

        datos_pe = ml.vector_caracteristicas(fila, True)
        matriz_caracteristicas.append(datos_pe)

    dataset = pd.DataFrame.from_dict(matriz_caracteristicas, orient='columns')
    dataset.set_index('sha256', inplace=True)

    #se guarda el dataset en formato csv para futuras pruebas y generación de estadísticas
    dataset.to_csv("pelyzer/recursos/dataset.csv")
    del dataset

    dataset = pd.read_csv("pelyzer/recursos/dataset.csv")
    X = dataset.drop(['sha256', 'malware'], axis=1).values
    y = dataset['malware'].values

    print("[+]Generando datasets de entrenamiento y prueba (80%%//20%%)")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    #borrado de variables no necesarias para ahorrar memoria
    del dataset
    del X
    del y

    print("[+]Entrenando algoritmo XGBoost")

    algoritmo = xgb.XGBClassifier(silent=False,
                                  learning_rate=0.19,
                                  colsample_bytree=0.53,
                                  subsample=1.0,
                                  objective='binary:logistic',
                                  n_estimators=5400,
                                  max_depth=8,
                                  gamma=0.59,
                                  min_child_weight=6.0,
                                  n_jobs=-1)

    algoritmo.fit(X_train, y_train)
    score = algoritmo.score(X_test, y_test)
    res = algoritmo.predict(X_test)
    mt = confusion_matrix(y_test, res)
    print("[*]El algoritmo se ha entrenado con un scoring del {} %".format(score * 100))
    print("[*]Ratio de falsos positivos : {} %".format((mt[0][1] / float(sum(mt[0]))) * 100))
    print('[*]Ratio de falsos negativos : {} %'.format((mt[1][0] / float(sum(mt[1]))) * 100))

    #se guarda el modelo generado en formato pickle en la ruta ml/modelos
    joblib.dump(algoritmo, os.path.join(os.path.dirname(os.path.realpath(__file__)),"modelos/modelo_xgboost.pkl"))
    print("\n[*]Modelo de predicciones generado correctamente")

