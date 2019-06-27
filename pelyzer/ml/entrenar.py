#modulo encargado de entrenar el modelo de predicción empelando como algoritmo XGBoosting
#una vez entrenado, se muestra el scoring resulante y se guarda en formato pickle (propio de sklearn)
#el modelo resultante


import os
import pandas as pd
import numpy as np
from pymongo import MongoClient

from sklearn.model_selection import train_test_split
from sklearn import metrics
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

    print("[+]Generando datasets de entrenamiento y prueba (80%/20%)")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    #borrado de variables no necesarias para ahorrar memoria
    del dataset
    del X
    del y

    print("[+]Entrenando algoritmo XGBoost")

    algoritmo = xgb.XGBClassifier(silent=False,
                                  learning_rate=0.1,
                                  colsample_bytree=0.52,
                                  subsample=0.9500000000000001,
                                  objective='binary:logistic',
                                  n_estimators=2100,
                                  max_depth=28,
                                  gamma=0.76,
                                  min_child_weight=2.0,
                                  n_jobs=-1)

    algoritmo.fit(X_train, y_train)
    predicciones = algoritmo.predict(X_test)

    #calculo de puntuaciones y ratios
    score = algoritmo.score(X_test, y_test)
    accuracy = metrics.accuracy_score(y_test, predicciones)
    precision = metrics.precision_score(y_test, predicciones)
    matriz_confusion = metrics.confusion_matrix(y_test, predicciones)

    TP = matriz_confusion[1, 1]
    TN = matriz_confusion[0, 0]
    FP = matriz_confusion[0, 1]
    FN = matriz_confusion[1, 0]

    FPR = FP / float(TN + FP)
    FNR = FN / float(TP + FN)

    print("[*]El algoritmo se ha entrenado con un scoring del {}%".format((score * 100)))
    print("[*]Ratio de falsos positivos : {} %".format((FPR * 100)))
    print('[*]Ratio de falsos negativos : {} %'.format((FNR * 100)))

    #se guarda el modelo generado en formato pickle en la ruta ml/modelos
    joblib.dump(algoritmo, os.path.join(os.path.dirname(os.path.realpath(__file__)),"modelos/modelo_xgboost.pkl"))
    print("\n[*]Modelo de predicciones generado correctamente")

