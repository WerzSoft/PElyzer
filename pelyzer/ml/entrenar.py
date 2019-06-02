import pandas as pd
from pymongo import MongoClient

from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
import xgboost as xgb

import pelyzer.ml as ml

HOST = "192.168.6.8"
DB = "tfg"
COLLECTION = "samples_data"

def entrenar_XGBoost():

    cliente = MongoClient(HOST, 27017)
    db = cliente[DB]
    coleccion = db[COLLECTION]

    df = pd.DataFrame(list(coleccion.find()))

    matriz_caracteristicas = []
    for indice, fila in df.iterrows():

        datos_pe = ml.vector_caracteristicas(fila, True)
        matriz_caracteristicas.append(datos_pe)

    dataset = pd.DataFrame.from_dict(matriz_caracteristicas, orient='columns')
    dataset.set_index('sha256', inplace=True)

    X = dataset.drop(['sha256', 'malware'], axis=1).values
    y = dataset['malware'].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    del dataset
    del X
    del y
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