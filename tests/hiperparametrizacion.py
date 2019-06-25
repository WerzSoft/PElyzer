import pandas as pd, numpy as np
from sklearn.metrics import roc_auc_score
import xgboost as xgb
from hyperopt import hp, fmin, tpe, STATUS_OK, Trials
from sklearn.model_selection import train_test_split


dataset = pd.read_csv("dataset.csv")
X = dataset.drop(['sha256','malware'], axis=1).values
y = dataset['malware'].values
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

def objective(space):

    clf = xgb.XGBClassifier(n_jobs=-1,
							n_estimators=int(space['n_estimators']),
							learning_rate=space['learning_rate'],
                            max_depth=int(space['max_depth']),
                            min_child_weight=int(space['min_child_weight']),
                            subsample=space['subsample'],
							gamma=space['gamma'],
							colsample_bytree=space['colsample_bytree']
							)

    eval_set  = [( X_train, y_train), (X_test, y_test)]

    clf.fit(X_train, y_train,
            eval_set=eval_set, eval_metric="auc",
            early_stopping_rounds=30)

    pred = clf.predict_proba(X_test)[:,1]
    auc = roc_auc_score(y_test, pred)
    print("SCORE:", auc)

    return{'loss':1-auc, 'status': STATUS_OK }


space ={
		'n_estimators' : hp.quniform('n_estimators', 100, 10000, 50),
		'learning_rate' : hp.quniform('learning_rate', 0.01, 0.1, 0.01),
        'max_depth' : hp.quniform('max_depth', 1, 30, 1),
        'min_child_weight': hp.quniform ('min_child_weight', 1, 30, 1),
        'subsample': hp.quniform('subsample', 0, 1, 0.01),
		'gamma' : hp.quniform('gamma', 0, 5, 0.01),
        'colsample_bytree' : hp.quniform('colsample_bytree', 0.1, 1, 0.01)
    }


trials = Trials()
best = fmin(fn=objective,
            space=space,
            algo=tpe.suggest,
            max_evals=200,
            trials=trials)

print(best)
