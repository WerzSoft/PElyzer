import pandas as pd
import numpy as np
from itertools import product

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.gaussian_process import GaussianProcessClassifier
from sklearn.gaussian_process.kernels import RBF
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier, GradientBoostingClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis
from sklearn.metrics import confusion_matrix, mean_squared_error, accuracy_score, precision_recall_curve, roc_curve, roc_auc_score, auc, precision_score
import xgboost as xgb

import seaborn as sns
import matplotlib.pyplot as plt


def ROC(algo, clf, X_test, y_test):
    plt.style.use('ggplot')

    y_predict_probabilities = clf.predict_proba(X_test)[:,1]

    fpr, tpr, _ = roc_curve(y_test, y_predict_probabilities)
    roc_auc = auc(fpr, tpr)

    plt.figure()
    plt.plot(fpr, tpr, color='darkorange',
             lw=2, label='%s (área = %0.4f)' % (algo, roc_auc))
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('Ratio de falsos positivos')
    plt.ylabel('Ratio de verdaderos positivos')
    plt.title('Curva ROC {}'.format(algo))
    plt.legend(loc="lower right")
    plt.savefig('imagenes/{}_roc.png'.format(algo))
    plt.clf()

def CM(algo, cm, clases, fig=None, title='Matriz de Confusión', cmap=plt.get_cmap('Blues')):
    # This function prints and plots the confusion matrix.
    if fig is None:
        fig = plt.imshow(cm, interpolation='nearest', cmap=cmap)
    else:
        plt.imshow(cm, interpolation='nearest', cmap=cmap)

    title = title + ' ' + algo
    plt.title(title)
    plt.colorbar()
    tick_marks = np.arange(len(clases))
    plt.xticks(tick_marks, clases, rotation=45)
    plt.yticks(tick_marks, clases)
    plt.grid(visible=False)

    cm_norm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
    thresh = (cm.max() + cm.min()) / 2

    for i, j in product(range(cm.shape[0]), range(cm.shape[1])):
        plt.text(j, i, '%d\n%.2f%%' % (cm[i, j], cm_norm[i, j] * 100),
                 horizontalalignment='center', color='white' if cm[i, j] > thresh else 'black')

    plt.tight_layout()
    plt.ylabel('Valores Reales')
    plt.xlabel('Predicciones')

    fig.figure.savefig('imagenes/{}_cm.png'.format(algo))
    plt.clf()

dataset = pd.read_csv("pelyzer/recursos/dataset.csv")
#dataset.set_index('sha256', inplace=True)
X = dataset.drop(['sha256', 'malware'], axis=1).values
y = dataset['malware'].values

labels = ['benigno','malware']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

#borramos datasets innecesarios para liberar memoria
del dataset
del X
del y


#Algorithm comparison
algoritmos = {
	"Regresión Logística": LogisticRegression(solver='saga',n_jobs=-1),
	"Vecinos más cercanos": KNeighborsClassifier(5, n_jobs=-1),
	"Árbol de decisión": DecisionTreeClassifier(max_depth=5),
	"Bosque aleatorio": RandomForestClassifier(n_estimators=100, n_jobs=-1),
	"Potenciación del gradiente": GradientBoostingClassifier(n_estimators=100),
	"Red neuronal": MLPClassifier(alpha=0.0001, max_iter=1000),
	"AdaBoost": AdaBoostClassifier(n_estimators=100),
	"Análisis discriminante cuadrático": QuadraticDiscriminantAnalysis(tol=0.000000001),
	"Naive Bayes": GaussianNB(),
	"XGBoost": xgb.XGBClassifier(learning_rate =0.1, n_estimators=1000, max_depth=5, min_child_weight=1, gamma=0, subsample=0.8, colsample_bytree=0.8, objective= 'binary:logistic', n_jobs=-1, scale_pos_weight=1)
    }

results = {}
print("\nTesteando algoritmos de ML")
for algo in algoritmos:
    clf = algoritmos[algo]
    clf.fit(X_train, y_train)
    preds= clf.predict(X_test)

    predictions = [round(value) for value in preds]
    accuracy = accuracy_score(y_test, predictions)
    precision, recall, thresholds = precision_recall_curve(y_test, preds)
    area = auc(recall, precision)
    cm = confusion_matrix(y_test, preds)
    ROC(algo, clf, X_test, y_test)
    CM(algo, cm, labels)

    TP = cm[0][0]
    FP = cm[0][1]
    FN = cm[1][0]
    TN = cm[1][1]


    print("Algoritmo: {}".format(algo))
    print("Precisión: %.2f%%" % (accuracy * 100.0))
    print('Matriz de Confusion: {}'.format(cm))
    print('ROC: {}'.format(roc_auc_score(y_test, preds)))
    print('Area Bajo Curva: {}'.format(area))

    print('Ratio Falsos Positivos: {}%'.format((FP/(FP+TN))*100))
    print('Ratio de Falsos Negativos: {}%'.format((FN/(FN+TP))*100))

    print('\n')
