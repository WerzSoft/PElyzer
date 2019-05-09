from pymongo import MongoClient
import pandas as pd
import sklearn.ensemble as ske
from sklearn.feature_selection import SelectFromModel
from sklearn.model_selection import train_test_split
import numpy as np

import pickle
from sklearn import tree, linear_model
from sklearn.feature_selection import SelectFromModel
from sklearn.externals import joblib
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import confusion_matrix


def procesar_dos_nt_header(dos_nt_header):
    return np.hstack([dos_nt_header['e_magic'],
        dos_nt_header['e_cblp'],
        dos_nt_header['e_cp'],
        dos_nt_header['e_crlc'],
        dos_nt_header['e_cparhdr'],
        dos_nt_header['e_minalloc'],
        dos_nt_header['e_maxalloc'],
        dos_nt_header['e_ss'],
        dos_nt_header['e_sp'],
        dos_nt_header['e_csum'],
        dos_nt_header['e_ip'],
        dos_nt_header['e_cs'],
        dos_nt_header['e_lfarlc'],
        dos_nt_header['e_ovno'],
        dos_nt_header['e_oemid'],
        dos_nt_header['e_oeminfo'],
        dos_nt_header['e_lfanew'],
        dos_nt_header['nt_signature']]).astype(np.float32)

def procesar_file_header():
    pass

def procesar_optional_header():
    pass

def procesar_sections():
    pass

def procesar_imports():
    pass

def procesar_exports():
    pass


def procesar_pe_header(pe_header):
    print(procesar_dos_nt_header(pe_header['dos_nt_header']))
    procesar_file_header()
    procesar_optional_header()
    procesar_sections()
    procesar_imports()
    procesar_exports()

cliente = MongoClient('127.0.0.1', 27017)
db = cliente['tfg']
coleccion = db['samples_data']

df = pd.DataFrame(list(coleccion.find()))

for indice, fila in df.iterrows():
    sha = fila['sha256']
    pe_header = fila['pe_header']
    opcodes = fila['opcodes']
    unk_opcodes = fila['unk_opcodes']
    cadenas = fila['cadenas']
    packers = fila['packers']

    procesar_pe_header(pe_header)
