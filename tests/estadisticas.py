import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
import matplotlib.pyplot as plt
import matplotlib.cm as cm
from mpl_toolkits.mplot3d import Axes3D
import seaborn as sns


datos = pd.read_csv("pelyzer/recursos/dataset.csv")

#visualizacion valores nulos
sns.heatmap(datos.isnull(), cbar=True, cmap="OrRd_r")
plt.title("Nulos heatmap")
plt.savefig("imagenes/nulos_heatmap.png")
plt.clf()

sns.countplot('is_exe', hue='malware', data=datos)
plt.title("Malware por tipo - exe")
plt.savefig("imagenes/tipo_exe.png")
plt.clf()

sns.barplot(x='is_exe', y='malware', data=datos)
plt.ylabel("Índice Malware")
plt.title("Índice de malware por tipo (exe)")
plt.savefig("imagenes/indice_tipo_exe.png")
plt.clf()

sns.countplot('is_dll', hue='malware', data=datos)
plt.title("Malware por tipo - dll")
plt.savefig("imagenes/tipo_dll.png")
plt.clf()

sns.barplot(x='is_dll', y='malware', data=datos)
plt.ylabel("Índice Malware")
plt.title("Índice de malware por tipo (dll)")
plt.savefig("imagenes/indice_tipo_dll.png")
plt.clf()


sns.countplot('is_driver', hue='malware', data=datos)
plt.title("Malware por tipo - driver")
plt.savefig("imagenes/tipo_driver.png")
plt.clf()

sns.barplot(x='is_driver', y='malware', data=datos)
plt.ylabel("Índice Malware")
plt.title("Índice de malware por tipo (driver)")
plt.savefig("imagenes/indice_tipo_driver.png")
plt.clf()


sns.countplot('unk_opcodes', hue='malware', data=datos)
plt.title("Malware por opdcodes desconocidos")
plt.savefig("imagenes/unk_opcodes.png")
plt.clf()

sns.barplot(x='unk_opcodes', y='malware', data=datos)
plt.ylabel("Índice Malware")
plt.title("Índice de malware por opcodes desconocidos")
plt.savefig("imagenes/indice_unk_opcodes.png")
plt.clf()


sns.countplot('n_std_sec', hue='malware', data=datos)
plt.title("Malware por secciones estandar")
plt.savefig("imagenes/secciones_estandar.png")
plt.clf()

sns.barplot(x='n_std_sec', y='malware', data=datos)
plt.ylabel("Índice Malware")
plt.title("Índice de malware por secciones estandar")
plt.savefig("imagenes/indice_secciones_estandar.png")
plt.clf()


sns.countplot('n_susp_sec', hue='malware', data=datos)
plt.title("Malware por secciones sospechosas")
plt.savefig("imagenes/secciones_sospechosas.png")
plt.clf()

sns.barplot(x='n_susp_sec', y='malware', data=datos)
plt.ylabel("Índice Malware")
plt.title("Índice de malware por secciones sospechosas")
plt.savefig("imagenes/indice_secciones_sospechosas.png")
plt.clf()

sns.countplot('checksum_invalido', hue='malware', data=datos)
plt.title("Malware por checksum invalido")
plt.savefig("imagenes/checksum.png")
plt.clf()

sns.barplot(x='checksum_invalido', y='malware', data=datos)
plt.ylabel("Índice Malware")
plt.title("Índice de malware por checksum invalido")
plt.savefig("imagenes/indice_checksum.png")
plt.clf()


sns.countplot('firmado', hue='malware', data=datos)
plt.title("Malware por firma")
plt.savefig("imagenes/firmado.png")
plt.clf()

sns.barplot(x='firmado', y='malware', data=datos)
plt.ylabel("Índice Malware")
plt.title("Índice de malware por firma")
plt.savefig("imagenes/indice_firma.png")
plt.clf()
