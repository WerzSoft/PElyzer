#Este módulo maneja el punto de entrada de la aplicación,
#mostrando la interfaz de usuario via CLI y llamando a las
#distintas funciones necesarias para su funcionamiento


from art import *
from colorama import init,Fore, Back, Style
import click
import pe
import ml
import time
import utils
import utils.config as config


#mostrar ayuda y versión de la aplicación
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version=config.SW_VERSION)
def cli():
    pass


#analizar ficheros o directorios. Si se pasa como parámetro un directorio, busca recursivamente
#todos los ficheros en el mismo. Se recomienda
#realizar este proceso en una máquina con los recursos hardware apropiados.
@cli.command()
@click.argument('ruta', metavar="archivo/directorio", required=True, type=click.Path(exists=True))
def analizar(ruta):
    """Analizar archivos o carpetas"""
    t0 = time.time()
    if os.path.isdir(ruta):
        ml.analizar_directorio(ruta)
    else:
        ml.analizar_archivo(ruta)
    t1 = time.time()
    print("\n\n[+]Proceso finalizado en {} segundos".format(t1 - t0))


#extrae las caracteristicas de las muestras de malware y goodware existentes, almacenándolas en una base
#de datos mongodb
@cli.command()
@click.option('--malwareDir', required=True, metavar="<dir>", help="Directorio con muestras de malware")
@click.option('--goodwareDir', required=True, metavar="<dir>", help="Directorio con muestras benignas")
def procesar(malwaredir: str, goodwaredir: str):
    """Procesa los samples disponibles"""
    if utils.comprobar_db():
        pe.procesar_samples(malwaredir, goodwaredir)
    else:
        utils.mostrar_mensaje("rojo", "Error: Base de datos no disponible.")


#entrena el modelo de machine learning por medio del algoritmo XGBoost, cogiendo los datos de la base de datos
#previamene creada y almacenando el modelo en formato binario para su posterior utilización. Se recomienda
#realizar este proceso en una máquina con los recursos hardware apropiados.
@cli.command()
def entrenar():
    """Entrena el algoritmo de ML (XGBoost)"""
    #si no está disponible la base de datos no se inicia el proceso
    if utils.comprobar_db():
        if not utils.db_vacia():
            ml.entrenar_XGBoost()
        else:
            utils.mostrar_mensaje("rojo", "Error: Debe procesar primero las muestras")
    else:
        utils.mostrar_mensaje("rojo", "Error: Base de datos no disponible.")


#muestra el cli al usuario
def run():
    init()
    logo = text2art(config.NOMBRE_APP, font="alligator2")
    print(Fore.GREEN+logo)
    print(Fore.LIGHTBLUE_EX+"Machine Learning Aplicado a Ciberseguridad: Detector de Malware\n")
    print(Fore.BLUE + "Trabajo Fin de Grado")
    print(Fore.BLUE + "David Rodríguez Regueira\n")
    print("##################################################################################")
    print(Fore.YELLOW)
    utils.inicializar()
    print(Fore.BLUE)
    print("##################################################################################\n")
    print(Style.RESET_ALL)

    cli()