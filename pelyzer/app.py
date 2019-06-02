from art import *
from colorama import init,Fore, Back, Style
import click
import pelyzer.pe as pe
import pelyzer.ml as ml
import time

nombre_app = "PElyzer"
descripcion_app = "{} permite analizar archivos PE y determinar si son benignos o maliciosos\n" \
                  "empleando algoritmos de machine learning".format(nombre_app)
epilog_app = "Para más información visitar https://github.com/sknfvjkdnfbkjdfn"

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version='0.0.1')
def cli():
    pass

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


@cli.command()
@click.option('--malwareDir', required=True, metavar="<dir>", help="Directorio con muestras de malware")
@click.option('--goodwareDir', required=True, metavar="<dir>", help="Directorio con muestras benignas")
def procesar(malwaredir: str, goodwaredir: str):
    """Procesa los samples disponibles"""
    pe.procesar_samples(malwaredir, goodwaredir)


@cli.command()
def entrenar():
    """Entrena el algoritmo de ML (XGBoost)"""
    ml.entrenar_XGBoost()


def run():
    init()
    logo = text2art("PELyzer", font="alligator2")
    print(Fore.GREEN+logo)
    print(Fore.LIGHTBLUE_EX+"Machine Learning Aplicado a Ciberseguridad: Detector de Malware\n")
    print(Fore.BLUE + "Trabajo Fin de Grado")
    print(Fore.BLUE + "David Rodríguez Regueira\n")
    print("##################################################################################\n")
    print(Style.RESET_ALL)

    cli()