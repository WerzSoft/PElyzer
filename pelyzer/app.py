from art import *
from colorama import init,Fore, Back, Style
import click
from .pe import analizar_archivo
from .pe import entrenar_algoritmo

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
@click.argument('PEFile', metavar="PEFile", required=True)
def analizar(file):
    """Analiza un archivo PE"""
    print(file)

@cli.command()
@click.option('--malwareDir', required=True, metavar="<dir>", help="Directorio con muestras de malware")
@click.option('--goodwareDir', required=True, metavar="<dir>", help="Directorio con muestras benignas")
def entrenar(malwaredir: str, goodwaredir: str):
    """Entrena el algoritmo de ML"""
    entrenar_algoritmo(malwaredir, goodwaredir)


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