#este mnódulo inicializa algunas características necesarios para la aplicación, como las reglas YARA.
#También comprueba que la base de datos esté activa

import pelyzer.utils as utils
import pelyzer.utils.config as config


def inicializar():
    print("Versión Software: {}".format(config.SW_VERSION))
    print("Versión modelo predicciones: {}".format(config.MODEL_VERSION))

    yara = utils.compilar_yara()
    print("Reglas YARA cargadas: {}".format(yara))

    mongo_db = utils.comprobar_db()
    if not mongo_db:
        print("BASE DE DATOS NO DISPONIBLE!!!")
