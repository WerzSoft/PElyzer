#constantes empleadas en la aplicación

SW_VERSION = "1.0.0"
MODEL_VERSION = "1.0.0"

NOMBRE_APP = "PELyzer"
DESC_APP = "{} permite analizar archivos PE y determinar si son benignos o maliciosos\n" \
                  "empleando algoritmos de machine learning".format(NOMBRE_APP)
EPILOG_APP = "Para más información visitar https://github.com/sknfvjkdnfbkjdfn"


USE_DB = True
USE_DB_AUTH = False

#### A CAMBIAR POR EL USUARIO ####

#IP del host de la base de datos
MONGO_SERVER = "localhost"
#usuario de la base de datos
MONGO_USERNAME = "xxxxxxxx"
#password
MONGO_PASSWORD = "xxxxxxxx"

##################################

MONGO_DB = "tfg"
MONGO_COLLECTION = "samples_data"