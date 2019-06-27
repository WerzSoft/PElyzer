#PElyzer
##Machine Learning aplicado a la ciberseguridad: Detección de Malware

Pelyzer es una herramienta de detección de malware basada en técnicas de machine learning para archivos con formato PE. 
Mediante el código presentado en este repositorio, es posible generar un modelo de predicción capaz de discernir, con
elevada exactitud, si un archivo es malware o no.

#Instalación

PElyzer requiere Python 3, el gestor de paquetes pip y una base de datos mongodb para su correcto funcionamiento.

Una vez estos requisitos se han cumplido, basta con ejecutar el siguiente comando para instalar los paquetes y librerías
necesarias:


```
pip install -r requirements.txt
```

#Uso

Una vez se han instalado los requisitos anteriores, bastará con ejecutar el siguiente código para iniciar la apliación:

```
python pelyzer
```
