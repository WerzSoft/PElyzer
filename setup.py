from setuptools import setup

setup(
    name='PElyzer',
    version='0.0.1',
    packages=['tests', 'pelyzer', 'pelyzer.pe'],
    entry_points={
        'console_scripts': ['pelyzer = pelyzer.app:run']
    },
    url='xxxxxx',
    license='MIT',
    author='David Rodriguez Regueira',
    author_email='david.rodriguez.regueira@alumnos.ui1.es',
    description='Trabajo Fin de Grado - Machine Learning aplicado a ciberseguridad: Detector de Malware'
)
