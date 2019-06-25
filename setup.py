import os
from setuptools import setup

with open('requirements.txt') as f:
    required = f.read().splitlines()

setup(
    name='PElyzer',
    version='1.0.0',
    packages=['tests', 'pelyzer', 'pelyzer.ml', 'pelyzer.pe', 'pelyzer.utils'],
    url='https://github.com/WerzSoft/PElyzer',
    license='MIT',
    author='David Rodriguez Regueira',
    author_email='werzsoft@gmail.com',
    description='Trabajo Fin de Grado. Machine Learning Aplicado a Ciberseguridad: Detector de Malware',
    requires_python = '>=3.6.0',
    entry_points={
        'console_scripts': [
            'pelyzer=pelyzer.__main__:main',
        ],
    },
    install_requires=required,
)
