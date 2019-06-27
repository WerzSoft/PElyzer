import pelyzer.pe.pe_caracteristicas as cars
import pelyzer.utils as utils
from tqdm import tqdm
from functools import partial
from multiprocessing import Pool


dir = "/datos/Downloads/clean_hashed"

print("[+]Compilando reglas yara...")
utils.compilar_yara()
print("[+]Listando archivos....")
muestras = cars.get_samples(dir)

total = len(muestras)

print("[+]Analizando {} samples...".format(total))

sub = partial(cars.extraer_y_almacenar, 0)

print("[*]Usando {} Cores".format(20))

with Pool(processes=20) as p:
    with tqdm(total=total, desc='[*]Analizando archivos', position=0) as pbar:
        for i, _ in tqdm(enumerate(p.imap_unordered(sub, muestras))):
            pbar.update()
