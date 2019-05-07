import pefile
import mmap
from collections import *
from capstone import *
import numpy
from sklearn.feature_extraction import FeatureHasher
from pelyzer.utils import tupla_a_str

INSTRUCIONES_x86 = {'mov', 'xchg', 'stc', 'clc', 'cmc', 'std', 'cld', 'sti', 'cli', 'push', 'pushf', 'pusha',
                    'pop', 'popf', 'popa', 'ccombw', 'cwd', 'cwde', 'in', 'out', 'add', 'adc', 'sub', 'sbb',
                    'div', 'idiv', 'mul', 'imul', 'inc', 'dec', 'cmp', 'sal', 'sar', 'rcl', 'rcr', 'rol', 'ror',
                    'neg', 'not', 'and', 'or', 'xor', 'shl', 'shr', 'nop', 'lea', 'int', 'call', 'jmp', 'je',
                    'jz', 'jcxz', 'jp', 'jpe', 'ja', 'jae', 'jb', 'jbe', 'jna', 'jnae', 'jnb', 'jnbe', 'jc',
                    'jnc', 'ret', 'jne', 'jnz', 'jecxz', 'jnp', 'jpo', 'jg', 'jge', 'jl', 'jle', 'jng', 'jnge', 'jnl',
                    'jnle', 'jo', 'jno', 'js', 'jns', 'jns', 'popa', 'rol', 'popf', 'jnz', 'imul', 'lds', 'jna', 'jng',
                    'jno', 'jnl', 'arpl', 'cli', 'cld', 'clc', 'add', 'adc', 'scasd', 'scasb', 'daa', 'mov', 'das', 'nop',
                    'repne', 'jnc', 'cmc', 'leave', 'jmpf', 'cmp', 'hlt', 'loope', 'pusha', 'pushf', 'out', 'xor', 'sub', 'rep',
                    'ret', 'jecxz', 'xchg', 'cwd', 'lea', 'jz', 'jp', 'js', 'jl', 'jo', 'jg', 'ja', 'jc', 'sbb', 'sahf',
                    'stosb', 'movsd', 'movsb', 'les', 'xlat', 'or', 'into', 'bound', 'pop', 'fildl', 'retf', 'retn', 'fadds',
                    'faddl', 'call', 'wait', 'sldt', 'fiaddl', 'jmp', 'int1', 'int3', 'std', 'aad', 'aaa', 'stc', 'aam', 'sti',
                    'aas', 'lahf', 'dec', 'loop', 'and', 'jpo', 'int', 'lock', 'in', 'flds', 'fldl', 'cbw', 'fild', 'inc',
                    'cmpsb', 'callf', 'cmpsd', 'test', 'fiadd', 'stosd', 'insb', 'outsv', 'iret', 'outsb', 'insv', 'loopne',
                    'salc', 'lodsb', 'lodsd', 'enter', 'push'}


def extraer_opcodes(datos_binarios, pe_oh_aoep, pe_oh_ib):
    instrucciones_desconocidas = 0
    try:
        datos_mem = mmap.mmap(datos_binarios.fileno(), 0, access=mmap.ACCESS_READ)
        datos_pe = pefile.PE(data=datos_mem)
    except OSError as e:
        print(e)
        datos_pe = None
    except pefile.PEFormatError as e:
        print("[-] PEFormatError: %s" % e.value)
        datos_pe = None

    pe_dir_entrada = pe_oh_aoep + pe_oh_ib
    codigo_pe = datos_pe.get_memory_mapped_image()[pe_dir_entrada:]
    dissasembler = Cs(CS_ARCH_X86, CS_MODE_32)

    instrucciones = []

    for instruccion in dissasembler.disasm(codigo_pe, pe_dir_entrada):
        if instruccion.mnemonic in INSTRUCIONES_x86:
            instrucciones.append(instruccion.mnemonic)
        else:
            instrucciones_desconocidas += 1

    opngramlist = [tupla_a_str(tuple(instrucciones[i:i + 2])) for i in range(len(instrucciones) - 2)]
    opngram = Counter(opngramlist)

    return dict(opngram), instrucciones_desconocidas
