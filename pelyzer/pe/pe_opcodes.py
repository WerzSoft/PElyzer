#modulo encargado de extraer características del código máquina de las muestras


from collections import *
from capstone import *
import pelyzer.utils as utils

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


def extraer_opcodes(datos_pe):
    instrucciones_desconocidas = 0

    try:
        eop = datos_pe.OPTIONAL_HEADER.AddressOfEntryPoint
        seccion_code = datos_pe.get_section_by_rva(eop)

        dump_code = seccion_code.get_data()
        dir_code = datos_pe.OPTIONAL_HEADER.ImageBase + seccion_code.VirtualAddress

        dissasembler = Cs(CS_ARCH_X86, CS_MODE_32)

        instrucciones = []

        for instruccion in dissasembler.disasm(dump_code, dir_code):
            if instruccion.mnemonic in INSTRUCIONES_x86:
                instrucciones.append(instruccion.mnemonic)
            else:
                instrucciones_desconocidas += 1

        opngramlist = [utils.tupla_a_str(tuple(instrucciones[i:i + 2])) for i in range(len(instrucciones) - 2)]
        opngram = dict(Counter(opngramlist))
    except:
        #añadir algun tipo de log
        opngram = dict()

    return opngram, instrucciones_desconocidas
