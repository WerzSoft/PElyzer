#modulo encargado de extraer características de las cabeceras de las muestras


import pelyzer.utils as utils

# http://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
# secciones más utilizadas
SECCIONES_ESTANDAR = ['.00cfg', '.arch', '.autoload_text', '.bindat', '.bootdat', '.bss', '.BSS', '.buildid',
                      '.CLR_UEF', '.code', '.cormeta', '.complua', '.CRT', '.cygwin_dll_common', '.data', '.DATA',
                      '.data1', '.data2', '.data3', '.debug', '.debug$F', '.debug$P', '.debug$S', '.debug$T',
                      '.drectve', '.didat', '.didata', '.edata', '.eh_fram', '.export', '.fasm', '.flat', '.gfids',
                      '.giats', '.gljmp', '.glue_7t', '.glue_7', '.idata', '.idlsym', '.impdata', '.itext', '.ndata',
                      '.orpc', '.pdata', '.rdata', '.reloc', '.rodata', '.rsrc', '.sbss', '.script', '.shared',
                      '.sdata', '.srdata', '.stab', '.stabstr', '.sxdata', '.text', '.text0', '.text1', '.text2',
                      '.text3', '.textbss', '.tls', '.tls$', '.udata', '.vsdata', '.xdata', '.wixburn', 'BSS', 'CODE',
                      'DATA', 'DGROUP', 'edata', 'idata', 'INIT', 'minATL', 'PAGE', 'rdata', 'sdata', 'shared',
                      'Shared', 'testdata', 'text']


def get_dos_nt_header(datos_pe):
    tmp = dict()
    tmp['e_magic'] = datos_pe.DOS_HEADER.e_magic if hasattr(datos_pe.DOS_HEADER, 'e_magic') else 0
    tmp['e_cblp'] = datos_pe.DOS_HEADER.e_cblp if hasattr(datos_pe.DOS_HEADER, 'e_cblp') else 0
    tmp['e_cp'] = datos_pe.DOS_HEADER.e_cp if hasattr(datos_pe.DOS_HEADER, 'e_cp') else 0
    tmp['e_crlc'] = datos_pe.DOS_HEADER.e_crlc if hasattr(datos_pe.DOS_HEADER, 'e_crlc') else 0
    tmp['e_cparhdr'] = datos_pe.DOS_HEADER.e_cparhdr if hasattr(datos_pe.DOS_HEADER, 'e_cparhdr') else 0
    tmp['e_minalloc'] = datos_pe.DOS_HEADER.e_minalloc if hasattr(datos_pe.DOS_HEADER, 'e_minalloc') else 0
    tmp['e_maxalloc'] = datos_pe.DOS_HEADER.e_maxalloc if hasattr(datos_pe.DOS_HEADER, 'e_maxalloc') else 0
    tmp['e_ss'] = datos_pe.DOS_HEADER.e_ss if hasattr(datos_pe.DOS_HEADER, 'e_ss') else 0
    tmp['e_sp'] = datos_pe.DOS_HEADER.e_sp if hasattr(datos_pe.DOS_HEADER, 'e_sp') else 0
    tmp['e_csum'] = datos_pe.DOS_HEADER.e_csum if hasattr(datos_pe.DOS_HEADER, 'e_csum') else 0
    tmp['e_ip'] = datos_pe.DOS_HEADER.e_ip if hasattr(datos_pe.DOS_HEADER, 'e_ip') else 0
    tmp['e_cs'] = datos_pe.DOS_HEADER.e_cs if hasattr(datos_pe.DOS_HEADER, 'e_cs') else 0
    tmp['e_lfarlc'] = datos_pe.DOS_HEADER.e_lfarlc if hasattr(datos_pe.DOS_HEADER, 'e_lfarlc') else 0
    tmp['e_ovno'] = datos_pe.DOS_HEADER.e_ovno if hasattr(datos_pe.DOS_HEADER, 'e_ovno') else 0
    #tmp['e_res'] = int.from_bytes(datos_pe.DOS_HEADER.e_res, byteorder='little') if hasattr(datos_pe.DOS_HEADER, 'e_res') else 0
    tmp['e_oemid'] = datos_pe.DOS_HEADER.e_oemid if hasattr(datos_pe.DOS_HEADER, 'e_oemid') else 0
    tmp['e_oeminfo'] = datos_pe.DOS_HEADER.e_oeminfo if hasattr(datos_pe.DOS_HEADER, 'e_oeminfo') else 0
    #tmp['e_res2'] = int.from_bytes(datos_pe.DOS_HEADER.e_res2, byteorder='little') if hasattr(datos_pe.DOS_HEADER, 'e_res2') else 0
    tmp['e_lfanew'] = datos_pe.DOS_HEADER.e_lfanew if hasattr(datos_pe.DOS_HEADER, 'e_lfanew') else 0
    tmp['nt_signature'] = datos_pe.NT_HEADERS.Signature if hasattr(datos_pe.NT_HEADERS, 'Signature') else 0

    # convetir todos los valores a float
    tmp = utils.valores_dict_to_float(tmp)

    return tmp


def get_file_header(datos_pe):
    tmp = dict()
    tmp['Machine'] = datos_pe.FILE_HEADER.Machine if hasattr(datos_pe.FILE_HEADER, 'Machine') else 0
    tmp['NumberOfSections'] = datos_pe.FILE_HEADER.NumberOfSections if hasattr(datos_pe.FILE_HEADER, 'NumberOfSections') else 0
    tmp['TimeDateStamp'] = datos_pe.FILE_HEADER.TimeDateStamp if hasattr(datos_pe.FILE_HEADER, 'TimeDateStamp') else 0
    tmp['PointerToSymbolTable'] = datos_pe.FILE_HEADER.PointerToSymbolTable if hasattr(datos_pe.FILE_HEADER, 'PointerToSymbolTable') else 0
    tmp['NumberOfsymbols'] = datos_pe.FILE_HEADER.NumberOfsymbols if hasattr(datos_pe.FILE_HEADER, 'NumberOfsymbols') else 0
    tmp['SizeOfOptionalHeader'] = datos_pe.FILE_HEADER.SizeOfOptionalHeader if hasattr(datos_pe.FILE_HEADER, 'SizeOfOptionalHeader') else 0
    tmp['Characteristics'] = datos_pe.FILE_HEADER.Characteristics if hasattr(datos_pe.FILE_HEADER, 'Characteristics') else 0

    # convetir todos los valores a float
    tmp = utils.valores_dict_to_float(tmp)

    return tmp


def get_optional_header(datos_pe):
    tmp = dict()

    tmp['Magic'] = datos_pe.OPTIONAL_HEADER.Magic if hasattr(datos_pe.OPTIONAL_HEADER.Magic, 'Magic') else 0
    tmp['MajorLinkerVersion'] = datos_pe.OPTIONAL_HEADER.MajorLinkerVersion if hasattr(datos_pe.OPTIONAL_HEADER, 'MajorLinkerVersion') else 0
    tmp['MinorLinkerVersion'] = datos_pe.OPTIONAL_HEADER.MinorLinkerVersion if hasattr(datos_pe.OPTIONAL_HEADER, 'MinorLinkerVersion') else 0
    tmp['SizeOfCode'] = datos_pe.OPTIONAL_HEADER.SizeOfCode if hasattr(datos_pe.OPTIONAL_HEADER, 'SizeOfCode') else 0
    tmp['SizeOfInitializedData'] = datos_pe.OPTIONAL_HEADER.SizeOfInitializedData if hasattr(datos_pe.OPTIONAL_HEADER, 'SizeOfInitializedData') else 0
    tmp['SizeOfUninitializedData'] = datos_pe.OPTIONAL_HEADER.SizeOfUninitializedData if hasattr(datos_pe.OPTIONAL_HEADER, 'SizeOfUninitializedData') else 0
    tmp['AddressOfEntryPoint'] = datos_pe.OPTIONAL_HEADER.AddressOfEntryPoint if hasattr(datos_pe.OPTIONAL_HEADER, 'AddressOfEntryPoint') else 0
    tmp['BaseOfCode'] = datos_pe.OPTIONAL_HEADER.BaseOfCode if hasattr(datos_pe.OPTIONAL_HEADER, 'BaseOfCode') else 0
    tmp['BaseOfData'] = datos_pe.OPTIONAL_HEADER.BaseOfData if hasattr(datos_pe.OPTIONAL_HEADER, 'BaseOfData') else 0
    tmp['ImageBase'] = datos_pe.OPTIONAL_HEADER.ImageBase if hasattr(datos_pe.OPTIONAL_HEADER, 'ImageBase') else 0x40000 #ver trello
    tmp['SectionAlignment'] = datos_pe.OPTIONAL_HEADER.SectionAlignment if hasattr(datos_pe.OPTIONAL_HEADER, 'SectionAlignment') else 0
    tmp['FileAlignment'] = datos_pe.OPTIONAL_HEADER.FileAlignment if hasattr(datos_pe.OPTIONAL_HEADER, 'FileAlignment') else 0
    tmp['MajorOperatingSystemVersion'] = datos_pe.OPTIONAL_HEADER.MajorOperatingSystemVersion if hasattr(datos_pe.OPTIONAL_HEADER, 'MajorOperatingSystemVersion') else 0
    tmp['MinorOperatingSystemVersion'] = datos_pe.OPTIONAL_HEADER.MinorOperatingSystemVersion if hasattr(datos_pe.OPTIONAL_HEADER, 'MinorOperatingSystemVersion') else 0
    tmp['MajorImageVersion'] = datos_pe.OPTIONAL_HEADER.MajorImageVersion if hasattr(datos_pe.OPTIONAL_HEADER, 'MajorImageVersion') else 0
    tmp['MinorImageVersion'] = datos_pe.OPTIONAL_HEADER.MinorImageVersion if hasattr(datos_pe.OPTIONAL_HEADER, 'MinorImageVersion') else 0
    tmp['MajorSubsystemVersion'] = datos_pe.OPTIONAL_HEADER.MajorSubsystemVersion if hasattr(datos_pe.OPTIONAL_HEADER, 'MajorSubsystemVersion') else 0
    tmp['MinorSubsystemVersion'] = datos_pe.OPTIONAL_HEADER.MinorSubsystemVersion if hasattr(datos_pe.OPTIONAL_HEADER, 'MinorSubsystemVersion') else 0
    tmp['Reserved1'] = datos_pe.OPTIONAL_HEADER.Reserved1 if hasattr(datos_pe.OPTIONAL_HEADER, 'Reserved1') else 0
    tmp['SizeOfImage'] = datos_pe.OPTIONAL_HEADER.SizeOfImage if hasattr(datos_pe.OPTIONAL_HEADER, 'SizeOfImage') else 0
    tmp['SizeOfHeaders'] = datos_pe.OPTIONAL_HEADER.SizeOfHeaders if hasattr(datos_pe.OPTIONAL_HEADER, 'SizeOfHeaders') else 0
    tmp['CheckSum'] = datos_pe.OPTIONAL_HEADER.CheckSum if hasattr(datos_pe.OPTIONAL_HEADER, 'CheckSum') else 0
    tmp['Subsystem'] = datos_pe.OPTIONAL_HEADER.Subsystem if hasattr(datos_pe.OPTIONAL_HEADER, 'Subsystem') else 0
    tmp['DllCharacteristics'] = datos_pe.OPTIONAL_HEADER.DllCharacteristics if hasattr(datos_pe.OPTIONAL_HEADER, 'DllCharacteristics') else 0
    tmp['SizeOfStackReserve'] = datos_pe.OPTIONAL_HEADER.SizeOfStackReserve if hasattr(datos_pe.OPTIONAL_HEADER, 'SizeOfStackReserve') else 0
    tmp['SizeOfStackCommit'] = datos_pe.OPTIONAL_HEADER.SizeOfStackCommit if hasattr(datos_pe.OPTIONAL_HEADER, 'SizeOfStackCommit') else 0
    tmp['SizeOfHeapReserve'] = datos_pe.OPTIONAL_HEADER.SizeOfHeapReserve if hasattr(datos_pe.OPTIONAL_HEADER, 'SizeOfHeapReserve') else 0
    tmp['SizeOfHeapCommit'] = datos_pe.OPTIONAL_HEADER.SizeOfHeapCommit if hasattr(datos_pe.OPTIONAL_HEADER, 'SizeOfHeapCommit') else 0
    tmp['LoaderFlags'] = datos_pe.OPTIONAL_HEADER.LoaderFlags if hasattr(datos_pe.OPTIONAL_HEADER, 'LoaderFlags') else 0
    tmp['NumberOfRvaAndSizes'] = datos_pe.OPTIONAL_HEADER.NumberOfRvaAndSizes if hasattr(datos_pe.OPTIONAL_HEADER, 'NumberOfRvaAndSizes') else 0

    # convetir todos los valores a float
    tmp = utils.valores_dict_to_float(tmp)

    return tmp


def get_pe_sections(datos_pe):
    tmp = dict()
    tmp['sections'] = []
    num_secciones_estandar = 0
    num_secciones_sospechosas = 0

    try:
        for seccion in datos_pe.sections:
            aux = {}
            nombre_seccion = seccion.Name.split(b'\x00')[0].decode('utf-8')
            if nombre_seccion in SECCIONES_ESTANDAR:
                num_secciones_estandar += 1
            else:
                num_secciones_sospechosas += 1

            aux['name'] = nombre_seccion
            aux['s_size'] = seccion.SizeOfRawData
            aux['s_vsize'] = seccion.Misc_VirtualSize
            aux['s_entropy'] = seccion.get_entropy()
            aux['s_isExecutable'] = True if seccion.Characteristics & 0x00000020 > 0 or seccion.Characteristics & 0x20000000 > 0 else False
            aux['s_isWritable'] = True if seccion.Characteristics & 0x80000000 > 0 else False
            aux['s_isReadable'] = True if seccion.Characteristics & 0x40000000 > 0 else False

            tmp['sections'].append(aux)
    except:
        pass

    tmp['n_std_sec'] = num_secciones_estandar
    tmp['n_susp_sec'] = num_secciones_sospechosas

    return tmp


def get_pe_imports(datos_pe):
    tmp = dict()

    if hasattr(datos_pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry_import in datos_pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry_import.dll.decode('UTF-8').replace('.','_')
            if dll_name not in tmp:
                tmp[dll_name] = []

            for func in entry_import.imports:
                if func.name is not None:
                    tmp[dll_name].append(func.name.decode('UTF-8'))

    return tmp


def get_pe_exports(datos_pe):
    tmp = []

    if hasattr(datos_pe, "DIRECTORY_ENTRY_EXPORT"):
        for entry_export in datos_pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if entry_export.name is not None:
                tmp.append(entry_export.name.decode('UTF-8'))
    return tmp


def extraer_cabecera(datos_pe):
    datos_cabecera = dict()

    datos_cabecera['dos_nt_header'] = get_dos_nt_header(datos_pe)
    datos_cabecera['file_header'] = get_file_header(datos_pe)
    datos_cabecera['optional_header'] = get_optional_header(datos_pe)
    datos_cabecera['sections'] = get_pe_sections(datos_pe)
    datos_cabecera['imports'] = get_pe_imports(datos_pe)
    datos_cabecera['exports'] = get_pe_exports(datos_pe)

    return datos_cabecera
