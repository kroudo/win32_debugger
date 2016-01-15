import pefile
import sys
import os
import string
from shutil import *
from ctypes import *
from capstone import *
import struct

CP_HANDLER = WINFUNCTYPE(None, c_uint, c_uint)
LOAD_DLL_HANDLER = WINFUNCTYPE(None, c_char_p, c_uint, c_uint,c_uint,c_uint)
BP_HANDLER = WINFUNCTYPE(c_int, c_uint,c_uint)
CT_HANDLER = WINFUNCTYPE(c_int, c_uint,c_uint)
SS_HANDLER = WINFUNCTYPE(c_int, c_uint,POINTER(c_ubyte),c_uint)
UNLOAD_DLL_HANDLER = WINFUNCTYPE(None, c_uint)

class BP_INFO(Structure):
    _fields_ = [("Address", c_uint),
                ("Name", c_char_p),
                ("Recursive", c_uint),
                ("Instruction", c_ubyte),
                ("Count", c_uint)]

pe_info = {}
SetBP = None

md = Cs(CS_ARCH_X86, CS_MODE_32)


def get_module(dll_info,address):

    for base,dll in dll_info.iteritems():
        if address > dll.Base and address < (dll.Base + dll.Size):
            return dll.Name

    return 'None'


def dissy(kode):
    global md

    code = ''
    b = ''
    
    for k in range(0,16):
        code += struct.pack('<B',kode[k])
        b += '%02x'%(kode[k])
    #print len(code)
    asm = md.disasm(code,0x1000)
    for k in asm:
        break
        
    return k.mnemonic,k.op_str,k.size,b[:k.size*2]


def set_breakpoint(address,name):
    bInst =  c_ubyte()
    ret = SetBP(address,byref(bInst))
    print 'SetBP ret:%d binst:%x add:%x'%(ret,bInst.value,address)
    if ret:
        bp = BP_INFO(address,name,1,bInst.value,0)
    else:
        return None
        
    return bp

def get_api_address(info,api_name,dll_name):
    global pe_info

    address = 0    
    try:
        pe = pe_info[dll_name]
    except:
        pe = pefile.PE(info.Path)
        pe_info[dll_name] = pe
                
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name == api_name:
            address = info.Base + exp.address
            break
    
    return address

def main():
    global SetBP
    
    print 'In main..'
    dll_source_path = r'D:\rnd\ProjektPythonDebugger\v1_debugger\Release\v1_debugger.dll'
    dll = r'v1_debugger.dll'
    copyfile(dll_source_path,dll)
    
    pe = pefile.PE(dll)
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal

    debugger = WinDLL('v1_debugger.dll')
    
    AttachPid = debugger.AttachPid
    AttachPid.argtypes = [c_uint, c_uint,CP_HANDLER,LOAD_DLL_HANDLER,BP_HANDLER,CT_HANDLER,SS_HANDLER,UNLOAD_DLL_HANDLER]
    AttachPid.restype = c_int

    ExitDebugging = debugger.ExitDebugging
    ExitDebugging.argtypes = []
    ExitDebugging.restype = c_int

    SetBP = debugger.SetBP
    SetBP.argtypes = [c_uint,POINTER(c_ubyte)]
    SetBP.restype = c_int

    FixBP = debugger.FixBP
    FixBP.argtypes = [c_uint,c_ubyte,c_uint]
    FixBP.restype = c_int

    EnableSS = debugger.EnableSS
    EnableSS.argtypes = []
    EnableSS.restype = c_uint

    GetStackArgument = debugger.GetStackArgument
    GetStackArgument.argtypes = [c_uint,POINTER(c_uint)]
    GetStackArgument.restype = c_uint
    
    return AttachPid,ExitDebugging,SetBP,FixBP,EnableSS,GetStackArgument


if __name__ == "__main__":
    main()
