from ctypes import *
import string
import sys
import time
from capstone import *
from debugger import *
import struct
import list_process
import debugger
import thread

class DLL_INFO(Structure):
    _fields_ = [("Path", c_char_p),
                ("Base", c_uint),
                ("Name", c_char_p),
                ("Size", c_uint)]

class THREAD_INFO(Structure):
    _fields_ = [("StartProc", c_uint),
                ("ThreadId", c_uint)]

dll_info = {}
thread_info = []
bp_info = {}
bp_last = None

bSingleStep = False

def exe_cmd(args):
    global thread_info
    global dll_info
    global bp_info
    global bSingleStep

    while True:
        cmd = raw_input('?')
        print 'executing:',cmd
        if cmd == 'q':
            print 'Exiting..'
            for address,bp in bp_info.iteritems():                
                FixBP(bp.Address,bp.Instruction,1)
                print 'Fixing:%s'%(bp.Name)
            ExitDebugging()
            return
        if cmd == 'dlls':
            for base,info in dll_info.iteritems():
                print '%x %s'%(info.Base,info.Path)
        if cmd == 'bl':
            for address,info in bp_info.iteritems():
                print '%x %s'%(info.Address,info.Name)
        if cmd == 'threads':
            for thread in thread_info:
                print 'Proc:%x id:%d'%(thread.StartProc,thread.ThreadId)
        if cmd[:2] == 'bp':
            arg = cmd.split()[1]
            dll,api = arg.split('.')
            print 'setting bp @ ',dll,api
            for base,info in dll_info.iteritems():
                if info.Name == dll:
                    break
            address = debugger.get_api_address(info,api,dll)
            
            if address != 0:
                bp = debugger.set_breakpoint(address,api)
            else:
                print 'API could not be resolved'
                bp = None

            if bp != None:
                bp_info[address] = bp
                bSingleStep = True
                print bp_info
            else:
                print 'BP not set'
        break
    return
            
            

def cp_handler(base,oep):
    print 'create process event base:%x oep:%x'%(base,oep)
    return

def unload_handler(base):
    global dll_info
    dll_info.__delitem__(base)
    print 'Unload event base:%x'%(base)
    return 

def load_dll_handler(dll_name,base,size,base_of_code,size_of_code):
    global dll_info
    
    consta_string = '\Device\HarddiskVolume'
    disk_id = dll_name[22]
    if disk_id == '3':
        path = string.replace(dll_name,consta_string+'3','C:',1)
    if disk_id == '4':
        path = string.replace(dll_name,consta_string+'4','D:',1)

    name = path[path.rfind('\\')+1:].split('.')[0]
    dll = DLL_INFO(path,base,name,size)
    dll_info[base] = dll
    
    #print 'dll load:',path
    
    return

def bp_handler(address,tid):
    global bp_info
    global bp_last
    global bSingleStep

    found = 0
    for add,bp in bp_info.iteritems():
        print 'ITERATING %x %s'%(add,bp.Name)
        if add == address:    
            print 'BreakPoint Event:%s %x bSS:%x'%(bp.Name,bp.Address,bSingleStep)
            ret = FixBP(bp.Address,bp.Instruction,0)
            bp_last = bp
            found = 1
            if bp.Name == 'Return':
                EnableSS()
    
        
    
    if found == 0:
        ret = 0x80010001   # not handled
        print 'bp_event %x[no_info]'%(address)
     
    else:
        ret = 0x00010002  # continueb
    return ret

def ss_handler(address,kode):
    global bp_last
    global bSingleStep
    global bp_info
    global dll_info

    mod = debugger.get_module(dll_info,address)
    i,o,s,b = debugger.dissy(kode)
    print 'ss @ %s_%x   %s    %s'%(mod,address,i,o)
        
    if bp_last != None:
        if bp_last.Name != 'Return':
            bInst =  c_ubyte()
            ret = SetBP(bp_last.Address,byref(bInst))
            print '<Setting bp again:%d>'%(ret)
        else:
            print '<Not setting BP>'
            bSingleStep = True
            bp_info.__delitem__(bp_last.Address)
        
        bp_last = None

    if i == 'call':
        bSingleStep = False
        bp = debugger.set_breakpoint(address + s,'Return')
        if bp != None:
            bp_info[address + s] = bp
            bSingleStep = False
            print '<setting bp at return>'

    if bSingleStep:
        print 'enabling ss'
        EnableSS()   
    
    return 1

def ct_handler(startaddress,tid):
    global thread_info
    thread = THREAD_INFO(startaddress,tid)
    thread_info.append(thread)
    print 'thread start:%x tid:%d'%(startaddress,tid)    
    return 1

def main():        
    pid = list_process.get_pid_exe(sys.argv[1])
    verbose = string.atoi(sys.argv[2],10)
    print 'attaching... ',pid    
    AttachPid(verbose,pid,cp_handler,load_dll_handler,bp_handler,ct_handler,ss_handler,unload_handler)

AttachPid,ExitDebugging,SetBP,FixBP,EnableSS,GetStackArgument = debugger.main()

cp_handler = debugger.CP_HANDLER(cp_handler)
load_dll_handler = debugger.LOAD_DLL_HANDLER(load_dll_handler)
bp_handler = debugger.BP_HANDLER(bp_handler)
ct_handler = debugger.CT_HANDLER(ct_handler)
ss_handler = debugger.SS_HANDLER(ss_handler)
unload_handler = debugger.UNLOAD_DLL_HANDLER(unload_handler)

if __name__ == "__main__":
    main()
