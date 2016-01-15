from ctypes import c_long , c_int , c_uint , c_char , c_ubyte , c_char_p , c_void_p
from ctypes import windll
from ctypes import Structure
from ctypes import sizeof , POINTER , pointer , cast

# const variable
TH32CS_SNAPPROCESS = 2
STANDARD_RIGHTS_REQUIRED = 0x000F0000
SYNCHRONIZE = 0x00100000
PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF)
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPTHREAD = 0x00000004


# struct 
class PROCESSENTRY32(Structure):
    _fields_ = [ ( 'dwSize' , c_uint ) , 
                 ( 'cntUsage' , c_uint) ,
                 ( 'th32ProcessID' , c_uint) ,
                 ( 'th32DefaultHeapID' , c_uint) ,
                 ( 'th32ModuleID' , c_uint) ,
                 ( 'cntThreads' , c_uint) ,
                 ( 'th32ParentProcessID' , c_uint) ,
                 ( 'pcPriClassBase' , c_long) ,
                 ( 'dwFlags' , c_uint) ,
                 ( 'szExeFile' , c_char * 260 ) , 
                 ( 'th32MemoryBase' , c_long) ,
                 ( 'th32AccessKey' , c_long ) ]

# forigen function
## CreateToolhelp32Snapshot
CreateToolhelp32Snapshot= windll.kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.reltype = c_long
CreateToolhelp32Snapshot.argtypes = [ c_int , c_int ]
## Process32First
Process32First = windll.kernel32.Process32First
Process32First.argtypes = [ c_void_p , POINTER( PROCESSENTRY32 ) ]
Process32First.rettype = c_int
## Process32Next
Process32Next = windll.kernel32.Process32Next
Process32Next.argtypes = [ c_void_p , POINTER(PROCESSENTRY32) ]
Process32Next.rettype = c_int
CloseHandle = windll.kernel32.CloseHandle
CloseHandle.argtypes = [ c_void_p ]
CloseHandle.rettype = c_int
## GetLastError
GetLastError = windll.kernel32.GetLastError
GetLastError.rettype = c_long


# main
def find_process(name):
    hProcessSnap = c_void_p(0)
    hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , 0 )


    pe32 = PROCESSENTRY32()
    pe32.dwSize = sizeof( PROCESSENTRY32 )
    ret = Process32First( hProcessSnap , pointer( pe32 ))

    if pe32.szExeFile.lower() == name:
        return True

    while ret :
        #print "Process Name : %s " % pe32.szExeFile        
        ret = Process32Next( hProcessSnap, pointer(pe32) )
        if pe32.szExeFile.lower() == name:
            return True

    return False

def get_pid_exe(name):
    hProcessSnap = c_void_p(0)
    hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , 0 )

    print name
    pe32 = PROCESSENTRY32()
    pe32.dwSize = sizeof( PROCESSENTRY32 )
    ret = Process32First( hProcessSnap , pointer( pe32 ))

    
    #print pe32.szExeFile.lower()
    if pe32.szExeFile.lower() == name.lower():
        return pe32.th32ProcessID
   

    while ret :
        #print "Process Name : %s " % pe32.szExeFile        
        ret = Process32Next( hProcessSnap, pointer(pe32) )
        #print pe32.szExeFile.lower()
        if pe32.szExeFile.lower() == name.lower():
            return pe32.th32ProcessID

    
    return 0
    

def get_pid_process_name(pid):
    hProcessSnap = c_void_p(0)
    hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , 0 )


    pe32 = PROCESSENTRY32()
    pe32.dwSize = sizeof( PROCESSENTRY32 )
    ret = Process32First( hProcessSnap , pointer( pe32 ))

    ie = {}

    if pe32.th32ProcessID == pid:
        return pe32.szExeFile.lower()
   

    while ret :
        #print "Process Name : %s " % pe32.szExeFile        
        ret = Process32Next( hProcessSnap, pointer(pe32) )
        if pe32.th32ProcessID == pid:
            return pe32.szExeFile.lower()

    
    return 'none'
    

def get_child_ie():
    hProcessSnap = c_void_p(0)
    hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , 0 )


    pe32 = PROCESSENTRY32()
    pe32.dwSize = sizeof( PROCESSENTRY32 )
    ret = Process32First( hProcessSnap , pointer( pe32 ))


    if pe32.szExeFile.lower() == 'iexplore.exe':
        process = get_pid_process_name(pe32.th32ParentProcessID)
        if process == 'iexplore.exe':
            return pe32.th32ProcessID
   

    while ret :
        #print "Process Name : %s " % pe32.szExeFile        
        ret = Process32Next( hProcessSnap, pointer(pe32) )
        if pe32.szExeFile.lower() == 'iexplore.exe':
            process = get_pid_process_name(pe32.th32ParentProcessID)
            if process == 'iexplore.exe':
                return pe32.th32ProcessID

    
    return 0

if __name__ == '__main__' :
    r = find_process('python.exe')
    print r

