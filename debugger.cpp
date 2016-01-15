#include <Windows.h>
#include <psapi.h>
#include <stdio.h>


#include "log.h"
#include "debugger.h"

#define Msg(m)  MessageBoxA(0,m,"dll",MB_OK)

//----------- globals

extern DWORD dwVerbose;
DEBUG_EVENT dbg_event;
HANDLE hProcess;
DWORD dwPid;

//------------

typedef void (__stdcall *CP_HANDLER)(DWORD,DWORD);
CP_HANDLER create_process_handler;

typedef void (__stdcall *LOAD_DLL_HANDLER)(char *,DWORD,DWORD,DWORD,DWORD);
LOAD_DLL_HANDLER load_dll_handler;

typedef void (__stdcall *UNLOAD_DLL_HANDLER)(DWORD);
UNLOAD_DLL_HANDLER unload_dll_handler;

typedef int (__stdcall *BP_HANDLER)(DWORD,DWORD);
BP_HANDLER breakpoint_handler;

typedef int (__stdcall *CT_HANDLER)(DWORD,DWORD);
CT_HANDLER createthread_handler;

typedef int (__stdcall *SS_HANDLER)(DWORD,BYTE*,DWORD);
SS_HANDLER singlestep_handler;

BOOL WINAPI read_dword_at_offset(DWORD dwOffset,DWORD &dwResult)
{
	DWORD dwRead;
	BYTE pbuffer[4];

	if (!ReadProcessMemory(hProcess,(LPCVOID)dwOffset,pbuffer,4,&dwRead))
	{
		Log("read_dword_at_offset:ReadProcessMemory failed:%d adddress:%x",GetLastError(),dwOffset);
		dwResult = 0;
		return 0;
	}

	dwResult = *(DWORD*)pbuffer;

	return 1;
}

BOOL WINAPI  read_word_at_offset(DWORD dwOffset,WORD &wResult)
{
	DWORD dwRead;
	BYTE pbuffer[2];

	if (!ReadProcessMemory(hProcess,(LPCVOID)dwOffset,pbuffer,2,&dwRead))
	{
		Log("read_word_at_offset:ReadProcessMemory failed:%d %x",GetLastError(),dwOffset);
		wResult = 0;
		return 0;
	}

	wResult = *(WORD*)pbuffer;
	return 1;
}


BOOL WINAPI  read_byte_at_offset(DWORD dwOffset,BYTE &bResult)
{
	DWORD dwRead;
	BYTE pbuffer;

	if (!ReadProcessMemory(hProcess,(LPCVOID)dwOffset,&pbuffer,1,&dwRead))
	{
		Log("read_byte_at_offset:ReadProcessMemory failed:%d",GetLastError());
		bResult = 0;
		return 0;
	}

	bResult = *(BYTE*)pbuffer;

	return 1;
}

int Load_Dll_Event(HANDLE hFile,DWORD dwBase)
{
	HANDLE hFileMapp;
	LPVOID lpMappedBase;
	char szDll[2048];
	WORD wMagicMZ;
	DWORD dwOffsetPE,dwMagicPE,dwRead;
	IMAGE_FILE_HEADER file_header;
	IMAGE_OPTIONAL_HEADER optional_header;
	MODULE_INFO module_info;

	hFileMapp = CreateFileMappingA(hFile,0,PAGE_READONLY,0,1,0);
	lpMappedBase = MapViewOfFile(hFileMapp,FILE_MAP_READ,0,0,1);
	if (hFileMapp == 0 || lpMappedBase == 0)
	{
		Log(" load dll handler err:%d  CFM:%d",GetLastError(),hFileMapp);
		return 0;
	}

	GetMappedFileNameA(GetCurrentProcess(),lpMappedBase,szDll,sizeof(szDll));
	if(!read_word_at_offset((DWORD)dwBase,wMagicMZ))
		return 0;
	if(!read_dword_at_offset((DWORD)dwBase+0x3c,dwOffsetPE))
		return 0;		
	if (!read_dword_at_offset((DWORD)dwBase+dwOffsetPE,dwMagicPE))
		return 0;
	
	memset(&file_header,0,sizeof(file_header));
	memset(&optional_header,0,sizeof(optional_header));
	ReadProcessMemory(hProcess,(LPCVOID)((DWORD)dwBase+dwOffsetPE+4),&file_header,sizeof(file_header),&dwRead);
	ReadProcessMemory(hProcess,(LPCVOID)((DWORD)dwBase+dwOffsetPE+4+sizeof(file_header)),&optional_header,sizeof(optional_header),&dwRead);
	
	module_info.lpBaseLow = (DWORD)dwBase;
	module_info.lpBaseHigh = (DWORD)dwBase + optional_header.SizeOfImage;
	module_info.dwSizeOfImage = optional_header.SizeOfImage;
	lstrcpyA(module_info.szModuleName,szDll);

	DWORD dwBaseOfCode,dwSizeOfCode;

	dwBaseOfCode = optional_header.BaseOfCode;
	dwSizeOfCode = optional_header.SizeOfCode;
	
	Log("mapped base:%x szDll:%s handler:%x",lpMappedBase,szDll,load_dll_handler);
	load_dll_handler(szDll,module_info.lpBaseLow,optional_header.SizeOfImage,dwBaseOfCode,dwSizeOfCode);

	UnmapViewOfFile(lpMappedBase);
	return 1;
}




void WINAPI EnterDebugging(DWORD dwPid)
{
	
	DWORD dwAction = DBG_CONTINUE;
	int ret;
	DWORD dwAddress,dwRead;	
	BYTE bCode[16];

	::dwPid = dwPid;
	DebugSetProcessKillOnExit(0);

	hProcess = OpenProcess(PROCESS_ALL_ACCESS,0,dwPid);
	if (hProcess == 0)
	{
		Log("OpenProcess[CREATE_PROCESS_DEBUG_EVENT:Pid:%d] failed:%d",dwPid,GetLastError());
		ExitProcess(0);
	}

	while (WaitForDebugEvent(&dbg_event,INFINITE))
	{
		dwAction = DBG_CONTINUE;			
		
		switch (dbg_event.dwDebugEventCode)
		{
			case CREATE_PROCESS_DEBUG_EVENT:
				Log("CREATE_PROCESS_DEBUG_EVENT:Base:%x OEP:%x",dbg_event.u.CreateProcessInfo.lpBaseOfImage,dbg_event.u.CreateProcessInfo.lpStartAddress);				
				create_process_handler((DWORD) dbg_event.u.CreateProcessInfo.lpBaseOfImage,(DWORD)dbg_event.u.CreateProcessInfo.lpStartAddress);
				Load_Dll_Event(dbg_event.u.CreateProcessInfo.hFile,(DWORD)dbg_event.u.CreateProcessInfo.lpBaseOfImage);
				hProcess = OpenProcess(PROCESS_ALL_ACCESS,0,dwPid);
				if (hProcess == 0)
				{
					Log("OpenProcess[CREATE_PROCESS_DEBUG_EVENT:Pid:%d] failed:%d",dwPid,GetLastError());
					ExitProcess(0);
				}
				break;
			case CREATE_THREAD_DEBUG_EVENT:
				Log("Thread starting... entry point:%x[ht:%x:id:%d] ",dbg_event.u.CreateThread.lpStartAddress,dbg_event.u.CreateThread.hThread,dbg_event.dwThreadId);
				createthread_handler((DWORD)dbg_event.u.CreateThread.lpStartAddress,(DWORD)dbg_event.dwThreadId);
				break;
			case EXCEPTION_DEBUG_EVENT:
				Log("EXCEPTION_DEBUG_EVENT(%x) fc:%x address:0x%x code:0x%x",EXCEPTION_DEBUG_EVENT,dbg_event.u.Exception.dwFirstChance,dbg_event.u.Exception.ExceptionRecord.ExceptionAddress,dbg_event.u.Exception.ExceptionRecord.ExceptionCode);
				dwAction = DBG_EXCEPTION_NOT_HANDLED;
				switch(dbg_event.u.Exception.ExceptionRecord.ExceptionCode)
				{
					case EXCEPTION_INVALID_HANDLE:
						Log("EXCEPTION_INVALID_HANDLE");
						break;
					case EXCEPTION_BREAKPOINT:
						
						dwAddress = (DWORD)dbg_event.u.Exception.ExceptionRecord.ExceptionAddress;
						ret = breakpoint_handler(dwAddress,dbg_event.dwThreadId);
						
						Log("BP exception at:%x ret:%x",dwAddress,ret);
						dwAction = ret;
						
						break;
					case EXCEPTION_SINGLE_STEP:
						Log("EXCEPTION_SINGLE_STEP:%x ",dbg_event.u.Exception.ExceptionRecord.ExceptionAddress);
						ReadProcessMemory(hProcess,dbg_event.u.Exception.ExceptionRecord.ExceptionAddress,bCode,16,&dwRead);
						singlestep_handler((DWORD)dbg_event.u.Exception.ExceptionRecord.ExceptionAddress,bCode,dbg_event.dwThreadId);
						dwAction = DBG_CONTINUE;
						break;
					}
				break;
				
			case EXIT_PROCESS_DEBUG_EVENT:
				Log("EXIT_PROCESS_DEBUG_EVENT");
				return;
			case EXIT_THREAD_DEBUG_EVENT:
				Log("Thread exiting... entry point:%x ",dbg_event.u.CreateThread.lpStartAddress);
				break;
			case LOAD_DLL_DEBUG_EVENT:
				Log("LOAD_DLL_DEBUG_EVENT:base:0x%x handle:0x%x",dbg_event.u.LoadDll.lpBaseOfDll,dbg_event.u.LoadDll.hFile);
				Load_Dll_Event(dbg_event.u.LoadDll.hFile,(DWORD)dbg_event.u.LoadDll.lpBaseOfDll);
				break;
			case OUTPUT_DEBUG_STRING_EVENT:
				Log("OUTPUT_DEBUG_STRING_EVENT");
				break;
			case RIP_EVENT:
				Log("RIP_EVENT");
				break;
			case UNLOAD_DLL_DEBUG_EVENT:
				Log("UNLOAD_DLL_DEBUG_EVENT:%x",dbg_event.u.UnloadDll.lpBaseOfDll);
				unload_dll_handler((DWORD)dbg_event.u.UnloadDll.lpBaseOfDll);
				break;
		}		
		ContinueDebugEvent(dwPid,dbg_event.dwThreadId,dwAction);
	}
	return;
}


extern "C" int __declspec(dllexport) AttachPid(DWORD dwVer_bose,DWORD dwPid,CP_HANDLER cp_handler,LOAD_DLL_HANDLER ld_handler,BP_HANDLER bp_handler,CT_HANDLER ct_handler,SS_HANDLER ss_handler,UNLOAD_DLL_HANDLER uld_handler)
{
	HANDLE hProcess;
			
	dwVerbose = dwVer_bose;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS,0,dwPid);
	if (hProcess == 0)
	{
		Log("OpenProcess Failed:%d:%d",dwPid,GetLastError());
		return 0;
	}
	if(!DebugActiveProcess(dwPid))
	{
		Log("DebugActiveProcess Failed:%d:%d",dwPid,GetLastError());
		return 0;
	}
		
	Log("Attached to PID:%d",dwPid);

	load_dll_handler = ld_handler;
	create_process_handler = cp_handler;
	breakpoint_handler = bp_handler;
	createthread_handler = ct_handler;
	singlestep_handler = ss_handler;
	unload_dll_handler = uld_handler;

	EnterDebugging(dwPid);
	// call enter debugging n other init routines....
	return 1;
}


extern "C" int __declspec(dllexport) ExitDebugging()
{
	DebugActiveProcessStop(dwPid);
	ExitProcess(0);
	return 1;
}

extern "C" int __declspec(dllexport) SetBP(DWORD dwAddress,BYTE &bInstruction)
{
	DWORD dwRead,dwWritten;
	BYTE int3=0xCC;	
	
	if (!ReadProcessMemory(hProcess,(LPCVOID)dwAddress,&bInstruction,1,&dwRead))
	{
		Log("set_breakpoint: ReadMemory Err:%d hProcess:%x dwAddress:%x",GetLastError(),hProcess,dwAddress);
		return 0;
	}
	
	Log("call to set BP at %x : %02x",dwAddress,bInstruction);
	if (bInstruction != 0xcc)
	{	
		if (!WriteProcessMemory(hProcess,(LPVOID)dwAddress,&int3,1,&dwWritten))
		{
			Log("BP WriteProcessMemory Failed: %d",GetLastError());
		}
		FlushInstructionCache(hProcess,(LPCVOID)dwAddress,1);
		Log("setting BP at %x : %02x",dwAddress,bInstruction);
	}
	else
	{
		Log("setting BP Failed CC present already.");
		return 0;
	}
	return 1;
}

extern "C" int __declspec(dllexport) FixBP(DWORD dwAddress,BYTE bInstruction,DWORD dwFinalClean)
{
	BOOL bret;
	DWORD dw;
	HANDLE hThread;
	CONTEXT context;

	if (dwFinalClean)
	{
		bret = WriteProcessMemory(hProcess,(LPVOID)dwAddress,&bInstruction,1,&dw);
		return 0;
	}

	
	hThread = OpenThread(THREAD_ALL_ACCESS,0,dbg_event.dwThreadId);

	memset(&context,0,sizeof(CONTEXT));
	context.ContextFlags = CONTEXT_ALL;
	bret = GetThreadContext(hThread,&context);
	if (bret == 0) return 0;   
	bret = WriteProcessMemory(hProcess,(LPVOID)dwAddress,&bInstruction,1,&dw);
	FlushInstructionCache(hProcess,(LPVOID)dwAddress, 1);
	
	if (bret == 0) return 0;	


	context.Eip = context.Eip - 1;	
	context.EFlags |= 0x100;	
	bret = SetThreadContext(hThread,&context);
	
	if (bret == 0)
		return 0;
	Log("hThread:%x EIP:%x bret:%d gle:%d",hThread,context.Eip,bret,GetLastError());							
	return 1;
}


extern "C" DWORD __declspec(dllexport) EnableSS()
{
	CONTEXT context;
	HANDLE hThread;
	BOOL bret;
	BYTE ch=0x00;
	
	context.ContextFlags = CONTEXT_ALL;
	hThread = OpenThread(THREAD_ALL_ACCESS,0,dbg_event.dwThreadId);

	if (hThread == 0)
	{
		Log("SS Fail[OpenThread]:%d",GetLastError());
		return 0;
	}
	
	bret = GetThreadContext(hThread,&context);
		
	context.EFlags |= 0x100;	
	bret = SetThreadContext(hThread,&context);
	CloseHandle(hThread);

	Log("Call to enabless");

	return 1;
}

extern "C" DWORD __declspec(dllexport) __stdcall GetStackArgument(DWORD dwIndex,DWORD *pdwValue)
{
	DWORD ret = 0,dwValue;
	CONTEXT c;
	HANDLE hThread;
	BOOL bret;


	hThread = OpenThread(THREAD_ALL_ACCESS,0,dbg_event.dwThreadId);

	if (hThread == 0)
	{
		Log("hThread Null,GetStackArg :%d",GetLastError());
		return 0;
	}

	memset(&c,0,sizeof(CONTEXT));
	c.ContextFlags = CONTEXT_ALL;
	bret = GetThreadContext(hThread,&c);

	CloseHandle(hThread);
	if (bret == 0) return 0;

	ret = read_dword_at_offset(c.Esp+dwIndex*4,dwValue);	
	*pdwValue = dwValue;
	Log("Value:%x",dwValue);
	if (ret == 0)
		return 0;

	return 1;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}