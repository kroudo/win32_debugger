struct MODULE_INFO
{
	DWORD lpBaseLow;
	DWORD lpBaseHigh;
	DWORD dwSizeOfImage;

	char szModuleName[MAX_PATH];
	char szTruePath[MAX_PATH];
	char szModInitial[MAX_PATH];
	MODULE_INFO *next;
};