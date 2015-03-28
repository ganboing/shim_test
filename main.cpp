#include <Windows.h>
#include <Subauth.h>
#include <algorithm>

#define ENV_NAME L"INSTRUMENTATION_DLLS"

#pragma pack(push, 1)

typedef union{
	ULONG_PTR DR6;
	struct{
		ULONG_PTR B0 : 1;
		ULONG_PTR B1 : 1;
		ULONG_PTR B2 : 1;
		ULONG_PTR B3 : 1;
	ULONG_PTR: 9;
		ULONG_PTR BD : 1;
		ULONG_PTR BS : 1;
		ULONG_PTR BT : 1;
	ULONG_PTR: sizeof(ULONG_PTR) * 8 - 16;
	};
}Dr6_t;

typedef union{
	ULONG_PTR DR7;
	struct{
		ULONG_PTR L0 : 1;
		ULONG_PTR G0 : 1;
		ULONG_PTR L1 : 1;
		ULONG_PTR G1 : 1;
		ULONG_PTR L2 : 1;
		ULONG_PTR G2 : 1;
		ULONG_PTR L3 : 1;
		ULONG_PTR G3 : 1;
		ULONG_PTR LE : 1;
		ULONG_PTR GE : 1;
	ULONG_PTR: 3;
		ULONG_PTR GD : 1;
	ULONG_PTR: 2;
		ULONG_PTR RW0 : 2;
		ULONG_PTR LEN0 : 2;
		ULONG_PTR RW1 : 2;
		ULONG_PTR LEN1 : 2;
		ULONG_PTR RW2 : 2;
		ULONG_PTR LEN2 : 2;
		ULONG_PTR RW3 : 2;
		ULONG_PTR LEN3 : 2;
	ULONG_PTR: sizeof(ULONG_PTR) * 8 - 32;
	};
}Dr7_t;

#pragma pack(pop)

static const DWORD MyException = 0xE0AABBCC;

struct ExtraDllInfo{
	LPCWSTR DllPath;
	HMODULE Handle;
};

ExtraDllInfo DllInfo[16];
SIZE_T DllLoaded;
WCHAR DllInfoString[32 * 1024];
PVOID ExeEntryPoint;

struct LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID EntryPoint;
	PVOID Reserved3;
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
};
typedef LDR_DATA_TABLE_ENTRY *PLDR_DATA_TABLE_ENTRY;


extern "C"{
	PVOID WINAPI GetHookAPIs(LPCSTR C, LPCWSTR S, PDWORD N){
		return NULL;
	}

	BOOL WINAPI NotifyShims(DWORD R, PLDR_DATA_TABLE_ENTRY P){
		return TRUE;
	}
}

LONG CALLBACK EntryPointResponder(
	_In_  PEXCEPTION_POINTERS ExceptionInfo
	);

int RedirectedEntryPoint(){
	RemoveVectoredExceptionHandler(EntryPointResponder);
	auto len = GetEnvironmentVariableW(ENV_NAME, DllInfoString, _countof(DllInfoString));
	auto pstr_current = DllInfoString;
	auto pstr_end = pstr_current + len;
	for (DllLoaded = 0; DllLoaded < _countof(DllInfo); ++DllLoaded){
		auto pstr_next = std::find(pstr_current, pstr_end, L';');
		if (pstr_next != pstr_end){
			*pstr_next = L'\0';
			DllInfo[DllLoaded].DllPath = pstr_current;
		}
		else{
			break;
		}
		pstr_current = ++pstr_next;
	}
	for (SIZE_T i = 0; i < DllLoaded; ++i){
		DllInfo[i].Handle = LoadLibraryW(DllInfo[i].DllPath);
	}
	//Call Exe EntryPoint
	return ((decltype(&RedirectedEntryPoint))ExeEntryPoint)();
}

LONG CALLBACK EntryPointResponder(
	_In_  PEXCEPTION_POINTERS ExceptionInfo
	){
	if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP){
		return EXCEPTION_CONTINUE_SEARCH;
	}
	if (ExceptionInfo->ExceptionRecord->ExceptionAddress != ExeEntryPoint){
		return EXCEPTION_CONTINUE_SEARCH;
	}
	Dr6_t dr6{ ExceptionInfo->ContextRecord->Dr6 };
	if (!dr6.B0){
		DbgRaiseAssertionFailure();
	}
	if (ExceptionInfo->ContextRecord->Dr0 != (ULONG_PTR)ExeEntryPoint){
		DbgRaiseAssertionFailure();
	}
	dr6.B0 = 0;
	ExceptionInfo->ContextRecord->Dr6 = dr6.DR6;
	Dr7_t dr7{ ExceptionInfo->ContextRecord->Dr7 };
	dr7.L0 = 0;
	ExceptionInfo->ContextRecord->Dr7 = dr7.DR7;
	ExceptionInfo->ContextRecord->Dr0 = 0;
	ExceptionInfo->ContextRecord->Eip = (ULONG_PTR)RedirectedEntryPoint;
	return EXCEPTION_CONTINUE_EXECUTION;
}

LONG CALLBACK BreakPointInstaller(
	_In_  PEXCEPTION_POINTERS ExceptionInfo
	){
	if (ExceptionInfo->ExceptionRecord->ExceptionCode != MyException){
		return EXCEPTION_CONTINUE_SEARCH;
	}
	ExceptionInfo->ContextRecord->Dr0 = (ULONG_PTR)ExeEntryPoint;
	Dr7_t dr7{ ExceptionInfo->ContextRecord->Dr7 };
	dr7.L0 = 1;
	dr7.RW0 = 0;
	dr7.LEN0 = 0;
	ExceptionInfo->ContextRecord->Dr7 = dr7.DR7;
	return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL WINAPI DllMain(
	_In_  HINSTANCE hinstDLL,
	_In_  DWORD fdwReason,
	_In_  LPVOID lpvReserved
	){
	switch (fdwReason){
	case DLL_PROCESS_ATTACH:
		auto image = (PBYTE)GetModuleHandleW(NULL);
		auto dos = (PIMAGE_DOS_HEADER)image;
		auto nt = (PIMAGE_NT_HEADERS)(image + dos->e_lfanew);
		ExeEntryPoint = image + nt->OptionalHeader.AddressOfEntryPoint;
		AddVectoredExceptionHandler(TRUE, BreakPointInstaller);
		RaiseException(MyException, 0, 0, NULL);
		RemoveVectoredExceptionHandler(BreakPointInstaller);
		AddVectoredExceptionHandler(TRUE, EntryPointResponder);
		break;
	}
	return TRUE;
}