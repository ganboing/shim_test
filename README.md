# shim_test

A test shim which inject DLLs into the new process.

The list of DLL to be injected should be assigned to the "INSTRUMENTATION_DLLS" environment variable. The effect of the injection is as if the process itself deliberately calls LoadLibrary from mainCRTStartup (EXE entry point) before initialization. Please note that the injected DLLs will not be FreeLibrary'ed at exit.
