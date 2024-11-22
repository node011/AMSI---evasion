bool Amsi::IsBlockedByAmsiScan(PVOID flatImageBytes, COUNT_T size)
{
    STANDARD_VM_CONTRACT;

    if (!InitializeLock())
        return false;

    // Lazily initialize AMSI because it is very expensive
    {
        CRITSEC_Holder csh(s_csAmsi);

        // Cache that we failed if this didn't work so we don't keep trying to reinitialize
        static bool amsiInitializationAttempted = false;
        if (s_amsiContext == nullptr && !amsiInitializationAttempted)
        {
            HMODULE amsi = CLRLoadLibraryEx(W("amsi.dll"), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (amsi != nullptr)
            {
                PAMSI_AMSIINITIALIZE_API AmsiInitialize = (PAMSI_AMSIINITIALIZE_API)GetProcAddress(amsi, "AmsiInitialize");
                if (AmsiInitialize != nullptr)
                {
                    HAMSICONTEXT amsiContext = nullptr;
                    if (AmsiInitialize(W("coreclr"), &amsiContext) == S_OK)
                    {
                        AmsiScanBuffer = (PAMSI_AMSISCANBUFFER_API)GetProcAddress(amsi, "AmsiScanBuffer");
                        if (AmsiScanBuffer != nullptr)
                        {
                            s_amsiContext = amsiContext;
                        }
                    }
                }
            }

            amsiInitializationAttempted = true;
        }
    }

    if (s_amsiContext == nullptr || AmsiScanBuffer == nullptr)
        return false;

    DWORD result;
    HRESULT hr = AmsiScanBuffer(s_amsiContext, flatImageBytes, size, nullptr, nullptr, &result);
    if (hr == S_OK && (AmsiResultIsMalware(result) || AmsiResultIsBlockedByAdmin(result)))
        return true;

    return false;
}
