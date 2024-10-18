# Detect CobaltStrike
CobaltStrike Beacon uses a well-known open-source static library: [libtomcrypt](https://github.com/libtom/libtomcrypt). During reverse engineering of Beacon, I discovered that Beacon uses the `rng_get_bytes` function.
![image](https://github.com/kyxiaxiang/DetectCobaltStrike/blob/main/img-folder/Pasted%20image%2020241018034840.png?raw=true)
This could potentially become a stronger detection method, even surpassing Wininet APIs. According to the release notes from CobaltStrike version 4.10, Fortra has introduced an evasion mechanism called **Beacon_Gate**. The file `beacon_gate.h` gives us some insight into how this works.
![image](https://github.com/kyxiaxiang/DetectCobaltStrike/blob/main/img-folder/Pasted%20image%2020241018035704.png?raw=true)
By writing some YARA rules and testing them on internet samples, I managed to identify some interesting cases. This is getting intriguing!
To validate my theory, I placed breakpoints on the following functions: `CryptAcquireContext`, `CryptGenRandom`, and `CryptReleaseContext`. Since these functions are often forwarded calls, we need to break on the stubs.
![image](https://github.com/kyxiaxiang/DetectCobaltStrike/blob/main/img-folder/Pasted%20image%2020241018040746.png?raw=true)
![image](https://github.com/kyxiaxiang/DetectCobaltStrike/blob/main/img-folder/Pasted%20image%2020241018040820.png?raw=true)
![image](https://github.com/kyxiaxiang/DetectCobaltStrike/blob/main/img-folder/Pasted%20image%2020241018040855.png?raw=true)

Oops, what do we have here? A strange caller—this is unusual, isn't it?
Aha, this looks very much like CobaltStrike, doesn't it?
![image](https://github.com/kyxiaxiang/DetectCobaltStrike/blob/main/img-folder/Pasted%20image%2020241018034840.png?raw=true)
Next, I tried testing `WININET!InternetOpenA`, which was also triggered. While they’ve mentioned that this API has been handled in the latest blog posts, they didn't mention the `CryptAcquireContext`, `CryptGenRandom`, or `CryptReleaseContext` APIs. I think the chances of false positives with these APIs are quite low (just my personal opinion).

![image](https://github.com/kyxiaxiang/DetectCobaltStrike/blob/main/img-folder/Pasted%20image%2020241018041608.png?raw=true)

While exploring additional samples, I believe I may have captured a Beacon from version 4.10. Check out this unusual address!

![image](https://github.com/kyxiaxiang/DetectCobaltStrike/blob/main/img-folder/Pasted%20image%2020241018050350.png?raw=true)

![image](https://github.com/kyxiaxiang/DetectCobaltStrike/blob/main/img-folder/Pasted%20image%2020241018050419.png?raw=true)
This is likely the **SleepMask**, as Fortra mentioned. In CobaltStrike 4.10, they’ve expanded the Sleepmask functionality to support arbitrary function execution, allowing Beacon to forward its Windows API calls to be executed via Sleepmask (aka BeaconGate).

This piqued my curiosity. Even though I’m still a beginner in red teaming, I tried extracting Beacon from memory and reversing it. The difference between this version and earlier ones is striking.
![image](https://github.com/kyxiaxiang/DetectCobaltStrike/blob/main/img-folder/Pasted%20image%2020241018052218.png?raw=true)
I noticed that APIs like `VirtualQuery` have been meticulously customized, which likely corresponds to the new APIs Fortra mentioned.
![image](https://github.com/kyxiaxiang/DetectCobaltStrike/blob/main/img-folder/Pasted%20image%2020241018052531.png?raw=true)
![image](https://github.com/kyxiaxiang/DetectCobaltStrike/blob/main/img-folder/Pasted%20image%2020241018052551.png?raw=true)

After diving deeper, I found many interesting things, but we’ll leave those for another time. Back to the point, now we can add detection for calls to `CryptAcquireContextA`, `CryptGenRandom`, and `CryptReleaseContext` to capture Beacons in memory.

For a detection demo, we can modify an existing open-source project like [MalMemDetect](https://github.com/waldo-irc/MalMemDetect/tree/main) to create a proof of concept. Here’s the modified POC code:

```c
// Hooked CryptAcquireContextA with return address and module checking
HCRYPTPROV WINAPI HookedCryptAcquireContextA(HCRYPTPROV *phProv, LPCSTR pszContainer, LPCSTR pszProvider, DWORD dwProvType, DWORD dwFlags) {
    DWORD callerId = GetCurrentThreadId();
    CHAR* log = (CHAR*)malloc(256);
    HMODULE hModule;
    char lpBaseName[256] = { 0 };

    // Check if the return address belongs to known libraries
    if (memcmp(_ReturnAddress(), "\x4c\x8b\xc0\x48\x85\xc0\x0f\x84", 8) == 0 || memcmp(_ReturnAddress(), "\x48\x8b\xd8\x48\x85\xc0\x0f\x84", 8) == 0) {
        strcpy_s(lpBaseName, "ntdll.dll");
    } else {
        if (::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)_ReturnAddress(), &hModule) == 1) {
            ::GetModuleBaseNameA(GetCurrentProcess(), hModule, lpBaseName, sizeof(lpBaseName));
        }
        snprintf(log, 255, "Suspicious CryptAcquireContextA() call from thread id:%d, pszContainer: %s, pszProvider: %s\n", callerId, pszContainer ? pszContainer : "NULL", pszProvider ? pszProvider : "NULL");
        LogDetected(&log);
    }

    std::string modName = lpBaseName;
    std::transform(modName.begin(), modName.end(), modName.begin(),
        [](unsigned char c) { return tolower(c); });

    if (dllMonitor != "NULL" && dllMonitor.find(modName) != std::string::npos) {
        snprintf(log, 255, "Suspicious CryptAcquireContextA() call from module: %s, pszContainer: %s\n", dllMonitor.c_str(), pszContainer ? pszContainer : "NULL");
        LogDetected(&log);
    }

    free(log);
    return OldCryptAcquireContextA(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
}

// Hooked CryptGenRandom with return address and module checking
BOOL WINAPI HookedCryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer) {
    DWORD callerId = GetCurrentThreadId();
    CHAR* log = (CHAR*)malloc(256);
    HMODULE hModule;
    char lpBaseName[256] = { 0 };

    if (memcmp(_ReturnAddress(), "\x4c\x8b\xc0\x48\x85\xc0\x0f\x84", 8) == 0 || memcmp(_ReturnAddress(), "\x48\x8b\xd8\x48\x85\xc0\x0f\x84", 8) == 0) {
        strcpy_s(lpBaseName, "ntdll.dll");
    } else {
        if (::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)_ReturnAddress(), &hModule) == 1) {
            ::GetModuleBaseNameA(GetCurrentProcess(), hModule, lpBaseName, sizeof(lpBaseName));
        }
        snprintf(log, 255, "Suspicious CryptGenRandom() call from thread id:%d, Length: %lu\n", callerId, dwLen);
        LogDetected(&log);
    }

    std::string modName = lpBaseName;
    std::transform(modName.begin(), modName.end(), modName.begin(),
        [](unsigned char c) { return tolower(c); });

    if (dllMonitor != "NULL" && dllMonitor.find(modName) != std::string::npos) {
        snprintf(log, 255, "Suspicious CryptGenRandom() call from module: %s, Length: %lu\n", dllMonitor.c_str(), dwLen);
        LogDetected(&log);
    }

    free(log);
    return OldCryptGenRandom(hProv, dwLen, pbBuffer);
}

// Hooked CryptReleaseContext with return address and module checking
BOOL WINAPI HookedCryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags) {
    DWORD callerId = GetCurrentThreadId();
    CHAR* log = (CHAR*)malloc(256);
    HMODULE hModule;
    char lpBaseName[256] = { 0 };

    if (memcmp(_ReturnAddress(), "\x4c\x8b\xc0\x48\x85\xc0\x0f\x84", 8) == 0 || memcmp(_ReturnAddress(), "\x48\x8b\xd8\x48\x85\xc0\x0f\x84", 8) == 0) {
        strcpy_s(lpBaseName, "ntdll.dll");
    } else {
        if (::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)_ReturnAddress(), &hModule) == 1) {
            ::GetModuleBaseNameA(GetCurrentProcess(), hModule, lpBaseName, sizeof(lpBaseName));
        }
        snprintf(log, 255, "Suspicious CryptReleaseContext() call from thread id:%d, Flags: %lu\n", callerId, dwFlags);
        LogDetected(&log);
    }

    std::string modName = lpBaseName;
    std::transform(modName.begin(), modName.end(), modName.begin(),
        [](unsigned char c) { return tolower(c); });

    if (dllMonitor != "NULL" && dllMonitor.find(modName) != std::string::npos) {
        snprintf(log, 255, "Suspicious CryptReleaseContext() call from module: %s, Flags: %lu\n", dllMonitor.c_str(), dwFlags);
        LogDetected(&log);
    }

    free(log);
    return OldCryptReleaseContext(hProv, dwFlags);
}
```
