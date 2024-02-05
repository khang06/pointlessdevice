#include <Windows.h>
#include <vector>
#include <bitset>
#include <mutex>
#include <mimalloc.h>
#include "patch_util.h"

#define GAME 10

#if GAME == 6
#define INPUT_ADDR 0x69D904
#define UPDATE_CALL_ADDR 0x4204FF
#define UPDATE_CONV __thiscall
#elif GAME == 10
#define INPUT_ADDR 0x474E30
#define UPDATE_CALL_ADDR 0x438D31
#define UPDATE_CONV __stdcall
#else
#error invalid game
#endif

#define ROUND_TO_PAGES(Size)  (((ULONG_PTR)(Size) + 0xFFF) & ~0xFFF)

std::mutex g_mutex;
bool g_dirty_tracking = false;
std::bitset<0x100000> g_tracked_pages;
std::bitset<0x100000> g_queued_to_track;
std::vector<std::pair<uintptr_t, void*>> g_dirty_pages;

// Assuming start and len are page-aligned...
void track_region(void* start, size_t len) {
    std::lock_guard<std::mutex> guard(g_mutex);
    for (auto i = (uintptr_t)start; i < (uintptr_t)start + len; i += 0x1000)
        (g_dirty_tracking ? g_queued_to_track : g_tracked_pages).set(i >> 12);
}

void untrack_region(void* start, size_t len) {
    std::lock_guard<std::mutex> guard(g_mutex);
    for (auto i = (uintptr_t)start; i < (uintptr_t)start + len; i += 0x1000)
        g_tracked_pages.reset(i >> 12);
}

PVOID WeirdVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    auto ret = VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    printf("WeirdVirtualAlloc(0x%zX, 0x%zX, 0x%X, 0x%X) -> 0x%zX\n", lpAddress, dwSize, flAllocationType, flProtect, ret);
    track_region(ret, dwSize);
    return ret;
}

BOOL WeirdVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    if (g_dirty_tracking) {
        printf("Should not free while dirty tracking\n");
        DebugBreak();
    }

    printf("WeirdVirtualFree(0x%zX, 0x%zX, 0x%X)\n", lpAddress, dwSize, dwFreeType);
    untrack_region(lpAddress, dwSize);
    return VirtualFree(lpAddress, dwSize, dwFreeType);
}

LPVOID __stdcall hooked_HeapAlloc(HANDLE, DWORD dwFlags, SIZE_T dwBytes) {
    if (dwFlags & HEAP_ZERO_MEMORY)
        return mi_calloc(1, dwBytes);
    else
        return mi_malloc(dwBytes);
}

BOOL __stdcall hooked_HeapFree(HANDLE, DWORD dwFlags, LPVOID lpMem) {
    mi_free(lpMem);
    return TRUE;
}

// ReadFile will return an error instead of hitting the exception handler if an invalid pointer is given
BOOL __stdcall hooked_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    if (lpNumberOfBytesRead)
        *lpNumberOfBytesRead = 0;
    memset(lpBuffer, 0, nNumberOfBytesToRead);
    return ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

void reprot_pages() {
    // TODO: This sucks but it's good enough for a PoC
    printf("Reprotecting pages...");
    DWORD old_prot;
    for (size_t i = 0; i < g_tracked_pages.size(); i++) {
        if (g_tracked_pages.test(i))
            VirtualProtect((LPVOID)(i << 12), 0x1000, PAGE_READONLY, &old_prot);
    }
    printf("done\n");
}

// Game-specific...
uint16_t g_last_input = 0;
int (UPDATE_CONV* g_orig_update)(void*) = nullptr;
int UPDATE_CONV hooked_update(void* self) {
    auto pressed = *(uint16_t*)INPUT_ADDR & ~g_last_input;
    g_last_input = *(uint16_t*)INPUT_ADDR;
    if (pressed & 0x200) { // Q
        printf("Initiating save\n");
        std::lock_guard<std::mutex> guard(g_mutex);

        // Enable dirty tracking
        g_dirty_tracking = true;

        // Track any pages that were queued to be tracked (two savestates without a load between them)
        g_tracked_pages |= g_queued_to_track;
        g_queued_to_track.reset();

        // Clear any dirty pages from the previous savestate if they exist
        for (auto& entry : g_dirty_pages)
            free(entry.second);
        g_dirty_pages.clear();

        // Mark all tracked pages as read-only
        reprot_pages();
    } else if (pressed & 0x400) { // S
        printf("Initiating load\n");
        std::lock_guard<std::mutex> guard(g_mutex);

        // Purge "queued to track" list
        g_queued_to_track.reset();

        // Copy back the original pages and reprotect
        printf("Restoring pages...");
        DWORD old_prot;
        for (auto& entry : g_dirty_pages) {
            memcpy((void*)entry.first, entry.second, 0x1000);
            free(entry.second);
            VirtualProtect((void*)entry.first, 0x1000, PAGE_READONLY, &old_prot);
        }
        printf("copied %u pages\n", g_dirty_pages.size());
        g_dirty_pages.clear();
    }
    return g_orig_update(self);
}

LONG WINAPI exception_handler(struct _EXCEPTION_POINTERS* ExceptionInfo) {
    auto target = ExceptionInfo->ExceptionRecord->ExceptionInformation[1] & ~0xFFF;
    if (!g_dirty_tracking || ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || !g_tracked_pages.test(target >> 12))
        return EXCEPTION_CONTINUE_SEARCH;

    std::lock_guard<std::mutex> guard(g_mutex);
    DWORD old_prot;
    //printf("Reprotecting page at 0x%X\n", target);
    VirtualProtect((LPVOID)target, 0x1000, PAGE_READWRITE, &old_prot);
    auto orig = malloc(0x1000);
    memcpy(orig, (void*)target, 0x1000);
    g_dirty_pages.push_back(std::make_pair(target, orig));
    return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        // Spawn a console
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        freopen("CONIN$", "r", stdin);

        // Install hooks
        iat_hook(NULL, "kernel32.dll", "HeapAlloc", (void*)hooked_HeapAlloc);
        iat_hook(NULL, "kernel32.dll", "HeapFree", (void*)hooked_HeapFree);
        iat_hook(NULL, "kernel32.dll", "ReadFile", (void*)hooked_ReadFile);
        iat_hook(L"dsound.dll", "kernel32.dll", "HeapAlloc", (void*)hooked_HeapAlloc);
        iat_hook(L"dsound.dll", "kernel32.dll", "HeapFree", (void*)hooked_HeapFree);
        iat_hook(L"dsound.dll", "kernel32.dll", "ReadFile", (void*)hooked_ReadFile);

        // Configure mimalloc
        mi_option_set(mi_option_purge_delay, -1);

        // Install custom exception handler
        AddVectoredExceptionHandler(1, exception_handler);

        // Track any writable sections
        auto pe = (char*)GetModuleHandleW(NULL);
        auto nt_header = (PIMAGE_NT_HEADERS32)(pe + ((PIMAGE_DOS_HEADER)pe)->e_lfanew);
        auto file_header = (PIMAGE_FILE_HEADER)(&nt_header->FileHeader);
        auto section_headers = (PIMAGE_SECTION_HEADER)((char*)nt_header + sizeof(IMAGE_NT_HEADERS32));
        char name_tmp[9] = {};
        for (size_t i = 0; i < file_header->NumberOfSections; i++) {
            if (section_headers[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
                auto addr = pe + section_headers[i].VirtualAddress;
                auto size = ROUND_TO_PAGES(section_headers[i].Misc.VirtualSize);
                memcpy(name_tmp, section_headers[i].Name, 8);
                printf("Tracking section %s (addr 0x%X, size 0x%X)\n", name_tmp, addr, size);
                track_region(addr, size);
            }
        }

        // Game-specific stuff...
        // Hook update (oilp-compatible lol)
        *(uint32_t*)&g_orig_update = UPDATE_CALL_ADDR + *(uint32_t*)(UPDATE_CALL_ADDR + 1) + 5;
        patch_call(UPDATE_CALL_ADDR, (void*)hooked_update);
    }
    return TRUE;
}

