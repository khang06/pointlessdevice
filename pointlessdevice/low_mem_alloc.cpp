
#include <stdlib.h>
#include <stdint.h>

#define NOMINMAX
#include "Windows.h"
#include <winternl.h>

#include "zero/util.h"

#define FAR_CALL_IMM(seg, addr, ret, ...) __asm__ volatile ("lcall %[Seg],%[Addr]":ret: [Seg]"i"(seg), [Addr]"i"(addr) __VA_OPT__(,) __VA_ARGS__)

struct NtDll64Data {
	PTR64<> ldr_get_procedure_addresss;
	PTR64<> ldr_load_dll_address;
	PTR64<> nt_allocate_virtual_memory;
	PTR64<> nt_query_virtual_memory;
	PTR64<> nt_free_virtual_memory;
	PTR64<> nt_protect_virtual_memory;
	PTR64<> nt_read_virtual_memory;
	PTR64<> nt_write_virtual_memory;
	HMODULE handle;
};
struct Kernel3264Data {
	PTR64<> get_proc_addresss;
	PTR64<> virtual_alloc_64;
	HMODULE handle;
};

extern "C" {
	dllexport NtDll64Data ntdll64_data asm("ntdll64_data");
	dllexport Kernel3264Data kernel3264_data asm("kernel3264_data");
}

dllexport gnu_noinline naked
PTR64<>						// EDX:EAX, XMM0
regcall GetModuleHandleW64Adapter(
	PTR64<const wchar_t> name	// EDX:EAX
) {
	__asm__ volatile (
		INTEL_64_DIRECTIVE
		"SHL RDX, 32 \n"
		"MOV EAX, EAX \n"
		"OR RAX, RDX \n"
		"JZ 3f \n"
		"MOV RCX, QWORD PTR GS:[0x60] \n"
		"MOV R8, QWORD PTR [RCX+0x18] \n"
		"MOV RDI, QWORD PTR [R8+0x10] \n"
		"ADD R8, 0x10 \n"
		"1: \n"
		"MOVZX ESI, WORD PTR [RDI+0x58] \n"
		"TEST ESI, ESI \n"
		"JNZ 1f \n"
		"2: \n"
		"MOV RDI, QWORD PTR [RDI] \n"
		"CMP RDI, R8 \n"
		"JNE 1b \n"
		"XOR EAX, EAX \n"
		"3: \n"
		"XORPS XMM0, XMM0 \n"
		"RETF \n"
		"1: \n"
		"MOV R9, QWORD PTR [RDI+0x60] \n"
		"MOV RBX, RAX \n"
		"SUB R9, RAX \n"
		"1: \n"
		"MOVZX ECX, BYTE PTR [RBX] \n"
		"CMP CL, BYTE PTR [RBX*1+R9] \n"
		"JNE 2b \n"
		"INC RBX \n"
		"DEC ESI \n"
		"JNZ 1b \n"
		"MOVQ XMM0, QWORD PTR [RDI+0x30] \n"
		"MOV RAX, QWORD PTR [RDI+0x30] \n"
		"MOV RDX, RAX \n"
		"SHR RDX, 32 \n"
		"RETF"
		);
}

template<typename T> requires(std::is_pointer_v<T>&& std::is_same_v<remove_pointer_t<T>, const wchar_t>)
inline PTR64<> regparm(2) GetModuleHandleW64(T name) {
	PTR64<> ret;
	if constexpr (std::is_same_v<T, PTR64<const wchar_t>>) {
		FAR_CALL_IMM(0x33, GetModuleHandleW64Adapter,
			"=A"(ret),
			"a"((uint32_t)name), "d"((uint32_t)((uint64_t)name >> 32))
			: clobber_list("ecx", "ebx", "esi", "edi", "xmm0")
		);
	}
	else {
		FAR_CALL_IMM(0x33, GetModuleHandleW64Adapter,
			"=A"(ret),
			"a"((uint32_t)name), "d"(0)
			: clobber_list("ecx", "ebx", "esi", "edi", "xmm0")
		);
	}
	return ret;
}

dllexport gnu_noinline naked
PTR64<>							// EDX:EAX, XMM0
regcall GetProcAddress64Adapter(
	PTR64<> module_handle,			// EDX:EAX
	PTR64<const char> lookup_name	// EDI:ECX
) {
	__asm__ volatile (
		INTEL_64_DIRECTIVE
		"XORPS XMM0, XMM0 \n"
		"SHL RDX, 32 \n"
		"MOV EAX, EAX \n"
		"LEA RSI, [RAX*1+RDX] \n"
		"MOV EAX, DWORD PTR [RAX*1+RDX+0x3C] \n"
		"MOV EDX, DWORD PTR [RSI*1+RAX+0x88] \n"
		"TEST RAX, RAX \n"
		"JZ 1f \n"
		"SHL RDI, 32 \n"
		"MOV ECX, ECX \n"
		"OR RCX, RDI \n"
		"CMP RCX, 0x10000 \n"
		"JB 2f \n"
		"MOV EDI, DWORD PTR [RDX*1+RSI+0x18] \n"
		"MOV R8D, DWORD PTR [RDX*1+RSI+0x20] \n"
		"ADD R8, RSI \n"
		"JMP 3f \n"
		".align 16, 0xCC \n"
		"4: \n"
		"CMP AL, R11B \n"
		"JE 4f \n"
		"3: \n"
		".byte 0x48, 0x81, 0xEF, 0x01, 0x00, 0x00, 0x00 \n" // "SUB RDI, 1 \n" (wide encoding)
		"JB 1f \n"
		"MOV R9D, DWORD PTR [RDI*4+R8] \n"
		"ADD R9, RSI \n"
		"XOR R10D, R10D \n"
		".align 16 \n"
		"5: \n"
		"MOVZX R11D, BYTE PTR [R10*1+RCX] \n"
		"INC R10 \n"
		"MOVZX EAX, BYTE PTR [R9*1+R10-1] \n"
		"TEST R11B, R11B \n"
		"JZ 4b \n"
		"CMP AL, R11B \n"
		"JE 5b \n"
		"JMP 3b \n"
		"2: \n"
		"CMP ECX, DWORD PTR [RDX*1+RSI+0x14] \n"
		"JB 2f \n"
		"1: \n"
		"XOR EAX, EAX \n"
		"XOR EDX, EDX \n"
		"RETF \n"
		"4: \n"
		"MOV EAX, DWORD PTR [RDX*1+RSI+0x24] \n"
		"ADD RAX, RSI \n"
		"MOVZX ECX, WORD PTR [RDI*2+RAX] \n"
		"2: \n"
		"MOV EAX, DWORD PTR [RDX*1+RSI+0x1C] \n"
		"ADD RAX, RSI \n"
		"MOV EAX, DWORD PTR [RCX*4+RAX] \n"
		"ADD RAX, RSI \n"
		"MOVQ XMM0, RAX \n"
		"MOV RDX, RAX \n"
		"SHR RDX, 32 \n"
		"RETF"
		);
}

template<typename T>
static forceinline auto handle_to_base_ptr(T handle) {
	if constexpr (std::is_same_v<T, HMODULE>) {
		return (T)((uintptr_t)handle & ~(uintptr_t)3);
	}
#if NATIVE_BITS == 32
	if constexpr (std::is_same_v<T, PTR64<>>) {
		return (T)((uint64_t)handle & ~(uint64_t)3);
	}
#elif NATIVE_BITS == 64
	if constexpr (std::is_same_v<T, PTR32Z<>> || std::is_same_v<T, PTR32S<>>) {
		return (T)((uint32_t)handle & ~(uint32_t)3);
	}
#endif
}

template <typename T> requires(std::is_pointer_v<T>&& std::is_same_v<remove_pointer_t<T>, const char>)
inline PTR64<> regcall GetProcAddress64(PTR64<> module_handle, T search_name) {
	PTR64<> ret;
	if constexpr (std::is_same_v<T, PTR64<const char>>) {
		FAR_CALL_IMM(0x33, GetProcAddress64Adapter,
			"=A"(ret),
			"A"(handle_to_base_ptr(module_handle)),
			"c"((uint32_t)search_name), "D"((uint32_t)((uint64_t)search_name >> 32))
			: clobber_list("esi", "xmm0")
		);
	}
	else {
		FAR_CALL_IMM(0x33, GetProcAddress64Adapter,
			"=A"(ret),
			"A"(handle_to_base_ptr(module_handle)),
			"c"((uint32_t)search_name), "D"(0)
			: clobber_list("esi", "xmm0")
		);
	}
	__asm__ volatile ("":::clobber_list("ecx", "edi"));
	return ret;
}

dllexport bool init_unwow64_ntdll() {
	if (PTR64<> ntdll64_handle = GetModuleHandleW64(L"ntdll.dll")) {
		PTR64<> nt_allocate_virtual_memory = ntdll64_data.nt_allocate_virtual_memory = GetProcAddress64(ntdll64_handle, "NtAllocateVirtualMemory");
		PTR64<> nt_query_virtual_memory = ntdll64_data.nt_query_virtual_memory = GetProcAddress64(ntdll64_handle, "NtQueryVirtualMemory");
		PTR64<> nt_free_virtual_memory = ntdll64_data.nt_free_virtual_memory = GetProcAddress64(ntdll64_handle, "NtFreeVirtualMemory");
		PTR64<> nt_protect_virtual_memory = ntdll64_data.nt_protect_virtual_memory = GetProcAddress64(ntdll64_handle, "NtProtectVirtualMemory");
		PTR64<> nt_read_virtual_memory = ntdll64_data.nt_read_virtual_memory = GetProcAddress64(ntdll64_handle, "NtReadVirtualMemory");
		PTR64<> nt_write_virtual_memory = ntdll64_data.nt_write_virtual_memory = GetProcAddress64(ntdll64_handle, "NtWriteVirtualMemory");
		if (
			nt_allocate_virtual_memory &&
			nt_query_virtual_memory &&
			nt_free_virtual_memory &&
			nt_protect_virtual_memory &&
			nt_read_virtual_memory &&
			nt_write_virtual_memory
			) {
			return true;
		}
	}
	return false;
}

dllexport gnu_noinline naked
PTR64<>						// EDX:EAX, XMM0
// NTSTATUS					// ECX
regcall VirtualAlloc64Adapter(
	PTR64<> base_address,		// EDX:EAX
	uint64_t size,				// EDI:ECX
	uint32_t allocation_type,	// ESI
	uint32_t protection			// EBX
) {
	__asm__ volatile (
		INTEL_64_DIRECTIVE
		"MOV R8D, ESI \n"
		"MOV ESI, ESP \n"
		"SUB ESP, 0x48 \n"
		"AND ESP, -0x10 \n"
		"MOV EAX, EAX \n"
		"SHL RDX, 32 \n"
		"OR RDX, RAX \n"
		"MOV QWORD PTR [RSP+0x38], RDX \n"
		"SHL RDI, 32 \n"
		"MOV EAX, ECX \n"
		"OR RAX, RDI \n"
		"MOV QWORD PTR [RSP+0x40], RAX \n"
		"MOV DWORD PTR [RSP+0x28], EBX \n"
		"MOV DWORD PTR [RSP+0x20], R8D \n"
		"XOR EDI, EDI \n"
		"LEA RDX, [RSP+0x38] \n"
		"LEA R9, [RSP+0x40] \n"
		"MOV RCX, -1 \n"
		"XOR R8D, R8D \n"
		"CALL QWORD PTR [ntdll64_data + 0x10] \n"
		"MOV ECX, EAX \n"
		"TEST EAX, EAX \n"
		"CMOVNS RDI, QWORD PTR [RSP+0x38] \n"
		"MOV RDX, RDI \n"
		"SHR RDX, 32 \n"
		"MOVQ XMM0, RDI \n"
		"MOV RAX, RDI \n"
		"MOV ESP, ESI \n"
		"RETF"
		);
}

dllexport gnu_noinline naked
PTR64<>			// EDX:EAX, XMM0
regcall memcpy64Adapter(
	PTR64<> dst,	// EDX:EAX
	PTR64<> src,	// EDI:ESI
	uint64_t size	// EBX:ECX
) {
	__asm__ volatile (
		INTEL_64_DIRECTIVE
		"MOV ESI, ESI \n"
		"SHL RDI, 32 \n"
		"OR RSI, RDI \n"
		"SHL RBX, 32 \n"
		"MOV ECX, ECX \n"
		"OR RCX, RBX \n"
		"MOV EDI, EAX \n"
		"MOV EBX, EDX \n"
		"SHL RBX, 32 \n"
		"OR RDI, RBX \n"
		"MOVQ XMM0, RDI \n"
		"REP movsb \n"
		"RETF"
		);
}
