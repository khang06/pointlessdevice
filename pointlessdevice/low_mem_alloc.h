#pragma once

#include <Windows.h>
#include <type_traits>
#include <utility>

#include "zero/util.h"

#define FAR_CALL_IMM(seg, addr, ret, ...) __asm__ volatile ("lcall %[Seg],%[Addr]":ret: [Seg]"i"(seg), [Addr]"i"(addr) __VA_OPT__(,) __VA_ARGS__)

bool init_unwow64_ntdll();

PTR64<> regcall VirtualAlloc64Adapter(PTR64<> base_address, uint64_t size, uint32_t allocation_type, uint32_t protection);
template<bool return_status = false, typename R = std::conditional_t<return_status, std::pair<PTR64<>, NTSTATUS>, PTR64<>>>
inline R
VirtualAlloc64(
	PTR64<> address,
	uint64_t size,
	uint32_t allocation_type,
	uint32_t protection
) {
	PTR64<> ret;
	NTSTATUS status;
	FAR_CALL_IMM(
		0x33, VirtualAlloc64Adapter,
		MACRO_EVAL("=A"(ret), "=c"(status)),
		"A"(address),
		"c"((uint32_t)size), "D"((uint32_t)(size >> 32)),
		"S"(allocation_type),
		"b"(protection)
		: clobber_list("xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5")
	);
	__asm__ volatile ("":::clobber_list("esi", "edi"));
	if constexpr (return_status) {
		return std::make_pair(ret, status);
	}
	else {
		return ret;
	}
}

PTR64<> regcall memcpy64Adapter(PTR64<> dst, PTR64<> src, uint64_t size);
template <typename T1, typename T2> requires(std::is_pointer_v<T1>&& std::is_same_v<remove_pointer_t<T1>, void>&& std::is_pointer_v<T2>&& std::is_same_v<remove_pointer_t<T2>, void>)
inline PTR64<> regcall memcpy64(T1 dst, T2 src, uint64_t size) {
	PTR64<> ret;
	if constexpr (std::is_same_v<T1, PTR64<>> && std::is_same_v<T2, PTR64<>>) {
		FAR_CALL_IMM(0x33, memcpy64Adapter,
			"=A"(ret),
			"A"(dst),
			"S"((uint32_t)src), "D"((uint32_t)((uint64_t)src >> 32)),
			"c"((uint32_t)size), "b"((uint32_t)(size >> 32))
			: clobber_list("xmm0")
		);
	}
	else if constexpr (std::is_same_v<T1, PTR64<>>) {
		FAR_CALL_IMM(0x33, memcpy64Adapter,
			"=A"(ret),
			"A"(dst),
			"S"((uint32_t)src), "D"(0),
			"c"((uint32_t)size), "b"((uint32_t)(size >> 32))
			: clobber_list("xmm0")
		);
	}
	else if constexpr (std::is_same_v<T2, PTR64<>>) {
		FAR_CALL_IMM(0x33, memcpy64Adapter,
			"=A"(ret),
			"a"((uint32_t)dst), "d"(0),
			"S"((uint32_t)src), "D"((uint32_t)((uint64_t)src >> 32)),
			"c"((uint32_t)size), "b"((uint32_t)(size >> 32))
			: clobber_list("xmm0")
		);
	}
	else {
		FAR_CALL_IMM(0x33, memcpy64Adapter,
			"=A"(ret),
			"a"((uint32_t)dst), "d"(0),
			"S"((uint32_t)src), "D"(0),
			"c"((uint32_t)size), "b"((uint32_t)(size >> 32))
			: clobber_list("xmm0")
		);
	}
	__asm__ volatile ("":::clobber_list("ecx", "ebx", "esi", "edi"));
	return ret;
}
