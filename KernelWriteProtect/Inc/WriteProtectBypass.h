// ========================================================================
// File: WriteProtectBypass.h
//
// Author: winterknife
//
// Description: Header file for WriteProtectBypass.cpp source file
//
// Modifications:
//  2026-05-12	Created
//  2026-05-15  Updated
// ========================================================================

// ========================================================================
// Pragmas
// ========================================================================

#pragma once

// ========================================================================
// Includes
// ========================================================================

#include "Common.h"

// ========================================================================
// Structures/Enumerations/Unions
// ========================================================================

#pragma region STRUCTS_ENUMS_UNIONS

// Windows x64 hardware PxE (MMU's interpretation)
typedef struct _MMPTE_HARDWARE {
    QWORD Valid               : 1;  // Present
    QWORD Dirty1              : 1;  // Read/Write (cleared together with Dirty bit)
    QWORD Owner               : 1;  // User/Supervisor
    QWORD WriteThrough        : 1;  // Page-level Write Through
    QWORD CacheDisable        : 1;  // Page-level Cache Disable
    QWORD Accessed            : 1;  // Accessed
    QWORD Dirty               : 1;  // Dirty
    QWORD LargePage           : 1;  // Page Attribute Table (PAT) or Page Size (PS)
    QWORD Global              : 1;  // Global
    QWORD CopyOnWrite         : 1;  // Copy On Write (CoW)
    QWORD Unused              : 1;  // Ignored
    QWORD Write               : 1;  // Used by the Memory Manager to recognize the page as writable
    QWORD PageFrameNumber     : 36; // Page Frame Number (PFN)
    QWORD ReservedForHardware : 4;  // Reserved (must be 0)
    QWORD ReservedForSoftware : 4;  // Reserved (must be 0)
    QWORD WsleAge             : 4;  // Working Set List Entry (WSLE)
    QWORD WsleProtection      : 3;  // Working Set List Entry (WSLE)
    QWORD NoExecute           : 1;  // Execute Disable (XD/NX)
} MMPTE_HARDWARE, *PMMPTE_HARDWARE;

#pragma endregion

// ========================================================================
// Undocumented kernel API function prototypes
// ========================================================================

#pragma region PROTOTYPES

EXTERN_C NTSYSAPI PVOID NTAPI RtlPcToFileHeader(
	_In_  PVOID  PcValue,
	_Out_ PVOID* BaseOfImage
);

EXTERN_C NTSYSAPI PVOID NTAPI RtlFindExportedRoutineByName(
	_In_   PVOID BaseOfImage,
	_In_z_ PCSTR RoutineName
);

#pragma endregion

// ========================================================================
// C routine declarations
// ========================================================================

#pragma region DECLARATIONS

/// @brief Copies the contents of a source memory block to a destination memory block with write protect bypass using CR0.WP manipulation
/// @param pDestination Pointer to the destination memory block to copy the bytes to
/// @param pcSource Pointer to the source memory block to copy the bytes from
/// @param dwptrLength Number of bytes to copy from the source to the destination
_IRQL_requires_max_(DISPATCH_LEVEL)
EXTERN_C DECLSPEC_NOINLINE VOID __stdcall copy_memory_cr0_wp(
	_Out_writes_bytes_all_(dwptrLength) VOID*       pDestination,
	_In_reads_bytes_(dwptrLength)       CONST VOID* pcSource,
	_In_                                DWORD_PTR   dwptrLength
);

/// @brief Copies the contents of a source memory block to a destination memory block with write protect bypass using double mapping
/// @param pDestination Pointer to the destination memory block to copy the bytes to
/// @param pcSource Pointer to the source memory block to copy the bytes from
/// @param dwptrLength Number of bytes to copy from the source to the destination
_IRQL_requires_max_(DISPATCH_LEVEL)
EXTERN_C DECLSPEC_NOINLINE VOID __stdcall copy_memory_double_mapping(
	_Out_writes_bytes_all_(dwptrLength) VOID*       pDestination,
	_In_reads_bytes_(dwptrLength)       CONST VOID* pcSource,
	_In_                                DWORD_PTR   dwptrLength
);

/// @brief Copies the contents of a source memory block to a destination memory block with write protect bypass using PTE manipulation
/// @param pDestination Pointer to the destination memory block to copy the bytes to
/// @param pcSource Pointer to the source memory block to copy the bytes from
/// @param dwptrLength Number of bytes to copy from the source to the destination
_IRQL_requires_max_(DISPATCH_LEVEL)
EXTERN_C DECLSPEC_NOINLINE VOID __stdcall copy_memory_pte(
	_Out_writes_bytes_all_(dwptrLength) VOID*       pDestination,
	_In_reads_bytes_(dwptrLength)       CONST VOID* pcSource,
	_In_                                DWORD_PTR   dwptrLength
);

#pragma endregion