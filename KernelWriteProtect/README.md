# EVENSTAR - KernelWriteProtect

## Version

- `v2.0.0`

## Brief

- `ISA: x86`
- `Mode: Long`
- `Bitness: 64-bit`
- `CPL: 0`
- `OS: Windows`
- `Language: C`
- Sample code that demonstrates three techniques for writing into read-only pages in kernel space using `CR0.WP` manipulation, `MDL` double mapping, and `PTE` manipulation

## Usage

```
0: kd> vertarget
Windows 10 Kernel Version 26100 MP (2 procs) Free x64
Edition build lab: 26100.1.amd64fre.ge_release.240331-1435
Kernel base = 0xfffff801`ece00000 PsLoadedModuleList = 0xfffff801`edcf5150
Debug session time: Mon May 18 11:32:44.468 2026 (UTC - 4:00)
System Uptime: 0 days 1:46:43.304

0: kd> g
[DBG]: +++ KernelWriteProtect.sys Loaded +++
[DBG]: KernelWriteProtect.sys Built May 18 2026 11:31:17
[DBG]: KernelWriteProtect: DriverObject = FFFFBD0FF0496E20
[DBG]: KernelWriteProtect: RegistryPath = \REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\KernelWriteProtect
[DBG]: --- KernelWriteProtect.sys Unloaded ---
Break instruction exception - code 80000003 (first chance)
*******************************************************************************
*                                                                             *
*   You are seeing this message because you pressed either                    *
*       CTRL+C (if you run console kernel debugger) or,                       *
*       CTRL+BREAK (if you run GUI kernel debugger),                          *
*   on your debugger machine's keyboard.                                      *
*                                                                             *
*                   THIS IS NOT A BUG OR A SYSTEM CRASH                       *
*                                                                             *
* If you did not intend to break into the debugger, press the "g" key, then   *
* press the "Enter" key now.  This message might immediately reappear.  If it *
* does, press "g" and "Enter" again.                                          *
*                                                                             *
*******************************************************************************
nt!DbgBreakPointWithStatus:
fffff801`ed2fb1b0 cc              int     3

0: kd> !pte 0xFFFFF78000000738
                                           VA fffff78000000738
PXE at FFFFF2793C9E4F78    PPE at FFFFF2793C9EF000    PDE at FFFFF2793DE00000    PTE at FFFFF27BC0000000
contains 0000000000286063  contains 0000000000285063  contains 0000000000284063  contains 8A00000000283121
pfn 286       ---DA--KWEV  pfn 285       ---DA--KWEV  pfn 284       ---DA--KWEV  pfn 283       -G--A--KR-V

0: kd> db 0xFFFFF78000000738 LC
fffff780`00000738  41 41 41 41 41 41 41 41-41 41 41 41              AAAAAAAAAAAA
```

## Tested OS Versions

- `Windows 11 25H2 Build 26200 Revision 8246 64-bit`

## References

1. [BattlEye hypervisor detection](https://secret.club/2020/01/12/battleye-hypervisor-detection.html)
2. [ac](https://github.com/donnaskiez/ac)
3. [EfiGuard](https://github.com/Mattiwatti/EfiGuard)
4. [kernelhook](https://github.com/adrianyy/kernelhook)
5. [Exploit Development: Leveraging Page Table Entries for Windows Kernel Exploitation](https://connormcgarr.github.io/pte-overwrites/)
6. [g_CiOptions in a Virtualized World](https://trustedsec.com/blog/g_cioptions-in-a-virtualized-world)