# Minimal debugger in C on Windows #

_March. 24, 2023_

Sometimes you need to use a debugger, but not for traditional debugging. Instead, you need to leverage the power of a debugger for an automated task, like dumping memory everytime something specific happens.

In this article I'll go over writing a minimal custom debugger in C using the win32 debug and process APIs. This debugger will attach to a running process, set a breakpoint and handle everything necessary to debug the process cleanly.

Such an exercise also offers a small window into the internals of debugger tools you might use everyday, like x64dbg, and might help understand how debugging actually works under the hood.

First off, the headers:

```c
#include <Windows.h>
#include <Psapi.h>
#include <winuser.h>
#include <stdio.h>
```

Then, we'll open the process and start debugging:

```c
int main()
{
	DWORD pid = 1234;
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!process) {
		printf("Failed to open process %d\n", pid);
		return -1;
	}
	if (!DebugActiveProcess(pid)) {
		printf("Failed to attach debugger to process %d.\n", pid);
		return -1;
	}
```

Opening the process and starting to debug it are two independant tasks, but we'll need both down the line. As for the process ID (pid), how you obtain it is up to you. The [full code](https://helyos96.github.io/debugger.c) contains a function to retrieve a pid from an executable name.

Next up, we'll retrieve the process' base address. This is not strictly required, but if like me you want to place breakpoints at specific offsets, then you'll need the base address to compute the final address where you can break. Nowadays most processes on Windows use [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization), meaning that their base address is randomized on every run.

```c
	MODULEINFO module_info;
	HMODULE module_handle;
	DWORD dummy;
	if (!EnumProcessModules(process, &module_handle, sizeof(module_handle), &dummy)) {
		printf("Failed to retrieve module handle. Error %u\n", GetLastError());
		return -1;
	}

	if (!GetModuleInformation(process, module_handle, &module_info, sizeof(module_info))) {
		printf("Failed to retrieve module information.\n");
		return -1;
	}

	printf("Process base address: %p\n", module_info.lpBaseOfDll);
```

Then, we'll want to place our breakpoint. More specifically, a software breakpoint. Setting it up is rather easy: figure out the address where you want to break, and overwrite the byte at this location with `0xCC`.

`0xCC` is x86 bytecode for the INT3 instruction. It instructs the CPU to pause the execution and notify the OS that an interrupt was hit.

Let's create some helper to do that:

```c
typedef struct Breakpoint {
	BYTE old_instruction;
	LPVOID address;
} Breakpoint;

const BYTE int3 = 0xCC;	// INT 3

int set_breakpoint(Breakpoint *bp, HANDLE process, LPVOID address)
{
	DWORD old_protection;

	if (!VirtualProtectEx(process, address, 1, PAGE_EXECUTE_READWRITE, &old_protection)) {
		printf("Failed to set memory protection.\n");
		return 0;
	}

	// Save the old byte
	if (!ReadProcessMemory(process, address, &bp->old_instruction, 1, NULL)) {
		printf("Failed to read memory.\n");
		return 0;
	}

	// Overwrite it with 0xCC
	if (!WriteProcessMemory(process, address, &int3, 1, NULL)) {
		printf("Failed to write memory.\n");
		return 0;
	}

	if (!VirtualProtectEx(process, address, 1, old_protection, &old_protection)) {
		printf("Failed to set memory protection.\n");
		return 0;
	}

	bp->address = address;
	return 1;
}
```

Notice how we save what the previous byte is before overwriting it (`bp->old_instruction`). It'll come up later.

The calls to `VirtualProtectEx` are here to make sure the pages where we want to write the breakpoint are writable. Otherwise the call to `WriteProcessMemory` would fail.

Back to our main, we can set a breakpoint and start the debugging loop:

```c
	const unsigned int offset = 0x1337;
	Breakpoint bp;
	if (!set_breakpoint(&bp, process, (LPVOID)((char*) module_info.lpBaseOfDll + offset))) {
		printf("Failed to set breakpoint\n");
		return -1;
	}

	while(1) {
		DEBUG_EVENT debug_event;
		DWORD continue_status = DBG_CONTINUE;

		if (!WaitForDebugEvent(&debug_event, INFINITE)) {
			printf("Failed to wait for debug event.\n");
			break;
		}
		
		switch (debug_event.dwDebugEventCode) {
		case EXCEPTION_DEBUG_EVENT:
			if (debug_event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
				printf("Breakpoint hit at address %p\n", debug_event.u.Exception.ExceptionRecord.ExceptionAddress);
				if (debug_event.u.Exception.ExceptionRecord.ExceptionAddress == bp.address) {
					printf("Our breakpoint was hit!\n");
					/* You can do anything here now */

				} else {
					continue_status = DBG_EXCEPTION_NOT_HANDLED;
				}
			} else {
				continue_status = DBG_EXCEPTION_NOT_HANDLED;
			}
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			CloseHandle(debug_event.u.CreateThread.hThread);
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			CloseHandle(debug_event.u.CreateProcessInfo.hFile);
			break;
		case LOAD_DLL_DEBUG_EVENT:
			CloseHandle(debug_event.u.LoadDll.hFile);
			break;
		case EXIT_THREAD_DEBUG_EVENT:
		case EXIT_PROCESS_DEBUG_EVENT:
		case UNLOAD_DLL_DEBUG_EVENT:
		case OUTPUT_DEBUG_STRING_EVENT:
		case RIP_EVENT:
			break;
		default:
			printf("Unhandled event 0x%08X\n", debug_event.dwDebugEventCode);
			continue_status = DBG_EXCEPTION_NOT_HANDLED;
			break;
		}
		if (!ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)) {
			printf("Failed to continue debug event.\n");
			break;
		}
	}

	if (!DebugActiveProcessStop(pid)) {
		printf("Failed to detach debugger from process %d.\n", pid);
		return -1;
	}
	CloseHandle(process);
	return 0;
}
```

There's a lot of code here, but most of it is boilerplate. The juicy parts are:

* The `WaitForDebugEvent` call. This will trigger for many things that don't interest us, but once in a while it'll be our breakpoint hitting.
* What happens in `case EXCEPTION_DEBUG_EVENT:`. We check that the `ExceptionCode` is `EXCEPTION_BREAKPOINT` to know if a breakpoint was hit, and then we check if it is ours by comparing its `ExceptionAddress` with ours.
* Past all the boilerplate, we finally call `ContinueDebugEvent` which resumes the process execution. The last parameter is important. You want to use `DBG_CONTINUE` for events that you handled, like your own breakpoints. This tells the OS not to handle them for you.
For anything else though, you should pass in `DBG_EXCEPTION_NOT_HANDLED`. This tells the OS to handle it like usual. For instance, an application using `mmap()` on a file will most likely trigger pagefault exceptions when it tries to access the content. This is normal, these exceptions are meant to be caught by the OS who can then load the content in its exception handling routine.

There is a fatal flaw in the code so far: we hit our breakpoint, but then we just resume execution. Even though we overwrote an important byte when we set it. That byte was regular bytecode meant to execute whatever, but it is vital to the process' proper execution.

To resume execution properly, we are gonna need to rewind:
* Move the instruction pointer 1 byte back
* Restore the original byte
* Run the process for one instruction (single step)
* Write our breakpoint 0xCC back again

```c
int reset_breakpoint(const Breakpoint *bp, HANDLE process, HANDLE thread, DEBUG_EVENT *debug_event)
{
	CONTEXT context;
	context.ContextFlags = CONTEXT_CONTROL;
	if (!GetThreadContext(thread, &context)) {
		printf("Failed to get thread context.\n");
		return 1;
	}
	// Move back one byte to re-execute the original instruction
	context.Rip -= 1;
	// Set the thread context to resume execution with a single step
	context.EFlags |= 0x100;
	if (!SetThreadContext(thread, &context)) {
		printf("Failed to set thread context. Error %u\n", GetLastError());
		return 1;
	}

	// Rewrite the original instruction
	DWORD old_protection;
	if (!VirtualProtectEx(process, bp->address, 1, PAGE_EXECUTE_READWRITE, &old_protection)) {
		printf("Failed to set memory protection.\n");
		return 1;
	}
	if (!WriteProcessMemory(process, bp->address, &bp->old_instruction, 1, NULL)) {
		printf("Failed to restore original instruction.\n");
		return 1;
	}
	if (!VirtualProtectEx(process, bp->address, 1, old_protection, &old_protection)) {
		printf("Failed to set memory protection.\n");
		return 1;
	}

	// Continue execution
	if (!ContinueDebugEvent(debug_event->dwProcessId, debug_event->dwThreadId, DBG_CONTINUE)) {
		printf("Failed to continue debug event.\n");
		return 1;
	}

	DEBUG_EVENT debug_event2;
	// Wait for the single step to complete
	while (WaitForDebugEvent(&debug_event2, INFINITE))
	{
		if (debug_event2.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
			debug_event2.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
		{
			// Rewrite the INT3 breakpoint
			if (!VirtualProtectEx(process, bp->address, 1, PAGE_EXECUTE_READWRITE, &old_protection)) {
				printf("Failed to set memory protection.\n");
				return 1;
			}

			if (!WriteProcessMemory(process, bp->address, &int3, 1, NULL)) {
				printf("Failed to rewrite breakpoint.\n");
				return 1;
			}

			if (!VirtualProtectEx(process, bp->address, 1, old_protection, &old_protection)) {
				printf("Failed to set memory protection.\n");
				return 1;
			}

			CONTEXT context_inner;
			context_inner.ContextFlags = CONTEXT_CONTROL;
			if (!GetThreadContext(thread, &context_inner)) {
				printf("Failed to get thread context_inner.\n");
				return 1;
			}

			// Clear the single step flag in the EFLAGS register
			context_inner.EFlags &= ~0x100;

			if (!SetThreadContext(thread, &context_inner)) {
				printf("Failed to set thread context_inner.\n");
				return 1;
			}

			break;
		}
		else
		{
			if (!ContinueDebugEvent(debug_event2.dwProcessId, debug_event2.dwThreadId, DBG_EXCEPTION_NOT_HANDLED)) {
				printf("Failed to continue debug event.\n");
				return 1;
			}
		}
	}

	return 0;
}
```

Again, quite a lot to unpack here. Here are the key points:

* We're using `GetThreadContext` to get the thread's `CONTEXT` struct. It contains all the CPU registers and their current value. We set `ContextFlags` to `CONTEXT_CONTROL` to ask only for the control\* registers (EFLAGS and RIP are the ones we're interested in).
    * RIP is the current instruction pointer, i.e the address of the next instruction to be executed. Since our breakpoint 0xCC consumed one byte, we need to decrement it by 1.
	* EFLAGS lets us add the flag 0x100 which corresponds to a single step trap: the CPU will execute one instruction and then generate a debug event.
* We then keep debugging until we hit a `EXCEPTION_DEBUG_EVENT` of type `EXCEPTION_SINGLE_STEP`.
* Once we hit it, we write back our 0xCC breakpoint and remove the 0x100 single step flag from EFLAGS.

\* _You can also use `CONTEXT_INTEGER` for general purpose registers (RAX, RDX, R8..) or `CONTEXT_DEBUG_REGISTERS` for the debug registers. You can combine these flags if you want everything._

Et voilà, we just reset our breakpoint and we can keep the execution going.

We just need to update our code in main to call reset_breakpoint at the end of our handler

```c
	case EXCEPTION_DEBUG_EVENT:
		if (debug_event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
			printf("Breakpoint hit at address %p\n", debug_event.u.Exception.ExceptionRecord.ExceptionAddress);
			if (debug_event.u.Exception.ExceptionRecord.ExceptionAddress == bp.address) {
				printf("Our breakpoint was hit!\n");
				/* You can do anything here now */

				HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, debug_event.dwThreadId);
				if (!thread) {
					printf("Failed to open thread.\n");
					return 1;
				}
				reset_breakpoint(&bp, process, thread, &debug_event);
				CloseHandle(thread);
			} else {
				continue_status = DBG_EXCEPTION_NOT_HANDLED;
			}
		} else {
			continue_status = DBG_EXCEPTION_NOT_HANDLED;
		}
		break;
```

That's all! You can view the full code [here](https://helyos96.github.io/debugger.c).

One question you might have is, "what do I do once my breakpoint hits?". Well, that's up to you! If you need to know what's in the registers, call `GetThreadContext`. You can also call `ReadProcessMemory` and `WriteProcessMemory`.

Note that there are likely bugs in this implementation. Biggest one I can think of is is the process does heavy multithreading, the same breakpoint could be hit multiple times before the thread with the single step reinitializes it. Or it could be missed because a thread flew by while the old byte was written in. It's good enough and a good exercise but I wouldn't recommend using the code as-is for anything super serious.

Some nice TODOs would be:

* Handle CTRL-C event so that the debugger can detach cleanly from the process. Right now the process is killed if you CTRL-C the debugger.
* Do reset_breakpoint better where the SINGLE_STEP debug event is handled in the main loop rather than its own loop.
* Hardware breakpoints would be a nice follow-up exercise.