#include <Windows.h>
#include <Psapi.h>
#include <winuser.h>
#include <stdio.h>

DWORD get_pid_by_name(const char *process_name)
{
	DWORD process_ids[1024], bytes_needed, num_processes;
	if (!EnumProcesses(process_ids, sizeof(process_ids), &bytes_needed))
	{
		printf("Failed to enumerate processes.\n");
		return 0;
	}

	num_processes = bytes_needed / sizeof(DWORD);
	for (DWORD i = 0; i < num_processes; i++)
	{
		HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_ids[i]);
		if (process) {
			char name[MAX_PATH];
			if (GetModuleBaseName(process, NULL, name, sizeof(name))) {
				if (strcmp(name, process_name) == 0)
				{
					CloseHandle(process);
					return process_ids[i];
				}
			}
			CloseHandle(process);
		}
	}

	printf("Failed to find process '%s'.\n", process_name);
	return 0;
}

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

int main()
{
	DWORD pid = get_pid_by_name("process.exe");
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!process) {
		printf("Failed to open process %d\n", pid);
		return -1;
	}
	if (!DebugActiveProcess(pid)) {
		printf("Failed to attach debugger to process %d.\n", pid);
		return -1;
	}

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