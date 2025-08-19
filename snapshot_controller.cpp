#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h> // For suspending/resuming threads

// Replicate the target's state struct so we know its size and layout
struct ProgramState {
    long long iteration_count;
    long long last_update_timestamp;
    int suspicion_counter;
    char status_message[64];
};

// Helper function to suspend/resume a process by its PID on Windows
void setProcessSuspended(DWORD pid, bool suspend) {
    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnapshot == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hThreadSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    if (suspend) SuspendThread(hThread);
                    else ResumeThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnapshot, &te));
    }
    CloseHandle(hThreadSnapshot);
}

void printSnapshot(const ProgramState& s, const std::string& title) {
    std::cout << "\n--- " << title << " ---" << std::endl;
    std::cout << "  Iteration Count: " << s.iteration_count << std::endl;
    std::cout << "  Timestamp:       " << s.last_update_timestamp << std::endl;
    std::cout << "  Suspicion Level: " << s.suspicion_counter << std::endl;
    std::cout << "  Status Message:  \"" << s.status_message << "\"" << std::endl;
    std::cout << "----------------------" << std::endl;
}

int main(int argc, char* argv[]) {
    // --- Step 1: Parse Command-Line Arguments ---
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <PID> <HexAddressOfState>" << std::endl;
        std::cerr << "Example: " << argv << " 1234 0x7ff6b3a20040" << std::endl;
        return 1;
    }

    DWORD target_pid;
    uintptr_t target_addr_val;

    // Parse PID (decimal)
    try {
        target_pid = std::stoi(argv[1]);
    } catch (const std::exception& e) {
        std::cerr << "Error: Invalid PID provided. Please enter a number." << std::endl;
        return 1;
    }

    // Parse Address (hexadecimal) - C++17 compatible method
    try {
        std::string addr_str = argv[2];
        target_addr_val = std::stoull(addr_str, nullptr, 16);
    } catch (const std::exception& e) {
        std::cerr << "Error: Invalid hexadecimal address provided." << std::endl;
        return 1;
    }

    void* target_addr = reinterpret_cast<void*>(target_addr_val);
    std::cout << "Targeting process with PID: " << target_pid << " at address " << target_addr << std::endl;

    // --- Step 2: Open the Target Process ---
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, target_pid);
    if (!hProcess) {
        std::cerr << "Error: Could not open target process. (Maybe run as admin?)" << std::endl;
        return 1;
    }

    ProgramState snapshot1 = {0}, snapshot2 = {0};
    SIZE_T bytesRead;

    // --- Step 3: Take the first memory snapshot ---
    std::cout << "\nTaking initial memory snapshot..." << std::endl;
    if (!ReadProcessMemory(hProcess, target_addr, &snapshot1, sizeof(ProgramState), &bytesRead) || bytesRead != sizeof(ProgramState)) {
        std::cerr << "Error reading process memory." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    printSnapshot(snapshot1, "Snapshot 1 (Before Suspend)");

    // --- Step 4: Suspend, Wait, and Resume ---
    std::cout << "\nSuspending target process for 5 seconds..." << std::endl;
    setProcessSuspended(target_pid, true);
    Sleep(5000);
    std::cout << "Resuming target process..." << std::endl;
    setProcessSuspended(target_pid, false);

    // Give the target a moment to run its "self-awareness" check
    Sleep(1000);

    // --- Step 5: Take the second memory snapshot ---
    std::cout << "\nTaking final memory snapshot..." << std::endl;
    ReadProcessMemory(hProcess, target_addr, &snapshot2, sizeof(ProgramState), &bytesRead);
    printSnapshot(snapshot2, "Snapshot 2 (After Resume)");

    // --- Step 6: Analyze the difference ---
    std::cout << "\n--- ANALYSIS ---" << std::endl;
    if (snapshot2.suspicion_counter > snapshot1.suspicion_counter) {
        std::cout << "SUCCESS: The target process detected the suspension." << std::endl;
        std::cout << "Its 'suspicion_counter' increased from " << snapshot1.suspicion_counter << " to " << snapshot2.suspicion_counter << "." << std::endl;
    } else {
        std::cout << "FAILURE: The target process did not appear to update its suspicion level." << std::endl;
    }
    std::cout << "The iteration count also shows the process was paused." << std::endl;

    CloseHandle(hProcess);
    return 0;
}
