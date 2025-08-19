#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

// This struct represents the "mind" of our application.
// The Controller will take snapshots of this struct's memory.
struct ProgramState {
    long long iteration_count;
    long long last_update_timestamp; // Timestamp in milliseconds
    int suspicion_counter; // Incremented when suspension is detected
    char status_message[64];
};

// Helper to get the current system time in milliseconds
long long getCurrentTimeMillis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

// Helper to get the current Process ID
int getCurrentPid() {
#ifdef _WIN32
    return GetCurrentProcessId();
#else
    return getpid();
#endif
}

const std::string PID_FILE = "target.pid";
const std::string ADDR_FILE = "target.addr";

int main() {
    // --- Setup and Advertising ---
    ProgramState state = {0, 0, 0, "Initializing..."};
    int pid = getCurrentPid();
    
    std::cout << "Target App started. My PID: " << pid << std::endl;
    std::cout << "My state is located at memory address: " << &state << std::endl;

    // Write PID and state address to files for the Controller to find
    std::ofstream(PID_FILE) << pid;
    std::ofstream(ADDR_FILE) << std::hex << reinterpret_cast<uintptr_t>(&state);
    
    // --- Main Loop ---
    state.last_update_timestamp = getCurrentTimeMillis();
    while (true) {
        // Normal state update
        state.iteration_count++;
        snprintf(state.status_message, sizeof(state.status_message), "Running loop %lld", state.iteration_count);
        
        long long currentTime = getCurrentTimeMillis();
        long long time_diff = currentTime - state.last_update_timestamp;

        // --- The "Self-Awareness" Check ---
        // If more than 2 seconds have passed since the last loop, something is wrong (e.g., suspension).
        if (time_diff > 2000) {
            std::cout << "[!!!] Anomaly detected! Time jump of " << time_diff << "ms. I must have been suspended." << std::endl;
            state.suspicion_counter++;
            snprintf(state.status_message, sizeof(state.status_message), "Suspicion level: %d", state.suspicion_counter);
        }

        state.last_update_timestamp = currentTime;

        // Print status to show it's running
        std::cout << "State: " << state.status_message << ", Suspicion: " << state.suspicion_counter << std::endl;

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    // In a real app, you'd clean up the files on exit.
    // std::remove(PID_FILE.c_str());
    // std::remove(ADDR_FILE.c_str());
    return 0;
}
