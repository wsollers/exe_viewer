#include <chrono>
#include <fstream>
#include <string>
#include <thread>

int main(int argc, char** argv) {
    if (argc == 3 && std::string(argv[1]) == "echo") {
        std::ofstream file(argv[2]); file << argv[2]; return file ? 0 : 1;
    }
    if (argc == 2 && std::string(argv[1]) == "sleep") {
        std::this_thread::sleep_for(std::chrono::seconds(30)); return 0;
    }
    return 7;
}
