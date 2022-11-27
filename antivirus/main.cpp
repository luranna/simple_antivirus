
#include "headers/controller.h"
#include "headers/antivirus.h"


int main() {
    Statistics statistics;
    AllScanStatistics allScanStatistics;
    std::string path;
    performMainLoop(path, statistics, allScanStatistics);
    return 0;
}
