//
// Created by a on 25.04.2021.
//

#ifndef ANTIVIRUS_DATASTRUCTURE_H
#define ANTIVIRUS_DATASTRUCTURE_H

#include <vector>

struct Statistics {
    std::string scannedItemName;
    bool ifScanned;
    unsigned int numberOfAllExistingFiles = 0;
    unsigned int numberOfScannedFiles = 0;
    unsigned int numberOfDetectedViruses = 0;
    unsigned int numberOfFilesMovedToQuarantine = 0;
    std::vector<std::string> namesOfDetectedFiles;
    std::vector<std::string> namesOfFilesMovedToQuarantine;
};

struct AllScanStatistics {
    std::vector<Statistics> allScanStatistics;
};

#endif //ANTIVIRUS_DATASTRUCTURE_H
