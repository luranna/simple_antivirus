//
// Created by a on 25.04.2021.
//

#include <string>
#include <iostream>
#include <experimental/filesystem>
#include "../headers/controller.h"
#include "../headers/antivirus.h"


void performMainLoop(std::string path, Statistics &statistics, AllScanStatistics &allScanStatistics) {
    bool exit = false;
    char choice;
    while (!exit) {
        std::cout << "*************************************************" << std::endl;
        std::cout << "*                  ANTIVIRUS                    *" << std::endl;
        std::cout << "* Choose operation:                             *" << std::endl;
        std::cout << "*1. Single file scan                            *" << std::endl;
        std::cout << "*2. Scan directory                              *" << std::endl;
        std::cout << "*3. Show all today's scanning statistics        *" << std::endl;
        std::cout << "*4. Exit                                        *" << std::endl;
        std::cout << "*************************************************" << std::endl;
        choice = getchar();
        switch (choice) {
            case '1': {
                eraseStatistics(statistics);
                getFileOrDirectory(path, false);
                bool ifDirectory = checkIfDirectory(path);
                bool ifRegularFile = checkIfRegularFile(path);
                if (!ifDirectory && ifRegularFile) {
                    performScanning(path, false, statistics);
                    allScanStatistics.allScanStatistics.push_back(statistics);
                    performShowStatistics(statistics);
                    allScanStatistics.allScanStatistics.push_back(statistics);
                } else {
                    std::cout << "Cannot open this file." << std::endl;
                    statistics.scannedItemName = path;
                    statistics.ifScanned = false;
                }
                std::cout << "Press ENTER To continue\n";
                break;
            }
            case '2': {
                eraseStatistics(statistics);
                getFileOrDirectory(path, true);
                if (checkIfDirectory(path)) {
                    performScanning(path, true, statistics);
                    allScanStatistics.allScanStatistics.push_back(statistics);
                    performShowStatistics(statistics);
                } else {
                    std::cout << "Cannot open this file." << std::endl;
                    statistics.scannedItemName = path;
                    statistics.ifScanned = false;
                    allScanStatistics.allScanStatistics.push_back(statistics);
                }
                std::cout << "Press ENTER To continue\n";
                break;
            }
            case '3':
                performShowAllStatistics(allScanStatistics.allScanStatistics);
                std::cout << "Press ENTER To continue\n";
                break;
            case '4':
                exit = true;
                break;
            default :
                std::cout << "Choose one of the given options \nPress ENTER to continue." << std::endl;
        }
        if (!exit) {
            getchar();
            getchar();
        }
    }
}

void eraseStatistics(Statistics &statistics) {
    statistics.numberOfDetectedViruses = 0;
    statistics.namesOfDetectedFiles.clear();
    statistics.numberOfScannedFiles = 0;
    statistics.numberOfAllExistingFiles = 0;
    statistics.numberOfFilesMovedToQuarantine = 0;
    statistics.namesOfFilesMovedToQuarantine.clear();
}

void performShowAllStatistics(std::vector<Statistics> &allStatistics) {
    if (allStatistics.empty()) {
        std::cout << "No scanning done today." << std::endl;
    } else {
        for (auto &allStatistic : allStatistics) {
            performShowStatistics(allStatistic);
        }
    }
}

void performShowStatistics(Statistics &statistics) {
    std::cout << std::endl << "SCANNING RESULTS" << std::endl;
    std::cout << "Scanned item: " << statistics.scannedItemName << std::endl;
    if (!statistics.ifScanned) {
        std::cout << "Unable to open this file." << std::endl;
    } else {
        if (statistics.numberOfScannedFiles != 0) {
            std::cout << "Number of scanned files: " << statistics.numberOfScannedFiles << std::endl;
        }
        if (statistics.numberOfDetectedViruses != 0) {
            std::cout << "Number of detected viruses: " << statistics.numberOfDetectedViruses
                      << " in the following files: "
                      << std::endl;
            for (unsigned int i = 0; i < statistics.numberOfDetectedViruses; i++) {
                std::cout << statistics.namesOfDetectedFiles[i] << std::endl;
            }
            std::cout << std::endl;
            std::cout << "Quarantine applied on " << statistics.numberOfFilesMovedToQuarantine << " out of "
                      << statistics.numberOfDetectedViruses << " detected files in total." << std::endl;
            if (statistics.numberOfFilesMovedToQuarantine != 0) {
                std::cout << "Following files has been moved to quarantine:" << std::endl;
                for (unsigned int i = 0; i < statistics.numberOfFilesMovedToQuarantine; i++) {
                    std::cout << statistics.namesOfFilesMovedToQuarantine[i] << std::endl;
                }
            }
        } else
            std::cout << "No viruses has been detected." << std::endl;
    }
}


void performScanning(const std::string &path, bool multiMode, Statistics &statistics) {
    statistics.scannedItemName = path;
    if (!multiMode) {
        std::string hash = get_md5hash(path);
        bool scanningResult = compareFileWithDatabase(hash);
        if (hash == "Unable to open this file.") {
            std::cout << "Unable to open this file.";
            statistics.ifScanned = false;
        } else {
            statistics.ifScanned = true;
            statistics.numberOfScannedFiles = (statistics.numberOfScannedFiles + 1);
            if (scanningResult == 1) {
                statistics.numberOfDetectedViruses = (statistics.numberOfDetectedViruses + 1);
                statistics.namesOfDetectedFiles.push_back(path);
                std::cout << "Virus detected\n";
                std::cout << "Do you want to move the file to quarantine? Yes/No" << std::endl;
                std::string choice2;
                std::cin >> choice2;
                if (choice2 == "Yes") {
                    statistics.numberOfFilesMovedToQuarantine = (statistics.numberOfFilesMovedToQuarantine + 1);
                    moveFileToQuarantine(path, statistics);
                }
            } else {
                std::cout << "Virus not detected\n";
            }
        }

    } else {
        std::vector<std::string> files = getAllFilesRecursive(path, statistics);

        for (auto &file : files) {
            if (checkIfRegularFile(file)) {
                std::string hash = get_md5hash(file);
                bool scanningResult = compareFileWithDatabase(hash);
                statistics.numberOfScannedFiles = (statistics.numberOfScannedFiles + 1);
                std::cout << "Scanned " << statistics.numberOfScannedFiles << " out of "
                          << statistics.numberOfAllExistingFiles << " files in total." << std::endl;
                statistics.ifScanned = true;
                if (scanningResult == 1) {
                    statistics.ifScanned = true;
                    statistics.numberOfDetectedViruses = (statistics.numberOfDetectedViruses + 1);
                    statistics.namesOfDetectedFiles.push_back(file);

                    std::cout << "Virus detected in " + file << std::endl;
                    std::cout << "Do you want to move the file to quarantine? Yes/No" << std::endl;
                    std::string choice2;
                    std::cin >> choice2;
                    if (choice2 == "Yes") {
                        statistics.ifScanned = true;
                        statistics.numberOfFilesMovedToQuarantine = (statistics.numberOfFilesMovedToQuarantine + 1);
                        moveFileToQuarantine(file, statistics);
                    }
                }
            } else {
                statistics.ifScanned = false;
                std::cout << "Cannot open this file: " + file << std::endl;
            }
        }
    }
}

void getFileOrDirectory(std::string &path, bool isDirectory) {
    std::cout << "Provide the path of the " << (!isDirectory ? "file: " : "directory: ") << std::endl;
    std::cin >> path;
}

bool checkIfDirectory(const std::string& path) {
    if (std::experimental::filesystem::is_directory(path)) {
        return true;
    } else
        return false;
}

bool checkIfRegularFile(const std::string& path) {
    if (std::experimental::filesystem::is_regular_file(path)) {
        return true;
    } else
        return false;
}
