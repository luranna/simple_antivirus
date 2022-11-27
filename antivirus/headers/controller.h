//
// Created by a on 25.04.2021.
//

#ifndef ANTIVIRUS_CONTROLLER_H
#define ANTIVIRUS_CONTROLLER_H

#include "controller.h"
#include <string>
#include "dataStructure.h"


void getFileOrDirectory(std::string &path, bool isFile);

void performMainLoop(std::string path, Statistics &statistics, AllScanStatistics &allScanStatistics);

void performShowStatistics(Statistics &statistics);

void performShowAllStatistics(std::vector<Statistics> &allStatistics);

void performScanning(const std::string &fileOrDirectory, bool multiMode, Statistics &statistics);

void eraseStatistics(Statistics &statistics);

bool checkIfDirectory(const std::string& path);

bool checkIfRegularFile(const std::string& path);


#endif //ANTIVIRUS_CONTROLLER_H
