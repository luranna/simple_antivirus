//
// Created by a on 25.04.2021.
//

#ifndef ANTIVIRUS_ANTIVIRUS_H
#define ANTIVIRUS_ANTIVIRUS_H

#include <string>
#include <vector>
#include "dataStructure.h"


const std::string database = "../database.txt";
const std::string quarantineDirectory = "../quarantine/";

bool compareFileWithDatabase(const std::string &hash);

std::string get_md5hash(const std::string &filepath);

std::string getFileNameFromPath(std::string filepath);

void moveFileToQuarantine(std::string virusFilePath, Statistics &statistics);

std::vector<std::string> getAllFilesRecursive(const std::string &path, Statistics &statistics);

std::string des_encrypt(const std::string &input, const std::string &key);

std::vector<std::string> getAllFilesFromQuarantine();

std::string checkNamingInQuarantine(std::string virusName);

void fileEncryption(const std::string &filename);

#endif //ANTIVIRUS_ANTIVIRUS_H
