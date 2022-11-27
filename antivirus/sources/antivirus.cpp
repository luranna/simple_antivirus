//
// Created by a on 25.04.2021.
//

#include "../headers/antivirus.h"
#include <string>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <experimental/filesystem>
#include <openssl/md5.h>
#include <sys/stat.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <cstring>
#include <algorithm>


bool compareFileWithDatabase(const std::string &hash) {
    bool result = false;
    std::ifstream file;
    std::string line;
    file.open(database);
    if (file.is_open()) {
        while (!file.eof()) {
            getline(file, line);
            if (line.find(hash) != std::string::npos) {
                file.close();
                return true;
            }

        }
        file.close();
    } else
        std::cout << "Unable to open database." << std::endl;

    return result;
}

void fileEncryption(const std::string &filename) {
    std::ifstream file;
    std::string fileContent;
    std::string line;
    file.open(filename);
    if (file.is_open()) {
        while (!file.eof()) {
            getline(file, line);
            fileContent += line;
        }
        std::string fileEncrypted = des_encrypt(fileContent, "key12");
        file.close();
        std::ofstream output;
        output.open(filename);
        output << fileEncrypted;
        output.close();
    }


}

std::string des_encrypt(const std::string &input, const std::string &key) {
    std::string cipherText;

    DES_cblock keyEncrypt;
    memset(keyEncrypt, 0, 8);

    // construction of key (length must be equal to 8, key must be char)
    if (key.length() <= 8)
        memcpy(keyEncrypt, key.c_str(), key.length());
    else
        memcpy(keyEncrypt, key.c_str(), 8);

    // key replacement
    DES_key_schedule keySchedule;
    DES_set_key_unchecked(&keyEncrypt, &keySchedule);

    // Loop encryption, once every 8 bytes
    const_DES_cblock inputText;
    DES_cblock outputText;
    std::vector<unsigned char> vecCiphertext;
    unsigned char tmp[8];

    for (int i = 0; i < input.length() / 8; i++) {
        memcpy(inputText, input.c_str() + i * 8, 8); // why +i*8?
        DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);
        memcpy(tmp, outputText, 8);

        for (unsigned char & j : tmp)
            vecCiphertext.push_back(j);
    }

    if (input.length() % 8 != 0) {
        int tmp1 = input.length() / 8 * 8;
        int tmp2 = input.length() - tmp1;
        memset(inputText, 0, 8);
        strncpy((char *)inputText, input.c_str() + tmp1, tmp2);
        inputText[tmp2] = '\0';
        DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);//Encryption function
        memcpy(tmp, outputText, 8);

        for (unsigned char & j : tmp)
            vecCiphertext.push_back(j);
    }

    cipherText.clear();
    cipherText.assign(vecCiphertext.begin(), vecCiphertext.end()); //convert vector with strings to string
    return cipherText;
}


std::string get_md5hash(const std::string &filepath) {
    int BUFFSIZE = 16384;
    char buffer[BUFFSIZE];
    unsigned char digest[MD5_DIGEST_LENGTH];
    std::stringstream strstream;
    std::string md5string;
    std::ifstream stream;
    MD5_CTX md5Context;
    MD5_Init(&md5Context);

    stream.open(filepath, std::ifstream::binary);

    if (stream.is_open()) {
        while (!stream.eof()) {
            stream.read(buffer, BUFFSIZE);
            MD5_Update(&md5Context, buffer, stream.gcount());
        }
    } else {
        return "Unable to open this file.";
    }

    stream.close();

    int result = MD5_Final(digest, &md5Context);

    if (result == 0) // hash failed
        return {"Failed to hash the given file."};

    // set up stringstream format
    strstream << std::hex << std::uppercase << std::setfill('0');


    for (unsigned char uc: digest)
        strstream << std::setw(2) << (int) uc;

    md5string = strstream.str();

    return md5string;
}

std::string getFileNameFromPath(std::string filepath) {
    const size_t lastSlashPosition = filepath.find_last_of('/');
    if (std::string::npos != lastSlashPosition) {
        filepath.erase(0, lastSlashPosition + 1);
    }
    return filepath;
}

std::string checkNamingInQuarantine(std::string virusName) {
    std::vector<std::string> existingFilesInQuarantine = getAllFilesFromQuarantine();
    std::string newVirusPath;
    int counter = 0;
    bool doExist = true;
    std::string tmp = virusName;
    size_t lastIndex = virusName.find_last_of('.');
    std::string rawVirusName = virusName.substr(0, lastIndex);
    std::string virusNameExtension = virusName.substr(lastIndex, virusName.size());
    while (doExist) {
        if (std::find(existingFilesInQuarantine.begin(), existingFilesInQuarantine.end(), tmp) !=
            existingFilesInQuarantine.end()) {
            counter++;
            std::string counterToString = std::to_string(counter);
            tmp = std::string(rawVirusName).append("_").append(counterToString).append(virusNameExtension);
        } else {
            virusName = tmp;
            doExist = false;
        }
    }
    newVirusPath = quarantineDirectory + virusName;
    return newVirusPath;
}

void moveFileToQuarantine(std::string virusFilePath, Statistics &statistics) {
    std::string virusName = getFileNameFromPath(virusFilePath);
    char *virus_charArray;
    virus_charArray = &virusFilePath[0]; //conversion from string to char array to make remove work

    std::string newVirusPath = checkNamingInQuarantine(virusName);

    char *virusNew_charArray;
    virusNew_charArray = &newVirusPath[0];


    std::ifstream in(virusFilePath, std::ios::in | std::ios::binary);
    fileEncryption(virusFilePath);
    std::ofstream out(newVirusPath, std::ios::out | std::ios::binary);
    out << in.rdbuf();
    statistics.namesOfFilesMovedToQuarantine.push_back(newVirusPath);
  //  fileEncryption(newVirusPath);
    chmod(virusNew_charArray, S_IRUSR | S_IROTH | S_IRGRP);
    std::remove(virus_charArray);
    std::cout << "Successfully moved\n";
}

std::vector<std::string> getAllFilesRecursive(const std::string &path, Statistics &statistics) {
    std::vector<std::string> files;
    for (const auto &p: std::experimental::filesystem::recursive_directory_iterator(path)) {
        if (!std::experimental::filesystem::is_directory(p)) {
            files.push_back(p.path());
            statistics.numberOfAllExistingFiles = (statistics.numberOfAllExistingFiles + 1);
        }
    }
    return files;
}

std::vector<std::string> getAllFilesFromQuarantine() {
    std::vector<std::string> files;
    for (const auto &p: std::experimental::filesystem::recursive_directory_iterator(quarantineDirectory)) {
        if (!std::experimental::filesystem::is_directory(p)) {
            files.push_back(getFileNameFromPath(p.path()));
        }
    }
    return files;
}




