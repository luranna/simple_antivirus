cmake_minimum_required(VERSION 3.19)
project(antivirus)

set(CMAKE_CXX_STANDARD 14)
find_package(OpenSSL REQUIRED)

add_executable(antivirus main.cpp sources/antivirus.cpp headers/antivirus.h headers/dataStructure.h sources/controller.cpp headers/controller.h)
target_link_libraries(${PROJECT_NAME} stdc++fs)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)