# Specify cmake version
cmake_minimum_required(VERSION 3.25)

# add_compile_options(-std=c++11)

# Specify c++ version
set(CMAKE_CXX_STANDARD 14)

# set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Specify project version
set(PROJECT_VERSION 0.1)

# Description of project
project(genfalcon
    DESCRIPTION "Executiable for generating falcon signatures in polynomial form"
    LANGUAGES CXX C)

# #
aux_source_directory(./falcon_c DIR_C)
aux_source_directory(. DIR_CPP)

# set(CMAKE_CXX_FLAGS "-g ${CMAKE_CXX_FLAGS}")
# set(CMAKE_C_FLAGS "-std=gnu99 ${CMAKE_C_FLAGS}")
set(BOOST_ROOT "/opt/homebrew/Cellar/boost/1.81.0_1/")

# include boost
FIND_PACKAGE(Boost)
INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR})
ADD_DEFINITIONS("-DHAS_BOOST")
LINK_DIRECTORIES(${Boost_LIBRARY_DIRS})

IF(Boost_FOUND)
    MESSAGE(STATUS "Boost_LIB_VERSION = ${Boost_LIB_VERSION}.")
    MESSAGE(STATUS "Boost_INCLUDE_DIRS = ${Boost_INCLUDE_DIRS}.")
    MESSAGE(STATUS "Boost_LIBRARY_DIRS = ${Boost_LIBRARY_DIRS}.")
ENDIF()

add_executable(${PROJECT_NAME} ${DIR_CPP} ${DIR_C})
target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES})