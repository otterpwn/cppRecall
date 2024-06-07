#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING

/*
* cppRecall - Extract data from the Microsoft Recall folder
* 
* @author otter
* 
* @reference Original Python tool - https://github.com/xaitax/TotalRecall/tree/main
* @reference Post about forensics made on the MS Recall data and how to set up the environment - https://cybercx.com/blog/forensic-applications-of-microsoft-recall/
* @reference Setup guide for Azure VM - https://www.golinuxcloud.com/create-vm-in-azure-step-by-step/
* @reference Windows 11 AI Workloads download link - https://archive.org/details/windows-workloads-0.3.252.0-arm-64.7z
* @reference Amperage Kit to install AI Workloads - https://github.com/thebookisclosed/AmperageKit/releases/tag/v2024.6.1
*/

#include <ctime>
#include <direct.h>
#include <experimental/filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include <Windows.h>

// https://www.sqlite.org/download.html -> sqlite-amalgamation-3460000.zip (sqlite3.c, sqlite3.h)
#include "sqlite3.h"

namespace fs = std::experimental::filesystem;

void printBanner();
void createDirectory(IN const std::string& path);
BOOL copyFile(IN const std::string& source, IN const std::string& destination);
BOOL copyFolder(IN const std::string& source, IN const std::string& destination);
BOOL renameFile(IN const std::string& oldName, IN const std::string& newName);
std::vector<std::string> listDirectories(IN const std::string& path);
std::vector<std::string> listFiles(IN const std::string& path);
std::string getEnvVariable(IN const std::string& variable);
std::string getCurrentTimestamp();

int main() {
	printBanner();

	// get username from env and derive path for the UKP folder
	std::string username = getEnvVariable("USERNAME");
	std::string basePath = "C:\\Users\\" + username + "\\AppData\\Local\\CoreAIPlatform.00\\UKP";

	// find GUID folder by listing all directories in the UKP folder
	std::vector<std::string> directories = listDirectories(basePath);
	if (directories.empty()) {
		printf("[!] Could not find GUID folder\n");
	}

	std::string guidFolder = directories.front();
	printf("[~] Recall folder found: %s\n", guidFolder.c_str());

	std::string dbPath = guidFolder + "\\ukg.db";
	std::string imageStorePath = guidFolder + "\\ImageStore";
	std::string timeStamp = getCurrentTimestamp();
	std::string extractionFolder = timeStamp + "_Recall_Extraction";

	// create folder for extraction results
	printf("[~] Creating extraction folder: %s\n", extractionFolder.c_str());
	createDirectory(extractionFolder.c_str());

	// copy ukg database file and ImageStore folder to extraction folder
	if (!copyFile(dbPath, (extractionFolder + "\\ukg.db"))) {
		printf("[!] Failed to copy database\n");
		return 1;
	}
	if (!copyFolder(imageStorePath, (extractionFolder + "\\ImageStore"))) {
		printf("[!] Failed to copy image store\n");
		return 1;
	}

	// rename all images in the extracted ImageStore folder to <NAME>.jgp
	// so they can be opened with a image viewer
	std::vector<std::string> imageFiles = listFiles((extractionFolder + "\\ImageStore").c_str());

	for (const auto& imagePath : imageFiles) {
		if (imagePath.find(".jpg") == std::string::npos) {
			if (!renameFile(imagePath.c_str(), (imagePath + ".jpg").c_str())) {
				printf("[!] Error while renaming image file %s\n", imagePath.c_str());
			}
		}
	}

	// use the sqlite3 library to open the ukg database
	sqlite3* db;
	int rc = sqlite3_open((extractionFolder + "\\ukg.db").c_str(), &db);

	if (rc) {
		printf("[!] Error while opening database: %s\n", sqlite3_errmsg(db));
		return 1;
	}

	// extract WindowTitle, TimeStamp and ImageToken tables from the database
	std::string query = "SELECT WindowTitle, TimeStamp, ImageToken FROM WindowCapture WHERE (WindowTitle IS NOT NULL OR ImageToken IS NOT NULL)";
	sqlite3_stmt* stmt;
	rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);

	if (rc != SQLITE_OK) {
		printf("[!] Error whil executing query: %s\n", sqlite3_errmsg(db));
		return 1;
	}

	int fromDateTimestamp = 0;
	int toDateTimestamp = 0;

	std::vector<std::string> capturedWindows;
	std::vector<std::string> imagesTaken;

	// extract table entries into vectors
	while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		const char* windowTitle = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
		int timestamp = sqlite3_column_int(stmt, 1);
		const char* imageToken = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));

		if ((fromDateTimestamp == 0 || fromDateTimestamp <= timestamp) && (toDateTimestamp == 0 || timestamp < toDateTimestamp)) {
			if (windowTitle && strlen(windowTitle) > 0) {
				capturedWindows.push_back(windowTitle);
			}
			if (imageToken && strlen(imageToken) > 0) {
				imagesTaken.push_back(imageToken);
			}
		}
	}

	// close all handles to the db
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	// output file formatting
	std::ofstream file(extractionFolder + "\\cppRecall.txt");

	file << "[~] Captured Windows:\n";
	for (const auto& window : capturedWindows) {
		file << window << "\n";
	}

	file << "\n[~] Images Taken:\n";
	for (const auto& image : imagesTaken) {
		file << image << "\n";
	}

	file.close();

	printf("[~] Finished extracting in output file: %s", (extractionFolder + "\\cppRecall.txt").c_str());
}

void printBanner() {
	printf("[<>] C++ Microsoft Recall dumper by otter\n");
	printf("[<>] Based off of https://github.com/xaitax/TotalRecall/tree/main\n\n");
}

void createDirectory(IN const std::string& path) {
	/*
	* Create a directory
	* 
	* @param std::string path - path of the directory to create
	*/
	_mkdir(path.c_str());
}

BOOL copyFile(IN const std::string& source, IN const std::string& destination) {
	/*
	* Copy a file from a source to a destination path
	* 
	* @param const std::string& source - source path of the file to be copied
	* @param const std::string& destination - destination path where the file will be copied
	* 
	* @returns BOOL - result of the copy operation
	*/
	return CopyFile(source.c_str(), destination.c_str(), FALSE);
}

BOOL copyFolder(IN const std::string& source, IN const std::string& destination) {
	/*
	* Copy contents of a directory from a source to a destination path
	* 
	* @param const std::string& source - source path of the directory to be copied
	* @param const std::string& destination - destination path where the directory and its contents will be copied
	* 
	* @returns BOOL - result of the copy operation
	*/
	createDirectory(destination);

	std::vector<std::string> files = listFiles(source);
	for (const auto& file : files) {
		std::string destFile = destination + "\\" + fs::path(file).filename().string();
		if (!copyFile(file, destFile)) {
			return FALSE;
		}
	}

	std::vector<std::string> dirs = listDirectories(source);
	for (const auto& dir : dirs) {
		std::string destDir = destination + "\\" + fs::path(dir).filename().string();
		if (!copyFolder(dir, destDir)) {
			return FALSE;
		}
	}

	return TRUE;
}

BOOL renameFile(IN const std::string& oldName, IN const std::string& newName) {
	/*
	* Rename a file
	* 
	* @param const std::string& oldName - old name of the file
	* @param const std::string& newName - new name of the file
	* 
	* @returns BOOL - result of the rename operation
	*/
	return rename(oldName.c_str(), newName.c_str()) == 0;
}

std::vector<std::string> listDirectories(IN const std::string& path) {
	/*
	* List subdirectories of a path (not recursive)
	* 
	* @param const std::string& path - path to list the subdirectories of
	* 
	* @returns std::vector<std::string> - vector containing the path of all the subdirectories
	* 
	* @note To make the function recursive swap `fs::directory_iterator(path)` with `fs::recursive_directory_iterator(path)`
	*/
	std::vector<std::string> filePaths;

	for (const auto& subPath : fs::directory_iterator(path)) {
		filePaths.push_back(subPath.path().string());
	}

	return filePaths;
}

std::vector<std::string> listFiles(IN const std::string& path) {
	/*
	* List files in a directory
	* 
	* @param const std::string& path - path to list files from
	* 
	* @returns std::vector<std::string> - vector containing the path of all the files in the requested path
	*/
	std::vector<std::string> filePaths;

	for (const auto& subPath : fs::directory_iterator(path)) {
		if (fs::is_regular_file(subPath)) {
			filePaths.push_back(subPath.path().string());
		}
	}

	return filePaths;
}

std::string getEnvVariable(IN const std::string& variable) {
	/*
	* Retrieve an environment variable from the current session
	* 
	* @param std::string& variable - name of the env variable to get
	* 
	* @returns std::string - value of the requested env variable
	*/
	char* buffer = nullptr;
	size_t size = 0;

	_dupenv_s(&buffer, &size, variable.c_str());
	std::string varValue = buffer ? buffer : "";
	free(buffer);

	return varValue;
}

std::string getCurrentTimestamp() {
	/*
	* Get current timestamp
	* 
	* @returns std::string - current timestamp as a string (for file format)
	*/
	std::time_t now = std::time(nullptr);
	std::stringstream ss;
	ss << now;

	return ss.str();
}