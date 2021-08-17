#include <stdio.h>
#include <windows.h>
#include <fileapi.h>
#include <winnt.h>

int main() {
    char szFilename[] = ".\\1.exe";
    HANDLE hFile = CreateFileA(
                szFilename,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_ARCHIVE,
                NULL
            );

    if (INVALID_HANDLE_VALUE == hFile) {
        printf("Open File Error!\n");
        return 1;
    }

    DWORD dwFileSize = GetFileSize(hFile, NULL);

    char *pData = malloc(dwFileSize);
    if (NULL == pData) {
        printf("Malloc Peace Error!\n");
        return 1;
    }

    DWORD dwRet = 0;
    ReadFile(hFile, pData, dwFileSize, &dwRet, NULL);
    CloseHandle(hFile);

}
