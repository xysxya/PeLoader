#include <stdio.h>
#include <windows.h>
#include <fileapi.h>
#include <winnt.h>
#include <minwindef.h>

//set Entry
BOOL CallEntry (char* chBaseAddress) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);
    char *ExeEntry = (char*)(chBaseAddress + pNt->OptionalHeader.AddressOfEntryPoint);
    __asm {
        mov eax, ExeEntry
        jmp eax
    }
    return TRUE;
}

BOOL SetImageBase(char* chBaseAddress) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);
    pNt->OptionalHeader.ImageBase = (ULONG32)chBaseAddress;

    return TRUE;
}

BOOL ImportTable(char* chBaseAddress) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pDos +
            pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    char *lpDllName = NULL;
    HMODULE hDll = NULL;
    PIMAGE_THUNK_DATA lpImportNameArray = NULL;
    PIMAGE_IMPORT_BY_NAME lpImportByName = NULL;
    PIMAGE_THUNK_DATA lpImportFuncAddrArray = NULL;
    FARPROC lpFuncAddress = NULL;
    DWORD i = 0;

    while(TRUE) {
        if (0 == pImportTable->OriginalFirstThunk) {
            break;
        }

        lpDllName = (char*)((DWORD)pDos + pImportTable->Name);
        hDll = GetModuleHandleA((lpDllName));
        if (NULL == hDll) {
            hDll = LoadLibraryA(lpDllName);
            if (NULL == hDll) {
                pImportTable++;
                continue;
            }
        }

        i = 0;
        lpImportNameArray = (PIMAGE_THUNK_DATA)((DWORD)pDos + pImportTable->OriginalFirstThunk);
        lpImportFuncAddrArray = (PIMAGE_THUNK_DATA)((DWORD)pDos + pImportTable->FirstThunk);
        while (TRUE) {
            if (0 == lpImportNameArray[i].u1.AddressOfData) {
                break;
            }
            lpImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pDos + lpImportNameArray[i].u1.AddressOfData);

            if (0x80000000 & lpImportNameArray[i].u1.Ordinal) {
                lpFuncAddress = GetProcAddress(hDll, (LPCSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF));
            }
            else {
                lpFuncAddress = GetProcAddress(hDll, (LPCSTR)lpImportByName->Name);
            }
            lpImportNameArray[i].u1.Function = (DWORD)lpFuncAddress;
            i++;
        }

        pImportTable++;
    }

    return TRUE;

}

BOOL ReLocationTable (char* chBaseAddress) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
    PIMAGE_NT_HEADERS  pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);
    PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)(chBaseAddress +
            pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    if ((char*)pLoc == (char*)pDos) {
        return TRUE;
    }

    while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) {
        WORD *pLocData = (WORD *)((PBYTE)pLoc + sizeof(IMAGE_BASE_RELOCATION));
        int nNumberOfReloc =
    }
}

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
