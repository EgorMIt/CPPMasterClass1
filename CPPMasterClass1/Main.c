#define _CRT_SECURE_NO_WARNINGS
#define PE_SIG_OFFSET_LOCATION 0x3c

#include <stdio.h>
#include <Windows.h>
#include <stdlib.h>


int main() {

    DWORD FileSize, PeHeaderAddress, Signature, exports, Characteristics_export, sectionNumber;
    errno_t err;
    FILE* fp = NULL;
    err = fopen_s(&fp, "D:\\Ex1.exe", "rb");

    IMAGE_DOS_HEADER DosHeader = { 0 };
    PIMAGE_DOS_HEADER dosHeader = { 0 };
    PIMAGE_NT_HEADERS PeHeader = { 0 };
    IMAGE_FILE_HEADER FileHeader = { 0 };
    IMAGE_OPTIONAL_HEADER OpHeader = { 0 };
    IMAGE_SECTION_HEADER SectionHeader = { 0 };
    IMAGE_EXPORT_DIRECTORY Export = { 0 };



    fseek(fp, 0, SEEK_END);
    FileSize = ftell(fp);

    if (FileSize < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS))
        printf("NOT PE file ");
    else
        printf("Reading PE FILE\n----------------------\n\n");

    printf("Reading DOS header \n----------------------\n");
    printf("size of DosHeder:\t\t %d \n", sizeof DosHeader); //sizeofDosHeader

    fseek(fp, 0, SEEK_SET);
    fread(&DosHeader, sizeof DosHeader, 1, fp);
    if (DosHeader.e_magic != 0x5a4d)
        printf("NOT PE file");

    printf("Magic number:\t\t\t MZ(%#x) \n", DosHeader.e_magic);    // e_magic
    printf("Adress of PE header(e_lfanew):\t %#xh \n", DosHeader.e_lfanew);     // e_lfanew
    printf("----------------------\n\n");
    PeHeaderAddress = DosHeader.e_lfanew;


    if (FileSize <= PeHeaderAddress + sizeof(IMAGE_NT_HEADERS))
        printf("NOT PE file");
    else
        printf("Reading PE Header \n----------------------\n");

    
    printf("\nPE File signature \n----------------------\n");
    fseek(fp, PeHeaderAddress, SEEK_SET);          
    fread(&Signature, sizeof(DWORD), 1, fp);      
    printf("Signature:\t\t %#x \n", Signature);     //Signature


    fread(&FileHeader, sizeof FileHeader, 1, fp);       //FileHeader
    sectionNumber = FileHeader.NumberOfSections;//NumberOfSection

    printf("number of section:\t %d \n", sectionNumber);
    printf("Size of optional Header: %d \n", FileHeader.SizeOfOptionalHeader);  //SizeOfOptionalHeader
    printf("Characteristics:\t\t %x \n", FileHeader.Characteristics);

    
    printf("\nPE Optional Header \n----------------------\n");

    fread(&OpHeader, 1, sizeof OpHeader, fp);            

    printf("Address of Entry Point:\t\t %#x\n", OpHeader.AddressOfEntryPoint);
    
    printf("----------------------\n\n");
    
    //fread(&SectionHeader, PeHeaderAddress + sizeof(IMAGE_NT_HEADERS), sizeof SectionHeader, fp);    //sectionHeader

    int secCount = 1;     
    printf(sectionNumber);
    /*
    
    while (secCount <= FileHeader.NumberOfSections)     
    {
        printf("section header (%d or %d) \n", secCount, FileHeader.NumberOfSections);
        printf("---------------------\n");
        printf("Section Header name \t\t:%s\n", SectionHeader.Name);
        printf("Virtual Size  \t\t\t:%#x\n", SectionHeader.Misc.VirtualSize);
        printf("Virtual Address \t\t:%#x\n", SectionHeader.VirtualAddress);
        printf("Size of raw data  \t\t:%#x\n", SectionHeader.SizeOfRawData);
        printf("Pointer to Raw Data \t\t:%#x\n\n", SectionHeader.PointerToRawData);
        fseek(fp, PeHeaderAddress + sizeof(IMAGE_NT_HEADERS) + secCount * sizeof(IMAGE_SECTION_HEADER), SEEK_SET);
        fread(&SectionHeader, sizeof SectionHeader, 1, fp);
        secCount++;
    }

    printf("Reading ExPort \n----------------------\n");
    exports = SectionHeader.Characteristics;
    fseek(fp, exports, SEEK_SET);                           //IMAGE_EXPORT 
    fread(&Characteristics_export, sizeof(DWORD), 1, fp);
    printf("characteristics \t: %#x \n", Characteristics_export);

    fread(&Export, sizeof Export, 1, fp);                   //IMAGE_EXPORT
    printf("nName \t\t\t: %x \n", Export.Name);
    printf("nBase \t\t\t: %x \n", Export.Base);
    printf("Number of Function \t: %d \n", Export.NumberOfFunctions);
    printf("Number of Name \t\t: %d \n", Export.NumberOfNames);
    printf("Address of function \t: %x \n", Export.AddressOfFunctions);
    printf("Adress Of Name \t\t: %x \n", Export.AddressOfNames);
    printf("Address of name ordinals: %x \n", Export.AddressOfNameOrdinals);

    

    */


    fclose(fp);
    system("pause");
}