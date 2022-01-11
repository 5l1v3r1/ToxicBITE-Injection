#include <stdio.h>
#include <string.h>

#include <elf.h>
#include <link.h>

#include <unistd.h>

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

void Addressor(void)
{
	int a = 1;
}

static char FakeStack[128]; // For manual stack alignment

unsigned long AlignTo(unsigned long number, unsigned long multiple)
{
	if (multiple == 0)
		return 0;

	unsigned long remainder = number % multiple;

	if (remainder == 0)
		return number;
	else
		return number + multiple - remainder;
}

Elf64_Ehdr* GetElfHeader()
{
	char* AddressorAddress = reinterpret_cast<char*>(Addressor);
	char* PageAlignedAddress = ((unsigned long) Addressor & (getpagesize()-1)) ?  reinterpret_cast<char*>((void *) (((unsigned long) Addressor+getpagesize()) & ~(getpagesize()-1))) : reinterpret_cast<char*>(Addressor);
	
	const char ElfHeaderMagic[4] = {0x7f, 0x45, 0x4c, 0x46}; // elf magic bytes
	for(; *PageAlignedAddress != ElfHeaderMagic[0] && *(PageAlignedAddress+1) != ElfHeaderMagic[1] && *(PageAlignedAddress+2) != ElfHeaderMagic[2] && *(PageAlignedAddress+3) != ElfHeaderMagic[3]; PageAlignedAddress -= getpagesize())
	{
	}

	return reinterpret_cast<Elf64_Ehdr*>(PageAlignedAddress);
}

void FindTables(Elf64_Sym*& SymbolTable, char*& GlobalOffsetTable, char*& StringTable, Elf64_Rel*& RelocationTable, Elf64_Rela*& RelocationATable, bool& IsRela)
{
	int IsRelaIndex = -1; // the index in the _DYNAMIC[i] array which points to the entry containing the information on whether the relocation table uses Elf64_Rela or Elf64_Rel entries

	for (int i = 0; _DYNAMIC[i].d_tag != DT_NULL; ++i)
	{
		switch(_DYNAMIC[i].d_tag)
		{
			case DT_SYMTAB:
				SymbolTable = reinterpret_cast<Elf64_Sym*>(_DYNAMIC[i].d_un.d_ptr);
				break;
			case DT_PLTGOT:
				GlobalOffsetTable = reinterpret_cast<char*>(_DYNAMIC[i].d_un.d_ptr);
				break;
			case DT_STRTAB:
				StringTable = reinterpret_cast<char*>(_DYNAMIC[i].d_un.d_ptr);
				break;
			case DT_JMPREL:
				IsRelaIndex = i;
				break;
			case DT_PLTREL:
				IsRela = _DYNAMIC[i].d_un.d_val == DT_RELA;
				break;
		}
	}
	
	if (IsRela)
	{
		RelocationATable = reinterpret_cast<Elf64_Rela*>(_DYNAMIC[IsRelaIndex].d_un.d_ptr);
	}
	else
	{
		RelocationTable = reinterpret_cast<Elf64_Rel*>(_DYNAMIC[IsRelaIndex].d_un.d_ptr);
	}
}

int main(void)
{
	char Shellcode[128] = "\x48\x83\xec\x08\x48\x8d\x3d\xa9\x0f\x00\x00\x31\xc0\x48\xBF\x00\x00\x00\x00\x00\x00\x00\x00\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x50\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x50\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0\x31\xc0\x48\x83\xc4\x08\xc3\x0f\x1f\x80\x00\x00\x00\x00";
	
	char dataBuf[6] = "id\x00";

	Elf64_Ehdr* ElfHeader = GetElfHeader();
	// char* ProgramHeaderTable = reinterpret_cast<char*>(ElfHeader) + ElfHeader->e_phoff;

	/*Elf64_Phdr* DynamicSectionProgramHeader = reinterpret_cast<Elf64_Phdr*>(ProgramHeaderTable);
	for(unsigned int i = 0; i < ElfHeader->e_phnum; ++i)
	{
		Elf64_Phdr* CurrentSection = reinterpret_cast<Elf64_Phdr*>(ProgramHeaderTable + i*ElfHeader->e_phentsize); // for byte ptr arithmetic
		if(CurrentSection->p_type == PT_DYNAMIC)
		{
			DynamicSectionProgramHeader = CurrentSection;
		}
	}*/

	// Elf64_Dyn* DynamicSection = reinterpret_cast<Elf64_Dyn*>(DynamicSectionProgramHeader->p_offset + reinterpret_cast<char*>(ElfHeader));
	
	Elf64_Sym* SymbolTable = NULL;
	char* GlobalOffsetTable = NULL;
	char* StringTable = NULL;
	
	Elf64_Rel* RelocationTable = NULL;
	Elf64_Rela* RelocationATable = NULL;
	bool IsRela = false; // does the relocation table uses Elf64_Rela or Elf64_Rel entries

	FindTables(SymbolTable, GlobalOffsetTable, StringTable, RelocationTable, RelocationATable, IsRela);
	//long* lmap = (long*)(GotPlt + 0x8);
	//*(char*)(*lmap + 0x1d0) = 0;

	long AlignedFakeStack = AlignTo(reinterpret_cast<unsigned long>(&FakeStack), 0x18);

	char* FakeRelocationTable = reinterpret_cast<char*>(AlignedFakeStack);
	unsigned long reloc_arg = 0;
	reloc_arg = AlignTo(FakeRelocationTable - reinterpret_cast<char*>(RelocationATable), 0x18); 
	FakeRelocationTable = (reinterpret_cast<char*>(RelocationATable)) + reloc_arg; // Relocate FakeReloc to ensure that reloc_arg % 0x18 == 0
	reloc_arg /= 0x18 ; // compact reloc_arg for dl_resolve

	char* FakeSymbolTable = FakeRelocationTable + 0x10 + sizeof(Elf64_Rela);
	const char* FakeStringTable = "system\x00";

	unsigned long RealToFakeSymbolTableOffset = AlignTo(FakeSymbolTable - (char*)SymbolTable, 0x18);
	FakeSymbolTable = (char*)SymbolTable + RealToFakeSymbolTableOffset;
	reinterpret_cast<Elf64_Sym*>(FakeSymbolTable)->st_other = 0x0;
	reinterpret_cast<Elf64_Sym*>(FakeSymbolTable)->st_name = FakeStringTable - StringTable;

	reinterpret_cast<Elf64_Rela*>(FakeRelocationTable)->r_info = (( RealToFakeSymbolTableOffset / 0x18 ) << 32 ) | 0x7;
	reinterpret_cast<Elf64_Rela*>(FakeRelocationTable)->r_offset = FakeSymbolTable - (char*)ElfHeader;

	long* PLT0 = reinterpret_cast<long*>(&GlobalOffsetTable[0x18]);
	long JumpAddress = *PLT0+5;
	//char* DataBufferAddress = reinterpret_cast<char*>(&dataBuf);

	char* DataBufferAddress = dataBuf;
	// emulate a function call
	memcpy(&Shellcode[15], &DataBufferAddress, 6); // populate rdi
	*((long*)(Shellcode+25)) = reinterpret_cast<long>(Shellcode+57); // push return address to the stack
	memcpy(&Shellcode[36], &reloc_arg, 8); // push reloc_arg
	memcpy(&Shellcode[47], &JumpAddress, 8); // populate rax
	
	((void (*)(void))Shellcode)();
	fflush( stdout );
}
