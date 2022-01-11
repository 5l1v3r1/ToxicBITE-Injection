#include <stdio.h>
#include <string.h>

int main(void)
{
	char execBuf[1024] = "\x48\x83\xec\x08\x48\x8d\x3d\xa9\x0f\x00\x00\x31\xc0\x48\xBF\x00\x00\x00\x00\x00\x00\x00\x00\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xd0\x31\xc0\x48\x83\xc4\x08\xc3\x0f\x1f\x80\x00\x00\x00\x00";
	
	char dataBuf[128] = "Hola!\x00";
	
	int* printf_addr = printf;
	char* dataBuf_addr = dataBuf;
	memcpy(&execBuf[15], &dataBuf_addr, 6); // populate rdi
	memcpy(&execBuf[25], &printf_addr, 8); // populate rax
	
	((void (*)(void))execBuf)();
	fflush( stdout );
}
