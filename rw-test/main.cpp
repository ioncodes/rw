#include <iostream>
#include <Windows.h>

int main()
{
	while (true)
	{
		uint8_t* addr = (uint8_t*)0x0000000140000000;
		printf("%c%c\n", addr[0], addr[1]);
		Sleep(1000);
	}
}