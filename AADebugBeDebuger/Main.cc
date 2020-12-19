#include <windows.h>

#include <iostream>


int main()
{
	
	std::cout << "process start" << std::endl;

	__debugbreak();

	std::cout << "process over" << std::endl;
	return 0;
}