// ahl.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "ahl.h"

int main()
{
    CODEGARBAGEINIT();
    CODEGARBAGE();
    Sleep(1000);
    std::cout << XorStr("Hello World ahl test here!\n");
    CODEGARBAGE();
    Sleep(1000);
    bool check = false;
    CODEGARBAGE();
    AhlIsDebuggerPresent(check);
    CODEGARBAGE();
    Sleep(1000);
    if (check)
    {
        std::cout << XorStr("Debugger Found!\n");
        Sleep(10000);
    }
    else 
    {
        std::cout << XorStr("Debugger NOT Found!\n");
    }
     Sleep(10000);
}

