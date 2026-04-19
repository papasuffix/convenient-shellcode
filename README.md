# Convenient Shellcode
Convenient C++ type for both Usermode and Windows Kernelmode allowing you to pass immediates directly into your shellcode definition rather than having to patch them into your byte array at a certain offset/index later on

# Usage
This class assumes all integer literals (int type) passed are intended to be instruction **bytes** and will automatically be narrowed down to a UINT8 type. To avoid this make sure to append the l(L)/ul(UL) suffix to any immediate value that is 32bits or under in size so that it does not get truncated and is treated as a 32bit value
```cpp
const uintptr_t function_address = 0xDEADBEEFDEADBEEF;
shellcode test = {
    0x48, 0xC7, 0xC1, 0x14ul,     // mov rcx, 14h - you could have also put 20/0x14 into a variable and passed it here
    0x48, 0xB8, function_address, // movabs rax, function_address - you could have also passed the value here directly
    0xFF, 0xD0                    // call rax
};
 
// output: 0x48 0xC7 0xC1 0x14 0x0 0x0 0x0 0x48 0xB8 0xEF 0xBE 0xAD 0xDE 0xEF 0xBE 0xAD 0xDE 0xFF 0xD0
```
