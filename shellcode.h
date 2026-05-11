#pragma once

#ifdef _KERNEL_MODE
#include <wdm.h>
#else
#include <basetsd.h>
#include <corecrt_malloc.h>
#include <vcruntime_string.h>
#endif

class shellcode {
private:
    unsigned char* buffer = nullptr;
    SIZE_T allocation_size = 0;
    SIZE_T buffer_size = 0;

    static constexpr SIZE_T page_size = 0x1000;

    static constexpr SIZE_T bytes_to_pages(const SIZE_T size) noexcept {
        return (((size) >> 12) + (((size) & (0xFFF)) != 0));
    }

    void free_buf() noexcept {
        if (buffer == nullptr)
            return;

#ifdef _KERNEL_MODE
        ExFreePoolWithTag(buffer, 0);
#else
        free(buffer);
#endif
        buffer = nullptr;
        allocation_size = 0;
        buffer_size = 0;
    }

    void ensure_capacity(SIZE_T extra) {
        if (buffer_size + extra > allocation_size)
            allocate_buf(buffer_size + extra);
    }

    void allocate_buf(SIZE_T size) {
        if (size == 0)
            size = page_size;

        const SIZE_T new_size = size <= page_size ? page_size : bytes_to_pages(size) * page_size; // to avoid frequent reallocations
        if (buffer && allocation_size >= new_size)
            return;

        free_buf();

        allocation_size = new_size;

#ifdef _KERNEL_MODE
        buffer = reinterpret_cast<unsigned char*>(ExAllocatePoolZero(NonPagedPoolNx, allocation_size, 0));
#else
        buffer = reinterpret_cast<unsigned char*>(malloc(allocation_size));
        memset(buffer, 0, allocation_size);
#endif
    }

    void append_byte(UINT8 byte) {
        ensure_capacity(1);
        buffer[buffer_size++] = byte;
    }

    template<typename type>
    void append_value(type value) {
        static_assert(__is_trivially_copyable(type), "type must be trivially copyable");
        ensure_capacity(sizeof(type));
        memcpy(buffer + buffer_size, &value, sizeof(type));
        buffer_size += sizeof(type);
    }

    void process_arg(int byte) {
        append_byte(static_cast<UINT8>(byte));
    }

    template <typename type>
    void process_arg(const type arg) {
        append_value(arg);
    }
public:
    shellcode() = default;

    template <typename... args_type>
    shellcode(args_type... args) {
        constexpr SIZE_T arg_size_bytes = (0 + ... + sizeof(args_type));
        allocate_buf(arg_size_bytes);
        (process_arg(args), ...);
    }

    shellcode(const shellcode& other) {
        allocate_buf(other.buffer_size ? other.allocation_size : page_size);

        buffer_size = other.buffer_size;

        if (other.buffer && buffer_size)
            memcpy(buffer, other.buffer, buffer_size);
    }

    shellcode(shellcode&& other) noexcept {
        buffer = other.buffer;
        allocation_size = other.allocation_size;
        buffer_size = other.buffer_size;

        other.buffer = nullptr;
        other.allocation_size = 0;
        other.buffer_size = 0;
    }

    shellcode& operator=(const shellcode& other) {
        if (this == &other)
            return *this;

        allocate_buf(other.buffer_size ? other.allocation_size : page_size);

        buffer_size = other.buffer_size;

        if (buffer_size)
            memcpy(buffer, other.buffer, buffer_size);

        return *this;
    }

    shellcode& operator=(shellcode&& other) noexcept {
        if (this == &other)
            return *this;

        if (buffer)
            free_buf();

        buffer = other.buffer;
        allocation_size = other.allocation_size;
        buffer_size = other.buffer_size;

        other.buffer = nullptr;
        other.allocation_size = 0;
        other.buffer_size = 0;

        return *this;
    }

    ~shellcode() noexcept {
        free_buf();
    }

    const unsigned char* get() const noexcept {
        return buffer;
    }

    SIZE_T size() const noexcept {
        return buffer_size;
    }

    SIZE_T allocated_size() const noexcept {
        return allocation_size;
    }

    void clear() noexcept {
        buffer_size = 0;
    }
};
