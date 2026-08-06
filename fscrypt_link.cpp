#define NOMINMAX
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <windows.h>
#include <bcrypt.h>
#include <winioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <algorithm>
#include <array>
#include <cwctype>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

#define is_debug 0

namespace fs = std::filesystem;

#pragma pack(push, 1)
struct FileMountHeader
{
    uint32_t total_size;

    wchar_t file_path[258];
    uint64_t startoffset;
    uint64_t volumeSize;
    uint32_t unk5;//maybe is_use_encryption
    uint32_t unk6;
    uint8_t aes_key[32];
    wchar_t tag_name[32];
};
struct FileUnmountHeader
{
    uint32_t total_size;

    wchar_t file_path[256];
};
#pragma pack(pop)

enum Command
{
    CMD_UNKNOWN,
    CMD_MOUNT,
    CMD_UNMOUNT,
    CMD_LINK
};

namespace {

constexpr size_t kAesBlockSize = 16;
constexpr size_t kBootIdEncryptedSize = 96;
using Block = std::array<uint8_t, kAesBlockSize>;

constexpr Block kBootIdKey = {
    0x09, 0xca, 0x5e, 0xfd, 0x30, 0xc9, 0xaa, 0xef,
    0x38, 0x04, 0xd0, 0xa7, 0xe3, 0xfa, 0x71, 0x20,
};

constexpr Block kBootIdIv = {
    0xb1, 0x55, 0xc2, 0x2c, 0x2e, 0x7f, 0x04, 0x91,
    0xfa, 0x7f, 0x0f, 0xdc, 0x21, 0x7a, 0xff, 0x90,
};

constexpr Block kNtfsHeader = {
    0xeb, 0x52, 0x90, 0x4e, 0x54, 0x46, 0x53, 0x20,
    0x20, 0x20, 0x20, 0x00, 0x10, 0x01, 0x00, 0x00,
};

constexpr Block kExfatHeader = {
    0xeb, 0x76, 0x90, 0x45, 0x58, 0x46, 0x41, 0x54,
    0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
};

struct BootIdInfo
{
    uint8_t container_type = 0;
    uint64_t block_count = 0;
    uint64_t block_size = 0;
    uint64_t header_block_count = 0;
    uint64_t offset = 0;
    uint64_t volume_size = 0;
};

struct MountKeyMaterial
{
    Block key{};
    Block iv{};
    uint32_t image_flag = 0;
    const char* image_type = "";
    const char* container_name = "";
};

struct MountPointReparseDataBuffer
{
    ULONG ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    USHORT SubstituteNameOffset;
    USHORT SubstituteNameLength;
    USHORT PrintNameOffset;
    USHORT PrintNameLength;
    WCHAR PathBuffer[1];
};

class ScopedHandle
{
public:
    explicit ScopedHandle(HANDLE handle = INVALID_HANDLE_VALUE) noexcept
        : handle_(handle)
    {
    }

    ~ScopedHandle() noexcept
    {
        if (handle_ != INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle_);
        }
    }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept
        : handle_(other.handle_)
    {
        other.handle_ = INVALID_HANDLE_VALUE;
    }

    ScopedHandle& operator=(ScopedHandle&& other) noexcept
    {
        if (this != &other)
        {
            if (handle_ != INVALID_HANDLE_VALUE)
            {
                CloseHandle(handle_);
            }

            handle_ = other.handle_;
            other.handle_ = INVALID_HANDLE_VALUE;
        }

        return *this;
    }

    [[nodiscard]] HANDLE get() const noexcept
    {
        return handle_;
    }

    [[nodiscard]] bool valid() const noexcept
    {
        return handle_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE handle_;
};

void PrintWideError(const std::wstring& message)
{
    wprintf(L"%ls\n", message.c_str());
}

std::wstring TrimTrailingWhitespace(std::wstring value)
{
    while (!value.empty())
    {
        const wchar_t ch = value.back();
        if (ch != L' ' && ch != L'\r' && ch != L'\n' && ch != L'\t')
        {
            break;
        }

        value.pop_back();
    }

    return value;
}

std::wstring WidenLossy(const std::string& text)
{
    return std::wstring(text.begin(), text.end());
}

std::wstring FormatLastErrorMessage(DWORD error)
{
    LPWSTR buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS;

    const DWORD chars = FormatMessageW(
        flags,
        nullptr,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr
    );

    if (chars == 0 || buffer == nullptr)
    {
        return L"Win32 error " + std::to_wstring(error);
    }

    std::wstring message(buffer, chars);
    LocalFree(buffer);
    return TrimTrailingWhitespace(message);
}

std::wstring FormatNtStatusMessage(NTSTATUS status)
{
    wchar_t buffer[16]{};
    swprintf_s(
        buffer,
        L"0x%08lX",
        static_cast<unsigned long>(status)
    );
    return buffer;
}

bool StartsWithInsensitive(std::wstring_view text, std::wstring_view prefix)
{
    if (text.size() < prefix.size())
    {
        return false;
    }

    for (size_t i = 0; i < prefix.size(); ++i)
    {
        if (std::towlower(text[i]) != std::towlower(prefix[i]))
        {
            return false;
        }
    }

    return true;
}

std::wstring EnsureTrailingBackslash(std::wstring value)
{
    if (value.empty() || value.back() != L'\\')
    {
        value.push_back(L'\\');
    }

    return value;
}

std::wstring NormalizeMountDirectory(std::wstring path)
{
    std::replace(path.begin(), path.end(), L'/', L'\\');

    while (path.size() > 3 && path.back() == L'\\')
    {
        path.pop_back();
    }

    return path;
}

std::wstring NormalizeNtTarget(std::wstring target)
{
    std::replace(target.begin(), target.end(), L'/', L'\\');

    if (StartsWithInsensitive(target, L"\\??\\.\\") && target.size() > 6)
    {
        target = L"\\??\\" + target.substr(6);
    }
    else if (StartsWithInsensitive(target, L"\\\\.\\") && target.size() > 4)
    {
        target = L"\\??\\" + target.substr(4);
    }
    else if (StartsWithInsensitive(target, L"\\\\?\\") && target.size() > 4)
    {
        target = L"\\??\\" + target.substr(4);
    }
    else if (StartsWithInsensitive(target, L"\\Device\\"))
    {
        target = L"\\??\\GLOBALROOT" + target;
    }
    else if (!StartsWithInsensitive(target, L"\\??\\"))
    {
        PrintWideError(
            L"Unsupported target path format: " + target +
            L"\nExpected examples: \\\\.\\FscryptDisk_OPT_SDGA_A005_0\\ or \\\\?\\Volume{GUID}\\"
        );
        return L"";
    }

    while (target.size() > 5 && target[4] == L'\\' && target[5] == L'\\')
    {
        target.erase(4, 1);
    }

    return EnsureTrailingBackslash(target);
}

std::wstring MakePrintName(const std::wstring& ntTarget)
{
    if (StartsWithInsensitive(ntTarget, L"\\??\\"))
    {
        return L"\\\\?\\" + ntTarget.substr(4);
    }

    return ntTarget;
}

bool EnsureMountDirectoryReady(const std::wstring& mountDir)
{
    std::error_code ec;
    const fs::path mountPath(mountDir);

    if (!fs::exists(mountPath, ec))
    {
        if (ec)
        {
            PrintWideError(L"Cannot check mount directory: " + WidenLossy(ec.message()));
            return false;
        }

        if (!fs::create_directories(mountPath, ec) && ec)
        {
            PrintWideError(L"Cannot create mount directory: " + WidenLossy(ec.message()));
            return false;
        }
    }
    else if (ec)
    {
        PrintWideError(L"Cannot check mount directory: " + WidenLossy(ec.message()));
        return false;
    }

    if (!fs::is_directory(mountPath, ec) || ec)
    {
        PrintWideError(L"Mount path is not a directory: " + mountDir);
        return false;
    }

    const DWORD attrs = GetFileAttributesW(mountDir.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES)
    {
        PrintWideError(
            L"GetFileAttributesW failed for " + mountDir + L": " +
            FormatLastErrorMessage(GetLastError())
        );
        return false;
    }

    if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
    {
        PrintWideError(L"Mount directory already contains a reparse point: " + mountDir);
        return false;
    }

    if (!fs::is_empty(mountPath, ec) || ec)
    {
        PrintWideError(L"Mount directory must be empty: " + mountDir);
        return false;
    }

    return true;
}

std::vector<BYTE> BuildMountPointReparseBuffer(
    const std::wstring& substituteName,
    const std::wstring& printName
)
{
    const size_t substituteBytes = substituteName.size() * sizeof(wchar_t);
    const size_t printBytes = printName.size() * sizeof(wchar_t);

    if (substituteBytes > 0xFFFFu || printBytes > 0xFFFFu)
    {
        PrintWideError(L"Target path is too long for a mount-point reparse record.");
        return {};
    }

    const DWORD pathBufferBytes = static_cast<DWORD>(
        substituteBytes + sizeof(wchar_t) + printBytes + sizeof(wchar_t)
    );
    const DWORD totalBytes =
        FIELD_OFFSET(MountPointReparseDataBuffer, PathBuffer) + pathBufferBytes;
    const DWORD reparseHeaderBytes = sizeof(ULONG) + sizeof(USHORT) + sizeof(USHORT);

    std::vector<BYTE> buffer(totalBytes, 0);
    auto* reparse = reinterpret_cast<MountPointReparseDataBuffer*>(buffer.data());
    reparse->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    reparse->ReparseDataLength = static_cast<USHORT>(totalBytes - reparseHeaderBytes);
    reparse->Reserved = 0;
    reparse->SubstituteNameOffset = 0;
    reparse->SubstituteNameLength = static_cast<USHORT>(substituteBytes);
    reparse->PrintNameOffset = static_cast<USHORT>(substituteBytes + sizeof(wchar_t));
    reparse->PrintNameLength = static_cast<USHORT>(printBytes);

    memcpy(reparse->PathBuffer, substituteName.c_str(), substituteBytes);
    reparse->PathBuffer[substituteName.size()] = L'\0';

    BYTE* printNamePtr = reinterpret_cast<BYTE*>(reparse->PathBuffer) + reparse->PrintNameOffset;
    memcpy(printNamePtr, printName.c_str(), printBytes);
    *reinterpret_cast<wchar_t*>(printNamePtr + printBytes) = L'\0';

    return buffer;
}

bool CreateMountPoint(const std::wstring& mountDir, const std::wstring& ntTarget)
{
    const std::wstring printName = MakePrintName(ntTarget);
    std::vector<BYTE> reparseBuffer = BuildMountPointReparseBuffer(ntTarget, printName);
    if (reparseBuffer.empty())
    {
        return false;
    }

    ScopedHandle directory(CreateFileW(
        mountDir.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    ));

    if (!directory.valid())
    {
        PrintWideError(
            L"CreateFileW failed for " + mountDir + L": " +
            FormatLastErrorMessage(GetLastError())
        );
        return false;
    }

    DWORD bytesReturned = 0;
    const BOOL ok = DeviceIoControl(
        directory.get(),
        FSCTL_SET_REPARSE_POINT,
        reparseBuffer.data(),
        static_cast<DWORD>(reparseBuffer.size()),
        nullptr,
        0,
        &bytesReturned,
        nullptr
    );

    if (!ok)
    {
        PrintWideError(
            L"FSCTL_SET_REPARSE_POINT failed: " +
            FormatLastErrorMessage(GetLastError())
        );
        return false;
    }

    return true;
}

uint64_t ReadLeU64(const uint8_t* bytes)
{
    uint64_t value = 0;

    for (size_t i = 0; i < sizeof(uint64_t); ++i)
    {
        value |= static_cast<uint64_t>(bytes[i]) << (8 * i);
    }

    return value;
}

Block XorBlocks(const Block& lhs, const Block& rhs)
{
    Block out{};

    for (size_t i = 0; i < kAesBlockSize; ++i)
    {
        out[i] = lhs[i] ^ rhs[i];
    }

    return out;
}

std::string HexString(const Block& block)
{
    static const char kHexDigits[] = "0123456789abcdef";
    std::string text;
    text.resize(block.size() * 2);

    for (size_t i = 0; i < block.size(); ++i)
    {
        text[i * 2] = kHexDigits[block[i] >> 4];
        text[i * 2 + 1] = kHexDigits[block[i] & 0x0F];
    }

    return text;
}

bool AesDecryptNoPadding(
    const uint8_t* ciphertext,
    size_t ciphertext_size,
    const Block& key,
    LPCWSTR chaining_mode,
    const Block* iv,
    std::vector<uint8_t>* plaintext,
    std::wstring* error_message
)
{
    if (ciphertext_size % kAesBlockSize != 0)
    {
        *error_message = L"Ciphertext size must be a multiple of 16 bytes.";
        return false;
    }

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_KEY_HANDLE imported_key = nullptr;
    std::vector<UCHAR> key_object;

    auto cleanup = [&]()
    {
        if (imported_key != nullptr)
        {
            BCryptDestroyKey(imported_key);
        }

        if (algorithm != nullptr)
        {
            BCryptCloseAlgorithmProvider(algorithm, 0);
        }
    };

    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm,
        BCRYPT_AES_ALGORITHM,
        nullptr,
        0
    );
    if (status < 0)
    {
        *error_message = L"BCryptOpenAlgorithmProvider failed with NTSTATUS " +
            FormatNtStatusMessage(status);
        cleanup();
        return false;
    }

    const ULONG mode_bytes = static_cast<ULONG>((wcslen(chaining_mode) + 1) * sizeof(wchar_t));
    status = BCryptSetProperty(
        algorithm,
        BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(chaining_mode)),
        mode_bytes,
        0
    );
    if (status < 0)
    {
        *error_message = L"BCryptSetProperty(BCRYPT_CHAINING_MODE) failed with NTSTATUS " +
            FormatNtStatusMessage(status);
        cleanup();
        return false;
    }

    ULONG key_object_length = 0;
    ULONG bytes_written = 0;
    status = BCryptGetProperty(
        algorithm,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&key_object_length),
        sizeof(key_object_length),
        &bytes_written,
        0
    );
    if (status < 0)
    {
        *error_message = L"BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed with NTSTATUS " +
            FormatNtStatusMessage(status);
        cleanup();
        return false;
    }

    key_object.resize(key_object_length);
    status = BCryptGenerateSymmetricKey(
        algorithm,
        &imported_key,
        key_object.data(),
        static_cast<ULONG>(key_object.size()),
        const_cast<PUCHAR>(key.data()),
        static_cast<ULONG>(key.size()),
        0
    );
    if (status < 0)
    {
        *error_message = L"BCryptGenerateSymmetricKey failed with NTSTATUS " +
            FormatNtStatusMessage(status);
        cleanup();
        return false;
    }

    std::vector<UCHAR> input(ciphertext, ciphertext + ciphertext_size);
    plaintext->assign(ciphertext_size, 0);

    std::vector<UCHAR> iv_copy;
    PUCHAR iv_ptr = nullptr;
    ULONG iv_size = 0;
    if (iv != nullptr)
    {
        iv_copy.assign(iv->begin(), iv->end());
        iv_ptr = iv_copy.data();
        iv_size = static_cast<ULONG>(iv_copy.size());
    }

    status = BCryptDecrypt(
        imported_key,
        input.data(),
        static_cast<ULONG>(input.size()),
        nullptr,
        iv_ptr,
        iv_size,
        plaintext->data(),
        static_cast<ULONG>(plaintext->size()),
        &bytes_written,
        0
    );
    if (status < 0)
    {
        *error_message = L"BCryptDecrypt failed with NTSTATUS " +
            FormatNtStatusMessage(status);
        cleanup();
        return false;
    }

    plaintext->resize(bytes_written);
    cleanup();
    return true;
}

bool AesDecryptEcbBlock(
    const Block& ciphertext,
    const Block& key,
    Block* plaintext,
    std::wstring* error_message
)
{
    std::vector<uint8_t> plain_bytes;
    if (!AesDecryptNoPadding(
        ciphertext.data(),
        ciphertext.size(),
        key,
        BCRYPT_CHAIN_MODE_ECB,
        nullptr,
        &plain_bytes,
        error_message))
    {
        return false;
    }

    if (plain_bytes.size() != kAesBlockSize)
    {
        *error_message = L"Unexpected ECB plaintext size.";
        return false;
    }

    memcpy(
        plaintext->data(),
        plain_bytes.data(),
        kAesBlockSize
    );
    return true;
}

bool ParseBootId(
    const std::vector<uint8_t>& bootid_plain,
    BootIdInfo* bootid,
    std::wstring* error_message
)
{
    if (bootid_plain.size() < 56)
    {
        *error_message = L"Decrypted BootId is too small.";
        return false;
    }

    bootid->container_type = bootid_plain[13];

    bootid->block_count = ReadLeU64(bootid_plain.data() + 32);
    bootid->block_size = ReadLeU64(bootid_plain.data() + 40);
    bootid->header_block_count = ReadLeU64(bootid_plain.data() + 48);

    bootid->offset =
        bootid->header_block_count *
        bootid->block_size;

    bootid->volume_size =
        (bootid->block_count - bootid->header_block_count) *
        bootid->block_size *
        0x100;

    return true;
}

bool GetContainerLayout(
    uint8_t container_type,
    uint32_t* image_flag,
    const char** image_type,
    const char** container_name,
    const Block** expected_header,
    std::wstring* error_message
)
{
    switch (container_type)
    {
    case 0x00:
        *image_flag = 0;
        *image_type = "NTFS Container";
        *container_name = "OS";
        *expected_header = &kNtfsHeader;
        return true;

    case 0x01:
        *image_flag = 0;
        *image_type = "NTFS Container";
        *container_name = "APP";
        *expected_header = &kNtfsHeader;
        return true;

    case 0x02:
        //*image_flag = 0x100000;
        *image_flag = 0x3A000000;
        *image_type = "EXFAT Container";
        *container_name = "OPTION";
        *expected_header = &kExfatHeader;
        return true;

    default:
        *error_message = L"Unsupported BootId container type: " +
            std::to_wstring(static_cast<unsigned>(container_type));
        return false;
    }
}

bool LoadMountKeyMaterial(
    const wchar_t* container_filename,
    const wchar_t* key_filename,
    MountKeyMaterial* material
)
{
    FILE* key_fp = nullptr;

    _wfopen_s(
        &key_fp,
        key_filename,
        L"rb"
    );

    if (!key_fp)
    {
        wprintf(L"Open key file failed: %ls\n", key_filename);
        return false;
    }

    const size_t key_bytes = fread(
        material->key.data(),
        1,
        material->key.size(),
        key_fp
    );

    fclose(key_fp);

    if (key_bytes != material->key.size())
    {
        printf(
            "Key file too small: need at least 16 bytes, got %zu\n",
            key_bytes
        );
        return false;
    }

    FILE* container_fp = nullptr;

    _wfopen_s(
        &container_fp,
        container_filename,
        L"rb"
    );

    if (!container_fp)
    {
        wprintf(L"Open container file failed: %ls\n", container_filename);
        return false;
    }

    uint8_t bootid_ciphertext[kBootIdEncryptedSize]{};
    if (fread(
        bootid_ciphertext,
        1,
        sizeof(bootid_ciphertext),
        container_fp) != sizeof(bootid_ciphertext))
    {
        wprintf(L"Read BootId failed: %ls\n", container_filename);
        fclose(container_fp);
        return false;
    }

    std::vector<uint8_t> bootid_plain;
    std::wstring error_message;
    if (!AesDecryptNoPadding(
        bootid_ciphertext,
        sizeof(bootid_ciphertext),
        kBootIdKey,
        BCRYPT_CHAIN_MODE_CBC,
        &kBootIdIv,
        &bootid_plain,
        &error_message))
    {
        PrintWideError(L"Decrypt BootId failed: " + error_message);
        fclose(container_fp);
        return false;
    }

    BootIdInfo bootid{};
    if (!ParseBootId(
        bootid_plain,
        &bootid,
        &error_message))
    {
        PrintWideError(L"Parse BootId failed: " + error_message);
        fclose(container_fp);
        return false;
    }

    const Block* expected_header = nullptr;
    if (!GetContainerLayout(
        bootid.container_type,
        &material->image_flag,
        &material->image_type,
        &material->container_name,
        &expected_header,
        &error_message))
    {
        PrintWideError(L"Recognize BootId container failed: " + error_message);
        fclose(container_fp);
        return false;
    }

    const uint64_t data_offset =
        bootid.header_block_count * bootid.block_size;

    if (_fseeki64(
        container_fp,
        static_cast<__int64>(data_offset),
        SEEK_SET) != 0)
    {
        wprintf(L"Seek encrypted data failed: %ls\n", container_filename);
        fclose(container_fp);
        return false;
    }

    Block first_block_ciphertext{};
    if (fread(
        first_block_ciphertext.data(),
        1,
        first_block_ciphertext.size(),
        container_fp) != first_block_ciphertext.size())
    {
        wprintf(L"Read encrypted first block failed: %ls\n", container_filename);
        fclose(container_fp);
        return false;
    }

    fclose(container_fp);

    Block decrypted_first_block{};
    if (!AesDecryptEcbBlock(
        first_block_ciphertext,
        material->key,
        &decrypted_first_block,
        &error_message))
    {
        PrintWideError(L"Decrypt first data block failed: " + error_message);
        return false;
    }

    material->iv = XorBlocks(
        decrypted_first_block,
        *expected_header
    );

    return true;
}

} // namespace

Command ParseCommand(const wchar_t* cmd)
{
    if (_wcsicmp(cmd, L"MOUNT") == 0)
        return CMD_MOUNT;

    if (_wcsicmp(cmd, L"UNMOUNT") == 0)
        return CMD_UNMOUNT;

    if (_wcsicmp(cmd, L"LINK") == 0)
        return CMD_LINK;

    return CMD_UNKNOWN;
}

void HexDump(const void* data, size_t size)
{
    const uint8_t* p = (const uint8_t*)data;

    for (size_t i = 0; i < size; i += 16)
    {
        printf("%04llX  ",
            (unsigned long long)i);

        for (size_t j = 0; j < 16; j++)
        {
            if (i + j < size)
                printf("%02X ", p[i + j]);
            else
                printf("   ");

            if (j == 7)
                printf("- ");
        }

        printf(" ");

        for (size_t j = 0; j < 16 && i + j < size; j++)
        {
            uint8_t c = p[i + j];

            if (c >= 0x20 && c <= 0x7E)
                printf("%c", c);
            else
                printf(".");
        }

        printf("\n");
    }
}

void ConvertFilePath(
    const wchar_t* input,
    wchar_t* output,
    size_t output_size
)
{
    wchar_t temp[512]{};

    size_t pos = 0;

    for (size_t i = 0; input[i] && pos < _countof(temp) - 1; i++)
    {
        wchar_t c = input[i];

        if (c == L'/')
        {
            c = L'\\';
        }

        if (c == L'\\')
        {
            if (input[i + 1] == L'\\')
            {
                temp[pos++] = L'\\';
                temp[pos++] = L'\\';
                i++;
            }
            else
            {
                temp[pos++] = L'\\';
                temp[pos++] = L'\\';
            }
        }
        else
        {
            temp[pos++] = c;
        }
    }

    temp[pos] = 0;

    swprintf_s(
        output,
        output_size,
        L"\\??\\%s",
        temp
    );
}

bool CheckFscryptDiskLink(const std::wstring& tag)
{
    std::wstring devicePath = L"\\\\.\\FscryptDisk_" + tag;

    HANDLE hDevice = CreateFileW(
        devicePath.c_str(),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    CloseHandle(hDevice);
    return true;
}

bool Mount(
    const wchar_t* path,
    const wchar_t* keyFile,
    const wchar_t* tag
)
{
    HANDLE hDevice = CreateFileW(
        L"\\\\.\\Fscrypt",
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf(
            "Open Fscrypt Driver Failed: %lu\n",
            GetLastError()
        );

        return false;
    }

    FileMountHeader packet{};
    BootIdInfo btid{};

    packet.total_size =
        sizeof(FileMountHeader);

    ConvertFilePath(
        path,
        packet.file_path,
        _countof(packet.file_path)
    );

    packet.startoffset = 0x200000;
    packet.unk5 = 1;
    packet.unk6 = 0;

    MountKeyMaterial key_material{};
    if (!LoadMountKeyMaterial(
        path,
        keyFile,
        &key_material))
    {
        CloseHandle(hDevice);
        return false;
    }

    memcpy(
        packet.aes_key,
        key_material.key.data(),
        key_material.key.size()
    );
    memcpy(
        packet.aes_key + key_material.key.size(),
        key_material.iv.data(),
        key_material.iv.size()
    );

    printf("Opened Fscrypt Driver\n");

    wcscpy_s(
        packet.tag_name,
        tag
    );
    packet.volumeSize = btid.volume_size;
    printf("Container type: %s\n", key_material.container_name);
    printf("Image type: %s\n", key_material.image_type);
    printf("Calculated IV: %s\n", HexString(key_material.iv).c_str());

    uint8_t output[0x400]{};

    DWORD returned = 0;

    BOOL result = DeviceIoControl(
        hDevice,
        0x22E008,

        &packet,
        sizeof(packet),

        output,
        sizeof(output),

        &returned,

        nullptr
    );

    if (!result)
    {
        printf(
            "DeviceIoControl failed\n"
        );

        printf(
            "Error = %lu\n",
            GetLastError()
        );

        CloseHandle(hDevice);
        return false;
    }

    if (CheckFscryptDiskLink(tag)) {
        printf(
            "MOUNT Success\n"
        );
    }
    else {
        printf("Query Symbol Link Failed");
    }

    CloseHandle(hDevice);

    return true;
}

bool UnMount(
    const wchar_t* tag
)
{
    HANDLE hDevice = CreateFileW(
        L"\\\\.\\Fscrypt",
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf(
            "Open Fscrypt Driver Failed: %lu\n",
            GetLastError()
        );

        return false;
    }

    FileUnmountHeader packet{};

    packet.total_size = 0x204;

    swprintf_s(
        packet.file_path,
        _countof(packet.file_path),
        L"\\??\\FscryptDisk_%s\\",
        tag
    );

    printf("Opened Fscrypt Driver\n");

    uint8_t output[0x400]{};

    DWORD returned = 0;

    BOOL result = DeviceIoControl(
        hDevice,

        0x22E00C,

        &packet,
        sizeof(packet),

        output,
        sizeof(output),

        &returned,

        nullptr
    );

    if (!result)
    {
        printf(
            "DeviceIoControl failed\n"
        );

        printf(
            "Error = %lu\n",
            GetLastError()
        );

        CloseHandle(hDevice);

        return false;
    }

    printf(
        "UNMOUNT Success\n"
    );

    CloseHandle(hDevice);

    return true;
}

bool Link(const wchar_t* tag, const wchar_t* path)
{
    if (!tag || !path)
    {
        printf("LINK failed: invalid arguments\n");
        return false;
    }
    if (!CheckFscryptDiskLink(tag)) {
        printf(
            "LINK failed: Non-existent device\n"
        );
        return false;
    }
    const std::wstring rawTarget = std::wstring(L"\\\\.\\FscryptDisk_") + tag + L"\\";
    const std::wstring mountDir = NormalizeMountDirectory(path);
    const std::wstring ntTarget = NormalizeNtTarget(rawTarget);
    if (ntTarget.empty())
    {
        return false;
    }

    if (!EnsureMountDirectoryReady(mountDir))
    {
        return false;
    }

    if (!CreateMountPoint(mountDir, ntTarget))
    {
        return false;
    }

    wprintf(L"Mounted %ls at %ls\n", rawTarget.c_str(), mountDir.c_str());
    wprintf(L"NT target used: %ls\n", ntTarget.c_str());
    return true;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 2)
    {
        printf(
            "Usage:\n"
            " fscrypt_link MOUNT <path> <key.bin> <tag>\n"
            " fscrypt_link UNMOUNT <tag>\n"
            " fscrypt_link LINK <tag> <path>\n"
            " \nWarn:UNMOUNT maybe unstable\n\n"
            "example: fscrypt_link MOUNT E:\\SDEZ_1.65.00_20260227202056_0.app SDEZ.bin APP_0\n"
            "         fscrypt_link MOUNT E:\\SDEZ_1.66.00_20260319165237_1_1.65.00.app SDEZ.bin APP_1\n"
            "         fscrypt_link MOUNT E:\\SDGA_A005_20260108115627_0.opt SDGA.bin OPT_SDGA_A005_0\n"
            "         fscrypt_link UNMOUNT OPT_SDGA_A005_0\n"
            "         fscrypt_link Link OPT_SDGA_A005_0 C:\\Mount\\Option\\A005\n"
        );

        return 1;
    }

    Command cmd = ParseCommand(argv[1]);

    switch (cmd)
    {
    case CMD_MOUNT:
    {
        if (argc < 5)
        {
            printf(
                "MOUNT requires:\n"
                " fscrypt_link MOUNT <path> <key.bin> <tag>\n"
            );

            return 1;
        }

        return Mount(
            argv[2],
            argv[3],
            argv[4]
        ) ? 0 : 1;
    }

    case CMD_UNMOUNT:
    {
        if (argc < 3)
        {
            printf(
                "UNMOUNT requires:\n"
                " fscrypt_link UNMOUNT <tag>\n"
            );

            return 1;
        }

        return UnMount(
            argv[2]
        ) ? 0 : 1;
    }

    case CMD_LINK:
    {
        if (argc < 4)
        {
            printf(
                "LINK requires:\n"
                " fscrypt_link LINK <tag> <path>\n"
            );

            return 1;
        }
        return Link(
            argv[2], argv[3]
        ) ? 0 : 1;
    }

    case CMD_UNKNOWN:
    default:

        printf(
            "Unknown command\n"
        );

        return 1;
    }
}
