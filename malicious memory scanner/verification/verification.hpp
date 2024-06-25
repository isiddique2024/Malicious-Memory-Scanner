
__forceinline bool calc_hash(HANDLE file_handle, unsigned char** hash, unsigned long* hash_size) {

    *hash_size = 0;
    CryptCATAdminCalcHashFromFileHandle(file_handle, hash_size, 0, 0);
    *hash = new BYTE[*hash_size];
    if (!(CryptCATAdminCalcHashFromFileHandle)(file_handle, hash_size, *hash, 0)) {
        delete[] * hash;
        return false;
    }

    return true;
}

__forceinline bool verify_catalog(BYTE* hash, DWORD hashSize) {
    auto cat_admin = HCATADMIN{};
    if (!CryptCATAdminAcquireContext(&cat_admin, 0, 0)) {
        return 0;
    }

    bool has_catalog_signature = false;

    if (const auto catalog_info = CryptCATAdminEnumCatalogFromHash(cat_admin, hash, hashSize, 0, nullptr); catalog_info != nullptr) 
    {
        auto catalog_info_ = CATALOG_INFO{};

        has_catalog_signature = CryptCATCatalogInfoFromContext(catalog_info, &catalog_info_, 0);

        CryptCATAdminReleaseCatalogContext(cat_admin, catalog_info, 0);
    }

    return has_catalog_signature;
}

__forceinline bool verify_dll(const std::wstring& file_name) {

    //first we'll verify using WinVerifyTrust, if it fails (it does on specific modules like uxtheme.dll), then we'll verify the catalog signature.
    //if the catalog signature fails then it's unsigned
    WINTRUST_FILE_INFO file_info = {};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = file_name.c_str();

    WINTRUST_DATA trust_data = {};
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;

    GUID action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    auto status = WinVerifyTrust(NULL, &action_guid, &trust_data);
    if (status == ERROR_SUCCESS) {
         return true;
    }

    auto file_handle = CreateFileW(file_name.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) {
        std::wcerr << encrypt(L"Failed to open handle on file: ") << file_name.c_str() << std::endl;
        return 1;
    }

    BYTE* hash = nullptr;
    DWORD hashSize = 0;

    bool ret = 0;
    if (calc_hash(file_handle, &hash, &hashSize)) {
        ret = verify_catalog(hash, hashSize);
    }

    sys(NTSTATUS, NtClose).call(file_handle);

    delete[] hash;
    return ret;
  
}