
auto calc_hash(void* file_handle, unsigned char** hash, unsigned long* hash_size) -> bool
{
    CryptCATAdminCalcHashFromFileHandle(file_handle, hash_size, nullptr, 0);
    *hash = new unsigned char[*hash_size];

    if (!CryptCATAdminCalcHashFromFileHandle(file_handle, hash_size, *hash, 0)) {
        delete[] * hash;
        return false;
    }

    return true;
}

auto verify_catalog(unsigned char* hash, unsigned long hash_size) -> bool
{
    HCATADMIN cat_admin{};
    if (!CryptCATAdminAcquireContext(&cat_admin, 0, 0)) {
        return false;
    }

    CATALOG_INFO catalog_info_{};
    auto catalog_info = CryptCATAdminEnumCatalogFromHash(cat_admin, hash, hash_size, 0, nullptr);

    bool has_catalog_signature = catalog_info && CryptCATCatalogInfoFromContext(catalog_info, &catalog_info_, 0);

    if (catalog_info) {
        CryptCATAdminReleaseCatalogContext(cat_admin, catalog_info, 0);
    }

    return has_catalog_signature;
}

auto verify_dll(const std::wstring& file_name) -> bool
{

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
    const auto status = WinVerifyTrust(NULL, &action_guid, &trust_data);
    if (status == ERROR_SUCCESS) {
         return true;
    }

    const auto file_handle = CreateFileW(file_name.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) {
        std::wcerr << encrypt(L"Failed to open handle on file: ") << file_name.c_str() << std::endl;
        return true;
    }

    unsigned char* hash = nullptr;
    unsigned long hash_size = 0;

    bool ret = 0;
    if (calc_hash(file_handle, &hash, &hash_size)) {
        ret = verify_catalog(hash, hash_size);
    }

    sys(NTSTATUS, NtClose).call(file_handle);

    delete[] hash;
    return ret;
  
}