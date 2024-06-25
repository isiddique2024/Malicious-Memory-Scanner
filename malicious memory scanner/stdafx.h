#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <codecvt>
#include <unordered_map>
#include <direct.h>
#include <vector>
#include <algorithm>
#include <psapi.h>
#include <tlhelp32.h>
#include <mscat.h>
#include <wincrypt.h>
#include <SoftPub.h>
#include <WinTrust.h>
#pragma comment (lib, "wintrust")

#include "util/structs.hpp"
#include "util/encrypt.hpp"
#include "util/shadow_syscall.hpp"
#include "util/li.hpp"
#include "util/util.hpp"