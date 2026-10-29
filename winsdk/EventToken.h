// Minimal EventToken.h shim for cross-compiling WebView2 with MinGW.
// The Windows SDK's WinRT EventToken.h is not shipped with MinGW; the
// WebView2 C API only needs the global EventRegistrationToken struct.
#pragma once

#include <cstdint>

#ifdef __cplusplus
typedef struct EventRegistrationToken
{
    int64_t value;
} EventRegistrationToken;
#else
typedef struct EventRegistrationToken
{
    int64_t value;
} EventRegistrationToken;
#endif
