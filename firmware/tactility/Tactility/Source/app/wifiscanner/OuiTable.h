#pragma once

#include <cstdint>

namespace tt::app::wifiscanner {

/** @return the abbreviated vendor name for the first three bytes of a MAC, or nullptr when unknown. */
const char* lookupVendor(const uint8_t* bssid);

} // namespace tt::app::wifiscanner
