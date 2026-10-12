// SPDX-License-Identifier: Apache-2.0
#include "romhack_splash_data.h"

#include <tactility/device.h>
#include <tactility/drivers/backlight.h>
#include <tactility/drivers/display.h>
#include <tactility/log.h>

#include <cstdlib>
#include <cstring>
#include <miniz.h>
#include <esp_random.h>

#define TAG "RomhackSplash"

namespace {

void clearToBlack(Device* display) {
    constexpr int CLEAR_BAND_HEIGHT = 40;
    const size_t band_bytes = (size_t) ROMHACK_SPLASH_SCREEN_W * CLEAR_BAND_HEIGHT * 2;
    auto* band = static_cast<uint8_t*>(malloc(band_bytes));
    if (band == nullptr) {
        return;
    }
    memset(band, 0, band_bytes);
    for (int y = 0; y < ROMHACK_SPLASH_SCREEN_H; y += CLEAR_BAND_HEIGHT) {
        int height = ROMHACK_SPLASH_SCREEN_H - y;
        if (height > CLEAR_BAND_HEIGHT) {
            height = CLEAR_BAND_HEIGHT;
        }
        display_draw_bitmap(display, 0, y, ROMHACK_SPLASH_SCREEN_W, y + height, band);
    }
    free(band);
}

} // namespace

/**
 * Paints the splash to the panel's GRAM before LVGL exists, then lights the backlight.
 * Dynamically picks one of the 4 pentesting bootsplashes (Award BIOS, Win98, Hacker Punk, Retro Terminal).
 */
extern "C" void romhack_draw_early_splash(void) {
    Device* display = nullptr;
    if (device_get_first_active_by_type(&DISPLAY_TYPE, &display) != ERROR_NONE) {
        LOG_W(TAG, "No active display for early splash");
        return;
    }

    clearToBlack(display);

    int splash_idx = (int)(esp_random() % ROMHACK_SPLASH_COUNT);
    const auto& item = ROMHACK_SPLASHES[splash_idx];
    LOG_I(TAG, "Drawing bootsplash [%d]: %s", splash_idx, item.name);

    auto* decompressed = static_cast<uint8_t*>(malloc(ROMHACK_SPLASH_RAW_SIZE));
    if (decompressed != nullptr) {
        size_t written = tinfl_decompress_mem_to_mem(
            decompressed,
            ROMHACK_SPLASH_RAW_SIZE,
            item.zlib_data,
            item.zlib_size,
            TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF
        );
        if (written == ROMHACK_SPLASH_RAW_SIZE) {
            display_draw_bitmap(display, 0, 0, ROMHACK_SPLASH_SCREEN_W, ROMHACK_SPLASH_SCREEN_H, decompressed);
        } else {
            LOG_E(TAG, "Failed to decompress splash (written: %zu)", written);
        }
        free(decompressed);
    } else {
        LOG_E(TAG, "Out of memory allocating splash buffer");
    }

    Device* backlight = nullptr;
    if (display_get_backlight(display, &backlight) == ERROR_NONE) {
        if (!device_is_ready(backlight) && device_start(backlight) != ERROR_NONE) {
            LOG_E(TAG, "Failed to start %s", backlight->name);
        }
        device_put(backlight);
    }

    device_put(display);
    LOG_I(TAG, "Early splash drawn successfully");
}
