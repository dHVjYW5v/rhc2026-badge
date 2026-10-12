// SPDX-License-Identifier: Apache-2.0
#include "romhack_splash_data.h"

#include <tactility/device.h>
#include <tactility/drivers/backlight.h>
#include <tactility/drivers/display.h>
#include <tactility/log.h>

#include <cstdlib>
#include <cstring>
#include <esp_random.h>

#define TAG "RomhackSplash"

extern "C" {
struct LodePNGDecompressSettings {
    unsigned ignore_adler32;
    unsigned ignore_nlen;
    size_t max_output_size;
    unsigned (*custom_zlib)(unsigned char**, size_t*, const unsigned char*, size_t, const struct LodePNGDecompressSettings*);
    unsigned (*custom_inflate)(unsigned char**, size_t*, const unsigned char*, size_t, const struct LodePNGDecompressSettings*);
    const void* custom_context;
};
extern const struct LodePNGDecompressSettings lodepng_default_decompress_settings;
unsigned lodepng_zlib_decompress(unsigned char** out, size_t* outsize,
                                 const unsigned char* in, size_t insize,
                                 const struct LodePNGDecompressSettings* settings);
}

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

    unsigned char* decompressed = nullptr;
    size_t decompressed_size = 0;
    unsigned err = lodepng_zlib_decompress(
        &decompressed,
        &decompressed_size,
        item.zlib_data,
        item.zlib_size,
        &lodepng_default_decompress_settings
    );

    if (err == 0 && decompressed != nullptr && decompressed_size == ROMHACK_SPLASH_RAW_SIZE) {
        constexpr int BAND_H = 40;
        for (int y = 0; y < ROMHACK_SPLASH_SCREEN_H; y += BAND_H) {
            int h = (y + BAND_H <= ROMHACK_SPLASH_SCREEN_H) ? BAND_H : (ROMHACK_SPLASH_SCREEN_H - y);
            display_draw_bitmap(display, 0, y, ROMHACK_SPLASH_SCREEN_W, y + h, decompressed + (y * ROMHACK_SPLASH_SCREEN_W * 2));
        }
        free(decompressed);
        LOG_I(TAG, "Bootsplash drawn successfully");
    } else {
        LOG_E(TAG, "Failed to decompress bootsplash, error: %u", err);
        if (decompressed != nullptr) free(decompressed);
    }

    Device* backlight = nullptr;
    if (display_get_backlight(display, &backlight) == ERROR_NONE) {
        if (!device_is_ready(backlight) && device_start(backlight) != ERROR_NONE) {
            LOG_E(TAG, "Failed to start %s", backlight->name);
        }
        device_put(backlight);
    }

    device_put(display);
}
