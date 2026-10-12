// SPDX-License-Identifier: Apache-2.0
#include <app/event.h>
#include <app/manager.h>
#include <app/manifest.h>
#include <app/scheduler.h>

#include <cstring>

#include <lvgl.h>
#include <lvgl/icons/launcher.h>
#include "HackingIcons.h"
#include <lvgl/fonts.h>
#include <lvgl/lvgl.h>

#include <lvgl_window_manager/window_manager.h>

#include <tactility/check.h>
#include <tactility/device.h>
#include <tactility/drivers/pointer.h>
#include <tactility/drivers/power_supply.h>
#include <tactility/log.h>
#include <tactility/memory.h>

#include <Tactility/app/setup/Setup.h>
#include <Tactility/settings/BootSettings.h>
#include <Tactility/Tactility.h>

namespace tt::app::launcher {

constexpr auto* TAG = "Launcher";

namespace {

[[maybe_unused]] uint32_t getButtonPadding(UiDensity density, uint32_t buttonSize) {
    if (density == LVGL_UI_DENSITY_COMPACT) {
        return 0;
    } else {
        return buttonSize / 8;
    }
}

void onAppPressed(lv_event_t* e) {
    auto* appId = static_cast<const char*>(lv_event_get_user_data(e));
    uint32_t instance_id = 0;
    app_manager_start(appId, &instance_id);
}

lv_obj_t* createAppButton(lv_obj_t* parent, UiDensity uiDensity, const void* imageSrc, const char* labelText, const char* appId, bool isDescriptor = false) {
    auto* apps_button = lv_button_create(parent);

    lv_obj_set_flex_flow(apps_button, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(apps_button, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_hor(apps_button, 10, LV_STATE_DEFAULT);
    lv_obj_set_style_pad_ver(apps_button, 4, LV_STATE_DEFAULT);
    lv_obj_set_style_pad_row(apps_button, 2, LV_STATE_DEFAULT);

    lv_obj_set_style_shadow_width(apps_button, 0, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_opa(apps_button, 0, LV_STATE_DEFAULT);
    lv_obj_set_style_border_width(apps_button, 0, LV_STATE_DEFAULT);
    lv_obj_set_style_radius(apps_button, 8, LV_STATE_DEFAULT);

    // Focused style: distinct high-contrast outline & semitransparent fill
    const lv_color_t primary = lv_theme_get_color_primary(parent);
    for (lv_state_t st : { LV_STATE_FOCUSED, LV_STATE_FOCUS_KEY }) {
        lv_obj_set_style_bg_color(apps_button, primary, st);
        lv_obj_set_style_bg_opa(apps_button, LV_OPA_30, st);
        lv_obj_set_style_border_width(apps_button, 2, st);
        lv_obj_set_style_border_color(apps_button, primary, st);
        lv_obj_set_style_border_opa(apps_button, LV_OPA_COVER, st);
        lv_obj_set_style_outline_width(apps_button, 2, st);
        lv_obj_set_style_outline_color(apps_button, primary, st);
        lv_obj_set_style_outline_pad(apps_button, 2, st);
        lv_obj_set_style_outline_opa(apps_button, LV_OPA_COVER, st);
    }

    // Create the icon image
    auto* button_image = lv_image_create(apps_button);
    if (isDescriptor) {
        lv_image_set_src(button_image, imageSrc);
    } else {
        lv_obj_set_style_text_font(button_image, lvgl_get_launcher_icon_font(), LV_STATE_DEFAULT);
        lv_image_set_src(button_image, static_cast<const char*>(imageSrc));
        lv_obj_set_style_text_color(button_image, lv_theme_get_color_primary(button_image), LV_STATE_DEFAULT);
        lv_obj_set_style_image_recolor(button_image, lv_theme_get_color_primary(parent), LV_STATE_DEFAULT);
        lv_obj_set_style_image_recolor_opa(button_image, LV_OPA_COVER, LV_STATE_DEFAULT);
        const auto icon_size = lvgl_get_launcher_icon_font_height();
        lv_obj_set_size(button_image, icon_size, icon_size);
    }

    // Text label underneath
    auto* label = lv_label_create(apps_button);
    lv_label_set_text(label, labelText);
    lv_obj_set_style_text_font(label, lvgl_get_text_font(FONT_SIZE_SMALL), LV_STATE_DEFAULT);
    lv_obj_set_style_text_color(label, lv_color_hex(0xE0E0E0), LV_STATE_DEFAULT);

    lv_obj_add_event_cb(apps_button, onAppPressed, LV_EVENT_SHORT_CLICKED, (void*)appId);

    return apps_button;
}

bool shouldShowPowerButton() {
    bool show_power_button = false;
    device_for_each_of_type(&POWER_SUPPLY_TYPE, &show_power_button, [](Device* device, void* context) {
        if (device_is_ready(device) && power_supply_supports_power_off(device)) {
            *static_cast<bool*>(context) = true;
            return false; // stop iterating
        } else {
            return true; // continue iterating
        }
    });
    return show_power_button;
}

void createWidgets(lv_obj_t* parent, void*) {
    auto* buttons_wrapper = lv_obj_create(parent);
    auto ui_density = lvgl_get_ui_density();

    lv_obj_align(buttons_wrapper, LV_ALIGN_CENTER, 0, -4);
    lv_obj_set_size(buttons_wrapper, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
    lv_obj_set_style_border_width(buttons_wrapper, 0, LV_STATE_DEFAULT);
    lv_obj_set_flex_grow(buttons_wrapper, 1);
    lv_obj_set_flex_flow(buttons_wrapper, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(buttons_wrapper, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(buttons_wrapper, 2, LV_STATE_DEFAULT);
    lv_obj_set_style_pad_row(buttons_wrapper, 6, LV_STATE_DEFAULT);

    // Row 1 (Top): Hacking and USB
    auto* top_row = lv_obj_create(buttons_wrapper);
    lv_obj_remove_style_all(top_row);
    lv_obj_set_size(top_row, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(top_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(top_row, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(top_row, 18, LV_STATE_DEFAULT);

    auto* hacking_button = createAppButton(top_row, ui_density, &icon_8bit_skull, "Hacking", "tactility.hacking", true);
    createAppButton(top_row, ui_density, &icon_usb_disk, "USB", "tactility.usbsettings", true);

    // Row 2 (Bottom): Apps, Musica, Impostazioni
    auto* bottom_row = lv_obj_create(buttons_wrapper);
    lv_obj_remove_style_all(bottom_row);
    lv_obj_set_size(bottom_row, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(bottom_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(bottom_row, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(bottom_row, 12, LV_STATE_DEFAULT);

    createAppButton(bottom_row, ui_density, LVGL_ICON_LAUNCHER_APPS, "Apps", "tactility.applist");
    createAppButton(bottom_row, ui_density, LVGL_ICON_LAUNCHER_MUSIC_NOTE, "Musica", "MusicPlayer");
    createAppButton(bottom_row, ui_density, LVGL_ICON_LAUNCHER_SETTINGS, "Impostazioni", "tactility.settings");

    // Default focus on Hacking
    if (!device_has_active_by_type(&POINTER_TYPE)) {
        lv_group_focus_obj(hacking_button);
        lv_obj_add_state(hacking_button, LV_STATE_FOCUS_KEY);
    }

    // Power off button for devices without power switches
    if (shouldShowPowerButton()) {
        auto* power_button = lv_button_create(parent);
        lv_obj_set_style_pad_all(power_button, 8, 0);
        lv_obj_align(power_button, LV_ALIGN_BOTTOM_MID, 0, -10);
        lv_obj_add_event_cb(power_button, onAppPressed, LV_EVENT_SHORT_CLICKED, (void*)"tactility.poweroff");
        lv_obj_set_style_shadow_width(power_button, 0, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(power_button, 0, LV_PART_MAIN);

        const lv_color_t primary = lv_theme_get_color_primary(parent);
        for (lv_state_t st : { LV_STATE_FOCUSED, LV_STATE_FOCUS_KEY }) {
            lv_obj_set_style_bg_color(power_button, primary, st);
            lv_obj_set_style_bg_opa(power_button, LV_OPA_30, st);
            lv_obj_set_style_border_width(power_button, 2, st);
            lv_obj_set_style_border_color(power_button, primary, st);
            lv_obj_set_style_border_opa(power_button, LV_OPA_COVER, st);
        }
        lv_obj_set_style_radius(power_button, 8, LV_STATE_DEFAULT);

        auto* power_label = lv_label_create(power_button);
        lv_label_set_text(power_label, LV_SYMBOL_POWER);
        lv_obj_set_style_text_color(power_label, primary, LV_STATE_DEFAULT);
    }
}

void runAutoStart() {
    settings::BootSettings boot_properties;
    AppManifest manifest;
    if (
        // Auto-start due to built-in requirement
        strcmp(CONFIG_TT_AUTO_START_APP_ID, "") != 0 &&
        app_manager_find_manifest(CONFIG_TT_AUTO_START_APP_ID, &manifest) == ERROR_NONE
    ) {
        LOG_I(TAG, "Starting %s", CONFIG_TT_AUTO_START_APP_ID);
        uint32_t app_launch_id;
        app_manager_start(CONFIG_TT_AUTO_START_APP_ID, &app_launch_id);
    } else if (
        // Auto-start due to user configuration
        settings::loadBootSettings(boot_properties) &&
        !boot_properties.autoStartAppId.empty() &&
        app_manager_find_manifest(boot_properties.autoStartAppId.c_str(), &manifest) == ERROR_NONE
    ) {
        LOG_I(TAG, "Starting %s", boot_properties.autoStartAppId.c_str());
        uint32_t app_launch_id;
        app_manager_start(boot_properties.autoStartAppId.c_str(), &app_launch_id);
    } else {
        // No auto-start, consider running system setup
        if (!setup::isCompleted()) {
            setup::start();
        }
    }
}

int32_t appMain(int argc, char* argv[]) {
    uint32_t appInstanceId = app_scheduler_current_app_id();
    runAutoStart();

    TaskEventGroup event_group {};
    task_event_group_construct(&event_group);

    AppEventSubscription sub {};
    check(app_event_subscribe(&sub, &event_group) == ERROR_NONE);

    WindowId window = window_manager_create(appInstanceId, createWidgets, nullptr);

    while (true) {
        task_event_group_wait_any(&event_group, nullptr, portMAX_DELAY);

        bool shouldClose = false;
        AppEvent event {};
        while (app_event_poll(&sub, &event) == ERROR_NONE) {
            if (event.type == APP_EVENT_CLOSE) {
                shouldClose = true;
                break;
            }
        }
        if (shouldClose) break;
    }

    window_manager_remove(window);
    check(app_event_unsubscribe(&sub) == ERROR_NONE);
    task_event_group_destruct(&event_group);
    return 0;
}

} // namespace

extern const ::AppManifest manifest = {
    .id = "tactility.launcher",
    .name = "Launcher",
    .category = APP_CATEGORY_SYSTEM,
    .location = { .type = APP_LOCATION_MEMORY, .location = reinterpret_cast<void*>(appMain) },
    .flags = APP_MANIFEST_FLAG_HIDDEN,
    .stack = { .depth = 3072, .desired_memory_capability = MEMORY_CAPABILITY_EXTERNAL }
};

uint32_t start() {
    uint32_t instance_id = 0;
    app_manager_start(manifest.id, &instance_id);
    return instance_id;
}

} // namespace tt::app::launcher
