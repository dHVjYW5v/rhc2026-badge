#include <Tactility/hal/usb/Usb.h>

#include <app/event.h>
#include <app/manager.h>
#include <app/manifest.h>
#include <app/scheduler.h>

#include <lvgl_window_manager/window_manager.h>

#include <tactility/check.h>

#include <lvgl.h>
#include <lvgl/widgets/toolbar.h>

#define TAG "usb_settings"

namespace tt::app::usbsettings {

extern const ::AppManifest manifest;

namespace {

struct Context {
    uint32_t appInstanceId;
    lv_obj_t* statusLabel = nullptr;
    lv_obj_t* btnLiveToggle = nullptr;
    lv_obj_t* labelLiveToggle = nullptr;
    lv_obj_t* btnSdReboot = nullptr;
    lv_obj_t* btnFlashReboot = nullptr;
};

static void updateUsbUI(Context* ctx) {
    if (ctx == nullptr || ctx->statusLabel == nullptr || ctx->btnLiveToggle == nullptr) return;
    bool isLive = (hal::usb::getMode() == hal::usb::Mode::MassStorageSdmmc || hal::usb::getMode() == hal::usb::Mode::MassStorageFlash);
    if (isLive) {
        lv_label_set_text(ctx->statusLabel, "USB Storage ACTIVE\nSD card shared with PC");
        lv_obj_set_style_text_color(ctx->statusLabel, lv_palette_main(LV_PALETTE_GREEN), 0);
        lv_label_set_text(ctx->labelLiveToggle, "Exit USB Mass Storage");
        lv_obj_set_style_bg_color(ctx->btnLiveToggle, lv_palette_main(LV_PALETTE_RED), 0);
        if (ctx->btnSdReboot) lv_obj_add_flag(ctx->btnSdReboot, LV_OBJ_FLAG_HIDDEN);
        if (ctx->btnFlashReboot) lv_obj_add_flag(ctx->btnFlashReboot, LV_OBJ_FLAG_HIDDEN);
    } else {
        lv_label_set_text(ctx->statusLabel, "Connect badge to PC via USB");
        lv_obj_set_style_text_color(ctx->statusLabel, lv_palette_main(LV_PALETTE_GREY), 0);
        lv_label_set_text(ctx->labelLiveToggle, "Start USB Storage (Live SD)");
        lv_obj_remove_local_style_prop(ctx->btnLiveToggle, LV_STYLE_BG_COLOR, 0);
        if (ctx->btnSdReboot) lv_obj_remove_flag(ctx->btnSdReboot, LV_OBJ_FLAG_HIDDEN);
        if (ctx->btnFlashReboot) lv_obj_remove_flag(ctx->btnFlashReboot, LV_OBJ_FLAG_HIDDEN);
    }
}

void onBackPressed(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    if (hal::usb::getMode() == hal::usb::Mode::MassStorageSdmmc || hal::usb::getMode() == hal::usb::Mode::MassStorageFlash) {
        hal::usb::stop();
    }
    app_event_emit_close(ctx->appInstanceId);
}

static void onLiveToggleClicked(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    bool isLive = (hal::usb::getMode() == hal::usb::Mode::MassStorageSdmmc || hal::usb::getMode() == hal::usb::Mode::MassStorageFlash);
    if (isLive) {
        hal::usb::stop();
    } else {
        hal::usb::startMassStorageWithSdmmc(false);
    }
    updateUsbUI(ctx);
}

void onRebootMassStorageSdmmc(lv_event_t* event) {
    hal::usb::rebootIntoMassStorageSdmmc();
}

// Flash reboot handler
void onRebootMassStorageFlash(lv_event_t* event) {
    hal::usb::rebootIntoMassStorageFlash();
}

void createWidgets(lv_obj_t* parent, void* userData) {
    auto* ctx = static_cast<Context*>(userData);

    auto* toolbar = lvgl_toolbar_create(parent, "USB Storage");
    lvgl_toolbar_set_nav_action(toolbar, LV_SYMBOL_CLOSE, onBackPressed, ctx);
    lv_obj_align(toolbar, LV_ALIGN_TOP_MID, 0, 0);

    // Create a wrapper container for buttons
    auto* wrapper = lv_obj_create(parent);
    lv_obj_set_flex_flow(wrapper, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(wrapper, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_row(wrapper, 10, 0);
    lv_obj_set_size(wrapper, lv_pct(100), LV_SIZE_CONTENT);
    lv_obj_align(wrapper, LV_ALIGN_CENTER, 0, 10);

    ctx->statusLabel = lv_label_create(wrapper);
    lv_obj_set_style_text_align(ctx->statusLabel, LV_TEXT_ALIGN_CENTER, 0);

    bool hasSd = hal::usb::canRebootIntoMassStorageSdmmc();
    bool hasFlash = hal::usb::canRebootIntoMassStorageFlash();

    if (hasSd || hal::usb::isSupported()) {
        ctx->btnLiveToggle = lv_button_create(wrapper);
        ctx->labelLiveToggle = lv_label_create(ctx->btnLiveToggle);
        lv_obj_add_event_cb(ctx->btnLiveToggle, onLiveToggleClicked, LV_EVENT_SHORT_CLICKED, ctx);
    }

    if (hasSd) {
        ctx->btnSdReboot = lv_button_create(wrapper);
        auto* label_sd = lv_label_create(ctx->btnSdReboot);
        lv_label_set_text(label_sd, "Reboot as USB storage (SD)");
        lv_obj_add_event_cb(ctx->btnSdReboot, onRebootMassStorageSdmmc, LV_EVENT_SHORT_CLICKED, nullptr);
    }

    if (hasFlash) {
        ctx->btnFlashReboot = lv_button_create(wrapper);
        auto* label_flash = lv_label_create(ctx->btnFlashReboot);
        lv_label_set_text(label_flash, "Reboot as USB storage (Flash)");
        lv_obj_add_event_cb(ctx->btnFlashReboot, onRebootMassStorageFlash, LV_EVENT_SHORT_CLICKED, nullptr);
    }

    if (!hasSd && !hasFlash && !ctx->btnLiveToggle) {
        bool supported = hal::usb::isSupported();
        const char* message = supported ? "USB storage not available" : "USB driver not supported";
        auto* label = lv_label_create(wrapper);
        lv_label_set_text(label, message);
    }

    updateUsbUI(ctx);
    if (ctx->btnLiveToggle) {
        lv_group_focus_obj(ctx->btnLiveToggle);
    }
}

int32_t appMain(int argc, char* argv[]) {
    uint32_t appInstanceId = app_scheduler_current_app_id();
    Context ctx {};
    ctx.appInstanceId = appInstanceId;

    TaskEventGroup event_group {};
    task_event_group_construct(&event_group);

    AppEventSubscription sub {};
    check(app_event_subscribe(&sub, &event_group) == ERROR_NONE);

    WindowId window = window_manager_create(appInstanceId, createWidgets, &ctx);

    bool shouldClose = false;
    while (!shouldClose) {
        task_event_group_wait_any(&event_group, nullptr, portMAX_DELAY);

        AppEvent event {};
        while (app_event_poll(&sub, &event) == ERROR_NONE) {
            switch (event.type) {
                case APP_EVENT_CLOSE:
                    shouldClose = true;
                    break;
                default:
                    break;
            }
            if (shouldClose) break;
        }
    }

    window_manager_remove(window);
    check(app_event_unsubscribe(&sub) == ERROR_NONE);
    task_event_group_destruct(&event_group);

    return 0;
}

} // namespace

extern const ::AppManifest manifest = {
    .id = "tactility.usbsettings",
    .name = "USB",
    .category = APP_CATEGORY_SETTINGS,
    .location = { APP_LOCATION_MEMORY, reinterpret_cast<void*>(appMain) }
};

} // namespace
