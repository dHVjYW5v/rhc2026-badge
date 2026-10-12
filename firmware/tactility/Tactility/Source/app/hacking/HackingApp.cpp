#include <app/event.h>
#include <app/manager.h>
#include <app/manifest.h>
#include <app/scheduler.h>

#include <lvgl_window_manager/window_manager.h>
#include <tactility/check.h>
#include <lvgl.h>
#include <lvgl/widgets/toolbar.h>

namespace tt::app::hacking {

extern const ::AppManifest manifest;

namespace {

struct Context {
    uint32_t appInstanceId;
};

void onBackPressed(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    app_event_emit_close(ctx->appInstanceId);
}

void onLaunchNetWhisperer(lv_event_t* event) {
    uint32_t id = 0;
    app_manager_start("WifiScanner", &id);
}

void createWidgets(lv_obj_t* parent, void* userData) {
    auto* ctx = static_cast<Context*>(userData);

    lv_obj_set_flex_flow(parent, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(parent, 0, LV_STATE_DEFAULT);

    auto* toolbar = lvgl_toolbar_create(parent, "Hacking");
    lvgl_toolbar_set_nav_action(toolbar, LV_SYMBOL_CLOSE, onBackPressed, ctx);

    lv_obj_t* list = lv_list_create(parent);
    lv_obj_set_width(list, LV_PCT(100));
    lv_obj_set_flex_grow(list, 1);

    // Primary tool: NetWhisperer
    lv_obj_t* btn1 = lv_list_add_button(list, LV_SYMBOL_WIFI, "NetWhisperer (Wi-Fi Recon & Sniffer)");
    lv_obj_add_event_cb(btn1, onLaunchNetWhisperer, LV_EVENT_SHORT_CLICKED, nullptr);
    
    // Auto focus the button for easy 1-click launch
    lv_group_focus_obj(btn1);
}

int32_t appMain(int argc, char* argv[]) {
    uint32_t appInstanceId = app_scheduler_current_app_id();
    Context ctx { appInstanceId };

    TaskEventGroup event_group {};
    task_event_group_construct(&event_group);

    AppEventSubscription sub {};
    check(app_event_subscribe(&sub, &event_group) == ERROR_NONE);

    WindowId window = window_manager_create(appInstanceId, createWidgets, &ctx);

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
    .id = "tactility.hacking",
    .name = "Hacking",
    .category = APP_CATEGORY_USER,
    .location = { .type = APP_LOCATION_MEMORY, .location = reinterpret_cast<void*>(appMain) },
    .flags = 0,
    .stack = { .depth = 2400, .desired_memory_capability = 0 }
};

} // namespace tt::app::hacking
