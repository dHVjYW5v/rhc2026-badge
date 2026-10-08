#include <Tactility/RecursiveMutex.h>
#include <Tactility/Timer.h>
#include <Tactility/app/wificonnect/WifiConnect.h>
#include <Tactility/service/wifi/Wifi.h>

#include <app/event.h>
#include <app/manager.h>
#include <app/manifest.h>
#include <app/scheduler.h>

#include <lvgl_window_manager/window_manager.h>

#include <tactility/check.h>
#include <tactility/log.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include <lvgl/lvgl.h>
#include <lvgl/widgets/toolbar.h>

namespace tt::app::wifiscanner {

extern const ::AppManifest manifest;

namespace {

constexpr auto* TAG = "WifiScanner";
constexpr uint16_t MAX_RECORDS = 40;
constexpr uint32_t REFRESH_MS = 1000;

// The chart spans channel -1 to 15 in half-channel steps, so channels 1..13 sit inside with margin
// for the bell of the outermost ones. An AP's bell is +-2 channels wide (a 20 MHz signal).
constexpr int MAX_SERIES = 8;
constexpr int CHART_POINTS = 33;
constexpr float BELL_HALF_WIDTH = 2.0f;
constexpr int32_t SIGNAL_FLOOR_DBM = -100;
constexpr int32_t SIGNAL_RANGE_DB = 70;

const uint32_t SERIES_COLORS[MAX_SERIES] = {
    0xE6194B, 0x3CB44B, 0xFFE119, 0x4363D8, 0xF58231, 0x911EB4, 0x42D4F4, 0xF032E6
};

struct Context {
    uint32_t appInstanceId;

    RecursiveMutex mutex;
    std::unique_ptr<Timer> timer = nullptr;
    // Rows shown in the list. Kept apart from the live scan so the list does not rebuild under the cursor.
    std::vector<WifiApRecord> listRecords;

    lv_obj_t* statusLabel = nullptr;
    lv_obj_t* graphPage = nullptr;
    lv_obj_t* listPage = nullptr;
    lv_obj_t* chart = nullptr;
    lv_obj_t* legend = nullptr;
    lv_obj_t* list = nullptr;
    lv_chart_series_t* series[MAX_SERIES] = {};
};

const char* authToString(WifiAuthenticationType type) {
    switch (type) {
        case WIFI_AUTHENTICATION_TYPE_OPEN: return "OPEN";
        case WIFI_AUTHENTICATION_TYPE_WEP: return "WEP";
        case WIFI_AUTHENTICATION_TYPE_WPA_PSK: return "WPA";
        case WIFI_AUTHENTICATION_TYPE_WPA2_PSK: return "WPA2";
        case WIFI_AUTHENTICATION_TYPE_WPA_WPA2_PSK: return "WPA/2";
        case WIFI_AUTHENTICATION_TYPE_WPA2_ENTERPRISE: return "WPA2-E";
        case WIFI_AUTHENTICATION_TYPE_WPA3_PSK: return "WPA3";
        case WIFI_AUTHENTICATION_TYPE_WPA2_WPA3_PSK: return "WPA2/3";
        default: return "?";
    }
}

const char* displaySsid(const WifiApRecord& record) {
    return record.ssid[0] != '\0' ? record.ssid : "(hidden)";
}

bool isRadioUsable() {
    using enum service::wifi::RadioState;
    auto state = service::wifi::getRadioState();
    return state == On || state == ConnectionPending || state == ConnectionActive;
}

void onSelectNetwork(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    auto index = reinterpret_cast<size_t>(lv_obj_get_user_data(lv_event_get_target_obj(event)));

    std::string ssid;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        if (index < ctx->listRecords.size()) {
            ssid = ctx->listRecords[index].ssid;
        }
        ctx->mutex.unlock();
    }
    if (ssid.empty()) return;

    service::wifi::settings::WifiApSettings settings;
    if (service::wifi::settings::load(ssid, settings)) {
        LOG_I(TAG, "Connecting with known credentials");
        service::wifi::connect(settings, false);
    } else {
        wificonnect::start(ssid);
    }
}

/** Must be called with the LVGL lock held. */
void rebuildList(Context* ctx, const std::vector<WifiApRecord>& records) {
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        ctx->listRecords = records;
        ctx->mutex.unlock();
    }
    if (ctx->list == nullptr) return;

    lv_obj_clean(ctx->list);
    for (size_t i = 0; i < records.size(); i++) {
        char line[96];
        snprintf(line, sizeof(line), "%s  ch%d  %d dBm  %s", displaySsid(records[i]),
            (int)records[i].channel, (int)records[i].rssi, authToString(records[i].authentication_type));
        auto* button = lv_list_add_button(ctx->list, nullptr, line);
        lv_obj_set_user_data(button, reinterpret_cast<void*>(i));
        lv_obj_add_event_cb(button, onSelectNetwork, LV_EVENT_SHORT_CLICKED, ctx);
    }
}

/** Must be called with the LVGL lock held. */
void updateGraph(Context* ctx, const std::vector<WifiApRecord>& records) {
    if (ctx->chart == nullptr) return;

    lv_obj_clean(ctx->legend);

    int used = 0;
    for (const auto& record : records) {
        if (used >= MAX_SERIES) break;
        if (record.channel < 1 || record.channel > 13) continue;

        int32_t values[CHART_POINTS];
        int32_t height = std::clamp<int32_t>(record.rssi - SIGNAL_FLOOR_DBM, 1, SIGNAL_RANGE_DB);
        for (int i = 0; i < CHART_POINTS; i++) {
            float channel = -1.0f + 0.5f * i;
            float distance = std::fabs(channel - (float)record.channel) / BELL_HALF_WIDTH;
            values[i] = distance <= 1.0f ? (int32_t)(height * (1.0f - distance * distance)) : LV_CHART_POINT_NONE;
        }
        lv_chart_set_series_values(ctx->chart, ctx->series[used], values, CHART_POINTS);
        lv_chart_hide_series(ctx->chart, ctx->series[used], false);

        char text[48];
        snprintf(text, sizeof(text), "%s %d", displaySsid(record), (int)record.rssi);
        auto* label = lv_label_create(ctx->legend);
        lv_label_set_text(label, text);
        lv_obj_set_style_text_color(label, lv_color_hex(SERIES_COLORS[used]), 0);
        used++;
    }
    for (int i = used; i < MAX_SERIES; i++) {
        lv_chart_hide_series(ctx->chart, ctx->series[i], true);
    }
}

void updateViews(Context* ctx) {
    auto records = service::wifi::getScanResults();
    std::sort(records.begin(), records.end(), [](const WifiApRecord& a, const WifiApRecord& b) {
        return a.rssi > b.rssi;
    });

    bool listIsEmpty = false;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        listIsEmpty = ctx->listRecords.empty();
        ctx->mutex.unlock();
    }

    lvgl_lock();
    if (ctx->statusLabel != nullptr) {
        char status[48];
        if (!isRadioUsable()) {
            snprintf(status, sizeof(status), "Wi-Fi spento, lo accendo...");
        } else {
            snprintf(status, sizeof(status), "%u reti%s", (unsigned)records.size(),
                service::wifi::isScanning() ? " (scansione...)" : "");
        }
        lv_label_set_text(ctx->statusLabel, status);
    }
    updateGraph(ctx, records);
    if (listIsEmpty && !records.empty()) {
        rebuildList(ctx, records);
    }
    lvgl_unlock();
}

void onTimer(Context* ctx) {
    using enum service::wifi::RadioState;
    auto state = service::wifi::getRadioState();
    if (state == Off) {
        service::wifi::setEnabled(true);
    } else if ((state == On || state == ConnectionActive) && !service::wifi::isScanning()) {
        // No scan while a connection is being set up: it would disturb the handshake.
        service::wifi::scan();
    }
    updateViews(ctx);
}

void stopTimer(Context* ctx) {
    std::unique_ptr<Timer> timer;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        timer = std::move(ctx->timer);
        ctx->mutex.unlock();
    }
    if (timer) {
        timer->stop();
    }
}

void showPage(Context* ctx, bool graph) {
    if (graph) {
        lv_obj_remove_flag(ctx->graphPage, LV_OBJ_FLAG_HIDDEN);
        lv_obj_add_flag(ctx->listPage, LV_OBJ_FLAG_HIDDEN);
    } else {
        lv_obj_add_flag(ctx->graphPage, LV_OBJ_FLAG_HIDDEN);
        lv_obj_remove_flag(ctx->listPage, LV_OBJ_FLAG_HIDDEN);
    }
}

void onShowGraph(lv_event_t* event) {
    showPage(static_cast<Context*>(lv_event_get_user_data(event)), true);
}

void onShowList(lv_event_t* event) {
    showPage(static_cast<Context*>(lv_event_get_user_data(event)), false);
}

void onRefreshList(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    auto records = service::wifi::getScanResults();
    std::sort(records.begin(), records.end(), [](const WifiApRecord& a, const WifiApRecord& b) {
        return a.rssi > b.rssi;
    });
    rebuildList(ctx, records);
    showPage(ctx, false);
}

void onBackPressed(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    app_event_emit_close(ctx->appInstanceId);
}

lv_obj_t* addButton(lv_obj_t* parent, const char* text, lv_event_cb_t callback, Context* ctx) {
    auto* button = lv_button_create(parent);
    lv_obj_add_event_cb(button, callback, LV_EVENT_SHORT_CLICKED, ctx);
    auto* label = lv_label_create(button);
    lv_label_set_text(label, text);
    lv_obj_center(label);
    return button;
}

lv_obj_t* createPage(lv_obj_t* parent) {
    auto* page = lv_obj_create(parent);
    lv_obj_set_flex_flow(page, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_width(page, LV_PCT(100));
    lv_obj_set_flex_grow(page, 1);
    lv_obj_set_style_pad_all(page, 0, 0);
    lv_obj_set_style_border_width(page, 0, 0);
    return page;
}

void createAxisLabels(lv_obj_t* parent) {
    auto* row = lv_obj_create(parent);
    lv_obj_set_size(row, LV_PCT(100), 16);
    lv_obj_set_style_pad_all(row, 0, 0);
    lv_obj_set_style_border_width(row, 0, 0);
    lv_obj_remove_flag(row, LV_OBJ_FLAG_SCROLLABLE);
    for (int channel = 1; channel <= 13; channel++) {
        char text[4];
        snprintf(text, sizeof(text), "%d", channel);
        auto* label = lv_label_create(row);
        lv_label_set_text(label, text);
        // Point i sits at i/32 of the width, so channel c sits at (c + 1) / 16.
        lv_obj_set_x(label, lv_pct(100 * (channel + 1) / 16));
        lv_obj_set_style_translate_x(label, channel < 10 ? -4 : -8, 0);
    }
}

void createWidgets(lv_obj_t* parent, void* userData) {
    auto* ctx = static_cast<Context*>(userData);

    lv_obj_set_flex_flow(parent, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(parent, 0, LV_STATE_DEFAULT);

    auto* toolbar = lvgl_toolbar_create(parent, "Wi-Fi Scanner");
    lvgl_toolbar_set_nav_action(toolbar, LV_SYMBOL_CLOSE, onBackPressed, ctx);

    auto* wrapper = lv_obj_create(parent);
    lv_obj_set_flex_flow(wrapper, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_width(wrapper, LV_PCT(100));
    lv_obj_set_flex_grow(wrapper, 1);
    lv_obj_set_style_pad_all(wrapper, 4, 0);

    auto* buttons = lv_obj_create(wrapper);
    lv_obj_set_size(buttons, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(buttons, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_all(buttons, 0, 0);
    lv_obj_set_style_border_width(buttons, 0, 0);
    addButton(buttons, "Grafico", onShowGraph, ctx);
    addButton(buttons, "Lista", onShowList, ctx);
    addButton(buttons, "Aggiorna", onRefreshList, ctx);

    ctx->statusLabel = lv_label_create(wrapper);
    lv_label_set_text(ctx->statusLabel, "...");

    ctx->graphPage = createPage(wrapper);
    ctx->chart = lv_chart_create(ctx->graphPage);
    lv_obj_set_size(ctx->chart, LV_PCT(100), 100);
    lv_obj_set_style_pad_all(ctx->chart, 0, 0);
    lv_chart_set_type(ctx->chart, LV_CHART_TYPE_LINE);
    lv_chart_set_point_count(ctx->chart, CHART_POINTS);
    lv_chart_set_axis_range(ctx->chart, LV_CHART_AXIS_PRIMARY_Y, 0, SIGNAL_RANGE_DB);
    lv_chart_set_div_line_count(ctx->chart, 3, 15);
    lv_obj_set_style_size(ctx->chart, 0, 0, LV_PART_INDICATOR);
    lv_obj_set_style_line_width(ctx->chart, 2, LV_PART_ITEMS);
    for (int i = 0; i < MAX_SERIES; i++) {
        ctx->series[i] = lv_chart_add_series(ctx->chart, lv_color_hex(SERIES_COLORS[i]), LV_CHART_AXIS_PRIMARY_Y);
        lv_chart_hide_series(ctx->chart, ctx->series[i], true);
    }
    createAxisLabels(ctx->graphPage);

    ctx->legend = lv_obj_create(ctx->graphPage);
    lv_obj_set_size(ctx->legend, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(ctx->legend, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_style_pad_all(ctx->legend, 0, 0);
    lv_obj_set_style_pad_column(ctx->legend, 8, 0);
    lv_obj_set_style_border_width(ctx->legend, 0, 0);

    ctx->listPage = createPage(wrapper);
    lv_obj_add_flag(ctx->listPage, LV_OBJ_FLAG_HIDDEN);
    ctx->list = lv_list_create(ctx->listPage);
    lv_obj_set_size(ctx->list, LV_PCT(100), LV_PCT(100));
}

int32_t appMain(int argc, char* argv[]) {
    uint32_t appInstanceId = app_scheduler_current_app_id();
    Context ctx;
    ctx.appInstanceId = appInstanceId;

    TaskEventGroup event_group {};
    task_event_group_construct(&event_group);

    AppEventSubscription sub {};
    check(app_event_subscribe(&sub, &event_group) == ERROR_NONE);

    WindowId window = window_manager_create(appInstanceId, createWidgets, &ctx);

    service::wifi::setScanRecords(MAX_RECORDS);
    // Auto-connect scans would compete with this app's own scans.
    service::wifi::setAutoScanPaused(true);

    ctx.timer = std::make_unique<Timer>(Timer::Type::Periodic, REFRESH_MS, [&ctx] {
        onTimer(&ctx);
    });
    ctx.timer->start();

    bool shouldClose = false;
    while (!shouldClose) {
        task_event_group_wait_any(&event_group, nullptr, portMAX_DELAY);

        AppEvent event {};
        while (app_event_poll(&sub, &event) == ERROR_NONE) {
            if (event.type == APP_EVENT_CLOSE) {
                shouldClose = true;
                break;
            }
        }
    }

    stopTimer(&ctx);
    service::wifi::setAutoScanPaused(false);

    window_manager_remove(window);
    check(app_event_unsubscribe(&sub) == ERROR_NONE);
    task_event_group_destruct(&event_group);

    return 0;
}

} // namespace

extern const ::AppManifest manifest = {
    .id = "WifiScanner",
    .name = "Wi-Fi Scanner",
    .category = APP_CATEGORY_SYSTEM,
    .location = { APP_LOCATION_MEMORY, reinterpret_cast<void*>(appMain) }
};

} // namespace tt::app::wifiscanner
