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

#include "OuiTable.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <lvgl/lvgl.h>
#include <lvgl/widgets/toolbar.h>

#ifdef ESP_PLATFORM
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#endif

namespace tt::app::wifiscanner {

extern const ::AppManifest manifest;

namespace {

constexpr auto* TAG = "WifiScanner";
constexpr uint16_t MAX_RECORDS = 40;
constexpr uint32_t REFRESH_MS = 1000;
constexpr uint32_t ROW_EXPIRY_MS = 20000;

// The chart spans channel -1 to 15 in half-channel steps, so channels 1..13 sit inside with margin
// for the bell of the outermost ones. An AP's bell is +-2 channels wide (a 20 MHz signal).
constexpr int MAX_SERIES = 8;
constexpr int CHART_POINTS = 33;
constexpr float BELL_HALF_WIDTH = 2.0f;
constexpr int32_t SIGNAL_FLOOR_DBM = -100;
constexpr int32_t SIGNAL_RANGE_DB = 70;
constexpr uint32_t HOP_INTERVAL_MS = 250;
constexpr int MAX_PROBED_SSIDS = 4;

const uint32_t SERIES_COLORS[MAX_SERIES] = {
    0xE6194B, 0x3CB44B, 0xFFE119, 0x4363D8, 0xF58231, 0x911EB4, 0x42D4F4, 0xF032E6
};

enum class Page { Graph, List, Detail };

uint64_t bssidKey(const uint8_t* bssid) {
    uint64_t key = 0;
    for (int i = 0; i < 6; i++) key = (key << 8) | bssid[i];
    return key;
}

uint64_t nowMs() { return (uint64_t)lv_tick_get(); }

/** One access point, merging whatever the active scan and the passive capture both know about it. */
struct SeenAp {
    WifiApRecord record{};
    uint64_t firstSeenMs = 0;
    uint64_t lastSeenMs = 0;
    int8_t rssiMin = 0;
    int8_t rssiMax = 0;
    bool fromCapture = false;
    uint32_t packetCount = 0;
};

/** A device seen only through passive capture: probing for a network, or associated to one. */
struct CapturedClient {
    uint8_t mac[6] = {};
    uint64_t firstSeenMs = 0;
    uint64_t lastSeenMs = 0;
    int8_t lastRssi = 0;
    uint64_t associatedBssid = 0;
    std::vector<std::string> probedSsids;
    uint32_t packetCount = 0;
};

struct Context {
    uint32_t appInstanceId = 0;
    WindowId window = 0;

    RecursiveMutex mutex;
    std::unique_ptr<Timer> timer = nullptr;

    Page page = Page::Graph;
    std::map<uint64_t, SeenAp> seen;
    std::map<uint64_t, CapturedClient> clients;
    std::vector<uint64_t> visible; // sorted by RSSI, rebuilt each refresh
    uint64_t selectedKey = 0;
    bool capturing = false;

    lv_obj_t* toolbar = nullptr;
    lv_obj_t* statusLabel = nullptr;

    lv_obj_t* graphPage = nullptr;
    lv_obj_t* chart = nullptr;
    lv_obj_t* labelLayer = nullptr;
    lv_chart_series_t* series[MAX_SERIES] = {};
    lv_obj_t* startButton = nullptr;
    lv_obj_t* stopButton = nullptr;

    lv_obj_t* listPage = nullptr;
    lv_obj_t* list = nullptr;
    std::map<uint64_t, lv_obj_t*> rows;

    lv_obj_t* detailPage = nullptr;
    lv_obj_t* detailInfo = nullptr;
    lv_obj_t* detailClients = nullptr;
    lv_obj_t* detailChart = nullptr;
    lv_chart_series_t* detailSeries[MAX_SERIES + 1] = {};
    lv_obj_t* connectButton = nullptr;
};

// ---- Capture engine (ESP32 only - passive sniffing needs direct esp_wifi access) ----

#ifdef ESP_PLATFORM

std::atomic<Context*> g_captureCtx{nullptr};
std::atomic<bool> g_captureRunning{false};
std::atomic<bool> g_captureStopped{true};
std::atomic<int> g_hopChannel{1};

/** Pulls the SSID (tag 0) and a WPA/WPA2/OPEN/WEP guess out of a beacon/probe-response's IEs.
 * No AKM parsing, so WPA3/SAE reads as WPA2 here - good enough to color the list, not a survey tool. */
void parseBeaconIes(const uint8_t* ies, int iesLen, uint16_t capability,
    std::string& ssidOut, bool& ssidSeen, WifiAuthenticationType& authOut) {
    bool privacy = (capability & 0x0010) != 0;
    bool hasRsn = false;
    bool hasWpa = false;
    ssidSeen = false;
    int i = 0;
    while (i + 2 <= iesLen) {
        uint8_t tag = ies[i];
        uint8_t len = ies[i + 1];
        if (i + 2 + len > iesLen) break;
        const uint8_t* data = ies + i + 2;
        if (tag == 0) {
            ssidOut.assign(reinterpret_cast<const char*>(data), len);
            ssidSeen = len > 0;
        } else if (tag == 48) {
            hasRsn = true;
        } else if (tag == 221 && len >= 4 && data[0] == 0x00 && data[1] == 0x50 && data[2] == 0xF2 && data[3] == 0x01) {
            hasWpa = true;
        }
        i += 2 + len;
    }
    if (!privacy) authOut = WIFI_AUTHENTICATION_TYPE_OPEN;
    else if (hasRsn && hasWpa) authOut = WIFI_AUTHENTICATION_TYPE_WPA_WPA2_PSK;
    else if (hasRsn) authOut = WIFI_AUTHENTICATION_TYPE_WPA2_PSK;
    else if (hasWpa) authOut = WIFI_AUTHENTICATION_TYPE_WPA_PSK;
    else authOut = WIFI_AUTHENTICATION_TYPE_WEP;
}

/** @return the SSID carried in a probe request's IEs, or empty if none/broadcast. */
std::string parseProbeRequestSsid(const uint8_t* ies, int iesLen) {
    int i = 0;
    while (i + 2 <= iesLen) {
        uint8_t tag = ies[i];
        uint8_t len = ies[i + 1];
        if (i + 2 + len > iesLen) break;
        if (tag == 0 && len > 0) {
            return std::string(reinterpret_cast<const char*>(ies + i + 2), len);
        }
        i += 2 + len;
    }
    return {};
}

void upsertApFromCapture(Context* ctx, const uint8_t* bssid, const std::string& ssid, bool ssidSeen,
    int channel, int8_t rssi, WifiAuthenticationType auth) {
    if (!ctx->mutex.lock(0)) return;
    uint64_t key = bssidKey(bssid);
    uint64_t now = nowMs();
    auto it = ctx->seen.find(key);
    if (it == ctx->seen.end()) {
        SeenAp ap{};
        memcpy(ap.record.bssid, bssid, 6);
        if (ssidSeen) {
            size_t len = std::min<size_t>(ssid.size(), sizeof(ap.record.ssid) - 1);
            memcpy(ap.record.ssid, ssid.data(), len);
            ap.record.ssid[len] = '\0';
        }
        ap.record.channel = channel;
        ap.record.rssi = rssi;
        ap.record.authentication_type = auth;
        ap.record.pairwise_cipher = WIFI_AP_CIPHER_UNKNOWN;
        ap.firstSeenMs = now;
        ap.lastSeenMs = now;
        ap.rssiMin = ap.rssiMax = rssi;
        ap.fromCapture = true;
        ap.packetCount = 1;
        ctx->seen.emplace(key, ap);
    } else {
        SeenAp& ap = it->second;
        if (ssidSeen && ap.record.ssid[0] == '\0') {
            size_t len = std::min<size_t>(ssid.size(), sizeof(ap.record.ssid) - 1);
            memcpy(ap.record.ssid, ssid.data(), len);
            ap.record.ssid[len] = '\0';
        }
        ap.record.channel = channel;
        ap.record.rssi = rssi;
        ap.lastSeenMs = now;
        ap.packetCount++;
        ap.rssiMin = std::min(ap.rssiMin, rssi);
        ap.rssiMax = std::max(ap.rssiMax, rssi);
        if (ap.fromCapture) ap.record.authentication_type = auth;
    }
    ctx->mutex.unlock();
}

void upsertClientProbe(Context* ctx, const uint8_t* mac, const std::string& probedSsid, int8_t rssi) {
    if (!ctx->mutex.lock(0)) return;
    uint64_t key = bssidKey(mac);
    uint64_t now = nowMs();
    auto& client = ctx->clients[key];
    if (client.packetCount == 0) {
        memcpy(client.mac, mac, 6);
        client.firstSeenMs = now;
    }
    client.lastSeenMs = now;
    client.lastRssi = rssi;
    client.packetCount++;
    if (!probedSsid.empty() &&
        std::find(client.probedSsids.begin(), client.probedSsids.end(), probedSsid) == client.probedSsids.end() &&
        client.probedSsids.size() < MAX_PROBED_SSIDS) {
        client.probedSsids.push_back(probedSsid);
    }
    ctx->mutex.unlock();
}

void upsertClientAssociation(Context* ctx, const uint8_t* mac, const uint8_t* bssid, int8_t rssi) {
    if (!ctx->mutex.lock(0)) return;
    uint64_t key = bssidKey(mac);
    uint64_t now = nowMs();
    auto& client = ctx->clients[key];
    if (client.packetCount == 0) {
        memcpy(client.mac, mac, 6);
        client.firstSeenMs = now;
    }
    client.lastSeenMs = now;
    client.lastRssi = rssi;
    client.associatedBssid = bssidKey(bssid);
    client.packetCount++;
    ctx->mutex.unlock();
}

/** Runs on the ESP-IDF WiFi task context (guaranteed by esp_wifi_set_promiscuous_rx_cb). */
void onPromiscuousPacket(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
    Context* ctx = g_captureCtx.load();
    if (ctx == nullptr) return;

    auto* pkt = static_cast<wifi_promiscuous_pkt_t*>(buf);
    const uint8_t* payload = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 24) return;

    uint16_t fc = payload[0] | (payload[1] << 8);
    uint8_t frameType = (fc >> 2) & 0x3;
    uint8_t frameSubtype = (fc >> 4) & 0xF;
    bool toDs = (fc & 0x0100) != 0;
    bool fromDs = (fc & 0x0200) != 0;
    const uint8_t* addr1 = payload + 4;
    const uint8_t* addr2 = payload + 10;
    const uint8_t* addr3 = payload + 16;
    int8_t rssi = pkt->rx_ctrl.rssi;
    int channel = pkt->rx_ctrl.channel;

    if (frameType == 0) { // management
        if ((frameSubtype == 8 || frameSubtype == 5) && len >= 24 + 12) { // beacon / probe response
            uint16_t capability = payload[24 + 10] | (payload[24 + 11] << 8);
            std::string ssid;
            bool ssidSeen = false;
            WifiAuthenticationType auth = WIFI_AUTHENTICATION_TYPE_OPEN;
            parseBeaconIes(payload + 24 + 12, len - 24 - 12, capability, ssid, ssidSeen, auth);
            upsertApFromCapture(ctx, addr3, ssid, ssidSeen, channel, rssi, auth);
        } else if (frameSubtype == 4) { // probe request
            std::string ssid = parseProbeRequestSsid(payload + 24, len - 24);
            upsertClientProbe(ctx, addr2, ssid, rssi);
        }
    } else if (frameType == 2) { // data
        if (toDs && !fromDs) {
            upsertClientAssociation(ctx, addr2, addr1, rssi); // addr1=BSSID, addr2=client
        } else if (!toDs && fromDs) {
            upsertClientAssociation(ctx, addr1, addr2, rssi); // addr1=client, addr2=BSSID
        }
    }
}

int32_t hopTask(void* /*arg*/) {
    esp_wifi_set_promiscuous_rx_cb(&onPromiscuousPacket);
    wifi_promiscuous_filter_t filter{};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);

    while (g_captureRunning.load()) {
        for (int channel = 1; channel <= 13 && g_captureRunning.load(); channel++) {
            esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
            g_hopChannel.store(channel);
            vTaskDelay(pdMS_TO_TICKS(HOP_INTERVAL_MS));
        }
    }

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    g_captureStopped.store(true);
    vTaskDelete(nullptr);
    return 0;
}

void startCapture(Context* ctx) {
    if (g_captureRunning.load()) return;
    g_captureCtx.store(ctx);
    g_captureStopped.store(false);
    g_captureRunning.store(true);
    xTaskCreatePinnedToCore(
        [](void* arg) { hopTask(arg); },
        "wifi_hop", 3072, nullptr, tskIDLE_PRIORITY + 1, nullptr, WIFI_TASK_CORE_ID);
}

void stopCapture(Context* ctx) {
    if (!g_captureRunning.load()) return;
    g_captureRunning.store(false);
    for (int i = 0; i < 100 && !g_captureStopped.load(); i++) {
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    g_captureCtx.store(nullptr);
    (void)ctx;
}

bool isCaptureSupported() { return true; }

#else

void startCapture(Context*) {}
void stopCapture(Context*) {}
bool isCaptureSupported() { return false; }

#endif // ESP_PLATFORM

// ---- Formatting helpers ----

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

/** Color-codes the list/detail by how open the network is; open is deliberately red, not green. */
uint32_t securityColor(WifiAuthenticationType type) {
    switch (type) {
        case WIFI_AUTHENTICATION_TYPE_OPEN: return 0xE53935;
        case WIFI_AUTHENTICATION_TYPE_WEP: return 0xFB8C00;
        case WIFI_AUTHENTICATION_TYPE_WPA_PSK: return 0xFDD835;
        case WIFI_AUTHENTICATION_TYPE_WPA2_PSK: return 0x7CB342;
        case WIFI_AUTHENTICATION_TYPE_WPA_WPA2_PSK: return 0x43A047;
        case WIFI_AUTHENTICATION_TYPE_WPA2_ENTERPRISE: return 0x1E88E5;
        case WIFI_AUTHENTICATION_TYPE_WPA3_PSK: return 0x8E24AA;
        case WIFI_AUTHENTICATION_TYPE_WPA2_WPA3_PSK: return 0x3949AB;
        default: return 0x757575;
    }
}

const char* cipherToString(WifiCipherType cipher) {
    switch (cipher) {
        case WIFI_AP_CIPHER_NONE: return "nessuna";
        case WIFI_AP_CIPHER_WEP: return "WEP";
        case WIFI_AP_CIPHER_TKIP: return "TKIP";
        case WIFI_AP_CIPHER_CCMP: return "CCMP (AES)";
        case WIFI_AP_CIPHER_TKIP_CCMP: return "TKIP+CCMP";
        case WIFI_AP_CIPHER_GCMP: return "GCMP";
        default: return "sconosciuta (solo cattura)";
    }
}

std::string phyToString(uint8_t flags) {
    std::string result;
    if (flags & WIFI_AP_PHY_11B) result += "b";
    if (flags & WIFI_AP_PHY_11G) result += "g";
    if (flags & WIFI_AP_PHY_11N) result += "n";
    if (flags & WIFI_AP_PHY_11AX) result += "ax";
    if (flags & WIFI_AP_PHY_WPS) result += " WPS";
    return result.empty() ? "?" : ("802.11" + result);
}

std::string macToString(const uint8_t* mac) {
    char text[18];
    snprintf(text, sizeof(text), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return text;
}

const char* displaySsid(const WifiApRecord& record) {
    return record.ssid[0] != '\0' ? record.ssid : "(nascosta)";
}

int frequencyMhz(int channel) { return 2407 + 5 * channel; }

float estimateDistanceMeters(int8_t rssi) {
    constexpr float txPowerAt1m = -40.0f;
    constexpr float pathLossExponent = 2.5f;
    return std::pow(10.0f, (txPowerAt1m - (float)rssi) / (10.0f * pathLossExponent));
}

bool isRadioUsable() {
    using enum service::wifi::RadioState;
    auto state = service::wifi::getRadioState();
    return state == On || state == ConnectionPending || state == ConnectionActive;
}

// ---- Shared state helpers ----

void connectTo(Context* ctx, const std::string& ssid) {
    service::wifi::settings::WifiApSettings settings;
    if (service::wifi::settings::load(ssid, settings)) {
        LOG_I(TAG, "Connecting with known credentials");
        service::wifi::connect(settings, false);
    } else {
        wificonnect::start(ssid);
    }
    (void)ctx;
}

/** Fills one bell-curve series centered on the given channel/RSSI. */
void fillBell(lv_obj_t* chart, lv_chart_series_t* series, int channel, int8_t rssi) {
    int32_t values[CHART_POINTS];
    int32_t height = std::clamp<int32_t>(rssi - SIGNAL_FLOOR_DBM, 1, SIGNAL_RANGE_DB);
    for (int i = 0; i < CHART_POINTS; i++) {
        float x = -1.0f + 0.5f * i;
        float distance = std::fabs(x - (float)channel) / BELL_HALF_WIDTH;
        values[i] = distance <= 1.0f ? (int32_t)(height * (1.0f - distance * distance)) : LV_CHART_POINT_NONE;
    }
    lv_chart_set_series_values(chart, series, values, CHART_POINTS);
}

/** Snapshot of ctx->seen as a vector sorted by signal strength, with stale rows dropped.
 * Must be called with ctx->mutex held. */
std::vector<SeenAp> sortedByRssi(Context* ctx) {
    std::vector<SeenAp> result;
    uint64_t now = nowMs();
    for (auto it = ctx->seen.begin(); it != ctx->seen.end();) {
        if (now - it->second.lastSeenMs > ROW_EXPIRY_MS) {
            it = ctx->seen.erase(it);
        } else {
            result.push_back(it->second);
            ++it;
        }
    }
    std::sort(result.begin(), result.end(), [](const SeenAp& a, const SeenAp& b) {
        return a.record.rssi > b.record.rssi;
    });
    return result;
}

/** Merges fresh active-scan results into ctx->seen. Must be called with ctx->mutex held. */
void mergeActiveScan(Context* ctx, const std::vector<WifiApRecord>& records) {
    uint64_t now = nowMs();
    for (const auto& record : records) {
        uint64_t key = bssidKey(record.bssid);
        auto it = ctx->seen.find(key);
        if (it == ctx->seen.end()) {
            SeenAp ap{};
            ap.record = record;
            ap.firstSeenMs = now;
            ap.lastSeenMs = now;
            ap.rssiMin = ap.rssiMax = record.rssi;
            ctx->seen.emplace(key, ap);
        } else {
            SeenAp& ap = it->second;
            ap.record = record; // the active scan is authoritative over our capture heuristics
            ap.fromCapture = false;
            ap.lastSeenMs = now;
            ap.rssiMin = std::min(ap.rssiMin, record.rssi);
            ap.rssiMax = std::max(ap.rssiMax, record.rssi);
        }
    }
}

// ---- Forward declarations ----

void showPage(Context* ctx, Page page);
void updateViews(Context* ctx);

// ---- Graph page ----

void updateGraph(Context* ctx, const std::vector<SeenAp>& aps) {
    if (ctx->chart == nullptr) return;

    lv_obj_clean(ctx->labelLayer);

    struct Placed { int x; int width; };
    std::vector<Placed> placed;

    int used = 0;
    for (const auto& ap : aps) {
        if (used >= MAX_SERIES) break;
        if (ap.record.channel < 1 || ap.record.channel > 13) continue;

        fillBell(ctx->chart, ctx->series[used], ap.record.channel, ap.record.rssi);
        lv_chart_hide_series(ctx->chart, ctx->series[used], false);

        auto* label = lv_label_create(ctx->labelLayer);
        lv_label_set_text(label, displaySsid(ap.record));
        lv_obj_set_style_text_color(label, lv_color_hex(SERIES_COLORS[used]), 0);
        lv_obj_update_layout(label);
        int width = lv_obj_get_width(label);
        // Peak sits at channel/16 of the chart's width (see createAxisLabels); nudge left/right
        // to avoid overlapping a previously placed label at a nearby channel.
        int chartWidth = lv_obj_get_width(ctx->chart);
        int xPx = chartWidth * ap.record.channel / 16 - width / 2;
        for (const auto& other : placed) {
            if (xPx < other.x + other.width + 2 && xPx + width + 2 > other.x) {
                xPx = other.x + other.width + 2;
            }
        }
        lv_obj_set_x(label, xPx);
        lv_obj_set_y(label, 2);
        placed.push_back({xPx, width});
        used++;
    }
    for (int i = used; i < MAX_SERIES; i++) {
        lv_chart_hide_series(ctx->chart, ctx->series[i], true);
    }
}

void onSelectFromList(lv_event_t* event);

void onShowList(lv_event_t* event) {
    showPage(static_cast<Context*>(lv_event_get_user_data(event)), Page::List);
}

void onStartCapture(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    startCapture(ctx);
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        ctx->capturing = true;
        ctx->mutex.unlock();
    }
    if (ctx->startButton != nullptr) lv_obj_add_state(ctx->startButton, LV_STATE_DISABLED);
    if (ctx->stopButton != nullptr) lv_obj_remove_state(ctx->stopButton, LV_STATE_DISABLED);
}

void onStopCapture(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    stopCapture(ctx);
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        ctx->capturing = false;
        ctx->mutex.unlock();
    }
    if (ctx->startButton != nullptr) lv_obj_remove_state(ctx->startButton, LV_STATE_DISABLED);
    if (ctx->stopButton != nullptr) lv_obj_add_state(ctx->stopButton, LV_STATE_DISABLED);
}

// ---- List page ----

void onSelectFromList(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    auto key = reinterpret_cast<uint64_t>(lv_obj_get_user_data(lv_event_get_target_obj(event)));
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        ctx->selectedKey = key;
        ctx->mutex.unlock();
    }
    showPage(ctx, Page::Detail);
}

lv_obj_t* createListRow(Context* ctx, uint64_t key) {
    auto* row = lv_obj_create(ctx->list);
    lv_obj_set_size(row, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_all(row, 4, 0);
    lv_obj_set_style_pad_column(row, 6, 0);
    lv_obj_add_flag(row, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_user_data(row, reinterpret_cast<void*>(key));
    lv_obj_add_event_cb(row, onSelectFromList, LV_EVENT_SHORT_CLICKED, ctx);

    auto* chip = lv_obj_create(row);
    lv_obj_set_size(chip, 8, LV_PCT(100));
    lv_obj_set_style_radius(chip, 2, 0);
    lv_obj_set_style_border_width(chip, 0, 0);
    lv_obj_remove_flag(chip, LV_OBJ_FLAG_SCROLLABLE);

    auto* label = lv_label_create(row);
    lv_label_set_long_mode(label, LV_LABEL_LONG_MODE_DOTS);
    lv_obj_set_flex_grow(label, 1);

    return row;
}

/** Updates existing rows in place and adds/removes rows so the list doesn't rebuild under the cursor. */
void updateRows(Context* ctx, const std::vector<SeenAp>& aps) {
    if (ctx->list == nullptr) return;

    std::vector<uint64_t> keys;
    for (const auto& ap : aps) keys.push_back(bssidKey(ap.record.bssid));

    for (auto it = ctx->rows.begin(); it != ctx->rows.end();) {
        if (std::find(keys.begin(), keys.end(), it->first) == keys.end()) {
            lv_obj_delete(it->second);
            it = ctx->rows.erase(it);
        } else {
            ++it;
        }
    }

    for (const auto& ap : aps) {
        uint64_t key = bssidKey(ap.record.bssid);
        lv_obj_t* row = nullptr;
        auto it = ctx->rows.find(key);
        if (it == ctx->rows.end()) {
            row = createListRow(ctx, key);
            ctx->rows[key] = row;
        } else {
            row = it->second;
        }

        auto* chip = lv_obj_get_child(row, 0);
        lv_obj_set_style_bg_color(chip, lv_color_hex(securityColor(ap.record.authentication_type)), 0);
        lv_obj_set_style_bg_opa(chip, LV_OPA_COVER, 0);

        auto* label = lv_obj_get_child(row, 1);
        char line[112];
        snprintf(line, sizeof(line), "%s  ch%d  %d dBm  %s%s", displaySsid(ap.record), (int)ap.record.channel,
            (int)ap.record.rssi, authToString(ap.record.authentication_type), ap.fromCapture ? " (cattura)" : "");
        lv_label_set_text(label, line);
    }

    // Re-order to match the sorted-by-RSSI list.
    for (size_t i = 0; i < keys.size(); i++) {
        lv_obj_move_to_index(ctx->rows[keys[i]], (int32_t)i);
    }
}

// ---- Detail page ----

void onConnectPressed(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    std::string ssid;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        auto it = ctx->seen.find(ctx->selectedKey);
        if (it != ctx->seen.end()) ssid = it->second.record.ssid;
        ctx->mutex.unlock();
    }
    if (!ssid.empty()) connectTo(ctx, ssid);
}

void updateDetail(Context* ctx) {
    if (ctx->detailInfo == nullptr) return;

    SeenAp ap{};
    bool found = false;
    std::vector<CapturedClient> relatedClients;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        auto it = ctx->seen.find(ctx->selectedKey);
        if (it != ctx->seen.end()) {
            ap = it->second;
            found = true;
            for (const auto& [clientKey, client] : ctx->clients) {
                if (client.associatedBssid == ctx->selectedKey) relatedClients.push_back(client);
            }
        }
        ctx->mutex.unlock();
    }
    if (!found) return;

    uint64_t now = nowMs();
    const char* vendor = lookupVendor(ap.record.bssid);
    char text[768];
    int offset = snprintf(text, sizeof(text),
        "SSID: %s\n"
        "MAC: %s (%s)\n"
        "Sicurezza: %s\n"
        "Cifratura: %s\n"
        "Canale: %d (%d MHz)\n"
        "Potenza: %d dBm (min %d / max %d)\n"
        "Distanza stimata: %.1f m\n"
        "PHY: %s\n"
        "Fonte: %s\n"
        "Visto da %u s, ultimo %u s fa\n",
        displaySsid(ap.record), macToString(ap.record.bssid).c_str(), vendor != nullptr ? vendor : "fornitore sconosciuto",
        authToString(ap.record.authentication_type), cipherToString(ap.record.pairwise_cipher),
        (int)ap.record.channel, frequencyMhz((int)ap.record.channel),
        (int)ap.record.rssi, (int)ap.rssiMin, (int)ap.rssiMax, estimateDistanceMeters(ap.record.rssi),
        phyToString(ap.record.phy_flags).c_str(), ap.fromCapture ? "cattura passiva" : "scansione attiva",
        (unsigned)((now - ap.firstSeenMs) / 1000), (unsigned)((now - ap.lastSeenMs) / 1000));

    if (ap.record.country[0] != '\0') {
        snprintf(text + offset, sizeof(text) - offset, "Paese: %.2s\n", ap.record.country);
    }
    lv_label_set_text(ctx->detailInfo, text);

    if (ctx->detailClients != nullptr) {
        if (relatedClients.empty()) {
            lv_label_set_text(ctx->detailClients, "Nessun client rilevato dalla cattura.");
        } else {
            std::string clientText = "Client visti (cattura passiva):\n";
            for (const auto& client : relatedClients) {
                bool randomMac = (client.mac[0] & 0x02) != 0;
                clientText += "- " + macToString(client.mac) + (randomMac ? " (MAC casuale)" : "") +
                    ", " + std::to_string(client.lastRssi) + " dBm\n";
            }
            lv_label_set_text(ctx->detailClients, clientText.c_str());
        }
    }

    if (ctx->detailChart != nullptr) {
        fillBell(ctx->detailChart, ctx->detailSeries[0], (int)ap.record.channel, ap.record.rssi);
        lv_chart_hide_series(ctx->detailChart, ctx->detailSeries[0], false);
    }
}

// ---- Page switching / toolbar back handling ----

void onHardwareBack(void* userData);

void setTitle(Context* ctx, const char* title) {
    if (ctx->toolbar != nullptr) lvgl_toolbar_set_title(ctx->toolbar, title);
}

void showPage(Context* ctx, Page page) {
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        ctx->page = page;
        ctx->mutex.unlock();
    }

    lv_obj_add_flag(ctx->graphPage, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(ctx->listPage, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(ctx->detailPage, LV_OBJ_FLAG_HIDDEN);

    switch (page) {
        case Page::Graph:
            lv_obj_remove_flag(ctx->graphPage, LV_OBJ_FLAG_HIDDEN);
            setTitle(ctx, "Wi-Fi Scanner");
            break;
        case Page::List:
            lv_obj_remove_flag(ctx->listPage, LV_OBJ_FLAG_HIDDEN);
            setTitle(ctx, "Reti rilevate");
            break;
        case Page::Detail:
            lv_obj_remove_flag(ctx->detailPage, LV_OBJ_FLAG_HIDDEN);
            setTitle(ctx, "Dettaglio rete");
            updateDetail(ctx);
            break;
    }

    // The physical back key steps one level instead of closing the app, except on the top page.
    lvgl_toolbar_set_back_override(page == Page::Graph ? nullptr : onHardwareBack, ctx);
}

void goBack(Context* ctx) {
    Page current;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        current = ctx->page;
        ctx->mutex.unlock();
    } else {
        return;
    }
    if (current == Page::Detail) showPage(ctx, Page::List);
    else if (current == Page::List) showPage(ctx, Page::Graph);
}

void onHardwareBack(void* userData) {
    goBack(static_cast<Context*>(userData));
}

void onBackPressed(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    Page current;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        current = ctx->page;
        ctx->mutex.unlock();
    } else {
        return;
    }
    if (current == Page::Graph) {
        app_event_emit_close(ctx->appInstanceId);
    } else {
        goBack(ctx);
    }
}

// ---- Periodic refresh ----

void updateViews(Context* ctx) {
    auto activeResults = service::wifi::getScanResults();
    bool capturing = false;

    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        mergeActiveScan(ctx, activeResults);
        capturing = ctx->capturing;
        ctx->mutex.unlock();
    } else {
        return;
    }

    std::vector<SeenAp> aps;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        aps = sortedByRssi(ctx);
        ctx->visible.clear();
        for (const auto& ap : aps) ctx->visible.push_back(bssidKey(ap.record.bssid));
        ctx->mutex.unlock();
    }

    size_t clientCount = 0;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        clientCount = ctx->clients.size();
        ctx->mutex.unlock();
    }

    lvgl_lock();
    if (ctx->statusLabel != nullptr) {
        char status[80];
        if (!isRadioUsable()) {
            snprintf(status, sizeof(status), "Wi-Fi spento, lo accendo...");
        } else if (capturing) {
#ifdef ESP_PLATFORM
            snprintf(status, sizeof(status), "Cattura: canale %d - %u reti, %u client",
                g_hopChannel.load(), (unsigned)aps.size(), (unsigned)clientCount);
#else
            snprintf(status, sizeof(status), "Cattura non disponibile in questo ambiente");
#endif
        } else {
            snprintf(status, sizeof(status), "%u reti%s", (unsigned)aps.size(),
                service::wifi::isScanning() ? " (scansione...)" : "");
        }
        lv_label_set_text(ctx->statusLabel, status);
    }

    Page page;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        page = ctx->page;
        ctx->mutex.unlock();
    } else {
        lvgl_unlock();
        return;
    }

    if (page == Page::Graph) updateGraph(ctx, aps);
    else if (page == Page::List) updateRows(ctx, aps);
    else if (page == Page::Detail) updateDetail(ctx);
    lvgl_unlock();
}

void onTimer(Context* ctx) {
    using enum service::wifi::RadioState;
    auto state = service::wifi::getRadioState();
    bool capturing = false;
    if (ctx->mutex.lock(0)) {
        capturing = ctx->capturing;
        ctx->mutex.unlock();
    }

    if (state == Off) {
        service::wifi::setEnabled(true);
    } else if (!capturing && (state == On || state == ConnectionActive) && !service::wifi::isScanning()) {
        // No active scan while capturing: it would fight the hopping task for the radio, and
        // no scan while a connection is being set up, since that would disturb the handshake.
        service::wifi::scan();
    }

    // Checked by window id, not app_scheduler_current_app_id(): this timer callback doesn't run
    // on the app's own task, so there is no "current app" thread-local to read here.
    if (window_manager_get_state(ctx->window) == WINDOW_STATE_GRANTED) updateViews(ctx);
}

void stopTimer(Context* ctx) {
    std::unique_ptr<Timer> timer;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        timer = std::move(ctx->timer);
        ctx->mutex.unlock();
    }
    if (timer) timer->stop();
}

// ---- Widget construction ----

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
        lv_obj_set_x(label, lv_pct(100 * (channel + 1) / 16));
        lv_obj_set_style_translate_x(label, channel < 10 ? -4 : -8, 0);
    }
}

lv_obj_t* createIconButton(lv_obj_t* parent, const char* icon, lv_event_cb_t callback, Context* ctx) {
    auto* button = lv_button_create(parent);
    lv_obj_set_size(button, 40, 40);
    auto* label = lv_label_create(button);
    lv_label_set_text(label, icon);
    lv_obj_center(label);
    lv_obj_add_event_cb(button, callback, LV_EVENT_SHORT_CLICKED, ctx);
    return button;
}

void createGraphPage(Context* ctx, lv_obj_t* parent) {
    ctx->graphPage = createPage(parent);

    auto* top = lv_obj_create(ctx->graphPage);
    lv_obj_set_size(top, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(top, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_all(top, 0, 0);
    lv_obj_set_style_pad_column(top, 4, 0);
    lv_obj_set_style_border_width(top, 0, 0);
    lv_obj_remove_flag(top, LV_OBJ_FLAG_SCROLLABLE);

    ctx->statusLabel = lv_label_create(top);
    lv_label_set_text(ctx->statusLabel, "...");
    lv_obj_set_flex_grow(ctx->statusLabel, 1);

    ctx->startButton = createIconButton(top, LV_SYMBOL_PLAY, onStartCapture, ctx);
    ctx->stopButton = createIconButton(top, LV_SYMBOL_STOP, onStopCapture, ctx);
    lv_obj_add_state(ctx->stopButton, LV_STATE_DISABLED);
    if (!isCaptureSupported()) lv_obj_add_state(ctx->startButton, LV_STATE_DISABLED);
    createIconButton(top, LV_SYMBOL_LIST, onShowList, ctx);

    auto* chartWrapper = lv_obj_create(ctx->graphPage);
    lv_obj_set_size(chartWrapper, LV_PCT(100), 100);
    lv_obj_set_style_pad_all(chartWrapper, 0, 0);
    lv_obj_set_style_border_width(chartWrapper, 0, 0);
    lv_obj_remove_flag(chartWrapper, LV_OBJ_FLAG_SCROLLABLE);

    ctx->chart = lv_chart_create(chartWrapper);
    lv_obj_set_size(ctx->chart, LV_PCT(100), 100);
    lv_obj_set_style_pad_all(ctx->chart, 0, 0);
    lv_chart_set_type(ctx->chart, LV_CHART_TYPE_LINE);
    lv_chart_set_point_count(ctx->chart, CHART_POINTS);
    lv_chart_set_axis_range(ctx->chart, LV_CHART_AXIS_PRIMARY_Y, 0, SIGNAL_RANGE_DB);
    lv_chart_set_div_line_count(ctx->chart, 3, 15);
    lv_obj_set_style_size(ctx->chart, 0, 0, LV_PART_INDICATOR);
    lv_obj_set_style_line_width(ctx->chart, 2, LV_PART_ITEMS);
    lv_obj_remove_flag(ctx->chart, LV_OBJ_FLAG_SCROLLABLE);
    for (int i = 0; i < MAX_SERIES; i++) {
        ctx->series[i] = lv_chart_add_series(ctx->chart, lv_color_hex(SERIES_COLORS[i]), LV_CHART_AXIS_PRIMARY_Y);
        lv_chart_hide_series(ctx->chart, ctx->series[i], true);
    }

    ctx->labelLayer = lv_obj_create(chartWrapper);
    lv_obj_set_size(ctx->labelLayer, LV_PCT(100), 100);
    lv_obj_set_style_pad_all(ctx->labelLayer, 0, 0);
    lv_obj_set_style_bg_opa(ctx->labelLayer, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(ctx->labelLayer, 0, 0);
    lv_obj_remove_flag(ctx->labelLayer, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(ctx->labelLayer, LV_OBJ_FLAG_CLICKABLE);

    createAxisLabels(ctx->graphPage);
}

void createListPage(Context* ctx, lv_obj_t* parent) {
    ctx->listPage = createPage(parent);
    lv_obj_add_flag(ctx->listPage, LV_OBJ_FLAG_HIDDEN);

    ctx->list = lv_obj_create(ctx->listPage);
    lv_obj_set_size(ctx->list, LV_PCT(100), LV_PCT(100));
    lv_obj_set_flex_flow(ctx->list, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(ctx->list, 2, 0);
    lv_obj_set_scroll_dir(ctx->list, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(ctx->list, LV_SCROLLBAR_MODE_AUTO);
}

void createDetailPage(Context* ctx, lv_obj_t* parent) {
    ctx->detailPage = createPage(parent);
    lv_obj_add_flag(ctx->detailPage, LV_OBJ_FLAG_HIDDEN);
    lv_obj_set_scroll_dir(ctx->detailPage, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(ctx->detailPage, LV_SCROLLBAR_MODE_AUTO);
    lv_obj_set_style_pad_all(ctx->detailPage, 4, 0);

    ctx->detailChart = lv_chart_create(ctx->detailPage);
    lv_obj_set_size(ctx->detailChart, LV_PCT(100), 70);
    lv_chart_set_type(ctx->detailChart, LV_CHART_TYPE_LINE);
    lv_chart_set_point_count(ctx->detailChart, CHART_POINTS);
    lv_chart_set_axis_range(ctx->detailChart, LV_CHART_AXIS_PRIMARY_Y, 0, SIGNAL_RANGE_DB);
    lv_obj_set_style_size(ctx->detailChart, 0, 0, LV_PART_INDICATOR);
    lv_obj_remove_flag(ctx->detailChart, LV_OBJ_FLAG_SCROLLABLE);
    ctx->detailSeries[0] = lv_chart_add_series(ctx->detailChart, lv_color_hex(SERIES_COLORS[0]), LV_CHART_AXIS_PRIMARY_Y);

    ctx->detailInfo = lv_label_create(ctx->detailPage);
    lv_label_set_long_mode(ctx->detailInfo, LV_LABEL_LONG_MODE_WRAP);
    lv_obj_set_width(ctx->detailInfo, LV_PCT(100));

    ctx->detailClients = lv_label_create(ctx->detailPage);
    lv_label_set_long_mode(ctx->detailClients, LV_LABEL_LONG_MODE_WRAP);
    lv_obj_set_width(ctx->detailClients, LV_PCT(100));

    ctx->connectButton = lv_button_create(ctx->detailPage);
    auto* connectLabel = lv_label_create(ctx->connectButton);
    lv_label_set_text(connectLabel, "Connetti");
    lv_obj_center(connectLabel);
    lv_obj_add_event_cb(ctx->connectButton, onConnectPressed, LV_EVENT_SHORT_CLICKED, ctx);
}

void createWidgets(lv_obj_t* parent, void* userData) {
    auto* ctx = static_cast<Context*>(userData);

    lv_obj_set_flex_flow(parent, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(parent, 0, LV_STATE_DEFAULT);

    ctx->toolbar = lvgl_toolbar_create(parent, "Wi-Fi Scanner");
    lvgl_toolbar_set_nav_action(ctx->toolbar, LV_SYMBOL_CLOSE, onBackPressed, ctx);

    auto* wrapper = lv_obj_create(parent);
    lv_obj_set_flex_flow(wrapper, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_width(wrapper, LV_PCT(100));
    lv_obj_set_flex_grow(wrapper, 1);
    lv_obj_set_style_pad_all(wrapper, 4, 0);

    createGraphPage(ctx, wrapper);
    createListPage(ctx, wrapper);
    createDetailPage(ctx, wrapper);

    showPage(ctx, ctx->page);
}

void destroyWidgets(void* userData) {
    auto* ctx = static_cast<Context*>(userData);
    lvgl_toolbar_set_back_override(nullptr, nullptr);
    ctx->toolbar = nullptr;
    ctx->statusLabel = nullptr;
    ctx->graphPage = nullptr;
    ctx->chart = nullptr;
    ctx->labelLayer = nullptr;
    for (auto& series : ctx->series) series = nullptr;
    ctx->startButton = nullptr;
    ctx->stopButton = nullptr;
    ctx->listPage = nullptr;
    ctx->list = nullptr;
    ctx->rows.clear();
    ctx->detailPage = nullptr;
    ctx->detailInfo = nullptr;
    ctx->detailClients = nullptr;
    ctx->detailChart = nullptr;
    for (auto& series : ctx->detailSeries) series = nullptr;
    ctx->connectButton = nullptr;
}

int32_t appMain(int /*argc*/, char* /*argv*/[]) {
    uint32_t appInstanceId = app_scheduler_current_app_id();
    Context ctx;
    ctx.appInstanceId = appInstanceId;

    TaskEventGroup event_group {};
    task_event_group_construct(&event_group);

    AppEventSubscription sub {};
    check(app_event_subscribe(&sub, &event_group) == ERROR_NONE);

    ctx.window = window_manager_create_ext(appInstanceId, createWidgets, destroyWidgets, &ctx);

    service::wifi::setScanRecords(MAX_RECORDS);
    // Auto-connect scans would compete with this app's own scans and with capture.
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
    stopCapture(&ctx);
    service::wifi::setAutoScanPaused(false);

    window_manager_remove(ctx.window);
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
