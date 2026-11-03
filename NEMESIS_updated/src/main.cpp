#define UNICODE
#define _UNICODE
#define NOMINMAX
#include <windows.h>
#include <windowsx.h>
#include <dwmapi.h>
#include <gdiplus.h>
#include <uxtheme.h>
#include <commdlg.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <cmath>
#include <fstream>
#include <ctime>
#include <cstring>
#include <thread>
#include <chrono>
#include <atomic>
#include "license_core.h"
#include "injector.h"

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "ntdll.lib")

using namespace Gdiplus;
namespace nemesis { bool RevokeInvites(const std::string&); bool RevokeSpecificInvite(const std::string&, const std::string&); std::string GetInviteList(const std::string&); bool BanIP(const std::string&, const std::string&); bool UnbanIP(const std::string&, const std::string&); bool UploadDLLToServer(const std::string&, const std::string&); void ReportDebugger(); void ReportClientPatch(); } 

const DWORD MY_HWID = 436241589; 
static bool g_isHwidValid = true;
static bool g_isClientPatched = false;

DWORD CheckHWID() {
    DWORD serial = 0;
    if (GetVolumeInformationW(L"C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0)) return serial;
    return 0;
}

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);
bool RealDebuggerCheck() {
    auto pNtQueryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!pNtQueryInfo) return false;
    DWORD debugPort = 0;
    if (pNtQueryInfo(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL) != 0) return false;
    if (debugPort != 0) return true;
    return false;
}
bool IsHookedByDebugger() { return false; }
void HideThreadFromDebugger() {
    auto pNtSetInformationThread = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread");
    if (pNtSetInformationThread) ((NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG))pNtSetInformationThread)(GetCurrentThread(), 0x11, 0, 0);
}

std::string GetSecretToken() { DWORD hwid = CheckHWID(); return "D33P" + std::to_string(hwid % 10000) + "S33K_N3M3S1S"; }
const unsigned char ENC_PAYLOAD[] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
void DecryptAndExecute() {
    std::string key = GetSecretToken();
    LPVOID pMem = VirtualAlloc(NULL, sizeof(ENC_PAYLOAD), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pMem) return;
    unsigned char* pBytes = (unsigned char*)pMem;
    for (size_t i = 0; i < sizeof(ENC_PAYLOAD); i++) pBytes[i] = ENC_PAYLOAD[i] ^ key[i % key.length()];
}

static HWND g_hwnd{}, g_invite{}, g_password{}, g_days{}, g_ban_ip{}, g_revoke_tok{}, g_bind_ip{}, g_unban_ip{}, g_logs{};
static HFONT g_editFont{};
static ULONG_PTR g_gdiplus{};
static bool g_devPanel = false, g_devUnlocked = false, g_adminPanel = false;
static bool g_menuTarget = false;
static float g_menuT = 0.0f;

static float g_scalePrimary = 1.0f, g_scaleDev = 1.0f, g_scaleExit = 1.0f, g_scaleAdmin = 1.0f, g_scaleBan = 1.0f, g_scaleRevoke = 1.0f, g_scaleUpload = 1.0f, g_scaleCheck = 1.0f, g_scaleUnban = 1.0f;
static bool g_hoverPrimary = false, g_hoverDev = false, g_hoverExit = false, g_hoverAdmin = false, g_hoverBan = false, g_hoverRevoke = false, g_hoverUpload = false, g_hoverCheck = false, g_hoverUnban = false;
static float g_anim = 0.0f;

static std::wstring g_status = L"PASTE YOUR INVITE TO CONTINUE";
static std::string g_adminList = "No generated invites.";
static std::string g_currentToken = "";
static std::string g_sessionKey = "";
static std::string g_devToken = "";
static std::atomic<bool> g_isLicenseValid{false};
#ifdef NEMESIS_DEV_BUILD
static std::atomic<unsigned> g_devGeneration{0};
static constexpr UINT WM_DEV_SESSION_LOST = WM_APP + 41;

static void StartDevHeartbeat(HWND hwnd, const std::string& token) {
    const unsigned generation = ++g_devGeneration;
    std::thread([hwnd, token, generation]() {
        while (g_devGeneration.load() == generation) {
            std::this_thread::sleep_for(std::chrono::seconds(3));
            if (g_devGeneration.load() != generation) return;
            if (!nemesis::CheckDevSession(token)) {
                PostMessageW(hwnd, WM_DEV_SESSION_LOST, static_cast<WPARAM>(generation), 0);
                return;
            }
        }
    }).detach();
}
#endif

struct Particle { float x, y, speed, phase; };
static std::vector<Particle> g_particles;

static void SetStatus(const std::wstring& s) { g_status = s; if (g_hwnd) InvalidateRect(g_hwnd, nullptr, FALSE); }
static std::string ToUtf8(const std::wstring& value) { if (value.empty()) return {}; int n = WideCharToMultiByte(CP_UTF8, 0, value.data(), (int)value.size(), nullptr, 0, nullptr, nullptr); std::string out(n, '\0'); WideCharToMultiByte(CP_UTF8, 0, value.data(), (int)value.size(), out.data(), n, nullptr, nullptr); return out; }
static std::wstring Utf8ToWide(const std::string& value) { if (value.empty()) return {}; int n = MultiByteToWideChar(CP_UTF8, 0, value.data(), (int)value.size(), nullptr, 0); std::wstring out(n, L'\0'); MultiByteToWideChar(CP_UTF8, 0, value.data(), (int)value.size(), out.data(), n); return out; }
static bool Hit(POINT p, int x, int y, int w, int h) { return p.x >= x && p.x < x+w && p.y >= y && p.y < y+h; }

static void CenterEditText(HWND edit) { 
    RECT r{}; GetClientRect(edit, &r); 
    RECT rc{ 2, 4, r.right - 2, r.bottom - 4 }; 
    SendMessageW(edit, EM_SETRECT, 0, (LPARAM)&rc); 
}

std::string GetSHA256(const std::wstring& input) {
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_HASH_HANDLE hHash = NULL; DWORD cbData = 0, cbHash = 0, cbHashObject = 0;
    PBYTE pbHashObject = NULL, pbHash = NULL; std::string resultHex = "";
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) >= 0) {
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
        BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
        pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject); pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
        if (BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0) >= 0) {
            std::string utf8 = ToUtf8(input);
            BCryptHashData(hHash, (PUCHAR)utf8.c_str(), (ULONG)utf8.length(), 0);
            BCryptFinishHash(hHash, pbHash, cbHash, 0);
            char hex[3]; for (DWORD i = 0; i < cbHash; i++) { sprintf_s(hex, "%02x", pbHash[i]); resultHex += hex; }
            BCryptDestroyHash(hHash);
        }
        if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject); if (pbHash) HeapFree(GetProcessHeap(), 0, pbHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    return resultHex;
}

void HeartbeatThread() {
    HideThreadFromDebugger();
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        if (RealDebuggerCheck()) { 
#ifdef NEMESIS_DEV_BUILD
            nemesis::ReportDebugger(); ExitProcess(0); 
#else
            nemesis::ReportClientPatch();
#endif
        }
#ifdef NEMESIS_DEV_BUILD
        if (CheckHWID() != MY_HWID) { g_isHwidValid = false; }
#endif
        if (g_menuTarget && !g_currentToken.empty()) {
            auto res = nemesis::VerifyInvite(g_currentToken, std::to_string(CheckHWID()));
            if (res.ok) { g_sessionKey = res.sessionKey; g_isLicenseValid = true; }
            else g_isLicenseValid = false;
        }
    }
}

void LoadAndInject(HWND hwnd) {
    if (g_sessionKey.empty()) { MessageBoxW(hwnd, L"Auth Error", L"Nemesis", MB_OK | MB_ICONERROR); ExitProcess(0); return; }
    if (!g_isHwidValid || g_isClientPatched) {
        nemesis::ReportClientPatch(); MessageBoxW(hwnd, L"Failed to download.", L"Nemesis", MB_OK | MB_ICONERROR); SetStatus(L"FAILED"); return;
    }
    
    if (!ManualMapper::IsProcessRunning(L"cs2.exe")) {
        MessageBoxW(hwnd, L"Please start Counter-Strike 2 before injecting.", L"Nemesis", MB_OK | MB_ICONWARNING);
        SetStatus(L"CS2 NOT RUNNING");
        return;
    }

#ifdef NEMESIS_DEV_BUILD
    if (GetCurrentThreadId() != GetWindowThreadProcessId(hwnd, NULL)) { ExitProcess(0); }
#endif
    DecryptAndExecute(); 
    SetStatus(L"DOWNLOADING DLL..."); InvalidateRect(hwnd, nullptr, FALSE);
    std::vector<unsigned char> dllData = nemesis::DownloadDLL(g_currentToken, std::to_string(CheckHWID()));
    
    if (dllData.empty() || dllData.size() < 1024) { 
        MessageBoxW(hwnd, L"Failed to download DLL from server (DLL not found on server or invalid). Upload cheat.dll via admin panel first.", L"Nemesis", MB_OK | MB_ICONERROR); 
        SetStatus(L"FAILED - NO DLL"); 
        return; 
    }
    
    SetStatus(L"INJECTING..."); InvalidateRect(hwnd, nullptr, FALSE);
    srand((unsigned int)time(NULL)); Sleep(rand() % 500 + 100); 
    
    if (ManualMapper::Inject(dllData, L"cs2.exe")) {
        MessageBoxW(hwnd, L"Injected successfully! Check inject_log.txt if anything crashes.", L"Nemesis", MB_OK);
        SetStatus(L"INJECTED");
    } else {
        MessageBoxW(hwnd, L"Injection failed! Check inject_log.txt for details.", L"Nemesis", MB_OK | MB_ICONERROR);
        SetStatus(L"INJECTION FAILED");
    }
    
    if (!dllData.empty()) SecureZeroMemory(dllData.data(), dllData.size());
    DWORD oldProtect; VirtualProtect((LPVOID)GetModuleHandle(NULL), 4096, PAGE_EXECUTE_READ, &oldProtect);
}

#ifdef NEMESIS_DEV_BUILD
std::string Base64Encode(const std::vector<unsigned char>& data) {
    DWORD outLen = 0; CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &outLen);
    std::string out(outLen, '\0'); CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &out[0], &outLen);
    return out;
}
void UploadCheat(HWND hwnd) {
    if (g_devToken.empty()) return;
    OPENFILENAMEW ofn; ZeroMemory(&ofn, sizeof(ofn)); ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = hwnd;
    wchar_t szFile[260] = {0}; ofn.lpstrFile = szFile; ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = L"DLL Files\0*.dll\0All Files\0*.*\0"; ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST; 
    if (GetOpenFileNameW(&ofn)) {
        std::ifstream file(szFile, std::ios::binary);
        if (file.is_open()) {
            std::vector<unsigned char> dllData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            std::string b64 = Base64Encode(dllData);
            SetStatus(L"UPLOADING...");
            if (nemesis::UploadDLLToServer(b64, g_devToken)) SetStatus(L"UPLOAD SUCCESSFUL");
            else SetStatus(L"UPLOAD FAILED");
        }
    }
}
#endif

static void DrawTextStr(Gdiplus::Graphics& g, const wchar_t* text, float x, float y, float size, Color color, bool bold = false) {
    FontFamily family(L"Segoe UI"); Font font(&family, size, bold ? FontStyleBold : FontStyleRegular, UnitPixel);
    SolidBrush brush(color); g.DrawString(text, -1, &font, PointF(x, y), &brush);
}
static void DrawCentered(Gdiplus::Graphics& g, const wchar_t* text, RectF r, float size, Color color, bool bold = false) {
    FontFamily family(L"Segoe UI"); Font font(&family, size, bold ? FontStyleBold : FontStyleRegular, UnitPixel);
    SolidBrush brush(color); StringFormat format; format.SetAlignment(StringAlignmentCenter); format.SetLineAlignment(StringAlignmentCenter);
    g.DrawString(text, -1, &font, r, &format, &brush);
}
static void RoundedRect(Gdiplus::Graphics& g, RectF r, float radius, Color fill, Color outline = Color(0,0,0,0)) {
    GraphicsPath path; float d = radius * 2.0f;
    path.AddArc(r.X, r.Y, d, d, 180, 90); path.AddArc(r.GetRight()-d, r.Y, d, d, 270, 90);
    path.AddArc(r.GetRight()-d, r.GetBottom()-d, d, d, 0, 90); path.AddArc(r.X, r.GetBottom()-d, d, d, 90, 90);
    path.CloseFigure(); SolidBrush brush(fill); g.FillPath(&brush, &path);
    if (outline.GetA()) { Pen pen(outline, 1.0f); g.DrawPath(&pen, &path); }
}

static void Paint(HWND hwnd) {
    PAINTSTRUCT ps{}; HDC target = BeginPaint(hwnd, &ps);
    RECT rc{}; GetClientRect(hwnd, &rc); int w = rc.right, h = rc.bottom;
    if (w <= 0 || h <= 0) { EndPaint(hwnd, &ps); return; }
    HDC memory = CreateCompatibleDC(target); HBITMAP bitmap = CreateCompatibleBitmap(target, w, h);
    HGDIOBJ old = SelectObject(memory, bitmap);
    {
        Graphics g(memory); g.SetSmoothingMode(SmoothingModeAntiAlias); g.SetTextRenderingHint(TextRenderingHintClearTypeGridFit);
        SolidBrush bg(Color(255, 7, 8, 11)); g.FillRectangle(&bg, 0, 0, w, h);
        
        for (const auto& p : g_particles) {
            int alpha = 24 + (int)(18.0f * (0.5f + 0.5f * sinf(g_anim + p.phase)));
            SolidBrush dot(Color((BYTE)alpha, 170, 180, 205)); g.FillEllipse(&dot, p.x, p.y, 2.0f, 2.0f);
        }

        SolidBrush top(Color(255, 11, 12, 16)); g.FillRectangle(&top, 0, 0, w, 56);
        Pen line(Color(255, 32, 34, 43), 1); g.DrawLine(&line, 0, 55, w, 55);
        DrawTextStr(g, L"Nemesis.dev", 26, 15, 17, Color(255, 246, 247, 250), true);
        DrawTextStr(g, L"PRIVATE CHEAT CLIENT", 151, 21, 8, Color(255, 126, 130, 143), true);

#ifdef NEMESIS_DEV_BUILD
        if (g_devUnlocked) {
            float sw = 70 * g_scaleAdmin, sh = 32 * g_scaleAdmin;
            float sx = (float)w-210 - (sw - 70)/2.0f, sy = 11 - (sh - 32)/2.0f;
            RoundedRect(g, RectF(sx, sy, sw, sh), 9, g_hoverAdmin ? Color(255, 43, 47, 58) : Color(255, 21, 23, 30), Color(255, 55, 59, 72));
            DrawCentered(g, L"ADMIN", RectF(sx,sy,sw,sh), 8, Color(255,240,242,247), true);
        }
        float dw = 62 * g_scaleDev, dh = 32 * g_scaleDev;
        float dx = (float)w-130 - (dw - 62)/2.0f, dy = 11 - (dh - 32)/2.0f;
        RoundedRect(g, RectF(dx, dy, dw, dh), 9, g_hoverDev ? Color(255, 43, 47, 58) : Color(255, 21, 23, 30), Color(255, 55, 59, 72));
        DrawCentered(g, g_devPanel ? L"USER" : L"DEV", RectF(dx,dy,dw,dh), 8, Color(255,240,242,247), true);
#endif

        float ew = 39 * g_scaleExit, eh = 34 * g_scaleExit;
        float ex = (float)w-59 - (ew - 39)/2.0f, ey = 10 - (eh - 34)/2.0f;
        RoundedRect(g, RectF(ex, ey, ew, eh), 10, g_hoverExit ? Color(255, 225, 75, 86) : Color(255, 24, 26, 33), Color(255, 62, 65, 77));
        DrawCentered(g, L"×", RectF(ex,ey-2,ew,eh), 19, Color(255,245,246,249), true);

        // КРАСИВОЕ МЕНЮ ЗАГРУЗКИ (без затемнения, чтобы видеть фон)
        if (g_menuT > 0.001f) {
            float cardW = 360, cardH = 240;
            float cardX = w/2.0f - cardW/2.0f, cardY = h/2.0f - cardH/2.0f;
            
            RoundedRect(g, RectF(cardX, cardY, cardW, cardH), 15, Color(240, 16, 18, 24), Color(255, 57, 62, 76));
            
            if (!g_sessionKey.empty()) {
                DrawCentered(g, L"NEVERLOSE CRACK", RectF(cardX, cardY + 40, cardW, 50), 28, Color(255, 255, 255, 255), true);
                DrawCentered(g, L"Counter-Strike 2", RectF(cardX, cardY + 90, cardW, 24), 12, Color(255, 115, 125, 140), false);
                
                RoundedRect(g, RectF(w/2.0f-60, cardY + 130, 120, 42), 10, Color(255, 224, 228, 237));
                DrawCentered(g, L"LOAD", RectF(w/2.0f-60, cardY + 130, 120, 42), 14, Color(255, 9, 11, 15), true);
            } else {
                DrawCentered(g, L"AUTHENTICATION FAILED", RectF(cardX, cardY + 80, cardW, 40), 20, Color(255, 255, 50, 50), true);
            }
            
            RoundedRect(g, RectF(cardX + 10, cardY + cardH - 40, 80, 30), 6, Color(255, 30, 30, 30), Color(255, 80, 80, 80));
            DrawCentered(g, L"EXIT", RectF(cardX + 10, cardY + cardH - 40, 80, 30), 10, Color(255, 200, 200, 200), true);
        } else {
            DrawCentered(g, L"Nemesis.dev", RectF(0, 80, (float)w, 62), 43, Color(255, 248, 249, 252), true);
            DrawCentered(g, L"PRIVATE CHEAT CLIENT", RectF(0, 144, (float)w, 24), 10, Color(255, 131, 135, 148), false);
            RoundedRect(g, RectF(w/2.0f-18, 180, 36, 2), 1, Color(255, 93, 113, 158));

            if (g_adminPanel) {
                DrawCentered(g, L"ADMIN PANEL", RectF(0, 200, (float)w, 20), 12, Color(255, 248, 249, 252), true);
                
                RoundedRect(g, RectF(100.0f, 230.0f, (float)w-200.0f, 80.0f), 10, Color(255, 16, 18, 24), Color(255, 57, 62, 76));
                
                DrawTextStr(g, L"TOKEN TO REVOKE", 100.0f, 326.0f, 8, Color(255, 151, 157, 174), true);
                RoundedRect(g, RectF(100.0f, 340.0f, 300.0f, 26.0f), 6, Color(255, 16, 18, 24), Color(255, 57, 62, 76));
                
                DrawTextStr(g, L"BAN IP", 100.0f, 386.0f, 8, Color(255, 151, 157, 174), true);
                RoundedRect(g, RectF(100.0f, 400.0f, 300.0f, 26.0f), 6, Color(255, 16, 18, 24), Color(255, 57, 62, 76));

                DrawTextStr(g, L"UNBAN IP", 100.0f, 446.0f, 8, Color(255, 151, 157, 174), true);
                RoundedRect(g, RectF(100.0f, 460.0f, 300.0f, 26.0f), 6, Color(255, 16, 18, 24), Color(255, 57, 62, 76));

                RoundedRect(g, RectF(410.0f, 340.0f, 80.0f, 26.0f), 6, g_hoverRevoke ? Color(255, 250, 251, 253) : Color(255, 224, 228, 237));
                DrawCentered(g, L"REVOKE", RectF(410.0f, 340.0f, 80.0f, 26.0f), 8, Color(255, 9, 11, 15), true);
                
                RoundedRect(g, RectF(410.0f, 400.0f, 80.0f, 26.0f), 6, g_hoverBan ? Color(255, 250, 251, 253) : Color(255, 224, 228, 237));
                DrawCentered(g, L"BAN", RectF(410.0f, 400.0f, 80.0f, 26.0f), 8, Color(255, 9, 11, 15), true);

                RoundedRect(g, RectF(410.0f, 460.0f, 80.0f, 26.0f), 6, g_hoverUnban ? Color(255, 250, 251, 253) : Color(255, 224, 228, 237));
                DrawCentered(g, L"UNBAN", RectF(410.0f, 460.0f, 80.0f, 26.0f), 8, Color(255, 9, 11, 15), true);

                RoundedRect(g, RectF(510.0f, 340.0f, 80.0f, 146.0f), 8, g_hoverUpload ? Color(255, 250, 251, 253) : Color(255, 224, 228, 237));
                DrawCentered(g, L"UPLOAD\nDLL", RectF(510.0f, 340.0f, 80.0f, 146.0f), 8, Color(255, 9, 11, 15), true);

                RoundedRect(g, RectF(600.0f, 340.0f, 80.0f, 146.0f), 8, g_hoverCheck ? Color(255, 250, 251, 253) : Color(255, 224, 228, 237));
                DrawCentered(g, L"CHECK\nBINDS", RectF(600.0f, 340.0f, 80.0f, 146.0f), 8, Color(255, 9, 11, 15), true);

                RoundedRect(g, RectF(100.0f, 510.0f, 100.0f, 36.0f), 8, Color(255, 224, 228, 237));
                DrawCentered(g, L"REVOKE ALL", RectF(100.0f, 510.0f, 100.0f, 36.0f), 8, Color(255, 9, 11, 15), true);
                
                RoundedRect(g, RectF((float)w-200.0f, 510.0f, 100.0f, 36.0f), 8, Color(255, 224, 228, 237));
                DrawCentered(g, L"BACK", RectF((float)w-200.0f, 510.0f, 100.0f, 36.0f), 9, Color(255, 9, 11, 15), true);
            } else if (g_devPanel) {
                DrawCentered(g, L"DEVELOPER SESSION", RectF(0, 230, (float)w, 20), 9, Color(255, 151, 157, 174), true);
                
                if (!g_devUnlocked) {
                    DrawTextStr(g, L"DEVELOPER PASSWORD", w/2.0f-150, 266, 8, Color(255, 151, 157, 174), true);
                    RoundedRect(g, RectF(w/2.0f-160, 286, 320, 46), 9, Color(255, 16, 18, 24), Color(255, 57, 62, 76));
                    
                    RoundedRect(g, RectF(w/2.0f-105, 366, 210, 48), 10, g_hoverPrimary ? Color(255, 250, 251, 253) : Color(255, 224, 228, 237));
                    DrawCentered(g, L"UNLOCK DEV ACCESS", RectF(w/2.0f-105, 366, 210, 48), 9, Color(255, 9, 11, 15), true);
                    
                    DrawCentered(g, g_status.c_str(), RectF(0, 420, (float)w, 18), 8, Color(255, 176, 181, 194), false);
                } else {
                    DrawTextStr(g, L"INVITE DAYS", w/2.0f-150, 266, 8, Color(255, 151, 157, 174), true);
                    RoundedRect(g, RectF(w/2.0f-160, 286, 320, 46), 9, Color(255, 16, 18, 24), Color(255, 57, 62, 76));
                    
                    DrawTextStr(g, L"BIND IP (Required)", w/2.0f-150, 346, 8, Color(255, 151, 157, 174), true);
                    RoundedRect(g, RectF(w/2.0f-160, 366, 320, 46), 9, Color(255, 16, 18, 24), Color(255, 57, 62, 76));

                    RoundedRect(g, RectF(w/2.0f-105, 430, 210, 48), 10, g_hoverPrimary ? Color(255, 250, 251, 253) : Color(255, 224, 228, 237));
                    DrawCentered(g, L"GENERATE INVITE", RectF(w/2.0f-105, 430, 210, 48), 9, Color(255, 9, 11, 15), true);
                    
                    DrawCentered(g, g_status.c_str(), RectF(0, 490, (float)w, 18), 8, Color(255, 176, 181, 194), false);
                }
            } else {
                DrawCentered(g, L"INVITE ACTIVATION", RectF(0, 230, (float)w, 20), 9, Color(255, 151, 157, 174), true);
                DrawTextStr(g, L"INVITE CODE", w/2.0f-150, 266, 8, Color(255, 151, 157, 174), true);
                RoundedRect(g, RectF(w/2.0f-160, 286, 320, 46), 9, Color(255, 16, 18, 24), Color(255, 57, 62, 76));
                
                RoundedRect(g, RectF(w/2.0f-90, 366, 180, 48), 10, g_hoverPrimary ? Color(255, 250, 251, 253) : Color(255, 224, 228, 237));
                DrawCentered(g, L"LOG IN", RectF(w/2.0f-90, 366, 180, 48), 12, Color(255, 9, 11, 15), true);
                DrawCentered(g, g_status.c_str(), RectF(0, 420, (float)w, 18), 8, Color(255, 176, 181, 194), false);
            }
        }
    }
    BitBlt(target, 0, 0, w, h, memory, 0, 0, SRCCOPY); SelectObject(memory, old); DeleteObject(bitmap); DeleteDC(memory);
    EndPaint(hwnd, &ps);
}

static void LayoutControls(HWND hwnd) {
    RECT r{}; GetClientRect(hwnd, &r); const int cx = r.right / 2;
    if (g_menuTarget) {
        if (g_invite) ShowWindow(g_invite, SW_HIDE); if (g_password) ShowWindow(g_password, SW_HIDE); if (g_days) ShowWindow(g_days, SW_HIDE); if (g_bind_ip) ShowWindow(g_bind_ip, SW_HIDE);
        if (g_ban_ip) ShowWindow(g_ban_ip, SW_HIDE); if (g_revoke_tok) ShowWindow(g_revoke_tok, SW_HIDE); if (g_unban_ip) ShowWindow(g_unban_ip, SW_HIDE); if (g_logs) ShowWindow(g_logs, SW_HIDE);
        return;
    }
    if (g_adminPanel) {
        if (g_invite) ShowWindow(g_invite, SW_HIDE); if (g_password) ShowWindow(g_password, SW_HIDE); if (g_days) ShowWindow(g_days, SW_HIDE); if (g_bind_ip) ShowWindow(g_bind_ip, SW_HIDE);
        
        if (g_logs) { SetWindowPos(g_logs, nullptr, 105, 235, (int)(r.right-210), 70, SWP_NOZORDER|SWP_NOACTIVATE); ShowWindow(g_logs, SW_SHOW); }
        if (g_revoke_tok) { SetWindowPos(g_revoke_tok, nullptr, 103, 343, 294, 20, SWP_NOZORDER|SWP_NOACTIVATE); ShowWindow(g_revoke_tok, SW_SHOW); CenterEditText(g_revoke_tok); }
        if (g_ban_ip) { SetWindowPos(g_ban_ip, nullptr, 103, 403, 294, 20, SWP_NOZORDER|SWP_NOACTIVATE); ShowWindow(g_ban_ip, SW_SHOW); CenterEditText(g_ban_ip); }
        if (g_unban_ip) { SetWindowPos(g_unban_ip, nullptr, 103, 463, 294, 20, SWP_NOZORDER|SWP_NOACTIVATE); ShowWindow(g_unban_ip, SW_SHOW); CenterEditText(g_unban_ip); }
        return;
    }
    if (g_logs) ShowWindow(g_logs, SW_HIDE);
    if (g_ban_ip) ShowWindow(g_ban_ip, SW_HIDE);
    if (g_revoke_tok) ShowWindow(g_revoke_tok, SW_HIDE);
    if (g_unban_ip) ShowWindow(g_unban_ip, SW_HIDE);
    
    if (g_bind_ip) {
        if (g_devPanel && g_devUnlocked) {
            SetWindowPos(g_bind_ip, nullptr, cx-150, 376, 300, 26, SWP_NOZORDER|SWP_NOACTIVATE); 
            ShowWindow(g_bind_ip, SW_SHOW); CenterEditText(g_bind_ip);
        } else {
            ShowWindow(g_bind_ip, SW_HIDE);
        }
    }

    if (g_invite) { SetWindowPos(g_invite, nullptr, cx-150, 296, 300, 26, SWP_NOZORDER|SWP_NOACTIVATE); ShowWindow(g_invite, g_devPanel ? SW_HIDE : SW_SHOW); CenterEditText(g_invite); }
    if (g_password) { SetWindowPos(g_password, nullptr, cx-150, 296, 300, 26, SWP_NOZORDER|SWP_NOACTIVATE); ShowWindow(g_password, g_devPanel && !g_devUnlocked ? SW_SHOW : SW_HIDE); CenterEditText(g_password); }
    if (g_days) { SetWindowPos(g_days, nullptr, cx-150, 296, 300, 26, SWP_NOZORDER|SWP_NOACTIVATE); ShowWindow(g_days, g_devPanel && g_devUnlocked ? SW_SHOW : SW_HIDE); CenterEditText(g_days); }
}

static void ClickPrimary(HWND hwnd) {
#ifdef NEMESIS_DEV_BUILD
    if (g_devPanel) {
        if (!g_devUnlocked) {
            wchar_t passBuf[256]{}; GetWindowTextW(g_password, passBuf, 256);
            std::wstring passW(passBuf);
            if (passW.empty()) { SetStatus(L"ENTER PASSWORD"); return; }
            std::string pwdHash = GetSHA256(passW);
            SetStatus(L"CHECKING SERVER...");
            std::string outToken;
            if (nemesis::ServerLogin(pwdHash, outToken)) {
                g_devUnlocked = true; g_devToken = outToken;
                SetWindowTextW(g_password, L"");
                StartDevHeartbeat(hwnd, g_devToken);
                SetStatus(L"DEV ACCESS GRANTED");
            }
            else SetStatus(L"INCORRECT PASSWORD");
            LayoutControls(hwnd); InvalidateRect(hwnd, nullptr, FALSE); return;
        }
        if ((GetWindowLongPtrW(g_days, GWL_STYLE) & ES_READONLY) != 0) {
            SendMessageW(g_days, EM_SETREADONLY, FALSE, 0); SetWindowTextW(g_days, L"30"); SetStatus(L"ENTER DAYS FOR NEW INVITE"); InvalidateRect(hwnd, nullptr, FALSE); return;
        }
        wchar_t daysText[32]{}; GetWindowTextW(g_days, daysText, 32); wchar_t* end = nullptr; unsigned long days = wcstoul(daysText, &end, 10);
        if (!daysText[0] || !end || *end || days > 36500) { SetStatus(L"ENTER DAYS: 0 TO 36500"); return; }
        
        wchar_t bindBuf[64]{}; GetWindowTextW(g_bind_ip, bindBuf, 64);
        std::string bindIp = ToUtf8(bindBuf);

        if (bindIp.empty()) {
            SetStatus(L"TYPE BIND IP TO GENERATE INVITE");
            return;
        }

        auto gen = nemesis::GenerateInvite(days, g_devToken, bindIp);
        if (!gen.ok) { SetStatus(L"GENERATION FAILED / SERVER OFFLINE"); return; }
        
        const std::wstring wide = Utf8ToWide(gen.token); SetWindowTextW(g_days, wide.c_str()); SendMessageW(g_days, EM_SETREADONLY, TRUE, 0); SetStatus(L"INVITE COPIED TO CLIPBOARD");
        if (OpenClipboard(hwnd)) {
            EmptyClipboard(); const SIZE_T bytes = (wide.size() + 1) * sizeof(wchar_t); HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
            if (mem) { void* dst = GlobalLock(mem); if(dst){ memcpy(dst, wide.c_str(), bytes); GlobalUnlock(mem); SetClipboardData(CF_UNICODETEXT, mem); } else GlobalFree(mem); }
            CloseClipboard();
        }
        InvalidateRect(hwnd, nullptr, FALSE); return;
    }
#endif
    wchar_t invite[4096]{}; GetWindowTextW(g_invite, invite, 4096);
    g_currentToken = ToUtf8(invite); 
    auto res = nemesis::VerifyInvite(g_currentToken, std::to_string(CheckHWID()));
    if (!res.ok) { SetStatus(L"INVITE INVALID / " + Utf8ToWide(res.reason)); return; }
    g_sessionKey = res.sessionKey; g_isLicenseValid = true;
    std::thread(HeartbeatThread).detach(); 
    g_menuTarget = true; g_menuT = 0.0f; LayoutControls(hwnd); SetStatus(L"INVITE ACCEPTED"); InvalidateRect(hwnd, nullptr, FALSE);
}

#ifdef NEMESIS_DEV_BUILD
static void ToggleAdmin(HWND hwnd) { 
    if (g_menuTarget) return; g_adminPanel = !g_adminPanel; 
    if (g_adminPanel) { 
        g_adminList = nemesis::GetInviteList(g_devToken); 
        SetWindowTextW(g_logs, Utf8ToWide(g_adminList).c_str());
        UpdateWindow(g_logs);
    }
    LayoutControls(hwnd); InvalidateRect(hwnd, nullptr, FALSE); 
}
static void ToggleDev(HWND hwnd) {
    if (g_menuTarget) return; ++g_devGeneration; g_devToken.clear(); g_devPanel = !g_devPanel; g_adminPanel = false; g_devUnlocked = false;
    SetWindowTextW(g_invite, L""); SetWindowTextW(g_password, L""); SetWindowTextW(g_days, L"30");
    SetWindowTextW(g_ban_ip, L""); SetWindowTextW(g_revoke_tok, L""); SetWindowTextW(g_bind_ip, L""); SetWindowTextW(g_unban_ip, L"");
    SendMessageW(g_days, EM_SETREADONLY, FALSE, 0); LayoutControls(hwnd);
    SetStatus(g_devPanel ? L"DEVELOPER SESSION" : L"PASTE YOUR INVITE TO CONTINUE"); InvalidateRect(hwnd, nullptr, FALSE);
}
#endif

static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        if (IsHookedByDebugger()) ExitProcess(0);
        std::thread(HeartbeatThread).detach(); 

        g_hwnd = hwnd; g_editFont = CreateFontW(-14,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        
        g_invite = CreateWindowExW(0, L"EDIT", L"", WS_CHILD|ES_AUTOHSCROLL|WS_TABSTOP, 0,0,10,10, hwnd, (HMENU)101, GetModuleHandleW(nullptr), nullptr);
        g_password = CreateWindowExW(0, L"EDIT", L"", WS_CHILD|ES_PASSWORD|ES_AUTOHSCROLL|WS_TABSTOP, 0,0,10,10, hwnd, (HMENU)102, GetModuleHandleW(nullptr), nullptr);
        g_days = CreateWindowExW(0,L"EDIT",L"30",WS_CHILD|ES_AUTOHSCROLL|WS_TABSTOP,0,0,10,10,hwnd,(HMENU)103,GetModuleHandleW(nullptr),nullptr);
        g_ban_ip = CreateWindowExW(0,L"EDIT",L"",WS_CHILD|ES_AUTOHSCROLL|WS_TABSTOP,0,0,10,10,hwnd,(HMENU)104,GetModuleHandleW(nullptr),nullptr);
        g_revoke_tok = CreateWindowExW(0,L"EDIT",L"",WS_CHILD|ES_AUTOHSCROLL|WS_TABSTOP,0,0,10,10,hwnd,(HMENU)105,GetModuleHandleW(nullptr),nullptr);
        g_bind_ip = CreateWindowExW(0,L"EDIT",L"",WS_CHILD|ES_AUTOHSCROLL|WS_TABSTOP,0,0,10,10,hwnd,(HMENU)106,GetModuleHandleW(nullptr),nullptr);
        g_unban_ip = CreateWindowExW(0,L"EDIT",L"",WS_CHILD|ES_AUTOHSCROLL|WS_TABSTOP,0,0,10,10,hwnd,(HMENU)108,GetModuleHandleW(nullptr),nullptr);
        g_logs = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY, 0, 0, 10, 10, hwnd, (HMENU)107, GetModuleHandleW(nullptr), nullptr);

        SendMessageW(g_invite, WM_SETFONT, (WPARAM)g_editFont, TRUE); SendMessageW(g_password, WM_SETFONT, (WPARAM)g_editFont, TRUE); SendMessageW(g_days, WM_SETFONT, (WPARAM)g_editFont, TRUE); SendMessageW(g_ban_ip, WM_SETFONT, (WPARAM)g_editFont, TRUE); SendMessageW(g_revoke_tok, WM_SETFONT, (WPARAM)g_editFont, TRUE); SendMessageW(g_bind_ip, WM_SETFONT, (WPARAM)g_editFont, TRUE); SendMessageW(g_unban_ip, WM_SETFONT, (WPARAM)g_editFont, TRUE);
        SendMessageW(g_logs, WM_SETFONT, (WPARAM)g_editFont, TRUE);
        
        SetWindowTheme(g_invite, L"", L""); SetWindowTheme(g_password, L"", L""); SetWindowTheme(g_days, L"", L""); SetWindowTheme(g_ban_ip, L"", L""); SetWindowTheme(g_revoke_tok, L"", L""); SetWindowTheme(g_bind_ip, L"", L""); SetWindowTheme(g_unban_ip, L"", L"");
        SetWindowTheme(g_logs, L"DarkMode_Explorer", NULL); 

        // Создаем кастомную каретку (2 пикселя шириной, 18 высотой)
        CreateCaret(g_invite, (HBITMAP)NULL, 2, 18);
        CreateCaret(g_password, (HBITMAP)NULL, 2, 18);
        CreateCaret(g_days, (HBITMAP)NULL, 2, 18);
        CreateCaret(g_bind_ip, (HBITMAP)NULL, 2, 18);
        CreateCaret(g_ban_ip, (HBITMAP)NULL, 2, 18);
        CreateCaret(g_revoke_tok, (HBITMAP)NULL, 2, 18);
        CreateCaret(g_unban_ip, (HBITMAP)NULL, 2, 18);

        SendMessageW(g_invite, EM_SETLIMITTEXT, 4096, 0);
        SendMessageW(g_password, EM_SETLIMITTEXT, 256, 0);
        SendMessageW(g_days, EM_SETLIMITTEXT, 32, 0);
        SendMessageW(g_ban_ip, EM_SETLIMITTEXT, 64, 0);
        SendMessageW(g_revoke_tok, EM_SETLIMITTEXT, 512, 0);
        SendMessageW(g_bind_ip, EM_SETLIMITTEXT, 64, 0);
        SendMessageW(g_unban_ip, EM_SETLIMITTEXT, 64, 0);

        for (int i=0;i<34;i++) { Particle p{}; p.x = (float)((i * 97 + 31) % 790); p.y = (float)((i * 53 + 17) % 465); p.speed = 0.25f + (i % 5) * 0.12f; p.phase = (float)i * 0.71f; g_particles.push_back(p); }
        LayoutControls(hwnd); SetTimer(hwnd, 1, 16, nullptr); return 0;
    }
    case WM_SIZE: LayoutControls(hwnd); InvalidateRect(hwnd,nullptr,FALSE); return 0;
#ifdef NEMESIS_DEV_BUILD
    case WM_DEV_SESSION_LOST:
        if (static_cast<unsigned>(wp) == g_devGeneration.load()) {
            ++g_devGeneration; g_devToken.clear(); g_devUnlocked = false; g_adminPanel = false;
            SetWindowTextW(g_days, L"30"); SendMessageW(g_days, EM_SETREADONLY, FALSE, 0);
            SetStatus(L"DEV SESSION EXPIRED / SERVER OFFLINE - LOGIN AGAIN");
            LayoutControls(hwnd); InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;
#endif
    case WM_TIMER:
#ifdef NEMESIS_DEV_BUILD
        if (!g_isHwidValid) { ExitProcess(0); }
#else
        if (!g_isHwidValid) { g_isClientPatched = true; }
#endif
        if (g_menuTarget && !g_isLicenseValid) { g_sessionKey = ""; }
        
        g_scalePrimary += ((g_hoverPrimary ? 1.03f : 1.0f) - g_scalePrimary) * 0.2f;
        g_scaleDev     += ((g_hoverDev ? 1.05f : 1.0f) - g_scaleDev) * 0.2f;
        g_scaleExit    += ((g_hoverExit ? 1.05f : 1.0f) - g_scaleExit) * 0.2f;
        g_scaleAdmin   += ((g_hoverAdmin ? 1.05f : 1.0f) - g_scaleAdmin) * 0.2f;
        g_scaleBan     += ((g_hoverBan ? 1.03f : 1.0f) - g_scaleBan) * 0.2f;
        g_scaleRevoke  += ((g_hoverRevoke ? 1.03f : 1.0f) - g_scaleRevoke) * 0.2f;
        g_scaleUpload  += ((g_hoverUpload ? 1.03f : 1.0f) - g_scaleUpload) * 0.2f;
        g_scaleCheck   += ((g_hoverCheck ? 1.03f : 1.0f) - g_scaleCheck) * 0.2f;
        g_scaleUnban   += ((g_hoverUnban ? 1.03f : 1.0f) - g_scaleUnban) * 0.2f;

        g_anim += 0.025f;
        for (auto& p : g_particles) { p.y -= p.speed; if (p.y < -4) { p.y = 470.0f; p.x = (float)((int)(p.x*13 + 71) % 790); } }
        if (g_menuTarget && g_menuT < 1.0f) g_menuT = (g_menuT + 0.075f > 1.0f) ? 1.0f : (g_menuT + 0.075f);
        InvalidateRect(hwnd, nullptr, FALSE); return 0;
    case WM_PAINT: Paint(hwnd); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_CTLCOLOREDIT: case WM_CTLCOLORSTATIC: { HDC dc = (HDC)wp; SetTextColor(dc, RGB(242,244,249)); SetBkColor(dc, RGB(16,18,24)); static HBRUSH brush = CreateSolidBrush(RGB(16,18,24)); return (LRESULT)brush; }
    case WM_NCHITTEST: { POINT p{GET_X_LPARAM(lp),GET_Y_LPARAM(lp)}; ScreenToClient(hwnd,&p); RECT r{}; GetClientRect(hwnd,&r); if (p.y < 55 && p.x < r.right-220) return HTCAPTION; return HTCLIENT; }
    case WM_MOUSEMOVE: {
        POINT p{GET_X_LPARAM(lp),GET_Y_LPARAM(lp)}; RECT r{}; GetClientRect(hwnd,&r); bool dev = false, adm = false, ban = false, rev = false, upl = false, chk = false, unb = false;
#ifdef NEMESIS_DEV_BUILD
        dev = Hit(p,r.right-130,11,62,32); adm = g_devUnlocked && Hit(p,r.right-210,11,70,32);
        if (g_adminPanel) { 
            ban = Hit(p, 410, 400, 80, 26); rev = Hit(p, 410, 340, 80, 26); upl = Hit(p, 510, 340, 80, 146); chk = Hit(p, 600, 340, 80, 146); unb = Hit(p, 410, 460, 80, 26);
        }
#endif
        bool ex = Hit(p,r.right-59,10,39,34); bool primary = (g_menuTarget) ? Hit(p,r.right/2-60, 255, 120, 42) : (g_adminPanel ? false : Hit(p,r.right/2-105,386,210,48));
        if (dev!=g_hoverDev || ex!=g_hoverExit || primary!=g_hoverPrimary || adm!=g_hoverAdmin || ban!=g_hoverBan || rev!=g_hoverRevoke || upl!=g_hoverUpload || chk!=g_hoverCheck || unb!=g_hoverUnban) { 
            g_hoverDev=dev; g_hoverExit=ex; g_hoverPrimary=primary; g_hoverAdmin=adm; g_hoverBan=ban; g_hoverRevoke=rev; g_hoverUpload=upl; g_hoverCheck=chk; g_hoverUnban=unb;
        }
        TRACKMOUSEEVENT t{sizeof(t),TME_LEAVE,hwnd,0}; TrackMouseEvent(&t); return 0;
    }
    case WM_MOUSELEAVE: g_hoverDev=g_hoverExit=g_hoverPrimary=g_hoverAdmin=g_hoverBan=g_hoverRevoke=g_hoverUpload=g_hoverCheck=g_hoverUnban=false; return 0;
    case WM_LBUTTONUP: {
        POINT p{GET_X_LPARAM(lp),GET_Y_LPARAM(lp)}; RECT r{}; GetClientRect(hwnd,&r); 
        int cx = r.right / 2, cy = r.bottom / 2;
        if (Hit(p,r.right-59,10,39,34)) { DestroyWindow(hwnd); return 0; }
        
        if (g_menuTarget) { 
            float cardX = cx - 180.0f, cardY = cy - 120.0f;
            if (Hit(p, (int)(cardX + 10), (int)(cardY + 240 - 40), 80, 30)) { DestroyWindow(hwnd); return 0; }
            if (Hit(p, cx - 60, (int)(cardY + 130), 120, 42)) { LoadAndInject(hwnd); } 
            return 0; 
        }
        
#ifdef NEMESIS_DEV_BUILD
        if (Hit(p,r.right-130,11,62,32)) { ToggleDev(hwnd); return 0; }
        if (g_devUnlocked && Hit(p,r.right-210,11,70,32)) { ToggleAdmin(hwnd); return 0; }
        if (g_adminPanel) { 
            if (Hit(p, 600, 340, 80, 146)) { 
                g_adminList = nemesis::GetInviteList(g_devToken); 
                SetWindowTextW(g_logs, Utf8ToWide(g_adminList).c_str());
                InvalidateRect(g_logs, NULL, TRUE);
                UpdateWindow(g_logs);
                SetStatus(L"BINDS CHECKED"); return 0; 
            }
            if (Hit(p, 510, 340, 80, 146)) { UploadCheat(hwnd); return 0; }
            if (Hit(p, 410, 340, 80, 26)) { 
                wchar_t tok[512]{}; GetWindowTextW(g_revoke_tok, tok, 512);
                if (nemesis::RevokeSpecificInvite(ToUtf8(tok), g_devToken)) { SetStatus(L"TOKEN REVOKED"); g_adminList = nemesis::GetInviteList(g_devToken); SetWindowTextW(g_logs, Utf8ToWide(g_adminList).c_str()); SetWindowTextW(g_revoke_tok, L""); }
                return 0; 
            } 
            if (Hit(p, 410, 400, 80, 26)) { 
                wchar_t ipBuf[64]{}; GetWindowTextW(g_ban_ip, ipBuf, 64);
                if (nemesis::BanIP(ToUtf8(ipBuf), g_devToken)) { SetStatus(L"IP BANNED"); g_adminList = nemesis::GetInviteList(g_devToken); SetWindowTextW(g_logs, Utf8ToWide(g_adminList).c_str()); SetWindowTextW(g_ban_ip, L""); }
                return 0; 
            } 
            if (Hit(p, 410, 460, 80, 26)) { 
                wchar_t ipBuf[64]{}; GetWindowTextW(g_unban_ip, ipBuf, 64);
                if (nemesis::UnbanIP(ToUtf8(ipBuf), g_devToken)) { SetStatus(L"IP UNBANNED"); g_adminList = nemesis::GetInviteList(g_devToken); SetWindowTextW(g_logs, Utf8ToWide(g_adminList).c_str()); SetWindowTextW(g_unban_ip, L""); }
                return 0; 
            } 
            if (Hit(p, 100, 510, 100, 36)) { 
                if (nemesis::RevokeInvites(g_devToken)) { SetStatus(L"ALL INVITES REVOKED"); g_adminList = nemesis::GetInviteList(g_devToken); SetWindowTextW(g_logs, Utf8ToWide(g_adminList).c_str()); } 
                return 0; 
            } 
            if (Hit(p, r.right-200, 510, 100, 36)) { ToggleAdmin(hwnd); return 0; } 
            return 0; 
        }
#endif
        if (!g_adminPanel && !g_menuTarget) {
            if (g_devPanel) {
                if (!g_devUnlocked && Hit(p, cx-105, 366, 210, 48)) { ClickPrimary(hwnd); return 0; }
                if (g_devUnlocked && Hit(p, cx-105, 430, 210, 48)) { ClickPrimary(hwnd); return 0; }
            } else {
                if (Hit(p, cx-90, 366, 180, 48)) { ClickPrimary(hwnd); return 0; }
            }
        }
        return 0;
    }
    case WM_KEYDOWN:
        if (wp==VK_RETURN) { 
            if (g_menuTarget) LoadAndInject(hwnd); 
            else if (!g_adminPanel) ClickPrimary(hwnd); 
            return 0; 
        }
        if (wp==VK_ESCAPE) { DestroyWindow(hwnd); return 0; } break;
    case WM_PASTE: {
        HWND hCtrl = (HWND)lp;
        if (hCtrl == g_invite || hCtrl == g_password) return 0;
        break;
    }
    case WM_SETFOCUS: {
        HWND focused = GetFocus();
        if (focused == g_invite) { ShowCaret(g_invite); }
        else if (focused == g_password) { ShowCaret(g_password); }
        else if (focused == g_days) { ShowCaret(g_days); }
        else if (focused == g_bind_ip) { ShowCaret(g_bind_ip); }
        break;
    }
    case WM_DESTROY: KillTimer(hwnd,1); if (g_invite) DestroyWindow(g_invite); if (g_password) DestroyWindow(g_password); if (g_days) DestroyWindow(g_days); if (g_ban_ip) DestroyWindow(g_ban_ip); if (g_revoke_tok) DestroyWindow(g_revoke_tok); if (g_bind_ip) DestroyWindow(g_bind_ip); if (g_unban_ip) DestroyWindow(g_unban_ip); if (g_logs) DestroyWindow(g_logs); if (g_editFont) DeleteObject(g_editFont); PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd,msg,wp,lp);
}

int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,PWSTR,int show) {
    GdiplusStartupInput gdip; if (GdiplusStartup(&g_gdiplus,&gdip,nullptr)!=Ok) return 1;
    WNDCLASSW wc{}; wc.lpfnWndProc=WindowProc; wc.hInstance=instance; wc.lpszClassName=L"nemesis.dev_LOADER_UI"; wc.hCursor=LoadCursorW(nullptr,IDC_ARROW); wc.hbrBackground=(HBRUSH)GetStockObject(BLACK_BRUSH);
    RegisterClassW(&wc); 
    
    HWND hwnd=CreateWindowExW(WS_EX_COMPOSITED, wc.lpszClassName, L"nemesis.dev Loader", WS_POPUP | WS_MINIMIZEBOX | WS_CLIPCHILDREN, 0,0,800,580,nullptr,nullptr,instance,nullptr);
    
    if (!hwnd) { GdiplusShutdown(g_gdiplus); return 1; }
    int x=(GetSystemMetrics(SM_CXSCREEN)-800)/2; int y=(GetSystemMetrics(SM_CYSCREEN)-580)/2; SetWindowPos(hwnd,nullptr,x,y,800,580,SWP_NOZORDER);
    
    // Фикс белой мерцающей рамки
    const DWORD darkMode = 1;
    DwmSetWindowAttribute(hwnd, 20, &darkMode, sizeof(darkMode)); // DWMWA_USE_IMMERSIVE_DARK_MODE
    COLORREF borderColor = RGB(7, 8, 11);
    DwmSetWindowAttribute(hwnd, 34, &borderColor, sizeof(borderColor)); // DWMWA_BORDER_COLOR (Windows 11)

    ShowWindow(hwnd,show); UpdateWindow(hwnd); MSG message{};
    while(GetMessageW(&message,nullptr,0,0)>0) { TranslateMessage(&message); DispatchMessageW(&message); }
    GdiplusShutdown(g_gdiplus); return (int)message.wParam;
}