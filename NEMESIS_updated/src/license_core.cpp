#define WIN32_LEAN_AND_MEAN
#include "license_core.h"
#include <windows.h>
#include <string>
#include <vector>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

namespace {
    const char* SERVER_IP = "26.112.49.228"; 
    const int SERVER_PORT = 8080;

    std::string BuildVerifyString() {
        char c1 = 'v' + 1; char c2 = 'e' - 1; char c3 = 'r' + 2; char c4 = 'i' - 2; char c5 = 'f'; 
        char c6 = 'y' - 1; char c7 = '?'; char c8 = 't'; char c9 = 'o' + 1; char c10 = 'k' - 1; char c11 = 'e'; char c12 = 'n'; char c13 = '='; 
        return std::string() + (char)(c1-1) + (char)(c2+1) + (char)(c3-2) + (char)(c4+2) + c5 + (char)(c6+1) + c7 + c8 + (char)(c9-1) + (char)(c10+1) + c11 + c12 + c13;
    }
    std::string BuildDownloadString() { return "download_dll?token="; }

    typedef int (WSAAPI* pWSAStartup)(WORD, LPWSADATA);
    typedef SOCKET (WSAAPI* psocket)(int, int, int);
    typedef int (WSAAPI* pconnect)(SOCKET, const struct sockaddr*, int);
    typedef int (WSAAPI* psend)(SOCKET, const char*, int, int);
    typedef int (WSAAPI* precv)(SOCKET, char*, int, int);
    typedef int (WSAAPI* pclosesocket)(SOCKET);
    typedef int (WSAAPI* pWSACleanup)();
    typedef int (WSAAPI* pioctlsocket)(SOCKET, long, u_long*);
    typedef int (WSAAPI* pselect)(int, fd_set*, fd_set*, fd_set*, const struct timeval*);
    typedef int (WSAAPI* psetsockopt)(SOCKET, int, int, const char*, int);
    typedef int (WSAAPI* pgetaddrinfo)(const char*, const char*, const struct addrinfo*, struct addrinfo**);
    typedef void (WSAAPI* pfreeaddrinfo)(struct addrinfo*);

    // ДОБАВЛЕН ПАРАМЕТР postBody
    std::string SendHttpRequest(const std::string& path, bool isBinary = false, std::vector<unsigned char>* outBin = nullptr, const std::string& postBody = "") {
        HMODULE hWs2 = LoadLibraryA("ws2_32.dll");
        if (!hWs2) return "";

        auto _WSAStartup = (pWSAStartup)GetProcAddress(hWs2, "WSAStartup");
        auto _socket = (psocket)GetProcAddress(hWs2, "socket");
        auto _connect = (pconnect)GetProcAddress(hWs2, "connect");
        auto _send = (psend)GetProcAddress(hWs2, "send");
        auto _recv = (precv)GetProcAddress(hWs2, "recv");
        auto _closesocket = (pclosesocket)GetProcAddress(hWs2, "closesocket");
        auto _WSACleanup = (pWSACleanup)GetProcAddress(hWs2, "WSACleanup");
        auto _ioctlsocket = (pioctlsocket)GetProcAddress(hWs2, "ioctlsocket");
        auto _select = (pselect)GetProcAddress(hWs2, "select");
        auto _setsockopt = (psetsockopt)GetProcAddress(hWs2, "setsockopt");
        auto _getaddrinfo = (pgetaddrinfo)GetProcAddress(hWs2, "getaddrinfo");
        auto _freeaddrinfo = (pfreeaddrinfo)GetProcAddress(hWs2, "freeaddrinfo");

        WSADATA wsaData; if (_WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return "";
        SOCKET sock = _socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) { _WSACleanup(); return ""; }

        struct addrinfo hints = {}, *result = nullptr;
        hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        if (_getaddrinfo(SERVER_IP, std::to_string(SERVER_PORT).c_str(), &hints, &result) != 0) { _closesocket(sock); _WSACleanup(); return ""; }

        u_long mode = 1; _ioctlsocket(sock, FIONBIO, &mode);
        _connect(sock, result->ai_addr, (int)result->ai_addrlen);
        fd_set fdset; FD_ZERO(&fdset); FD_SET(sock, &fdset);
        timeval tv = {5, 0}; 
        if (_select(0, NULL, &fdset, NULL, &tv) <= 0) { _freeaddrinfo(result); _closesocket(sock); _WSACleanup(); return ""; }
        mode = 0; _ioctlsocket(sock, FIONBIO, &mode);
        _freeaddrinfo(result);

        DWORD timeout = 5000; _setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        
        std::string req;
        if (!postBody.empty()) {
            req = "POST /" + path + " HTTP/1.1\r\nHost: " + SERVER_IP + "\r\nContent-Length: " + std::to_string(postBody.length()) + "\r\nConnection: close\r\n\r\n" + postBody;
        } else {
            req = "GET /" + path + " HTTP/1.1\r\nHost: " + SERVER_IP + "\r\nConnection: close\r\n\r\n";
        }

        // Цикл отправки для больших файлов (DLL)
        size_t totalSent = 0;
        while (totalSent < req.length()) {
            int sent = _send(sock, req.c_str() + totalSent, (int)(req.length() - totalSent), 0);
            if (sent <= 0) break;
            totalSent += sent;
        }

        std::string response; char buffer[4096]; int bytesRead;
        while ((bytesRead = _recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) { buffer[bytesRead] = '\0'; response.append(buffer, bytesRead); }
        _closesocket(sock); _WSACleanup();

        size_t headerEnd = response.find("\r\n\r\n");
        if (headerEnd != std::string::npos) {
            if (isBinary && outBin) { outBin->assign(response.begin() + headerEnd + 4, response.end()); return ""; }
            return response.substr(headerEnd + 4);
        }
        return "";
    }
}

namespace nemesis {
    InviteResult VerifyInvite(const std::string& token, const std::string& hwid) {
        std::string res = SendHttpRequest(BuildVerifyString() + token + "&hwid=" + hwid); 
        if (res.rfind("OK:", 0) == 0) return {true, "Invite accepted", res.substr(3)};
        if (res == "REVOKED") return {false, "Invite revoked by admin", ""};
        if (res == "EXPIRED") return {false, "Invite expired", ""};
        if (res == "BANNED") return {false, "Your IP is banned", ""};
        if (res == "WRONG_IP") return {false, "Invite bound to another IP", ""};
        if (res == "HWID_MISMATCH") return {false, "HWID mismatch", ""};
        return {false, "Server rejected token", ""};
    }

    std::vector<unsigned char> DownloadDLL(const std::string& token, const std::string& hwid) {
        std::vector<unsigned char> dllData;
        SendHttpRequest(BuildDownloadString() + token + "&hwid=" + hwid, true, &dllData);
        return dllData;
    }

    void ReportDebugger() { SendHttpRequest("autoban"); }
    void ReportClientPatch() { SendHttpRequest("autoban"); }

#ifdef NEMESIS_DEV_BUILD
    bool ServerLogin(const std::string& passwordHash, std::string& outToken) {
        std::string res = SendHttpRequest("dev_login?hash=" + passwordHash);
        if (res.rfind("OK:", 0) == 0) { outToken = res.substr(3); return true; }
        return false;
    }
    
    bool CheckDevSession(const std::string& devToken) { return SendHttpRequest("dev_heartbeat?devtoken=" + devToken) == "OK"; }

    GenerateResult GenerateInvite(unsigned days, const std::string& devToken, const std::string& bindIp) {
        std::string url = "generate?days=" + std::to_string(days) + "&devtoken=" + devToken;
        if (!bindIp.empty()) url += "&bindip=" + bindIp;
        std::string res = SendHttpRequest(url);
        if (res.rfind("OK:", 0) == 0) return {true, res.substr(3), "Invite generated"};
        return {false, {}, "Server failed"};
    }
    
    bool RevokeInvites(const std::string& devToken) { return SendHttpRequest("revokeall?devtoken=" + devToken) == "OK"; }
    bool RevokeSpecificInvite(const std::string& token, const std::string& devToken) { return SendHttpRequest("revokespecific?token=" + token + "&devtoken=" + devToken) == "OK"; }
    bool BanIP(const std::string& ip, const std::string& devToken) { return SendHttpRequest("ban?ip=" + ip + "&devtoken=" + devToken) == "OK"; }
    bool UnbanIP(const std::string& ip, const std::string& devToken) { return SendHttpRequest("unban?ip=" + ip + "&devtoken=" + devToken) == "OK"; }
    std::string GetInviteList(const std::string& devToken) { return SendHttpRequest("list?devtoken=" + devToken); }
    
    // ИСПРАВЛЕНО: Теперь передаем b64Data как тело POST-запроса
    bool UploadDLLToServer(const std::string& b64Data, const std::string& devToken) {
        return SendHttpRequest("upload_dll?devtoken=" + devToken, false, nullptr, b64Data) == "OK";
    }
#endif
}