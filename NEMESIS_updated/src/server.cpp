#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <cstdlib>
#include <fstream>
#include <wincrypt.h>
#include <algorithm>
#include <cctype>
#include "sqlite3.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

sqlite3* db = nullptr;
struct DevSession { std::string token; std::string ip; };
std::vector<DevSession> g_devSessions;
std::string g_devPasswordHash;

std::string GenerateRandomHex(size_t bytes) {
    HCRYPTPROV provider = 0;
    if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "[ERROR] Secure random provider unavailable.\n"; exit(1);
    }
    std::vector<BYTE> random(bytes);
    if (!CryptGenRandom(provider, static_cast<DWORD>(random.size()), random.data())) {
        CryptReleaseContext(provider, 0);
        std::cerr << "[ERROR] Secure random generation failed.\n"; exit(1);
    }
    CryptReleaseContext(provider, 0);
    constexpr char hex[] = "0123456789abcdef";
    std::string out; out.reserve(bytes * 2);
    for (BYTE b : random) { out.push_back(hex[b >> 4]); out.push_back(hex[b & 15]); }
    SecureZeroMemory(random.data(), random.size());
    return out;
}

std::string Sha256Hex(const std::string& value) {
    HCRYPTPROV provider = 0; HCRYPTHASH hash = 0;
    BYTE digest[32]{}; DWORD size = sizeof(digest);
    if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return {};
    bool ok = CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash) &&
              CryptHashData(hash, reinterpret_cast<const BYTE*>(value.data()), static_cast<DWORD>(value.size()), 0) &&
              CryptGetHashParam(hash, HP_HASHVAL, digest, &size, 0) && size == sizeof(digest);
    if (hash) CryptDestroyHash(hash);
    CryptReleaseContext(provider, 0);
    if (!ok) return {};
    constexpr char hex[] = "0123456789abcdef";
    std::string out; out.reserve(64);
    for (BYTE b : digest) { out.push_back(hex[b >> 4]); out.push_back(hex[b & 15]); }
    SecureZeroMemory(digest, sizeof(digest));
    return out;
}

bool EqualHash(const std::string& a, const std::string& b) {
    if (a.size() != 64 || b.size() != 64) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < 64; ++i) diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0;
}

std::string Base64Decode(const std::string& encoded) {
    DWORD needed = 0;
    if (!CryptStringToBinaryA(encoded.c_str(), (DWORD)encoded.length(), CRYPT_STRING_BASE64, nullptr, &needed, nullptr, nullptr)) return "";
    std::string out(needed, '\0');
    if (!CryptStringToBinaryA(encoded.c_str(), (DWORD)encoded.length(), CRYPT_STRING_BASE64, (BYTE*)out.data(), &needed, nullptr, nullptr)) return "";
    out.resize(needed); return out;
}

std::string GetParam(const std::string& req, const std::string& param) {
    size_t pos = req.find(param + "=");
    if (pos == std::string::npos) return "";
    pos += param.length() + 1;
    size_t end = req.find("&", pos);
    if (end == std::string::npos) end = req.find(" ", pos);
    if (end == std::string::npos) return req.substr(pos);
    return req.substr(pos, end - pos);
}

bool CheckDevToken(const std::string& token, const std::string& clientIp) {
    for (const auto& sess : g_devSessions) if (sess.token == token && sess.ip == clientIp) return true;
    return false;
}

void InitDb() {
    int rc = sqlite3_open("database.db", &db);
    if (rc) { std::cerr << "Can't open database.\n"; exit(1); }
    const char* sql = "CREATE TABLE IF NOT EXISTS invites (token TEXT PRIMARY KEY, expiry INTEGER, revoked INTEGER, bound_ip TEXT DEFAULT '', bound_hwid TEXT DEFAULT '');"
                      "CREATE TABLE IF NOT EXISTS bans (ip TEXT PRIMARY KEY);";
    char* errMsg = nullptr; sqlite3_exec(db, sql, nullptr, nullptr, &errMsg); if (errMsg) sqlite3_free(errMsg);
}

bool CheckAuth(const std::string& token, const std::string& clientIp, const std::string& clientHwid, std::string& res) {
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM bans WHERE ip = ?;", -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, clientIp.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) { res = "BANNED"; sqlite3_finalize(stmt); return false; }
        sqlite3_finalize(stmt);
    }
    if (sqlite3_prepare_v2(db, "SELECT expiry, revoked, bound_ip, bound_hwid FROM invites WHERE token = ?;", -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            unsigned long long expiry = sqlite3_column_int64(stmt, 0);
            int revoked = sqlite3_column_int(stmt, 1);
            std::string boundIp = (const char*)sqlite3_column_text(stmt, 2);
            std::string boundHwid = (const char*)sqlite3_column_text(stmt, 3);
            
            if (revoked) res = "REVOKED";
            else if (expiry != 0 && expiry < (unsigned long long)time(nullptr)) res = "EXPIRED";
            else if (boundIp.empty() || boundIp == clientIp) {
                if (boundHwid.empty()) {
                    sqlite3_stmt* up; 
                    if (sqlite3_prepare_v2(db, "UPDATE invites SET bound_hwid = ? WHERE token = ?;", -1, &up, nullptr) == SQLITE_OK) {
                        sqlite3_bind_text(up, 1, clientHwid.c_str(), -1, SQLITE_STATIC); sqlite3_bind_text(up, 2, token.c_str(), -1, SQLITE_STATIC);
                        sqlite3_step(up); sqlite3_finalize(up);
                    }
                } else if (boundHwid != clientHwid) { res = "HWID_MISMATCH"; sqlite3_finalize(stmt); return false; }
                if (boundIp.empty()) {
                    sqlite3_stmt* up; 
                    if (sqlite3_prepare_v2(db, "UPDATE invites SET bound_ip = ? WHERE token = ?;", -1, &up, nullptr) == SQLITE_OK) {
                        sqlite3_bind_text(up, 1, clientIp.c_str(), -1, SQLITE_STATIC); sqlite3_bind_text(up, 2, token.c_str(), -1, SQLITE_STATIC);
                        sqlite3_step(up); sqlite3_finalize(up);
                    }
                }
                res = "OK";
            }
            else res = "WRONG_IP";
            sqlite3_finalize(stmt); return res == "OK";
        }
        sqlite3_finalize(stmt);
    }
    res = "NOT_FOUND"; return false;
}

int main() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "====================================\n";
    std::cout << "      NEMESIS.DEV SERVER START      \n";
    std::cout << "====================================\n";
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    InitDb();
    std::string password = GenerateRandomHex(16);
    g_devPasswordHash = Sha256Hex(password);
    if (g_devPasswordHash.empty()) { std::cerr << "[ERROR] SHA-256 initialization failed.\n"; return 1; }
    std::cout << "[!] Temporary admin password (changes on every restart): " << password << "\n";
    std::cout << "[!] Keep this console private.\n";
    SecureZeroMemory(password.data(), password.size()); password.clear();
    WSADATA wsaData; WSAStartup(MAKEWORD(2, 2), &wsaData);
    SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = INADDR_ANY; addr.sin_port = htons(8080);

    if (bind(server, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) { return 1; }
    listen(server, SOMAXCONN);
    std::cout << "[+] Server running on port 8080...\n";

    while (true) {
        sockaddr_in clientAddr{}; int addrLen = sizeof(clientAddr);
        SOCKET client = accept(server, (sockaddr*)&clientAddr, &addrLen);
        std::string clientIp = inet_ntoa(clientAddr.sin_addr);
        
        std::string req; char buffer[8192]; int bytes;
        size_t contentLength = 0;
        bool headersParsed = false;
        
        // ИСПРАВЛЕНО: Читаем запрос полностью, учитывая Content-Length для POST
        while ((bytes = recv(client, buffer, sizeof(buffer), 0)) > 0) {
            req.append(buffer, bytes);
            
            if (!headersParsed) {
                size_t headerEnd = req.find("\r\n\r\n");
                if (headerEnd != std::string::npos) {
                    headersParsed = true;
                    std::string headers = req.substr(0, headerEnd);
                    size_t clPos = headers.find("Content-Length: ");
                    if (clPos != std::string::npos) {
                        contentLength = std::stoul(headers.substr(clPos + 16, headers.find("\r\n", clPos) - (clPos + 16)));
                    }
                }
            }
            if (headersParsed) {
                size_t headerEnd = req.find("\r\n\r\n");
                if (req.length() >= headerEnd + 4 + contentLength) {
                    break;
                }
            }
        }

        if (!req.empty()) {
            std::string firstLine = req.substr(0, req.find("\r\n"));
            size_t queryPos = firstLine.find('?');
            if (queryPos != std::string::npos) firstLine = firstLine.substr(0, queryPos) + "?[redacted]";
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << "[" << clientIp << "] " << firstLine << "\n";
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

            std::string response = "HTTP/1.1 200 OK\r\nContent-Length: ";
            
            if (req.find("GET /autoban") != std::string::npos) {
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO bans (ip) VALUES (?);", -1, &stmt, nullptr) == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, clientIp.c_str(), -1, SQLITE_STATIC); sqlite3_step(stmt); sqlite3_finalize(stmt);
                }
                response += "2\r\n\r\nOK";
            }
            else if (req.find("GET /dev_login?hash=") != std::string::npos) {
                std::string hash = GetParam(req, "hash");
                if (EqualHash(hash, g_devPasswordHash)) {
                    std::string token = "DEV-" + GenerateRandomHex(16);
                    g_devSessions.push_back({token, clientIp});
                    std::string res = "OK:" + token;
                    response += std::to_string(res.length()) + "\r\n\r\n" + res;
                } else response += "4\r\n\r\nFAIL";
            }
            else if (req.find("GET /dev_heartbeat?devtoken=") != std::string::npos) {
                std::string devToken = GetParam(req, "devtoken");
                const std::string res = CheckDevToken(devToken, clientIp) ? "OK" : "NO_AUTH";
                response += std::to_string(res.size()) + "\r\n\r\n" + res;
            }
            else if (req.find("GET /verify?token=") != std::string::npos) {
                std::string token = GetParam(req, "token");
                std::string hwid = GetParam(req, "hwid");
                std::string res; CheckAuth(token, clientIp, hwid, res);
                if (res == "OK") res = "OK:" + GenerateRandomHex(16);
                response += std::to_string(res.length()) + "\r\n\r\n" + res;
            } 
            else if (req.find("GET /download_dll?token=") != std::string::npos) {
                std::string token = GetParam(req, "token");
                std::string hwid = GetParam(req, "hwid");
                std::string res; CheckAuth(token, clientIp, hwid, res);
                if (res == "OK") {
                    std::ifstream dll("cheat.dll", std::ios::binary);
                    if (dll.is_open()) {
                        std::string dllData((std::istreambuf_iterator<char>(dll)), std::istreambuf_iterator<char>());
                        response = "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(dllData.length()) + "\r\n\r\n" + dllData;
                        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                        std::cout << "  -> Sent DLL (" << dllData.length() << " bytes)\n";
                    } else response += "5\r\n\r\nNO_DLL";
                } else response += std::to_string(res.length()) + "\r\n\r\n" + res;
            }
            else if (req.find("POST /upload_dll") != std::string::npos) {
                std::string devToken = GetParam(req, "devtoken");
                if (!CheckDevToken(devToken, clientIp)) {
                    response += "7\r\n\r\nNO_AUTH"; send(client, response.c_str(), (int)response.length(), 0); closesocket(client); continue;
                }
                
                size_t bodyPos = req.find("\r\n\r\n");
                if (bodyPos != std::string::npos) {
                    std::string b64 = req.substr(bodyPos + 4);
                    // Удаляем возможные пробелы и переносы строк из конца
                    b64.erase(std::remove_if(b64.begin(), b64.end(), [](unsigned char c) { return std::isspace(c); }), b64.end());
                    
                    std::string dllData = Base64Decode(b64);
                    std::ofstream out("cheat.dll", std::ios::binary);
                    out.write(dllData.data(), dllData.size());
                    out.close();
                    
                    response += "2\r\n\r\nOK";
                    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    std::cout << "  -> Uploaded DLL (" << dllData.length() << " bytes)\n";
                } else {
                    response += "4\r\n\r\nFAIL";
                }
            }
            else if (req.find("GET /generate?days=") != std::string::npos) {
                std::string daysStr = GetParam(req, "days");
                std::string devToken = GetParam(req, "devtoken");
                std::string bindIp = GetParam(req, "bindip");

                if (!CheckDevToken(devToken, clientIp)) {
                    response += "7\r\n\r\nNO_AUTH"; send(client, response.c_str(), (int)response.length(), 0); closesocket(client); continue;
                }
                unsigned long long days = std::stoull(daysStr);
                unsigned long long expiry = days == 0 ? 0 : (unsigned long long)time(nullptr) + 86400ULL * days;
                
                std::string token = "nemesis-" + GenerateRandomHex(16);
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "INSERT INTO invites (token, expiry, revoked, bound_ip) VALUES (?, ?, 0, ?);", -1, &stmt, nullptr) == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_STATIC); 
                    sqlite3_bind_int64(stmt, 2, expiry);
                    sqlite3_bind_text(stmt, 3, bindIp.c_str(), -1, SQLITE_STATIC);
                    sqlite3_step(stmt); sqlite3_finalize(stmt);
                }
                std::string res = "OK:" + token;
                response += std::to_string(res.length()) + "\r\n\r\n" + res;
            }
            else if (req.find("GET /revokespecific?token=") != std::string::npos) {
                std::string devToken = GetParam(req, "devtoken");
                if (!CheckDevToken(devToken, clientIp)) {
                    response += "7\r\n\r\nNO_AUTH"; send(client, response.c_str(), (int)response.length(), 0); closesocket(client); continue;
                }
                std::string token = GetParam(req, "token");
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "UPDATE invites SET revoked = 1 WHERE token = ?;", -1, &stmt, nullptr) == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_STATIC); sqlite3_step(stmt); sqlite3_finalize(stmt);
                }
                response += "2\r\n\r\nOK";
            }
            else if (req.find("GET /revokeall") != std::string::npos) {
                std::string devToken = GetParam(req, "devtoken");
                if (!CheckDevToken(devToken, clientIp)) {
                    response += "7\r\n\r\nNO_AUTH"; send(client, response.c_str(), (int)response.length(), 0); closesocket(client); continue;
                }
                sqlite3_exec(db, "UPDATE invites SET revoked = 1;", nullptr, nullptr, nullptr);
                response += "2\r\n\r\nOK";
            }
            else if (req.find("GET /ban?ip=") != std::string::npos) {
                std::string devToken = GetParam(req, "devtoken");
                if (!CheckDevToken(devToken, clientIp)) {
                    response += "7\r\n\r\nNO_AUTH"; send(client, response.c_str(), (int)response.length(), 0); closesocket(client); continue;
                }
                std::string ip = GetParam(req, "ip");
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO bans (ip) VALUES (?);", -1, &stmt, nullptr) == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_STATIC); sqlite3_step(stmt); sqlite3_finalize(stmt);
                }
                response += "2\r\n\r\nOK";
            }
            else if (req.find("GET /unban?ip=") != std::string::npos) {
                std::string devToken = GetParam(req, "devtoken");
                if (!CheckDevToken(devToken, clientIp)) {
                    response += "7\r\n\r\nNO_AUTH"; send(client, response.c_str(), (int)response.length(), 0); closesocket(client); continue;
                }
                std::string ip = GetParam(req, "ip");
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "DELETE FROM bans WHERE ip = ?;", -1, &stmt, nullptr) == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_STATIC); sqlite3_step(stmt); sqlite3_finalize(stmt);
                }
                response += "2\r\n\r\nOK";
            }
            else if (req.find("GET /list") != std::string::npos) {
                std::string devToken = GetParam(req, "devtoken");
                if (!CheckDevToken(devToken, clientIp)) {
                    response += "7\r\n\r\nNO_AUTH"; send(client, response.c_str(), (int)response.length(), 0); closesocket(client); continue;
                }
                std::string listStr = "";
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "SELECT token, bound_ip, revoked FROM invites;", -1, &stmt, nullptr) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        std::string tok = (const char*)sqlite3_column_text(stmt, 0);
                        std::string ip = (const char*)sqlite3_column_text(stmt, 1);
                        int rev = sqlite3_column_int(stmt, 2);
                        if (ip.empty()) ip = "unbound";
                        listStr += (rev ? "[REVOKED] " : "[ACTIVE] ") + ip + " -> " + tok + "\r\n";
                    }
                    sqlite3_finalize(stmt);
                }
                if (listStr.empty()) listStr = "No invites.";
                response += std::to_string(listStr.length()) + "\r\n\r\n" + listStr;
            }
            else { response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"; }
            send(client, response.c_str(), (int)response.length(), 0);
        }
        closesocket(client);
    }
    sqlite3_close(db); WSACleanup(); return 0;
}