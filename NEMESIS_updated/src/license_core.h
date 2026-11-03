#pragma once
#include <string>
#include <vector>

namespace nemesis {
    struct InviteResult { bool ok = false; std::string reason; std::string sessionKey; };
    struct GenerateResult { bool ok = false; std::string token; std::string reason; };

    InviteResult VerifyInvite(const std::string& token, const std::string& hwid);
    std::vector<unsigned char> DownloadDLL(const std::string& token, const std::string& hwid);
    void ReportDebugger();
    void ReportClientPatch();
    
#ifdef NEMESIS_DEV_BUILD
    bool ServerLogin(const std::string& passwordHash, std::string& outToken);
    bool CheckDevSession(const std::string& devToken);
    GenerateResult GenerateInvite(unsigned days, const std::string& devToken, const std::string& bindIp);
    bool RevokeInvites(const std::string& devToken);
    bool RevokeSpecificInvite(const std::string& token, const std::string& devToken);
    bool BanIP(const std::string& ip, const std::string& devToken);
    bool UnbanIP(const std::string& ip, const std::string& devToken); // <--- ДОБАВЛЕНО
    std::string GetInviteList(const std::string& devToken);
    bool UploadDLLToServer(const std::string& b64Data, const std::string& devToken);
#endif
}