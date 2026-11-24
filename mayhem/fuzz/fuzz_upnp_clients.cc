// HTTP request identity from any LAN client, before authentication: the client's address, its
// User-Agent and its request headers, as libupnp hands them to gerbera in a UpnpFileInfo.
// Headers(fileInfo) reads the header list (src/upnp/headers.cc, UpnpGetHeadersCompat in
// src/upnp/compat.cc), then Quirks -> ClientManager::getInfo (src/upnp/client_manager.cc) matches
// address and User-Agent against the built-in and configured client profiles, the way every UPnP
// action and file request does. Fixture after test/util/test_upnp_clients.cc (UpnpClientsTest).
//
// Input: byte 0 = flags (bit0: IPv6 client, bit1: headers as raw "Name: value" lines, libupnp's
// `resp` form, instead of name/value pairs), then the 4 or 16 address bytes, then text split on
// '\n': line 0 = User-Agent of the action request, line 1 = User-Agent of a later file request
// from the same address (the cache path), the rest = request header lines.
//
// State: the Config mock and its client list are built once and only read. A new ClientManager
// (with its client cache) is created for every input, so no client seen earlier is remembered.
#include "config/config_val.h"
#include "config/result/client_config.h"
#include "upnp/client_manager.h"
#include "upnp/clients.h"
#include "upnp/headers.h"
#include "upnp/quirks.h"
#include "util/grb_net.h"

#include "mock/config_mock.h"

#include <UpnpExtraHeaders.h>
#include <arpa/inet.h>
#include <gmock/gmock.h>
#include <netinet/in.h>
#include <spdlog/spdlog.h>

#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <string>
#include <vector>

namespace {

class FuzzConfigMock : public ConfigMock {
public:
    FuzzConfigMock() { list = std::make_shared<ClientConfigList>(); }
    std::shared_ptr<ClientConfigList> getClientConfigListOption(ConfigVal option) const override { return list; }
    long long getLongOption(ConfigVal option) const override
    {
        return option == ConfigVal::CLIENTS_CACHE_THRESHOLD ? 1 : ConfigMock::getLongOption(option);
    }
    std::shared_ptr<ClientConfigList> list;
};

std::shared_ptr<Config> makeConfig()
{
    auto config = std::make_shared<::testing::NiceMock<FuzzConfigMock>>();
    auto edit = EDIT_CAST(EditHelperClientConfig, config->list);
    // as in UpnpClientsTest: one host and one IPv4 range, plus an IPv6 range and a User-Agent match
    edit->add(std::make_shared<ClientConfig>(123, "default", "192.168.1.100", "added by config",
                  std::map<ClientMatchType, std::string>(), 1, -1, false, true),
        0);
    edit->add(std::make_shared<ClientConfig>(456, "range", "192.168.2.0/24", "added by config",
                  std::map<ClientMatchType, std::string>(), 1, -1, false, true),
        1);
    edit->add(std::make_shared<ClientConfig>(789, "v6", "fe80::/64", "added by config",
                  std::map<ClientMatchType, std::string>(), 2, 100, true, false),
        2);
    edit->add(std::make_shared<ClientConfig>(0x11, "ua", "", "Fuzz-Renderer/",
                  std::map<ClientMatchType, std::string>(), 1, 32, true, true),
        3);
    return config;
}

std::vector<std::string> splitLines(const char* p, size_t n)
{
    std::vector<std::string> out;
    std::string cur;
    for (size_t i = 0; i < n; i++) {
        if (p[i] == '\n') {
            out.push_back(std::move(cur));
            cur.clear();
        } else {
            cur.push_back(p[i]);
        }
    }
    out.push_back(std::move(cur));
    return out;
}

void addExtraHeader(UpnpFileInfo* info, const std::string& line, bool rawLine)
{
    auto head = const_cast<UpnpListHead*>(UpnpFileInfo_get_ExtraHeadersList(info));
    UpnpExtraHeaders* h = UpnpExtraHeaders_new();
    if (rawLine) {
        UpnpExtraHeaders_set_resp(h, line.c_str());
    } else {
        auto colon = line.find(':');
        std::string name = line.substr(0, colon);
        std::string value = colon == std::string::npos ? "" : line.substr(colon + 1);
        UpnpExtraHeaders_strcpy_name(h, name.c_str());
        UpnpExtraHeaders_strcpy_value(h, value.c_str());
    }
    UpnpListInsert(head, UpnpListEnd(head), const_cast<UpnpListHead*>(UpnpExtraHeaders_get_node(h)));
}

void freeExtraHeaders(UpnpFileInfo* info)
{
    auto head = const_cast<UpnpListHead*>(UpnpFileInfo_get_ExtraHeadersList(info));
    for (auto pos = UpnpListBegin(head); pos != UpnpListEnd(head);) {
        auto next = UpnpListErase(head, pos);
        UpnpExtraHeaders_delete(reinterpret_cast<UpnpExtraHeaders*>(pos));
        pos = next;
    }
}

constexpr Quirk allQuirks[] = {
    Quirk::Samsung, Quirk::SamsungBookmarkSeconds, Quirk::SamsungBookmarkMilliSeconds,
    Quirk::NoXmlDeclaration, Quirk::SamsungFeatures, Quirk::SamsungHideDynamic, Quirk::PvSubtitles,
    Quirk::StrictXML, Quirk::HideResourceThumbnail, Quirk::HideResourceSubtitle,
    Quirk::HideResourceTranscode, Quirk::SimpleDate, Quirk::DCM10, Quirk::HideContainerShortcuts,
    Quirk::AsciiXML, Quirk::ForceNoConversion, Quirk::ShowInternalSubtitles,
    Quirk::ForceSortCriteriaTitle, Quirk::CaptionProtocol, Quirk::NoSecNamespace,
    Quirk::NoSortExtensionCapabilities,
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static bool init = (spdlog::set_level(spdlog::level::off), true);
    (void)init;
    static const std::shared_ptr<Config> config = makeConfig();

    if (size < 1)
        return -1;
    const bool v6 = data[0] & 1;
    const bool rawLines = data[0] & 2;
    const size_t alen = v6 ? 16 : 4;
    if (size < 1 + alen)
        return -1;

    struct sockaddr_storage ss = {};
    if (v6) {
        auto sin6 = reinterpret_cast<struct sockaddr_in6*>(&ss);
        sin6->sin6_family = AF_INET6;
        std::memcpy(&sin6->sin6_addr, data + 1, 16);
    } else {
        auto sin = reinterpret_cast<struct sockaddr_in*>(&ss);
        sin->sin_family = AF_INET;
        std::memcpy(&sin->sin_addr, data + 1, 4);
    }
    auto addr = std::make_shared<GrbNet>(&ss);

    auto lines = splitLines(reinterpret_cast<const char*>(data + 1 + alen), size - 1 - alen);
    const std::string actionUA = lines[0];
    const std::string fileUA = lines.size() > 1 ? lines[1] : std::string();

    UpnpFileInfo* info = UpnpFileInfo_new();
    for (size_t i = 2; i < lines.size(); i++)
        addExtraHeader(info, lines[i], rawLines);

    try {
        auto clientManager = std::make_shared<ClientManager>(config, nullptr, nullptr);
        auto headers = std::make_shared<Headers>(info);

        // UPnP action request: identify the client, then ask the quirks what it supports
        Quirks quirks(nullptr, clientManager, addr, actionUA, headers);
        for (auto q : allQuirks)
            (void)quirks.hasFlag(q);
        (void)quirks.getGroup();
        (void)quirks.isAllowed();
        (void)quirks.getCaptionInfoCount();
        (void)quirks.getStringLimit();
        (void)quirks.getMultiValue();
        (void)quirks.getFullFilter();
        (void)quirks.getMimeMappings();
        (void)quirks.getDlnaMappings();
        (void)quirks.hasHeader("getCaptionInfo.sec", "1");
        (void)quirks.hasHeader("transferMode.dlna.org", "Streaming");
        (void)headers->getHeader("User-Agent");
        (void)headers->getHeader("range");

        // later file request from the same address, without headers: served from the cache
        Quirks fileQuirks(nullptr, clientManager, addr, fileUA, nullptr);
        (void)fileQuirks.getGroup();
        (void)fileQuirks.hasHeader("getCaptionInfo.sec", "1");

        // response: client-profile headers plus the request's own, written back to libupnp
        Headers response;
        quirks.updateHeaders(response);
        for (auto&& [key, value] : headers->getHeaders()) {
            response.addHeader(key, value);
            response.updateHeader(value, key);
        }
        UpnpFileInfo* out = UpnpFileInfo_new();
        response.writeHeaders(out);
        (void)Headers(out).getHeaders();
        freeExtraHeaders(out);
        UpnpFileInfo_delete(out);

        // web UI client list, then the admin removes the entry
        for (auto&& obs : clientManager->getClientList())
            (void)(obs.addr ? obs.addr->getNameInfo(false) : std::string());
        clientManager->removeClient(addr->getNameInfo(false), actionUA);
    } catch (const std::exception&) {
    }

    freeExtraHeaders(info);
    UpnpFileInfo_delete(info);
    return 0;
}
