// HTTP request strings from LAN clients: URL/query/path decoding helpers every request handler uses
// (src/util/url_utils.cc, src/util/tools.cc).
#include "util/tools.h"
#include "util/url_utils.h"

#include <spdlog/spdlog.h>
#include <cstdint>
#include <exception>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static bool init = (spdlog::set_level(spdlog::level::off), true);
    (void)init;
    std::string s(reinterpret_cast<const char*>(data), size);
    try {
        (void)URLUtils::dictDecode(s);
        (void)URLUtils::dictDecode(s, false);
        (void)URLUtils::pathToMap(s);
        (void)URLUtils::parseParameters(s, "/content/media");
        (void)URLUtils::urlUnescape(s);
        (void)URLUtils::urlUnescape(s, URLUtils::UrlMode::FilePath);
        (void)URLUtils::getQuery(s);
        (void)URLUtils::getFile(s);
        (void)URLUtils::splitUrl(s, '?');
        (void)hexDecodeString(s);
        (void)getValidUTF8CutPosition(s, static_cast<ssize_t>(size / 2));
        auto nl = s.find('\n');
        if (nl != std::string::npos)
            (void)URLUtils::resolveUriReference(s.substr(nl + 1), s.substr(0, nl));
    } catch (const std::exception&) {
    }
    return 0;
}
