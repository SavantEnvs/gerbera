// XML playlist import (WPL / XSPF / ASX): src/content/scripting/xml_playlist.cc + asx_playlist.cc.
// First byte picks the playlist type; the rest is the playlist file, parsed with the playlist's own
// pugixml flags. References to other playlists (ASX ENTRYREF) resolve to "missing" — no file access.
#include "content/scripting/xml_playlist.h"

#include <pugixml.hpp>
#include <spdlog/spdlog.h>
#include <cstdint>
#include <exception>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static bool init = (spdlog::set_level(spdlog::level::off), true);
    (void)init;
    if (size < 1)
        return -1;
    const XmlPlaylistType types[] = { XmlPlaylistType::Wpl, XmlPlaylistType::Xspf, XmlPlaylistType::Asx };
    auto type = types[data[0] % 3];
    try {
        auto pl = XmlPlaylist::create(type, [](const std::string& href, const fs::path&) {
            XmlPlaylist::Document doc;
            doc.warning = "missing " + href;
            return doc;
        });
        pugi::xml_document doc;
        if (!doc.load_buffer(data + 1, size - 1, pl->getParseFlags()))
            return 0;
        const char* name = type == XmlPlaylistType::Wpl ? "/tmp/fuzz.wpl" : type == XmlPlaylistType::Xspf ? "/tmp/fuzz.xspf" : "/tmp/fuzz.asx";
        pl->read(doc, name);
        int n = 0;
        while (pl->readPlaylistEntry() && ++n < 100000) { }
    } catch (const std::exception&) {
    }
    return 0;
}
