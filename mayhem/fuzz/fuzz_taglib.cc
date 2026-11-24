// Media import: audio tags via TagLib (taglib_handler.cc per-format extractors, artwork, BPM, aux tags).
// The first input byte picks the format (file extension + mime, as the importer's mime mapping would);
// the rest is the file. The scanned file is attacker-controlled.
#include "metadata_fixture.h"
#include "metadata/taglib_handler.h"

namespace {
struct Fmt {
    const char* ext;
    const char* mime;
};
const Fmt formats[] = {
    { ".mp3", "audio/mpeg" }, { ".flac", "audio/x-flac" }, { ".ogg", "audio/ogg" }, { ".m4a", "audio/mp4" },
    { ".wma", "audio/x-ms-wma" }, { ".ape", "audio/x-ape" }, { ".aiff", "audio/x-aiff" }, { ".wav", "audio/x-wav" },
    { ".opus", "audio/opus" }, { ".mp4", "video/mp4" }, { ".wv", "audio/x-wavpack" }, { ".mpc", "audio/x-musepack" },
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static fuzzfx::Env env;
    if (size < 1)
        return -1;
    const auto& f = formats[data[0] % (sizeof(formats) / sizeof(formats[0]))];
    auto path = env.writeInput(data + 1, size - 1, f.ext);
    auto item = fuzzfx::makeItem(path, f.mime, std::string(f.mime).rfind("video/", 0) == 0 ? "object.item.videoItem" : "object.item.audioItem.musicTrack");
    try {
        fuzzfx::runHandler<TagLibHandler>(env.context, item);
    } catch (const std::exception&) {
    }
    return 0;
}
