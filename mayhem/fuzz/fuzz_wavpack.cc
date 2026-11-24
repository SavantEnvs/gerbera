// Media import: WavPack audio (tags, attributes, embedded artwork) — wavpack_handler.cc.
// The scanned file is attacker-controlled (any file dropped into an autoscan directory).
#include "metadata_fixture.h"
#include "metadata/wavpack_handler.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static fuzzfx::Env env;
    auto path = env.writeInput(data, size, ".wv");
    auto item = fuzzfx::makeItem(path, "audio/x-wavpack", "object.item.audioItem.musicTrack");
    try {
        fuzzfx::runHandler<WavPackHandler>(env.context, item);
    } catch (const std::exception&) {
        // handlers report unreadable/corrupt media with exceptions; the importer catches them too
    }
    return 0;
}
