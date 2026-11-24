// Media import: Matroska/WebM (EBML walk, tags, cover-art attachments) — matroska_handler.cc.
// The scanned file is attacker-controlled (any file dropped into an autoscan directory).
#include "metadata_fixture.h"
#include "metadata/matroska_handler.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static fuzzfx::Env env;
    auto path = env.writeInput(data, size, ".mkv");
    auto item = fuzzfx::makeItem(path, "video/x-matroska", "object.item.videoItem");
    try {
        fuzzfx::runHandler<MatroskaHandler>(env.context, item);
    } catch (const std::exception&) {
        // handlers report unreadable/corrupt media with exceptions; the importer catches them too
    }
    return 0;
}
