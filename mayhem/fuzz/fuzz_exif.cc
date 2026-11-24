// Media import: JPEG/EXIF images (EXIF tags, thumbnail, resolution) — libexif_handler.cc.
// The scanned file is attacker-controlled (any file dropped into an autoscan directory).
#include "metadata_fixture.h"
#include "metadata/libexif_handler.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static fuzzfx::Env env;
    auto path = env.writeInput(data, size, ".jpg");
    auto item = fuzzfx::makeItem(path, "image/jpeg", "object.item.imageItem.photo");
    try {
        fuzzfx::runHandler<LibExifHandler>(env.context, item);
    } catch (const std::exception&) {
        // handlers report unreadable/corrupt media with exceptions; the importer catches them too
    }
    return 0;
}
