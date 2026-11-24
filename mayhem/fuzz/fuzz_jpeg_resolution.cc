// Image import: gerbera's own JPEG marker walker getJpegResolution() (src/util/jpeg_resolution.cc),
// fed through the in-memory IOHandler exactly like the file IOHandler used on import.
#include "iohandler/mem_io_handler.h"
#include "util/jpeg_resolution.h"

#include <spdlog/spdlog.h>
#include <cstdint>
#include <exception>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static bool init = (spdlog::set_level(spdlog::level::off), true);
    (void)init;
    MemIOHandler ioh(data, static_cast<int>(size));
    try {
        ioh.open(UPNP_READ);
        (void)getJpegResolution(ioh);
    } catch (const std::exception&) {
    }
    ioh.close();
    return 0;
}
