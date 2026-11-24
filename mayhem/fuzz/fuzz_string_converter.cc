// Charset conversion of tag strings / filenames (StringConverter::convert, src/util/string_converter.cc):
// first byte picks the source charset an import option could name; the rest is the string.
#include "util/string_converter.h"

#include <spdlog/spdlog.h>
#include <cstdint>
#include <exception>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static bool init = (spdlog::set_level(spdlog::level::off), true);
    (void)init;
    static const char* charsets[] = { "ISO-8859-1", "UTF-16", "UTF-16LE", "CP1252", "SHIFT_JIS", "UTF-8", "EUC-JP", "UTF-32" };
    if (size < 1)
        return -1;
    const char* cs = charsets[data[0] % 8];
    const bool validate = (data[0] & 0x80) != 0;
    try {
        StringConverter sc(cs, "UTF-8");
        (void)sc.convert(std::string(reinterpret_cast<const char*>(data + 1), size - 1), validate);
    } catch (const std::exception&) {
    }
    return 0;
}
