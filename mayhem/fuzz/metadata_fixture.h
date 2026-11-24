// Shared fixture for the media-metadata harnesses: a Context built the way upstream's
// test/core/test_bpm_metadata.cc builds it (ConfigMock + ConverterManager + Mime + ConfigDefinition),
// and a CdsItem pointing at the fuzz input written to a scratch file. Metadata handlers read the media
// file by path (item->getLocation()), exactly as the importer does for a scanned file.
#pragma once

#include "mock/config_mock.h"
#include "cds/cds_item.h"
#include "cds/cds_enums.h"
#include "cds/cds_resource.h"
#include "config/config_definition.h"
#include "config/config_option_enum.h"
#include "config/result/directory_tweak.h"
#include "context.h"
#include "iohandler/io_handler.h"
#include "metadata/metadata_enums.h"
#include "metadata/metadata_handler.h"
#include "util/mime.h"
#include "util/string_converter.h"

#include <spdlog/spdlog.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <string>
#include <unistd.h>

namespace fuzzfx {

class FuzzConfig final : public ConfigMock {
public:
    std::string getOption(ConfigVal option) const override
    {
        if (option == ConfigVal::IMPORT_LIBOPTS_ENTRY_SEP)
            return "; ";
        if (option == ConfigVal::IMPORT_LIBOPTS_ENTRY_LEGACY_SEP)
            return "\n";
        return "UTF-8";
    }
    // The metadata handlers are enabled in gerbera's default config; enable them (and their
    // content/comment extraction) here, as upstream's own handler tests do.
    bool getBoolOption(ConfigVal option) const override
    {
        switch (option) {
        case ConfigVal::IMPORT_LIBOPTS_EXIF_ENABLED:
        case ConfigVal::IMPORT_LIBOPTS_EXIF_CONTENT_ENABLED:
        case ConfigVal::IMPORT_LIBOPTS_EXIF_COMMENT_ENABLED:
        case ConfigVal::IMPORT_LIBOPTS_ID3_ENABLED:
        case ConfigVal::IMPORT_LIBOPTS_ID3_CONTENT_ENABLED:
        case ConfigVal::IMPORT_LIBOPTS_ID3_COMMENT_ENABLED:
        case ConfigVal::IMPORT_LIBOPTS_ID3_PREFER_HIGHEST_BPM_ACCURACY:
        case ConfigVal::IMPORT_LIBOPTS_MKV_ENABLED:
        case ConfigVal::IMPORT_LIBOPTS_MKV_CONTENT_ENABLED:
        case ConfigVal::IMPORT_LIBOPTS_MKV_COMMENT_ENABLED:
        case ConfigVal::IMPORT_LIBOPTS_WAVPACK_ENABLED:
        case ConfigVal::IMPORT_LIBOPTS_WAVPACK_CONTENT_ENABLED:
        case ConfigVal::IMPORT_LIBOPTS_WAVPACK_COMMENT_ENABLED:
            return true;
        default:
            return ConfigMock::getBoolOption(option);
        }
    }
    std::shared_ptr<ConfigOption> getConfigOption(ConfigVal option) const override
    {
        if (option == ConfigVal::IMPORT_LIBOPTS_ID3_PREFER_AMBIGOUS_BPM_VALUE)
            return std::make_shared<EnumOption<BpmSource>>(BpmSource::BpmTag, "");
        return ConfigMock::getConfigOption(option);
    }
    // Extra tags to copy into metadata / aux data (exercises the per-tag extraction paths).
    std::map<std::string, std::string> getDictionaryOption(ConfigVal option) const override
    {
        switch (option) {
        case ConfigVal::IMPORT_LIBOPTS_ID3_METADATA_TAGS_LIST:
        case ConfigVal::IMPORT_LIBOPTS_WAVPACK_METADATA_TAGS_LIST:
        case ConfigVal::IMPORT_LIBOPTS_MKV_METADATA_TAGS_LIST:
            return { { "BPM", "upnp:beatsPerMinute" }, { "INITIALKEY", "upnp:initialKey" }, { "COMPOSER", "upnp:composer" } };
        case ConfigVal::IMPORT_LIBOPTS_EXIF_METADATA_TAGS_LIST:
            return { { "EXIF_TAG_MODEL", "upnp:model" }, { "EXIF_TAG_DATE_TIME_ORIGINAL", "dc:date" } };
        default:
            return ConfigMock::getDictionaryOption(option);
        }
    }
    std::vector<std::string> getArrayOption(ConfigVal option) const override
    {
        switch (option) {
        case ConfigVal::IMPORT_LIBOPTS_ID3_AUXDATA_TAGS_LIST:
        case ConfigVal::IMPORT_LIBOPTS_WAVPACK_AUXDATA_TAGS_LIST:
        case ConfigVal::IMPORT_LIBOPTS_MKV_AUXDATA_TAGS_LIST:
            return { "TXXX:Album Artist", "ALBUMARTIST", "COMMENT", "LYRICS" };
        case ConfigVal::IMPORT_LIBOPTS_EXIF_AUXDATA_TAGS_LIST:
            return { "EXIF_TAG_MAKE", "EXIF_TAG_ARTIST", "EXIF_TAG_USER_COMMENT" };
        default:
            return ConfigMock::getArrayOption(option);
        }
    }
    std::shared_ptr<DirectoryConfigList> getDirectoryTweakOption(ConfigVal) const override
    {
        return std::make_shared<DirectoryConfigList>();
    }
};

struct Env {
    std::shared_ptr<FuzzConfig> config;
    std::shared_ptr<Context> context;
    std::string dir;
    Env()
    {
        spdlog::set_level(spdlog::level::off);
        config = std::make_shared<FuzzConfig>();
        auto converter = std::make_shared<ConverterManager>(config);
        auto mime = std::make_shared<Mime>(config);
        auto definition = std::make_shared<ConfigDefinition>();
        definition->init(definition);
        context = std::make_shared<Context>(definition, config, nullptr, mime, nullptr, nullptr, converter);
        const char* tmp = std::getenv("TMPDIR");
        std::string tmpl = std::string(tmp && *tmp ? tmp : "/tmp") + "/gerbera-fuzz-XXXXXX";
        if (!mkdtemp(tmpl.data()))
            abort();
        dir = tmpl;
    }
    /// Write the input to <scratch>/input<ext>; the same name is overwritten for every input.
    std::string writeInput(const uint8_t* data, size_t size, const std::string& ext) const
    {
        std::string path = dir + "/input" + ext;
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
        return path;
    }
};

inline std::shared_ptr<CdsItem> makeItem(const std::string& path, const std::string& mime, const std::string& upnpClass)
{
    auto item = std::make_shared<CdsItem>(CdsEntryType::File);
    item->setLocation(path, CdsEntryType::File);
    item->setMimeType(mime);
    item->setClass(upnpClass);
    item->addResource(std::make_shared<CdsResource>(ContentHandler::DEFAULT, ResourcePurpose::Content));
    return item;
}

/// fillMetadata, then serve every resource the handler added (artwork/attachments), reading it out.
template <class Handler>
void runHandler(const std::shared_ptr<Context>& ctx, const std::shared_ptr<CdsItem>& item)
{
    Handler handler(ctx);
    std::vector<int> ids;
    handler.fillMetadata(item, ids);
    for (auto&& res : item->getResources()) {
        if (res->getHandlerType() == ContentHandler::DEFAULT)
            continue;
        auto io = handler.serveContent(item, res);
        if (!io)
            continue;
        io->open(UPNP_READ);
        std::byte buf[4096];
        while (io->read(buf, sizeof(buf)) > 0) { }
        io->close();
    }
}

} // namespace fuzzfx
