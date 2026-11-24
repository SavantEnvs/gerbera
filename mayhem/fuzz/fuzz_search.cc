// UPnP ContentDirectory Search: the SearchCriteria string a LAN client sends is lexed, parsed and
// emitted as SQL by SearchParser/DefaultSQLEmitter (src/database/search_handler.cc). Fixture as in
// upstream's test/core/test_searchhandler.cc.
#include "mock/database_mock.h"
#include "config/config_setup.h"
#include "database/search_handler.h"
#include "exceptions.h"
#include "upnp/clients.h"
#include "metadata/metadata_enums.h"

#include <spdlog/spdlog.h>
#include <cstdint>
#include <memory>
#include <string>

namespace {
enum class Col { Id = 0, ItemId, PropertyName, PropertyValue, Number1, Number2, UpnpClass, RefId, LastUpdated };

struct Fixture {
    std::shared_ptr<Database> database;
    std::shared_ptr<EnumColumnMapper<Col>> mapper;
    Fixture()
    {
        spdlog::set_level(spdlog::level::off);
        database = std::make_shared<DatabaseMock>(nullptr);
        std::vector<std::pair<std::string, Col>> sortMap = {
            { "id", Col::Id },
            { UPNP_SEARCH_ID, Col::ItemId },
            { MetaEnumMapper::getMetaFieldName(MetadataFields::M_TRACKNUMBER), Col::Number1 },
            { MetaEnumMapper::getMetaFieldName(MetadataFields::M_PARTNUMBER), Col::Number2 },
            { META_NAME, Col::PropertyName },
            { META_VALUE, Col::PropertyValue },
            { UPNP_SEARCH_CLASS, Col::UpnpClass },
            { UPNP_SEARCH_REFID, Col::RefId },
            { UPNP_SEARCH_LAST_UPDATED, Col::LastUpdated },
        };
        std::map<Col, SearchProperty> colMap = {
            { Col::Id, { "t", "id" } },
            { Col::ItemId, { "t", "item_id" } },
            { Col::PropertyName, { "t", "property_name" } },
            { Col::Number1, { "t", "number1", FieldType::Integer } },
            { Col::Number2, { "t", "number2", FieldType::Integer } },
            { Col::PropertyValue, { "t", "property_value" } },
            { Col::UpnpClass, { "t", "upnp_class" } },
            { Col::RefId, { "t", "ref_id" } },
            { Col::LastUpdated, { "t", "last_updated", FieldType::Date } },
        };
        mapper = std::make_shared<EnumColumnMapper<Col>>('_', '_', "t", "TestTable", sortMap, colMap);
    }
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static Fixture fx;
    std::string criteria(reinterpret_cast<const char*>(data), size);
    try {
        // As SQLDatabase::search (src/database/sql_database.cc) does: parse with the configured
        // nesting limit (UPNP_SEARCH_NESTING_LIMIT, default 32), then emitSQL() on the root.
        DefaultSQLEmitter emitter(fx.database, fx.mapper, fx.mapper, fx.mapper, fx.mapper);
        fx.mapper->resetCnt();
        auto parser = SearchParser(emitter, criteria, 32);
        std::shared_ptr<ASTNode> root = parser.parse();
        if (root)
            (void)root->emitSQL();
    } catch (const std::exception&) {
        // invalid criteria are rejected with exceptions, as ContentDirectoryService does
    }
    return 0;
}
