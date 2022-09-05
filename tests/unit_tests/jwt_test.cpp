/**
 *  @file       jwt_test.cpp
 *
 *  @author     Tobias Anker <tobias.anker@kitsunemimi.moe>
 *
 *  @copyright  MIT License
 */

#include "jwt_test.h"

#include <libKitsunemimiJwt/jwt.h>
#include <libKitsunemimiJson/json_item.h>
#include <libKitsunemimiCommon/logger.h>

namespace Kitsunemimi
{
namespace Jwt
{

JWT_Test::JWT_Test()
    : Kitsunemimi::CompareTestHelper("JWT_Test")
{
    Kitsunemimi::initConsoleLogger(true);
    create_validate_HS256_Token_test();
}

/**
 * @brief create_validate_HS256_Token_test
 */
void
JWT_Test::create_validate_HS256_Token_test()
{
    // create test-secte
    const std::string testSecret = "your-256-bit-secret";
    CryptoPP::SecByteBlock key((unsigned char*)testSecret.c_str(), testSecret.size());

    // init test-class
    Jwt jwt(key);

    // prepare test-payload
    const std::string testPayload = "{"
                                    "    \"sub\":\"1234567890\","
                                    "    \"name\":\"Test-User\","
                                    "    \"iat\":1516239022"
                                    "}";
    Kitsunemimi::Json::JsonItem payloadJson;
    ErrorContainer error;
    std::string publicError = "";
    assert(payloadJson.parse(testPayload, error));
    error._errorMessages.clear();

    // test token-creation
    std::string token;
    TEST_EQUAL(jwt.create_HS256_Token(token, payloadJson, 1000, error), true);
    LOG_DEBUG("token: " + token);

    // test token-validation with valid token
    Kitsunemimi::Json::JsonItem resultPayloadJson;
    TEST_EQUAL(jwt.validateToken(resultPayloadJson, token, publicError, error), true);
    TEST_EQUAL(resultPayloadJson.get("name").getString(), "Test-User");
    error._errorMessages.clear();

    // test getter for token-payload without validation
    Kitsunemimi::Json::JsonItem resultPayloadJson2;
    TEST_EQUAL(Kitsunemimi::Jwt::getJwtTokenPayload(resultPayloadJson2, token, error), true);
    TEST_EQUAL(resultPayloadJson2.get("name").getString(), "Test-User");
    error._errorMessages.clear();

    // test token-validation with broken token
    token[token.size() - 5] = 'x';
    TEST_EQUAL(jwt.validateToken(resultPayloadJson, token, publicError, error), false);
    error._errorMessages.clear();
}

}
}

