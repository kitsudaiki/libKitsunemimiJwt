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

namespace Kitsunemimi
{
namespace Jwt
{

JWT_Test::JWT_Test()
    : Kitsunemimi::CompareTestHelper("JWT_Test")
{
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
                                    "    \"name\":\"John Doe\","
                                    "    \"iat\":1516239022"
                                    "}";
    Kitsunemimi::Json::JsonItem payloadJson;
    std::string errorMessage = "";
    assert(payloadJson.parse(testPayload, errorMessage));

    // test token-creation
    std::string token;
    TEST_EQUAL(jwt.create_HS256_Token(token, payloadJson.toString()), true);

    // test result
    const std::string compareToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                                     ".eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJ"
                                     "Kb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ"
                                     ".fdOPQ05ZfRhkST2-rIWgUpbqUsVhkkNVNcuG7Ki0s-8";
    TEST_EQUAL(token, compareToken);

    std::string payload;
    TEST_EQUAL(jwt.validate_HS256_Token(payload, token), true);
    const std::string comparePayload = "{\"iat\":1516239022,"
                                       "\"name\":\"John Doe\","
                                       "\"sub\":\"1234567890\"}";
    TEST_EQUAL(payload, comparePayload);

    token[24] = 'x';
    TEST_EQUAL(jwt.validate_HS256_Token(payload, token), false);
}

}
}

