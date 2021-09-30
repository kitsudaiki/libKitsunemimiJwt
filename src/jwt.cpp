/**
 *  @file       jwt.cpp
 *
 *  @author     Tobias Anker <tobias.anker@kitsunemimi.moe>
 *
 *  @copyright  MIT License
 */

#include <libKitsunemimiJwt/jwt.h>

#include <libKitsunemimiCrypto/signing.h>
#include <libKitsunemimiCrypto/common.h>
#include <libKitsunemimiJson/json_item.h>
#include <libKitsunemimiCommon/common_methods/string_methods.h>

namespace Kitsunemimi
{
namespace Jwt
{

/**
 * @brief constructor
 *
 * @param signingKey key for signing and validation
 */
Jwt::Jwt(const CryptoPP::SecByteBlock &signingKey)
{
    m_signingKey = signingKey;
}

/**
 * @brief create a new HS256-Token
 *
 * @param result reference for the resulting token
 * @param payload payload which has to be signed
 *
 * @return true, if successfull, else false
 */
bool
Jwt::create_HS256_Token(std::string &result,
                        const std::string &payload)
{
    // convert header
    const std::string header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    std::string headerBase64;
    Kitsunemimi::Crypto::encodeBase64(headerBase64, header.c_str(), header.size());
    Kitsunemimi::Crypto::base64ToBase64Url(headerBase64);
    result = headerBase64;

    // convert payload
    std::string payloadBase64;
    Kitsunemimi::Crypto::encodeBase64(payloadBase64, payload.c_str(), payload.size());
    Kitsunemimi::Crypto::base64ToBase64Url(payloadBase64);
    result += "." + payloadBase64;

    // create signature
    std::string secretHmac;
    Kitsunemimi::Crypto::create_HMAC_SHA256(secretHmac, result, m_signingKey);
    Kitsunemimi::Crypto::base64ToBase64Url(secretHmac);
    result += "." + secretHmac;

    return true;
}

/**
 * @brief validate a HS256-Token
 *
 * @param token token to validate
 *
 * @return true, if token is valid, else false
 */
bool
Jwt::validate_HS256_Token(const std::string &token)
{
    if(token.size() == 0) {
        return false;
    }

    std::vector<std::string> tokenParts;
    Kitsunemimi::splitStringByDelimiter(tokenParts, token, '.');

    if(tokenParts.size() != 3) {
        return false;
    }

    const std::string relevantPart = tokenParts.at(0) + "." + tokenParts.at(1);

    std::string compare;
    Kitsunemimi::Crypto::create_HMAC_SHA256(compare, relevantPart, m_signingKey);
    Kitsunemimi::Crypto::base64ToBase64Url(compare);

    const std::string signature = tokenParts.at(2);
    if(compare.size() == signature.size()
       && CRYPTO_memcmp(compare.c_str(), signature.c_str(), compare.size()) == 0)
    {
        return true;
    }

    return false;
}

}
}
