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
 * @brief validate a jwt-Token
 *
 * @param payload reference for returning the payload of the token, if valid
 * @param token token to validate
 * @param error reference for error-output
 *
 * @return true, if token is valid, else false
 */
bool
Jwt::validateToken(Json::JsonItem &payload,
                   const std::string &token,
                   ErrorContainer &error)
{
    // precheck token
    if(token.size() == 0)
    {
        error.addMeesage("Token is empty");
        LOG_ERROR(error);
        return false;
    }

    // filter relevant part from the token
    std::vector<std::string> tokenParts;
    Kitsunemimi::splitStringByDelimiter(tokenParts, token, '.');
    if(tokenParts.size() != 3)
    {
        error.addMeesage("Token is broken");
        LOG_ERROR(error);
        return false;
    }
    const std::string relevantPart = tokenParts.at(0) + "." + tokenParts.at(1);

    // convert header the get information
    Json::JsonItem header;
    std::string headerString = tokenParts.at(0);
    Kitsunemimi::Crypto::base64UrlToBase64(headerString);
    Kitsunemimi::Crypto::decodeBase64(headerString, headerString);
    if(header.parse(headerString, error) == false)
    {
        error.addMeesage("Jwt-header is broken");
        LOG_ERROR(error);
        return false;
    }

    // get values from header
    const std::string alg = header["alg"].getString();
    const std::string typ = header["typ"].getString();

    // check type
    if(typ != "JWT")
    {
        error.addMeesage("Token is not a JWT-token");
        LOG_ERROR(error);
        return false;
    }

    // try to validate the jwt-token
    if(validateSignature(alg, relevantPart, tokenParts.at(2), error) ==  false)
    {
        error.addMeesage("Validation of JWT-token failed.");
        LOG_ERROR(error);
        return false;
    }

    // convert payload for output
    std::string payloadString = tokenParts.at(1);
    Kitsunemimi::Crypto::base64UrlToBase64(payloadString);
    Kitsunemimi::Crypto::decodeBase64(payloadString, payloadString);
    if(payload.parse(payloadString, error) == false)
    {
        error.addMeesage("Jwt-payload is broken");
        LOG_ERROR(error);
        return false;
    }

    return true;
}

/**
 * @brief try to validate the JWT-token based on the used algorithm
 *
 * @param alg type of the jwt-algorithm for the validation
 * @param payload reference for returning the payload of the token, if valid
 * @param token token to validate
 * @param error reference for error-output
 *
 * @return true, if token can be validated and is valid, else false
 */
bool
Jwt::validateSignature(const std::string &alg,
                       const std::string &relevantPart,
                       const std::string &signature,
                       ErrorContainer &error)
{
    if(alg == "HS256") {
        return validate_HS256_Token(relevantPart, signature, error);
    }

    error.addMeesage("Jwt-token can not be validated, because the algorithm \"" + alg + "\"\n"
                     "is not supported by this library or doesn't even exist.");
    LOG_ERROR(error);
    return false;
}

/**
 * @brief validate a HS256-Token
 *
 * @param payload reference for returning the payload of the token, if valid
 * @param token token to validate
 * @param error reference for error-output
 *
 * @return true, if token is valid, else false
 */
bool
Jwt::validate_HS256_Token(const std::string &relevantPart,
                          const std::string &signature,
                          ErrorContainer &error)
{
    // create hmac again
    std::string compare;
    Kitsunemimi::Crypto::create_HMAC_SHA256(compare, relevantPart, m_signingKey);
    Kitsunemimi::Crypto::base64ToBase64Url(compare);

    // compare new create hmac-value with the one from the token
    if(compare.size() == signature.size()
            && CRYPTO_memcmp(compare.c_str(), signature.c_str(), compare.size()) == 0)
    {
        return true;
    }

    error.addMeesage("token is invalid");
    LOG_ERROR(error);

    return false;
}

}
}
