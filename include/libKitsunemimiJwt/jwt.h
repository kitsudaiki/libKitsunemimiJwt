/**
 *  @file       jwt.h
 *
 *  @author     Tobias Anker <tobias.anker@kitsunemimi.moe>
 *
 *  @copyright  MIT License
 */

#ifndef KITSUNEMIMI_JWT_H
#define KITSUNEMIMI_JWT_H

#include <cryptopp/secblock.h>
#include <chrono>

#include <libKitsunemimiCommon/logger.h>

namespace Kitsunemimi
{
namespace Json {
class JsonItem;
}
namespace Jwt
{

class Jwt
{
public:
    Jwt(const CryptoPP::SecByteBlock &signingKey);

    bool create_HS256_Token(std::string &result,
                            Kitsunemimi::Json::JsonItem &payload,
                            const u_int32_t validSeconds);

    bool validateToken(Kitsunemimi::Json::JsonItem &resultPayload,
                       const std::string &token,
                       std::string &publicError,
                       ErrorContainer &error);


private:
    CryptoPP::SecByteBlock m_signingKey;

    // signature
    bool validateSignature(const std::string &alg,
                           const std::string &relevantPart,
                           const std::string &signature,
                           ErrorContainer &error);
    bool validate_HS256_Signature(const std::string &relevantPart,
                                  const std::string &signature,
                                  ErrorContainer &error);

    // times
    void addTimesToPayload(Kitsunemimi::Json::JsonItem &payload,
                           const u_int32_t validSeconds);
    bool checkTimesInPayload(const Json::JsonItem &payload,
                             ErrorContainer &error);
    long getTimeSinceEpoch();
};

}
}

#endif // KITSUNEMIMI_JWT_H
