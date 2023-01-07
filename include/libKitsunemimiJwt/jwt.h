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
class JsonItem;

bool getJwtTokenPayload(JsonItem &parsedResult,
                        const std::string &token,
                        ErrorContainer &error);

class Jwt
{
public:
    Jwt(const CryptoPP::SecByteBlock &signingKey);

    bool create_HS256_Token(std::string &result,
                            JsonItem &payload,
                            const u_int32_t validSeconds,
                            ErrorContainer &error);

    bool validateToken(JsonItem &resultPayload,
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
    void addTimesToPayload(JsonItem &payload,
                           const u_int32_t validSeconds);
    bool checkTimesInPayload(const JsonItem &payload,
                             ErrorContainer &error);
    long getTimeSinceEpoch();
};

}  // namespace Kitsunemimi

#endif // KITSUNEMIMI_JWT_H
