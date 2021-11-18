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
                            const std::string &payload);

    bool validateToken(Kitsunemimi::Json::JsonItem &payload,
                       const std::string &token,
                       ErrorContainer &error);


private:
    CryptoPP::SecByteBlock m_signingKey;

    bool validateSignature(const std::string &alg,
                           const std::string &relevantPart,
                           const std::string &signature,
                           ErrorContainer &error);
    bool validate_HS256_Token(const std::string &relevantPart,
                              const std::string &signature,
                              ErrorContainer &error);
};

}
}

#endif // KITSUNEMIMI_JWT_H
