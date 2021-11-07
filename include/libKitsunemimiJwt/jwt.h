/**
 *  @file       jwt.h
 *
 *  @author     Tobias Anker <tobias.anker@kitsunemimi.moe>
 *
 *  @copyright  MIT License
 */

#ifndef JWT_H
#define JWT_H

#include <cryptopp/secblock.h>

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
    bool validate_HS256_Token(std::string &payload, const std::string &token);

private:
    CryptoPP::SecByteBlock m_signingKey;
};

}
}

#endif // JWT_H
