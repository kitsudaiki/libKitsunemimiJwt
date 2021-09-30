/**
 *  @file       jwt_test.h
 *
 *  @author     Tobias Anker <tobias.anker@kitsunemimi.moe>
 *
 *  @copyright  MIT License
 */

#ifndef JWT_TEST_H
#define JWT_TEST_H

#include <libKitsunemimiCommon/test_helper/compare_test_helper.h>

namespace Kitsunemimi
{
namespace Jwt
{

class JWT_Test
        : public Kitsunemimi::CompareTestHelper
{
public:
    JWT_Test();

private:
    void create_validate_HS256_Token_test();
};

}
}

#endif // JWT_TEST_H
