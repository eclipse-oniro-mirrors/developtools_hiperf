/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vector>

#include <gtest/gtest.h>

#include "dwarf_test.h"

using namespace testing::ext;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
namespace {
const unsigned char absptr {0xff};
constexpr int data2Size {2};
const unsigned char data2[data2Size] {0xff, 0xff};
const unsigned char data4[sizeof(int32_t)] {0xff, 0xff, 0xff, 0xff};
const unsigned char data8[sizeof(int64_t)] {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
constexpr int data128Size {128};
unsigned char data128[data128Size] {};
#ifdef NOT_USE
constexpr int num {9};
#else
constexpr int num {7};
#endif
const unsigned char *data[num] {};
std::vector<uint64_t> values {
    65535ULL,
    4294967295ULL,
    18446744073709551615ULL,
    18446744073709551615ULL,
    18446744073709551615ULL,
    18446744073709551615ULL,
    65535ULL,
    4294967295ULL,
    1921026034567241472ULL,
    18446744073709551615ULL,
    18446744073709551615ULL,
    1921026034567241472ULL,
    65535ULL,
    4294967295ULL,
    1921010641404477184ULL,
    18446744073709551615ULL,
    18446744073709551615ULL,
    1921010641404477184ULL,
    65535ULL,
    447241984ULL,
    1940452206006808832ULL,
    18446744073709551615ULL,
    447241984ULL,
    1940452206006808832ULL,
    65535ULL,
    447273728ULL,
    1940830438011371264ULL,
    18446744073709551615ULL,
    447273728ULL,
    1940830438011371264ULL,
    65535ULL,
    447266560ULL,
    1940830438011385600ULL,
    18446744073709551615ULL,
    447266560ULL,
    1940830438011385600ULL,
};
std::vector<dw_encode_t> vfs {
    DW_EH_PE_absptr,
#ifdef NOT_USE
    DW_EH_PE_uleb128,
#endif
    DW_EH_PE_udata2,  DW_EH_PE_udata4, DW_EH_PE_udata8,
#ifdef NOT_USE
    DW_EH_PE_sleb128,
#endif
    DW_EH_PE_sdata2,  DW_EH_PE_sdata4, DW_EH_PE_sdata8,
};
vector<dw_encode_t> ehas {
    DW_EH_PE_nothing, DW_EH_PE_pcrel,   DW_EH_PE_textrel, DW_EH_PE_datarel,
    DW_EH_PE_funcrel, DW_EH_PE_aligned, DW_EH_PE_omit,
};
} // namespace

class DwarfTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DwarfTest::SetUpTestCase(void) {}

void DwarfTest::TearDownTestCase(void) {}

void DwarfTest::SetUp()
{
    for (std::size_t index = 0; index < data128Size; ++index) {
        data128[index] = 0xff;
    }
    std::size_t index {0};
    data[index++] = &absptr;
#ifdef NOT_USE
    data[index++] = data128;
#endif
    data[index++] = data2;
    data[index++] = data4;
    data[index++] = data8;
#ifdef NOT_USE
    data[index++] = data128;
#endif
    data[index++] = data2;
    data[index++] = data4;
    data[index++] = data8;
}

void DwarfTest::TearDown() {}

HWTEST_F(DwarfTest, GetEnd, TestSize.Level1)
{
    for (std::size_t i = 0; i < ehas.size(); ++i) {
        for (std::size_t j = 0; j < num; ++j) {
            {
                dw_encode_t dwe = ehas[i] | vfs[j];
                DwarfEncoding dw {dwe, data[j]};
                if (!dw.IsOmit()) {
                    if (vfs[j] == DW_EH_PE_absptr) {
                        EXPECT_TRUE(data[j] == dw.GetEnd() - dw.GetSize());
                    } else {
                        EXPECT_TRUE(data[j] == dw.GetEnd());
                    }
                }
            }
        }
    }
}

HWTEST_F(DwarfTest, GetData, TestSize.Level0)
{
    for (std::size_t i = 0; i < ehas.size(); ++i) {
        for (std::size_t j = 0; j < num; ++j) {
            {
                dw_encode_t dwe = ehas[i] | vfs[j];
                DwarfEncoding dw {dwe, data[j]};
                if (!dw.IsOmit()) {
                    if (vfs[j] == DW_EH_PE_absptr) {
                        EXPECT_TRUE(data[j] == dw.GetData());
                    } else {
                        EXPECT_TRUE(data[j] == dw.GetData() + dw.GetSize());
                    }
                }
            }
        }
    }
}

HWTEST_F(DwarfTest, GetSize, TestSize.Level2)
{
    for (std::size_t i = 0; i < ehas.size(); ++i) {
        for (std::size_t j = 0; j < num; ++j) {
            {
                dw_encode_t dwe = ehas[i] | vfs[j];
                DwarfEncoding dw {dwe, data[j]};
                if (!dw.IsOmit()) {
                    EXPECT_TRUE(DWFormatSizeMap.at(vfs[j]) == dw.GetSize());
                }
            }
        }
    }
}

HWTEST_F(DwarfTest, ToString, TestSize.Level1)
{
    for (std::size_t j = 0; j < num; ++j) {
        dw_encode_t dwe = ehas[0] | vfs[j];
        DwarfEncoding dw {dwe, data[j]};
        EXPECT_TRUE(!dw.ToString().empty());
        printf("%s\n", dw.ToString().c_str());
    }
}

HWTEST_F(DwarfTest, IsOmit, TestSize.Level2)
{
    for (std::size_t i = 0; i < ehas.size(); ++i) {
        for (std::size_t j = 0; j < num; ++j) {
            {
                dw_encode_t dwe = ehas[i] | vfs[j];
                DwarfEncoding dw {dwe, data[j]};
                if (ehas[i] == DW_EH_PE_omit) {
                    EXPECT_TRUE(dw.IsOmit());
                } else {
                    EXPECT_FALSE(dw.IsOmit());
                }
            }
        }
    }
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
