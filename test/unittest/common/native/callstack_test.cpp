/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "callstack_test.h"

using namespace testing::ext;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class CallStackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::default_random_engine rnd_;
};

void CallStackTest::SetUpTestCase()
{
    DebugLogger::GetInstance()->Reset();
    DebugLogger::GetInstance()->OpenLog(DEFAULT_UT_LOG_DIR + "CallStackTest.txt");
}

void CallStackTest::TearDownTestCase()
{
    DebugLogger::GetInstance()->RestoreLog();
}

void CallStackTest::SetUp() {}

void CallStackTest::TearDown() {}

static void MakeMaps(VirtualThread &thread)
{
    for (const mmapDumpInfo &mmap : TEST_DWARF_MMAP) {
        thread.CreateMapItem(mmap.fileName, mmap.begin, mmap.len, mmap.pgoff);
    }
}

/**
 * @tc.name: ExpandCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, ExpendCallStackEmpty, TestSize.Level2)
{
    /*
                3    2    1
        cache   A -> B -> C
        new               C
        expand  A -> B -> C
    */
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH);
    CallStack callStack;

    std::vector<DfxFrame> stack1 = {
        {0x1u, 0x1u},
        {0x2u, 0x2u},
        {0x3u, 0x3u},
    };
    std::vector<DfxFrame> stack2 = {};

    ASSERT_EQ(callStack.ExpandCallStack(0, stack1), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack2), 0u);
    ASSERT_NE(stack1, stack2);
}

/**
 * @tc.name: ExpandCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, ExpendCallStackC, TestSize.Level0)
{
    /*
                3    2    1
        cache   A -> B -> C
        new               C
        expand  A -> B -> C
    */
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH);
    CallStack callStack;

    std::vector<DfxFrame> stack1 = {
        {0x1u, 0x1u},
        {0x2u, 0x2u},
        {0x3u, 0x3u},
    };
    std::vector<DfxFrame> stack2 = {
        {0x1u, 0x1u},
    };

    ASSERT_EQ(callStack.ExpandCallStack(0, stack1), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack2), 2u);
    ASSERT_EQ(stack1, stack2);
}

/**
 * @tc.name: ExpandCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, ExpendCallStackBC, TestSize.Level1)
{
    /*
                3    2    1
        cache   A -> B -> C
        new          B -> C
        expand  A -> B -> C
    */
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH);
    CallStack callStack;

    std::vector<DfxFrame> stack1 = {
        {0x1u, 0x1u},
        {0x2u, 0x2u},
        {0x3u, 0x3u},
    };
    std::vector<DfxFrame> stack2 = {
        {0x1u, 0x1u},
        {0x2u, 0x2u},
    };

    ASSERT_EQ(callStack.ExpandCallStack(0, stack1), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack2), 1u);
    ASSERT_EQ(stack1, stack2);
}

/**
 * @tc.name: ExpandCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, ExpendCallStackABC, TestSize.Level0)
{
    /*
                3    2    1
        cache   A -> B -> C
        new     A -> B -> C
        expand  A -> B -> C
    */
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH);
    CallStack callStack;

    std::vector<DfxFrame> stack1 = {
        {0x1u, 0x1u},
        {0x2u, 0x2u},
        {0x3u, 0x3u},
    };
    std::vector<DfxFrame> stack2 = {
        {0x1u, 0x1u},
        {0x2u, 0x2u},
        {0x3u, 0x3u},
    };

    ASSERT_EQ(callStack.ExpandCallStack(0, stack1), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack2), 0u);
    ASSERT_EQ(stack1, stack2);
}

/**
 * @tc.name: ExpandCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, ExpendCallStackAB, TestSize.Level1)
{
    /*
                3    2    1
        cache   A -> B -> C
        new     A -> B
        expand  A -> B
    */
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH);
    CallStack callStack;

    std::vector<DfxFrame> stack1 = {
        {0x1u, 0x1u},
        {0x2u, 0x2u},
        {0x3u, 0x3u},
    };
    std::vector<DfxFrame> stack2 = {
        {0x2u, 0x2u},
        {0x3u, 0x3u},
    };

    ASSERT_EQ(callStack.ExpandCallStack(0, stack1), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack2), 0u);
    ASSERT_NE(stack1, stack2);
}

/**
 * @tc.name: ExpandCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, ExpendCallStackA, TestSize.Level2)
{
    /*
                3    2    1
        cache   A -> B -> C
        new     A
        expand  A
    */
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH);
    CallStack callStack;

    std::vector<DfxFrame> stack1 = {
        {0x1u, 0x1u},
        {0x2u, 0x2u},
        {0x3u, 0x3u},
    };
    std::vector<DfxFrame> stack2 = {
        {0x3u, 0x3u},
    };

    ASSERT_EQ(callStack.ExpandCallStack(0, stack1), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack2), 0u);
    ASSERT_NE(stack1, stack2);
}

/**
 * @tc.name: ExpandCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, ExpendCallStackB, TestSize.Level2)
{
    /*
                3    2    1
        cache   A -> B -> C
        new          B
        expand  A -> B
    */
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH);
    CallStack callStack;

    std::vector<DfxFrame> stack1 = {
        {0x1u, 0x1u},
        {0x2u, 0x2u},
        {0x3u, 0x3u},
    };
    std::vector<DfxFrame> stack2 = {
        {0x2u, 0x2u},
    };
    std::vector<DfxFrame> stack3 = {
        {0x2u, 0x2u},
        {0x3u, 0x3u},
    };
    ASSERT_EQ(callStack.ExpandCallStack(0, stack1), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack2), 1u);
    ASSERT_NE(stack1, stack2);
    ASSERT_EQ(stack3, stack2);
}

/**
 * @tc.name: ExpandCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, ExpendCallStackB2, TestSize.Level2)
{
    /*
                3    2    1
        cache   A -> B -> C
        new          B
        expand  A -> B
    */
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH);
    CallStack callStack;

    std::vector<DfxFrame> stack1 = {
        {0x1u, 0x1u},
        {0x2u, 0x2u},
        {0x3u, 0x3u},
    };
    std::vector<DfxFrame> stack2 = {
        {0x2u, 0x2u},
    };
    std::vector<DfxFrame> stack3 = {
        {0x2u, 0x2u},
        {0x3u, 0x3u},
    };
    ASSERT_EQ(callStack.ExpandCallStack(0, stack1, 2), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack2, 2), 0u);
    ASSERT_NE(stack1, stack2);
    ASSERT_NE(stack3, stack2);
}

/**
 * @tc.name: ExpandCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, ExpendCallStackB0, TestSize.Level0)
{
    /*
                3    2    1
        cache   A -> B -> C
        new          B
        expand  A -> B
    */
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH);
    CallStack callStack;

    std::vector<DfxFrame> stack1 = {
        {0x1u, 0x1u},
        {0x2u, 0x2u},
        {0x3u, 0x3u},
    };
    std::vector<DfxFrame> stack2 = {
        {0x2u, 0x2u},
    };
    std::vector<DfxFrame> stack3 = {
        {0x2u, 0x2u},
        {0x3u, 0x3u},
    };
    ASSERT_EQ(callStack.ExpandCallStack(0, stack1, 0), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack2, 0), 0u);
    ASSERT_NE(stack1, stack2);
    ASSERT_NE(stack3, stack2);
}

/**
 * @tc.name: ExpandCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, ExpendCallStackBC2, TestSize.Level1)
{
    /*
                3    2    1
        cache   A -> B -> C
        new          B -> C
        expand  A -> B -> C
    */
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH, true);
    CallStack callStack;

    std::vector<DfxFrame> stack1 = {
        {0x1u, 0x1u},
        {0x2u, 0x2u},
        {0x3u, 0x3u},
    };
    std::vector<DfxFrame> stack2 = {
        {0x1u, 0x1u},
        {0x2u, 0x2u},
    };

    ASSERT_EQ(callStack.ExpandCallStack(0, stack1, 2), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack2, 2), 1u);
    ASSERT_EQ(stack1, stack2);
}

/**
 * @tc.name: ExpandCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, ExpendCallStackABCDE, TestSize.Level0)
{
    /*
        0. A -> B -> C -> E -> F
        1.           C -> E -> F
        2.      B -> C
        3. A -> B -> C
        4.      B -> F -> F
    */
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH);
    CallStack callStack;

    std::vector<DfxFrame> stackFull = {
        {0xE, 0xE}, {0xD, 0xD}, {0xC, 0xC}, {0xB, 0xB}, {0xA, 0xA},
    };
    std::vector<DfxFrame> stackBC = {
        {0xC, 0xC},
        {0xB, 0xB},
    };
    std::vector<DfxFrame> stackABC = {
        {0xC, 0xC},
        {0xB, 0xB},
        {0xA, 0xA},
    };
    std::vector<DfxFrame> stackBFF = {
        {0xF, 0xF},
        {0xF, 0xF},
        {0xB, 0xB},
    };
    std::vector<DfxFrame> stackBFF2 = {
        {0xF, 0xF},
        {0xF, 0xF},
        {0xB, 0xB},
    };

    ASSERT_EQ(callStack.ExpandCallStack(0, stackFull), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stackBC), 1u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stackABC), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stackBFF), 1u);

    // use stackBFF
    ASSERT_EQ(callStack.ExpandCallStack(0, stackBFF2, 2), 1u);
}

/**
 * @tc.name: ExpandCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, ExpendCallStackFailure, TestSize.Level3)
{
    /*
        0. A -> B -> C -> E -> F
        1.           C -> E -> F
        2.      B -> C
        3. A -> B -> C
        4.      B -> F -> F
    */
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH);
    CallStack callStack;

    std::vector<DfxFrame> stackFull = {
        {0xC, 0xC},
        {0xB, 0xB},
        {0xA, 0xA},
    };
    std::vector<DfxFrame> stackDE = {
        {0xE, 0xE},
        {0xD, 0xD},
    };

    ASSERT_EQ(callStack.ExpandCallStack(0, stackFull), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stackDE), 0u);
}

/**
 * @tc.name: ExpandCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, ExpendCallStackTwoChance, TestSize.Level0)
{
    /*
        0. A -> B -> C -> E -> F
        1.      2 -> C -> E -> F
        2.           C
    */
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH);
    CallStack callStack;

    std::vector<DfxFrame> stack0 = {
        {0xE, 0xE}, {0xD, 0xD}, {0xC, 0xC}, {0xB, 0xB}, {0xA, 0xA},
    };
    std::vector<DfxFrame> stack1 = {
        {0xE, 0xE},
        {0xD, 0xD},
        {0xC, 0xC},
        {0x2, 0x2},
    };
    std::vector<DfxFrame> stackC = {
        {0xC, 0xC},
    };
    std::vector<DfxFrame> stackC2 = {
        {0xC, 0xC},
        {0x2, 0x2},
    };
    ASSERT_EQ(callStack.ExpandCallStack(0, stack0), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack1), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stackC), 1u);
}

/**
 * @tc.name: ExpandCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, ExpendCallStackFullCache, TestSize.Level1)
{
    CallStack callStack;
    for (size_t i = 0; i < MAX_CALL_FRAME_EXPAND_CACHE_SIZE; i++) {
        std::vector<DfxFrame> stack = {{rnd_(), rnd_()}};
        callStack.ExpandCallStack(0, stack);
    }
    for (size_t i = 0; i < MAX_CALL_FRAME_EXPAND_CACHE_SIZE; i++) {
        std::vector<DfxFrame> stack = {{rnd_(), rnd_()}};
        callStack.ExpandCallStack(0, stack);
    }
    EXPECT_EQ(callStack.cachedCallFramesMap_[0].size(), MAX_CALL_FRAME_EXPAND_CACHE_SIZE);
}

/**
 * @tc.name: ExpandCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, ExpendCallStackSmall, TestSize.Level2)
{
    CallStack callStack;
    std::vector<DfxFrame> stack0 = {};
    std::vector<DfxFrame> stack1 = {{0x1, 0x1}};
    std::vector<DfxFrame> stack2 = {{0x1, 0x1}, {0x2, 0x2}};
    ASSERT_EQ(callStack.ExpandCallStack(0, stack0), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack1), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack1), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack2, 2), 0u);
}

/**
 * @tc.name: ExpandCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, ExpendCallStackLimit, TestSize.Level2)
{
    /*
                3    2    1    0
        cache   A -> B -> C
        stack2            C
        expand            C

        stack3       B -> C
        expand  A -> B -> C

        stack4            C -> D
        expand            C
    */
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH, true);
    CallStack callStack;

    std::vector<DfxFrame> stack1 = {
        {0x1u, 0x1u},
        {0x2u, 0x2u},
        {0x3u, 0x3u},
    };
    std::vector<DfxFrame> stack2 = {
        {0x1u, 0x1u},
    };
    std::vector<DfxFrame> stack3 = {
        {0x1u, 0x1u},
        {0x2u, 0x2u},
    };
    std::vector<DfxFrame> stack4 = {
        {0x0u, 0x0u},
        {0x1u, 0x1u},
    };

    ASSERT_EQ(callStack.ExpandCallStack(0, stack1, 2u), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack2, 2u), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack3, 2u), 1u);
    EXPECT_THAT(stack1, testing::ContainerEq(stack3));
    ASSERT_EQ(callStack.ExpandCallStack(0, stack4, 2u), 0u);
}

/**
 * @tc.name: ExpandCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, ExpendCallStackABABAB, TestSize.Level1)
{
    /*
                Caller                         Called
        cache   A -> B -> C -> A -> B -> C -> A -> B
        stack2                           C
        expand  A -> B -> C -> A -> B -> C

        stack3                      B -> C
        expand  A -> B -> C -> A -> B -> C

        stack4                           C -> D
        expand  A -> B -> C -> A -> B -> C -> D
    */
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH, true);
    CallStack callStack;

    std::vector<DfxFrame> stack1 = {
        {0xb, 0xb}, {0xa, 0xa}, {0xc, 0xc}, {0xb, 0xb},
        {0xa, 0xa}, {0xc, 0xc}, {0xb, 0xb}, {0xa, 0xa},
    };
    std::vector<DfxFrame> stack2 = {
        {0xc, 0xc},
    };
    std::vector<DfxFrame> stack3 = {
        {0xc, 0xc},
        {0xb, 0xb},
    };
    std::vector<DfxFrame> stack4 = {
        {0xd, 0xd},
        {0xc, 0xc},
    };

    ASSERT_EQ(callStack.ExpandCallStack(0, stack1), 0u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack2), 5u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack3), 4u);
    ASSERT_EQ(callStack.ExpandCallStack(0, stack4), 5u);
}

/**
 * @tc.name: UnwindCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, UnwindCallStack, TestSize.Level1)
{
#if !is_linux
    std::vector<u64> regs;
    std::vector<u8> data;
    LoadFromFile(PATH_RESOURCE_TEST_DWARF_DATA + TEST_DWARF_USER_REGS_0, regs);
    LoadFromFile(PATH_RESOURCE_TEST_DWARF_DATA + TEST_DWARF_USER_DATA_0, data);
    if (regs.size() > 0 and data.size() > 0) {
#ifdef __arm__
        ASSERT_EQ(regs.size(), 16u);
#endif
        std::vector<std::unique_ptr<SymbolsFile>> symbolsFiles;
        auto &symbolsFile = symbolsFiles.emplace_back(SymbolsFile::CreateSymbolsFile(
            SYMBOL_ELF_FILE, TEST_DWARF_ELF));
        ASSERT_EQ(symbolsFile->setSymbolsFilePath(PATH_RESOURCE_TEST_DWARF_DATA), true);
        ASSERT_EQ(symbolsFile->LoadSymbols(), true);
        // fix the name
        symbolsFile->filePath_ = TEST_DWARF_MMAP.front().fileName;

        VirtualThread thread(getpid(), symbolsFiles);
        MakeMaps(thread);
        std::vector<DfxFrame> callFrames;
        CallStack callStack;

        bool ret = callStack.UnwindCallStack(thread, false, regs.data(), regs.size(), data.data(), data.size(),
                                             callFrames);
        ASSERT_TRUE(ret);
        ASSERT_LE(TEST_DWARF_FRAMES.size(), callFrames.size());
    }
#endif
}

/**
 * @tc.name: ClearCache
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, ClearCache, TestSize.Level2)
{
    uint n = 0;
    CallStack callStack;
    callStack.lastPid_ = n++;
    callStack.lastAddr_ = n++;
    callStack.lastData_ = n++;
    callStack.stackPoint_ = n++;
    callStack.stackEnd_ = n++;
    callStack.regsNum_ = n++;
    callStack.stackSize_ = n++;
    callStack.ClearCache();
    EXPECT_EQ(callStack.lastPid_, -1);
    EXPECT_EQ(callStack.lastAddr_, 0);
    EXPECT_EQ(callStack.lastData_, 0);
    EXPECT_EQ(callStack.stackPoint_, 0);
    EXPECT_EQ(callStack.stackEnd_, 0);
    EXPECT_EQ(callStack.regs_, nullptr);
    EXPECT_EQ(callStack.regsNum_, 0);
    EXPECT_EQ(callStack.stack_, nullptr);
    EXPECT_EQ(callStack.stackSize_, 0);
    EXPECT_EQ(callStack.cachedCallFramesMap_.size(), 0);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
