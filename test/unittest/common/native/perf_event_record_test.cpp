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

#include "perf_event_record_test.h"

#include <cstring>
#include <thread>

using namespace testing::ext;

namespace OHOS {
namespace Developtools {
namespace HiPerf {
class PerfEventRecordTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static constexpr size_t HEADER_SIZE = sizeof(perf_event_header);
};

void PerfEventRecordTest::SetUpTestCase() {}

void PerfEventRecordTest::TearDownTestCase() {}

void PerfEventRecordTest::SetUp() {}

void PerfEventRecordTest::TearDown() {}

static int CompareByteStream(const uint8_t *a, const uint8_t *b, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        if (a[i] > b[i]) {
            return (a[i] - b[i]);
        } else if (a[i] < b[i]) {
            return (int(a[i]) - int(b[i]));
        }
    }
    return 0;
}

/**
 * @tc.name: Test
 * @tc.desc:
 * @tc.type: FUNC
 */
const std::string RECORDNAME_MMAP = "mmap";
HWTEST_F(PerfEventRecordTest, Mmap, TestSize.Level0)
{
    PerfRecordMmapData data {1, 2, 3, 4, 5, "testdatammap"};
    PerfRecordMmap recordIn {true,     data.pid,   data.tid,     data.addr,
                             data.len, data.pgoff, data.filename};

    ASSERT_EQ(recordIn.GetType(), PERF_RECORD_MMAP);
    ASSERT_EQ(recordIn.GetName(), RECORDNAME_MMAP);
    ASSERT_EQ(recordIn.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(recordIn.GetHeaderSize(), HEADER_SIZE);

    std::vector<uint8_t> header;
    recordIn.GetHeaderBinary(header);
    std::vector<uint8_t> buff;
    ASSERT_TRUE(recordIn.GetBinary(buff));
    ASSERT_EQ(CompareByteStream(header.data(), buff.data(), HEADER_SIZE), 0);

    size_t buffSize = HEADER_SIZE + sizeof(PerfRecordMmapData) - KILO + strlen(data.filename) + 1;
    ASSERT_EQ(recordIn.GetSize(), buffSize);

    PerfRecordMmap recordOut;
    recordOut.Init(buff.data());
    ASSERT_EQ(recordOut.GetType(), PERF_RECORD_MMAP);
    ASSERT_EQ(recordOut.GetName(), RECORDNAME_MMAP);
    ASSERT_EQ(recordOut.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(recordOut.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(recordOut.GetSize(), buffSize);
    ASSERT_EQ(recordOut.data_.pid, data.pid);
    ASSERT_EQ(recordOut.data_.tid, data.tid);
    ASSERT_EQ(recordOut.data_.addr, data.addr);
    ASSERT_EQ(recordOut.data_.len, data.len);
    ASSERT_EQ(recordOut.data_.pgoff, data.pgoff);
    ASSERT_EQ(strcmp(recordOut.data_.filename, data.filename), 0);
}

const std::string RECORDNAME_MMAP2 = "mmap2";
HWTEST_F(PerfEventRecordTest, Mmap2, TestSize.Level2)
{
    PerfRecordMmap2Data data {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, "testdatammap2"};
    PerfRecordMmap2 recordIn {true,     data.pid, data.tid, data.addr, data.len,   data.pgoff,
                              data.maj, data.min, data.ino, data.prot, data.flags, data.filename};

    ASSERT_EQ(recordIn.GetType(), PERF_RECORD_MMAP2);
    ASSERT_EQ(recordIn.GetName(), RECORDNAME_MMAP2);
    ASSERT_EQ(recordIn.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(recordIn.GetHeaderSize(), HEADER_SIZE);

    std::vector<uint8_t> header;
    recordIn.GetHeaderBinary(header);
    std::vector<uint8_t> buff;
    ASSERT_TRUE(recordIn.GetBinary(buff));
    ASSERT_EQ(CompareByteStream(header.data(), buff.data(), HEADER_SIZE), 0);

    size_t buffSize = HEADER_SIZE + sizeof(PerfRecordMmap2Data) - KILO + strlen(data.filename) + 1;
    ASSERT_EQ(recordIn.GetSize(), buffSize);

    PerfRecordMmap2 recordOut;
    recordOut.Init(buff.data());
    ASSERT_EQ(recordOut.GetType(), PERF_RECORD_MMAP2);
    ASSERT_EQ(recordOut.GetName(), RECORDNAME_MMAP2);
    ASSERT_EQ(recordOut.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(recordOut.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(recordOut.GetSize(), buffSize);
    ASSERT_EQ(recordOut.data_.pid, data.pid);
    ASSERT_EQ(recordOut.data_.tid, data.tid);
    ASSERT_EQ(recordOut.data_.addr, data.addr);
    ASSERT_EQ(recordOut.data_.len, data.len);
    ASSERT_EQ(recordOut.data_.pgoff, data.pgoff);
    ASSERT_EQ(recordOut.data_.maj, data.maj);
    ASSERT_EQ(recordOut.data_.min, data.min);
    ASSERT_EQ(recordOut.data_.ino, data.ino);
    ASSERT_EQ(recordOut.data_.prot, data.prot);
    ASSERT_EQ(recordOut.data_.flags, data.flags);
    ASSERT_EQ(strcmp(recordOut.data_.filename, data.filename), 0);
}

const std::string RECORDNAME_COMM = "comm";
HWTEST_F(PerfEventRecordTest, Comm, TestSize.Level0)
{
    PerfRecordCommData data {1, 2, "testdatcomm"};
    PerfRecordComm recordIn {true, data.pid, data.tid, data.comm};

    ASSERT_EQ(recordIn.GetType(), PERF_RECORD_COMM);
    ASSERT_EQ(recordIn.GetName(), RECORDNAME_COMM);
    ASSERT_EQ(recordIn.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(recordIn.GetHeaderSize(), HEADER_SIZE);

    std::vector<uint8_t> header;
    recordIn.GetHeaderBinary(header);
    std::vector<uint8_t> buff;
    ASSERT_TRUE(recordIn.GetBinary(buff));
    ASSERT_EQ(CompareByteStream(header.data(), buff.data(), HEADER_SIZE), 0);

    size_t buffSize = HEADER_SIZE + sizeof(PerfRecordCommData) - KILO + strlen(data.comm) + 1;
    ASSERT_EQ(recordIn.GetSize(), buffSize);
    PerfRecordComm recordOut;
    recordOut.Init(buff.data());
    ASSERT_EQ(recordOut.GetType(), PERF_RECORD_COMM);
    ASSERT_EQ(recordOut.GetName(), RECORDNAME_COMM);
    ASSERT_EQ(recordOut.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(recordOut.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(recordOut.GetSize(), buffSize);
    ASSERT_EQ(recordOut.data_.pid, data.pid);
    ASSERT_EQ(recordOut.data_.tid, data.tid);
    ASSERT_EQ(strcmp(recordOut.data_.comm, data.comm), 0);
}

const std::string RECORDNAME_LOST = "lost";
HWTEST_F(PerfEventRecordTest, Lost, TestSize.Level2)
{
    struct TestRecordLostst {
        perf_event_header h;
        PerfRecordLostData d;
    };
    TestRecordLostst data = {
        {PERF_RECORD_LOST_SAMPLES, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordLostst)},
        {1, 2}};

    PerfRecordLost record;
    record.Init((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_LOST_SAMPLES);
    ASSERT_EQ(record.GetName(), RECORDNAME_LOST);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

const std::string RECORDNAME_EXIT = "exit";
HWTEST_F(PerfEventRecordTest, Exit, TestSize.Level2)
{
    struct TestRecordExitst {
        perf_event_header h;
        PerfRecordExitData d;
    };
    TestRecordExitst data = {{PERF_RECORD_EXIT, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordExitst)},
                             {1, 2, 3, 4, 5}};

    PerfRecordExit record;
    record.Init((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_EXIT);
    ASSERT_EQ(record.GetName(), RECORDNAME_EXIT);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

const std::string RECORDNAME_THROTTLE = "throttle";
HWTEST_F(PerfEventRecordTest, Throttle, TestSize.Level2)
{
    struct TestRecordThrottlest {
        perf_event_header h;
        PerfRecordThrottleData d;
    };
    TestRecordThrottlest data = {
        {PERF_RECORD_THROTTLE, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordThrottlest)},
        {1, 2, 3}};

    PerfRecordThrottle record;
    record.Init((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_THROTTLE);
    ASSERT_EQ(record.GetName(), RECORDNAME_THROTTLE);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

const std::string RECORDNAME_UNTHROTTLE = "unthrottle";
HWTEST_F(PerfEventRecordTest, Unthrottle, TestSize.Level2)
{
    struct TestRecordUNThrottlest {
        perf_event_header h;
        PerfRecordThrottleData d;
    };
    TestRecordUNThrottlest data = {
        {PERF_RECORD_UNTHROTTLE, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordUNThrottlest)},
        {1, 2, 3}};

    PerfRecordUnthrottle record;
    record.Init((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_UNTHROTTLE);
    ASSERT_EQ(record.GetName(), RECORDNAME_UNTHROTTLE);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

const std::string RECORDNAME_FORK = "fork";
HWTEST_F(PerfEventRecordTest, Fork, TestSize.Level1)
{
    struct TestRecordForkst {
        perf_event_header h;
        PerfRecordForkData d;
    };
    TestRecordForkst data = {{PERF_RECORD_FORK, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordForkst)},
                             {1, 2, 3, 4, 5}};

    PerfRecordFork record;
    record.Init((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_FORK);
    ASSERT_EQ(record.GetName(), RECORDNAME_FORK);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

struct TestRecordSamplest {
    perf_event_header header_;
    PerfRecordSampleData data_;
};

static void InitTestRecordSample(TestRecordSamplest &record)
{
    record.header_.size = sizeof(perf_event_header);
    record.header_.size +=
        sizeof(record.data_.sample_id) + sizeof(record.data_.sample_id) + sizeof(record.data_.ip) +
        sizeof(record.data_.pid) + sizeof(record.data_.tid) + sizeof(record.data_.time) +
        sizeof(record.data_.addr) + sizeof(record.data_.id) + sizeof(record.data_.stream_id) +
        sizeof(record.data_.cpu) + sizeof(record.data_.res) + sizeof(record.data_.period);

    // v??

    record.data_.nr = 0;
    record.data_.ips = nullptr;
    record.header_.size += sizeof(record.data_.nr);
    record.data_.raw_size = 0;
    record.data_.raw_data = nullptr;
    record.header_.size += sizeof(record.data_.raw_size);
    record.data_.bnr = 0;
    record.data_.lbr = nullptr;
    record.header_.size += sizeof(record.data_.bnr);
    record.data_.user_abi = 0;
    record.data_.reg_mask = 0;
    record.header_.size += sizeof(record.data_.user_abi);
    record.data_.stack_size = 0;
    record.header_.size += sizeof(record.data_.stack_size);
    // others
}

static bool CompareRecordSample50(const TestRecordSamplest &record, const std::vector<u8> &buf,
                                  size_t offset)
{
    const uint8_t *p = buf.data() + offset;

    if (record.data_.nr != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    if (record.data_.raw_size != *(reinterpret_cast<const u32 *>(p))) {
        return false;
    }
    p += sizeof(u32);

    if (record.data_.bnr != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    if (record.data_.user_abi != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    if (record.data_.stack_size != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    return true;
}

static bool CompareRecordSample(const TestRecordSamplest &record, const std::vector<u8> &buf)
{
    if (buf.size() < record.header_.size) {
        return false;
    }
    const uint8_t *p = buf.data();
    p += sizeof(perf_event_header);

    if (record.data_.sample_id != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    if (record.data_.ip != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    if (record.data_.pid != *(reinterpret_cast<const u32 *>(p))) {
        return false;
    }
    p += sizeof(u32);

    if (record.data_.tid != *(reinterpret_cast<const u32 *>(p))) {
        return false;
    }
    p += sizeof(u32);

    if (record.data_.time != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    if (record.data_.addr != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    if (record.data_.id != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    if (record.data_.stream_id != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    if (record.data_.cpu != *(reinterpret_cast<const u32 *>(p))) {
        return false;
    }
    p += sizeof(u32);

    if (record.data_.res != *(reinterpret_cast<const u32 *>(p))) {
        return false;
    }
    p += sizeof(u32);

    if (record.data_.period != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    return CompareRecordSample50(record, buf, p - buf.data());
}

const std::string RECORDNAME_SAMPLE = "sample";
HWTEST_F(PerfEventRecordTest, Sample, TestSize.Level1)
{
    perf_event_attr attr {};
    attr.sample_type = UINT64_MAX;
    TestRecordSamplest data = {
        {PERF_RECORD_SAMPLE, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordSamplest)},
        {}};
    InitTestRecordSample(data);

    PerfRecordSample record;
    record.Init((uint8_t *)&data, attr);
    ASSERT_EQ(record.GetType(), PERF_RECORD_SAMPLE);
    ASSERT_EQ(record.GetName(), RECORDNAME_SAMPLE);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_TRUE(CompareRecordSample(data, buff));
}

HWTEST_F(PerfEventRecordTest, SampleReplaceWithCallStack1, TestSize.Level2)
{
    perf_event_attr attr {};
    attr.sample_type = UINT64_MAX;
    TestRecordSamplest data = {
        {PERF_RECORD_SAMPLE, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordSamplest)},
        {}};
    InitTestRecordSample(data);

    PerfRecordSample record;
    record.Init((uint8_t *)&data, attr);
    record.sampleType_ |= PERF_SAMPLE_REGS_USER;
    record.sampleType_ |= PERF_SAMPLE_STACK_USER;
    record.sampleType_ |= PERF_SAMPLE_CALLCHAIN;

    std::vector<u64> ips = {};
    record.data_.ips = ips.data();
    record.data_.nr = ips.size();
    record.callFrames_ = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    record.ReplaceWithCallStack();
    ASSERT_EQ(record.data_.reg_nr, 0u);
    ASSERT_EQ(record.data_.user_abi, 0u);
    ASSERT_EQ(record.data_.stack_size, 0u);
    ASSERT_EQ(record.data_.dyn_size, 0u);

    // include PERF_CONTEXT_USER
    ASSERT_EQ(record.callFrames_.size() + 1, record.data_.nr);
    ASSERT_EQ(record.data_.ips[0], PERF_CONTEXT_USER);
    for (size_t i = 1; i < record.data_.nr; i++) {
        ASSERT_EQ(record.data_.ips[i], record.callFrames_.at(i - 1).pc);
    }
    // result is 1 - 9
}

HWTEST_F(PerfEventRecordTest, SampleReplaceWithCallStack2, TestSize.Level2)
{
    perf_event_attr attr {};
    attr.sample_type = UINT64_MAX;
    TestRecordSamplest data = {
        {PERF_RECORD_SAMPLE, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordSamplest)},
        {}};
    InitTestRecordSample(data);

    PerfRecordSample record;
    record.Init((uint8_t *)&data, attr);
    record.sampleType_ |= PERF_SAMPLE_CALLCHAIN;

    std::vector<u64> ips = {};
    record.data_.ips = ips.data();
    record.data_.nr = ips.size();
    record.callFrames_ = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    record.ReplaceWithCallStack();
    // include PERF_CONTEXT_USER
    ASSERT_EQ(record.callFrames_.size() + 1, record.data_.nr);
    ASSERT_EQ(record.data_.ips[0], PERF_CONTEXT_USER);
    for (size_t i = 1; i < record.data_.nr; i++) {
        ASSERT_EQ(record.data_.ips[i], record.callFrames_.at(i - 1).pc);
    }
    // result is 1 - 9
}

HWTEST_F(PerfEventRecordTest, SampleReplaceWithCallStack3, TestSize.Level2)
{
    perf_event_attr attr {};
    attr.sample_type = UINT64_MAX;
    TestRecordSamplest data = {
        {PERF_RECORD_SAMPLE, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordSamplest)},
        {}};
    InitTestRecordSample(data);

    PerfRecordSample record;
    record.Init((uint8_t *)&data, attr);
    record.sampleType_ |= PERF_SAMPLE_CALLCHAIN;

    record.callFrames_ = {4, 5, 6, 7, 8, 9};
    std::vector<u64> ips = {0, 1, 2, 3};
    record.data_.ips = ips.data();
    record.data_.nr = ips.size();
    record.ReplaceWithCallStack();
    // include PERF_CONTEXT_USER
    ASSERT_EQ(record.callFrames_.size() + ips.size() + 1, record.data_.nr);
    for (size_t i = 0; i < ips.size(); i++) {
        ASSERT_EQ(record.data_.ips[i], ips[i]);
    }
    ASSERT_EQ(record.data_.ips[ips.size()], PERF_CONTEXT_USER);
    for (size_t i = 0; i < record.callFrames_.size(); i++) {
        ASSERT_EQ(record.data_.ips[i + ips.size() + 1], record.callFrames_.at(i).pc);
    }
    // result is 0 - 3 , PERF_CONTEXT_USER , 4 - 9
}

HWTEST_F(PerfEventRecordTest, SampleReplaceWithCallStack4, TestSize.Level3)
{
    perf_event_attr attr {};
    attr.sample_type = UINT64_MAX;
    TestRecordSamplest data = {
        {PERF_RECORD_SAMPLE, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordSamplest)},
        {}};
    InitTestRecordSample(data);

    PerfRecordSample record;
    record.Init((uint8_t *)&data, attr);
    record.sampleType_ |= PERF_SAMPLE_CALLCHAIN;

    record.callFrames_ = {};
    std::vector<u64> ips = {0, 1, 2, 3};
    record.data_.ips = ips.data();
    record.data_.nr = ips.size();
    record.ReplaceWithCallStack();
    // not PERF_CONTEXT_USER will add
    for (size_t i = 0; i < record.data_.nr; i++) {
        ASSERT_EQ(record.data_.ips[i], ips[i]);
    }
    // result is 0 - 3
}

const std::string RECORDNAME_READ = "read";
HWTEST_F(PerfEventRecordTest, Read, TestSize.Level1)
{
    struct PerfRecordReadst {
        perf_event_header h;
        PerfRecordReadData d;
    };
    PerfRecordReadst data = {{PERF_RECORD_READ, PERF_RECORD_MISC_KERNEL, sizeof(PerfRecordReadst)},
                             {1, 2, {11, 12, 13, 14}}};

    PerfRecordRead record;
    record.Init((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_READ);
    ASSERT_EQ(record.GetName(), RECORDNAME_READ);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

const std::string RECORDNAME_AUX = "aux";
HWTEST_F(PerfEventRecordTest, Aux, TestSize.Level2)
{
    struct PerfRecordAuxst {
        perf_event_header h;
        PerfRecordAuxData d;
    };
    PerfRecordAuxst data = {{PERF_RECORD_AUX, PERF_RECORD_MISC_KERNEL, sizeof(PerfRecordAuxst)},
                            {1, 2, 3}};

    PerfRecordAux record;
    record.Init((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_AUX);
    ASSERT_EQ(record.GetName(), RECORDNAME_AUX);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

const std::string RECORDNAME_ITRACE_START = "itraceStart";
HWTEST_F(PerfEventRecordTest, ItraceStart, TestSize.Level2)
{
    struct PerfRecordItraceStartst {
        perf_event_header h;
        PerfRecordItraceStartData d;
    };
    PerfRecordItraceStartst data = {
        {PERF_RECORD_ITRACE_START, PERF_RECORD_MISC_KERNEL, sizeof(PerfRecordItraceStartst)},
        {1, 2}};

    PerfRecordItraceStart record;
    record.Init((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_ITRACE_START);
    ASSERT_EQ(record.GetName(), RECORDNAME_ITRACE_START);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

const std::string RECORDNAME_LOST_SAMPLES = "lostSamples";
HWTEST_F(PerfEventRecordTest, LostSamples, TestSize.Level2)
{
    struct PerfRecordLostSamplesst {
        perf_event_header h;
        PerfRecordLostSamplesData d;
    };
    PerfRecordLostSamplesst data = {
        {PERF_RECORD_LOST_SAMPLES, PERF_RECORD_MISC_KERNEL, sizeof(PerfRecordLostSamplesst)},
        {1}};

    PerfRecordLostSamples record;
    record.Init((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_LOST_SAMPLES);
    ASSERT_EQ(record.GetName(), RECORDNAME_LOST_SAMPLES);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

const std::string RECORDNAME_SWITCH = "switch";
HWTEST_F(PerfEventRecordTest, Switch, TestSize.Level2)
{
    struct PerfRecordSwitchst {
        perf_event_header h;
        PerfRecordSwitchData d;
    };
    PerfRecordSwitchst data = {
        {PERF_RECORD_SWITCH, PERF_RECORD_MISC_KERNEL, sizeof(perf_event_header)},
        {}};

    PerfRecordSwitch record;
    record.Init((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_SWITCH);
    ASSERT_EQ(record.GetName(), RECORDNAME_SWITCH);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), HEADER_SIZE);

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), HEADER_SIZE), 0);
}

const std::string RECORDNAME_SWITCH_CPU_WIDE = "switchCpuWide";
HWTEST_F(PerfEventRecordTest, SwitchCpuWide, TestSize.Level2)
{
    struct PerfRecordSwitchCpuWidest {
        perf_event_header h;
        PerfRecordSwitchCpuWideData d;
    };
    PerfRecordSwitchCpuWidest data = {
        {PERF_RECORD_SWITCH_CPU_WIDE, PERF_RECORD_MISC_KERNEL, sizeof(PerfRecordSwitchCpuWidest)},
        {}};

    PerfRecordSwitchCpuWide record;
    record.Init((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_SWITCH_CPU_WIDE);
    ASSERT_EQ(record.GetName(), RECORDNAME_SWITCH_CPU_WIDE);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

HWTEST_F(PerfEventRecordTest, GetPerfEventRecord, TestSize.Level1)
{
    struct PerfRecordSwitchCpuWidest {
        perf_event_header h;
        PerfRecordSwitchCpuWideData d;
    };
    PerfRecordSwitchCpuWidest data = {
        {PERF_RECORD_SWITCH_CPU_WIDE, PERF_RECORD_MISC_KERNEL, sizeof(PerfRecordSwitchCpuWidest)},
        {}};
    perf_event_attr attr {};
    attr.sample_type = UINT64_MAX;
    for (size_t type = PERF_RECORD_MMAP; type <= PERF_RECORD_MAX; type++) {
        if (type == PERF_RECORD_SAMPLE) {
            continue;
        }
        PerfEventRecord& perfEventRecord =
            PerfEventRecordFactory::GetPerfEventRecord(static_cast<perf_event_type>(type),
                                                       reinterpret_cast<uint8_t *>(&data), attr);
        if (type < PERF_RECORD_NAMESPACES) {
            ASSERT_EQ(perfEventRecord.GetName() != nullptr, true);
        }
    }
    PerfEventRecord& perfEventRecord =
        PerfEventRecordFactory::GetPerfEventRecord(static_cast<perf_event_type>(PERF_RECORD_AUXTRACE),
                                                   reinterpret_cast<uint8_t *>(&data), attr);
    ASSERT_EQ(perfEventRecord.GetName() != nullptr, true);
}

HWTEST_F(PerfEventRecordTest, GetPerfEventRecord2, TestSize.Level2)
{
    struct PerfRecordSwitchCpuWidest {
        perf_event_header h;
        PerfRecordSwitchCpuWideData d;
    };
    PerfRecordSwitchCpuWidest data = {
        {PERF_RECORD_SWITCH_CPU_WIDE, PERF_RECORD_MISC_KERNEL, sizeof(PerfRecordSwitchCpuWidest)},
        {}};
    perf_event_attr attr {};
    attr.sample_type = UINT64_MAX;
    PerfEventRecord& perfEventRecord1 =
        PerfEventRecordFactory::GetPerfEventRecord(static_cast<perf_event_type>(PERF_RECORD_AUXTRACE),
                                                   reinterpret_cast<uint8_t *>(&data), attr);
    PerfEventRecord& perfEventRecord2 =
        PerfEventRecordFactory::GetPerfEventRecord(static_cast<perf_event_type>(PERF_RECORD_AUXTRACE),
                                                   reinterpret_cast<uint8_t *>(&data), attr);

    ASSERT_TRUE(&perfEventRecord1 == &perfEventRecord2);
}

HWTEST_F(PerfEventRecordTest, GetPerfEventRecord3, TestSize.Level2)
{
    struct PerfRecordSwitchCpuWidest {
        perf_event_header h;
        PerfRecordSwitchCpuWideData d;
    };
    PerfRecordSwitchCpuWidest data = {
        {PERF_RECORD_SWITCH_CPU_WIDE, PERF_RECORD_MISC_KERNEL, sizeof(PerfRecordSwitchCpuWidest)},
        {}};
    perf_event_attr attr {};
    attr.sample_type = UINT64_MAX;
    PerfEventRecord& perfEventRecord1 =
        PerfEventRecordFactory::GetPerfEventRecord(static_cast<perf_event_type>(PERF_RECORD_AUXTRACE),
                                                   reinterpret_cast<uint8_t *>(&data), attr);
    PerfEventRecord& perfEventRecord2 =
        PerfEventRecordFactory::GetPerfEventRecord(INT32_MAX,
                                                   reinterpret_cast<uint8_t *>(&data), attr);
    ASSERT_TRUE(perfEventRecord1.GetName() != nullptr);
    ASSERT_TRUE(perfEventRecord2.GetName() == nullptr);
}

HWTEST_F(PerfEventRecordTest, GetPerfEventRecord4, TestSize.Level2)
{
    static constexpr size_t sizeOffset = 20;
    std::vector<PerfRecordType> types = {
        PERF_RECORD_MMAP,
        PERF_RECORD_MMAP2,
        PERF_RECORD_LOST,
        PERF_RECORD_COMM,
        PERF_RECORD_EXIT,
        PERF_RECORD_THROTTLE,
        PERF_RECORD_UNTHROTTLE,
        PERF_RECORD_FORK,
        PERF_RECORD_READ,
        PERF_RECORD_AUX,
        PERF_RECORD_AUXTRACE,
        PERF_RECORD_ITRACE_START,
        PERF_RECORD_LOST_SAMPLES,
        PERF_RECORD_SWITCH,
        PERF_RECORD_SWITCH_CPU_WIDE
    };
    perf_event_header header;
    size_t size = sizeof(perf_event_header) + sizeOffset;
    header.size = size;
    uint8_t* data = static_cast<uint8_t*>(malloc(size));
    ASSERT_EQ(memset_s(data, size, 0, size), 0);
    ASSERT_EQ(memcpy_s(data, sizeof(perf_event_header),
        reinterpret_cast<uint8_t*>(&header), sizeof(perf_event_header)), 0);
    for (PerfRecordType type : types) {
        perf_event_attr attr = {};
        PerfEventRecord& record =
            PerfEventRecordFactory::GetPerfEventRecord(static_cast<perf_event_type>(type),
                                                       data, attr);
        EXPECT_NE(record.GetName(), nullptr);
    }
    free(data);
}

HWTEST_F(PerfEventRecordTest, GetPerfEventRecordMmap2, TestSize.Level2)
{
    struct PerfRecordMmap2est {
        perf_event_header h;
        PerfRecordMmap2Data d;
    };
    constexpr uint32_t pid = 10;
    constexpr uint32_t tid = 11;
    constexpr uint32_t testNum1 = 12;
    constexpr uint64_t addr = 111;
    constexpr uint64_t testNum2 = 13;
    PerfRecordMmap2est data = {
        {PERF_RECORD_MMAP2, PERF_RECORD_MISC_KERNEL, sizeof(PerfRecordMmap2est)},
        {pid, tid, addr, testNum2, testNum2, testNum1, testNum1, testNum2, testNum2,
         testNum1, testNum1, "testdatammap2"}};
    size_t size = HEADER_SIZE + sizeof(PerfRecordMmap2Data) - KILO + strlen(data.d.filename) + 1;
    data.h.size = size;
    perf_event_attr attr {};
    attr.sample_type = UINT64_MAX;
    PerfEventRecord& perfEventRecord1 =
        PerfEventRecordFactory::GetPerfEventRecord(static_cast<perf_event_type>(PERF_RECORD_MMAP2),
                                                   reinterpret_cast<uint8_t *>(&data), attr);
    PerfRecordMmap2& record1 = static_cast<PerfRecordMmap2&>(perfEventRecord1);
    EXPECT_EQ(record1.discard_, false);
    record1.discard_ = true;
    PerfEventRecord& perfEventRecord2 =
        PerfEventRecordFactory::GetPerfEventRecord(static_cast<perf_event_type>(PERF_RECORD_MMAP2),
                                                   reinterpret_cast<uint8_t *>(&data), attr);
    PerfRecordMmap2& record2 = static_cast<PerfRecordMmap2&>(perfEventRecord2);
    EXPECT_EQ(record2.discard_, false);
    EXPECT_EQ(record2.GetType(), PERF_RECORD_MMAP2);
    EXPECT_EQ(record2.GetName(), RECORDNAME_MMAP2);
    EXPECT_EQ(record2.GetMisc(), PERF_RECORD_MISC_KERNEL);
    EXPECT_EQ(record2.GetHeaderSize(), HEADER_SIZE);
    EXPECT_EQ(record2.GetSize(), size);
    EXPECT_EQ(record2.data_.pid, data.d.pid);
    EXPECT_EQ(record2.data_.tid, data.d.tid);
    EXPECT_EQ(record2.data_.addr, data.d.addr);
    EXPECT_EQ(record2.data_.len, data.d.len);
    EXPECT_EQ(record2.data_.pgoff, data.d.pgoff);
    EXPECT_EQ(record2.data_.maj, data.d.maj);
    EXPECT_EQ(record2.data_.min, data.d.min);
    EXPECT_EQ(record2.data_.ino, data.d.ino);
    EXPECT_EQ(record2.data_.prot, data.d.prot);
    EXPECT_EQ(record2.data_.flags, data.d.flags);
    EXPECT_EQ(strcmp(record2.data_.filename, data.d.filename), 0);
}

HWTEST_F(PerfEventRecordTest, MultiThreadGetPerfEventRecord, TestSize.Level1)
{
    struct PerfRecordSwitchCpuWidest {
        perf_event_header h;
        PerfRecordSwitchCpuWideData d;
    };
    PerfRecordSwitchCpuWidest data = {
        {PERF_RECORD_SWITCH_CPU_WIDE, PERF_RECORD_MISC_KERNEL, sizeof(PerfRecordSwitchCpuWidest)},
        {}};
    perf_event_attr attr {};
    attr.sample_type = UINT64_MAX;
    PerfEventRecord& perfEventRecord1 =
        PerfEventRecordFactory::GetPerfEventRecord(static_cast<perf_event_type>(PERF_RECORD_AUXTRACE),
                                                   reinterpret_cast<uint8_t *>(&data), attr);

    std::thread t1([&perfEventRecord1, &data, attr]() {
        PerfEventRecord& perfEventRecord2 =
            PerfEventRecordFactory::GetPerfEventRecord(static_cast<perf_event_type>(PERF_RECORD_AUXTRACE),
                                                       reinterpret_cast<uint8_t *>(&data), attr);
        ASSERT_TRUE(&perfEventRecord1 != &perfEventRecord2);
    });
    t1.join();
}

HWTEST_F(PerfEventRecordTest, CreatePerfRecordMmap, TestSize.Level1)
{
    perf_event_header header;
    header.size = sizeof(PerfRecordMmapData) + sizeof(perf_event_header);
    PerfRecordMmapData data;
    for (uint32_t i = 0; i < KILO; i++) {
        data.filename[i] = 'a';
    }
    size_t size = sizeof(PerfRecordMmapData) + sizeof(perf_event_header) + 10;
    uint8_t* p = static_cast<uint8_t*>(malloc(size));
    ASSERT_EQ(memset_s(p, size, 5, size), 0);
    ASSERT_EQ(memcpy_s(p, sizeof(perf_event_header),
        reinterpret_cast<uint8_t*>(&header), sizeof(perf_event_header)), 0);
    ASSERT_EQ(memcpy_s(p + sizeof(perf_event_header), sizeof(PerfRecordMmapData),
        reinterpret_cast<uint8_t*>(&data), sizeof(PerfRecordMmapData)), 0);

    PerfRecordMmap record;
    record.Init(p);
    std::string str = record.data_.filename;
    ASSERT_EQ(str.size(), KILO - 1);
    for (char c : str) {
        EXPECT_EQ(c, 'a');
    }
    free(p);
}

HWTEST_F(PerfEventRecordTest, CreatePerfRecordComm, TestSize.Level1)
{
    perf_event_header header;
    header.size = sizeof(PerfRecordCommData) + sizeof(perf_event_header);
    PerfRecordCommData data;
    for (uint32_t i = 0; i < KILO; i++) {
        data.comm[i] = 'a';
    }
    size_t size = sizeof(PerfRecordCommData) + sizeof(perf_event_header) + 10;
    uint8_t* p = static_cast<uint8_t*>(malloc(size));
    ASSERT_EQ(memset_s(p, size, 5, size), 0);
    ASSERT_EQ(memcpy_s(p, sizeof(perf_event_header),
        reinterpret_cast<uint8_t*>(&header), sizeof(perf_event_header)), 0);
    ASSERT_EQ(memcpy_s(p + sizeof(perf_event_header), sizeof(PerfRecordCommData),
        reinterpret_cast<uint8_t*>(&data), sizeof(PerfRecordCommData)), 0);

    PerfRecordComm record;
    record.Init(p);
    std::string str = record.data_.comm;
    ASSERT_EQ(str.size(), KILO - 1);
    for (char c : str) {
        EXPECT_EQ(c, 'a');
    }
    free(p);
}

HWTEST_F(PerfEventRecordTest, CreatePerfRecordAuxtrace, TestSize.Level2)
{
    perf_event_header header;
    const char* rawData = "rawData";
    size_t len = strlen(rawData) + 1;
    header.size = sizeof(PerfRecordAuxtraceData) + sizeof(perf_event_header);
    PerfRecordAuxtraceData data;
    uint8_t* p = static_cast<uint8_t*>(malloc(header.size + len));
    EXPECT_EQ(memset_s(p, header.size + len, 0, header.size + len), 0);
    if (memcpy_s(p, sizeof(perf_event_header), reinterpret_cast<const uint8_t *>(&header),
                 sizeof(perf_event_header)) != 0) {
        printf("memcpy_s perf_event_header return failed");
    }
    if (memcpy_s(p + sizeof(perf_event_header), sizeof(PerfRecordAuxtraceData),
                 reinterpret_cast<const uint8_t *>(&data), sizeof(PerfRecordAuxtraceData)) != 0) {
        printf("memcpy_s data return failed");
    }
    if (memcpy_s(p + header.size, len, reinterpret_cast<const uint8_t *>(rawData), len) != 0) {
        printf("memcpy_s rawData return failed");
    }
    PerfRecordAuxtrace record;
    record.Init(p);
    ASSERT_NE(record.rawData_, nullptr);
    free(p);
}

HWTEST_F(PerfEventRecordTest, CreatePerfRecordAuxtrace2, TestSize.Level2)
{
    PerfRecordAuxtrace* record = new PerfRecordAuxtrace();
    record->Init(nullptr, {});

    EXPECT_EQ(record->header_.type, PERF_RECORD_MMAP);
    EXPECT_EQ(record->header_.misc, PERF_RECORD_MISC_USER);
    EXPECT_EQ(record->header_.size, 0);

    EXPECT_EQ(record->data_.size, 0);
    EXPECT_EQ(record->data_.offset, 0);
    EXPECT_EQ(record->data_.reference, 0);
    EXPECT_EQ(record->data_.idx, 0);
    EXPECT_EQ(record->data_.tid, 0);
    EXPECT_EQ(record->data_.cpu, 0);
    EXPECT_EQ(record->data_.reserved__, 0);

    EXPECT_EQ(record->rawData_, nullptr);
}

HWTEST_F(PerfEventRecordTest, CreatePerfRecordAuxtrace3, TestSize.Level2)
{
    PerfRecordAuxtrace* record = new PerfRecordAuxtrace();
    record->Init(nullptr, {});
    record->header_.type = PERF_RECORD_AUXTRACE;
    record->header_.misc = PERF_RECORD_MISC_KERNEL;
    record->header_.size = PERF_RECORD_AUXTRACE;
    record->data_.size = 1;
    record->data_.offset = 1;
    record->data_.reference = 1;
    record->data_.idx = 1;
    record->data_.tid = 1;
    record->data_.cpu = 1;
    record->data_.reserved__ = 1;
    std::shared_ptr<u8> ptr = std::make_shared<u8>();
    record->rawData_ = ptr.get();

    record->Init(nullptr, {});
    EXPECT_EQ(record->header_.type, PERF_RECORD_MMAP);
    EXPECT_EQ(record->header_.misc, PERF_RECORD_MISC_USER);
    EXPECT_EQ(record->header_.size, 0);

    EXPECT_EQ(record->data_.size, 0);
    EXPECT_EQ(record->data_.offset, 0);
    EXPECT_EQ(record->data_.reference, 0);
    EXPECT_EQ(record->data_.idx, 0);
    EXPECT_EQ(record->data_.tid, 0);
    EXPECT_EQ(record->data_.cpu, 0);
    EXPECT_EQ(record->data_.reserved__, 0);

    EXPECT_EQ(record->rawData_, nullptr);
}

HWTEST_F(PerfEventRecordTest, SetDumpRemoveStack, TestSize.Level1)
{
    bool dump = PerfRecordSample::IsDumpRemoveStack();
    PerfRecordSample::SetDumpRemoveStack(!dump);
    EXPECT_EQ(PerfRecordSample::IsDumpRemoveStack(), !dump);
    PerfRecordSample::SetDumpRemoveStack(dump);
    EXPECT_EQ(PerfRecordSample::IsDumpRemoveStack(), dump);
}

HWTEST_F(PerfEventRecordTest, GetTime, TestSize.Level1)
{
    static constexpr uint64_t time = 1234u;
    PerfRecordSample sample;
    sample.data_.time = time;
    EXPECT_EQ(sample.GetTime(), time);
}

HWTEST_F(PerfEventRecordTest, AuxTraceInfo, TestSize.Level1)
{
    constexpr uint32_t type    = 4;
    constexpr uint32_t reserve = 0;
    constexpr uint64_t speType = 7;
    constexpr uint64_t cpuMmap = 2;
    struct PerfRecordAuxTraceInfost {
        perf_event_header h;
        PerfRecordAuxtraceInfoData d;
    };
    PerfRecordAuxTraceInfost data = {{PERF_RECORD_AUXTRACE_INFO, PERF_RECORD_MISC_KERNEL,
                                     static_cast<uint16_t>(sizeof(PerfRecordAuxTraceInfost))},
                                     {type, reserve, {speType, cpuMmap}}};

    PerfRecordAuxTraceInfo record;
    record.Init((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_AUXTRACE_INFO);
    ASSERT_EQ(record.GetName(), PERF_RECORD_TYPE_AUXTRACEINFO);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));
    ASSERT_EQ(record.data_.type, type);
    ASSERT_EQ(record.data_.priv[0], speType);
    ASSERT_EQ(record.data_.priv[1], cpuMmap);
}

HWTEST_F(PerfEventRecordTest, TimeConv, TestSize.Level2)
{
    constexpr uint64_t timeShift = 21;
    constexpr uint64_t timeDefalult = 1;
    constexpr uint8_t userTime = 1;
    struct PerfRecordTimeConvst {
        perf_event_header h;
        PerfRecordTtimeConvData d;
    };
    PerfRecordTimeConvst data = {{PERF_RECORD_TIME_CONV, PERF_RECORD_MISC_KERNEL,
                                 static_cast<uint16_t>(sizeof(PerfRecordTimeConvst))},
                                 {timeShift, timeDefalult, timeDefalult, timeDefalult, timeDefalult, userTime}};

    PerfRecordTimeConv record;
    record.Init((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_TIME_CONV);
    ASSERT_EQ(record.GetName(), PERF_RECORD_TYPE_TIMECONV);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));
    ASSERT_EQ(record.data_.time_shift, timeShift);
    ASSERT_EQ(record.data_.time_mult, timeDefalult);
}

HWTEST_F(PerfEventRecordTest, CpuMap, TestSize.Level1)
{
    constexpr uint16_t type = 0;
    constexpr uint16_t cpuNum = 16;
    struct PerfRecordCpuMapst {
        perf_event_header h;
        PerfRecordCpuMapData d;
    };
    PerfRecordCpuMapst data = {{PERF_RECORD_CPU_MAP, PERF_RECORD_MISC_KERNEL,
                               static_cast<uint16_t>(sizeof(PerfRecordCpuMapst))},
                               {type, cpuNum}};

    PerfRecordCpuMap record;
    record.Init((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_CPU_MAP);
    ASSERT_EQ(record.GetName(), PERF_RECORD_TYPE_CPUMAP);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));
    ASSERT_EQ(record.data_.nr, cpuNum);
}

HWTEST_F(PerfEventRecordTest, AuxtraceInit, TestSize.Level1)
{
    const char* rawData = "rawData";
    size_t len = strlen(rawData) + 1;
    perf_event_header header;
    header.size = sizeof(PerfRecordAuxtraceData) + sizeof(perf_event_header);
    header.type = PERF_RECORD_AUXTRACE;
    header.misc = PERF_RECORD_MISC_USER;
    PerfRecordAuxtraceData data;
    uint8_t* p = static_cast<uint8_t*>(malloc(header.size + len));
    EXPECT_EQ(memset_s(p, header.size + len, 0, header.size + len), 0);
    if (memcpy_s(p, sizeof(perf_event_header), reinterpret_cast<const uint8_t *>(&header),
                 sizeof(perf_event_header)) != 0) {
        printf("memcpy_s perf_event_header return failed");
    }
    if (memcpy_s(p + sizeof(perf_event_header), sizeof(PerfRecordAuxtraceData),
                 reinterpret_cast<const uint8_t *>(&data), sizeof(PerfRecordAuxtraceData)) != 0) {
        printf("memcpy_s data return failed");
    }
    if (memcpy_s(p + header.size, len, reinterpret_cast<const uint8_t *>(rawData), len) != 0) {
        printf("memcpy_s rawData return failed");
    }
    PerfRecordAuxtrace record;
    record.Init(p);
    ASSERT_NE(record.rawData_, nullptr);
    EXPECT_EQ(strcmp(reinterpret_cast<char*>(record.rawData_), "rawData"), 0);
    EXPECT_EQ(record.header_.type, PERF_RECORD_AUXTRACE);
    EXPECT_EQ(record.header_.misc, PERF_RECORD_MISC_USER);
    EXPECT_EQ(record.header_.size, sizeof(PerfRecordAuxtraceData) + sizeof(perf_event_header));
    EXPECT_EQ(record.data_.size, 0);
    EXPECT_EQ(record.data_.offset, 0);
    EXPECT_EQ(record.data_.reference, 0);
    EXPECT_EQ(record.data_.idx, 0);
    EXPECT_EQ(record.data_.tid, 0);
    EXPECT_EQ(record.data_.cpu, 0);
    EXPECT_EQ(record.data_.reserved__, 0);
    free(p);
}

HWTEST_F(PerfEventRecordTest, GetBinary1, TestSize.Level2)
{
    const char* rawData = "rawData";
    size_t len = strlen(rawData) + 1;
    perf_event_header header;
    header.size = sizeof(PerfRecordAuxtraceData) + sizeof(perf_event_header);
    header.type = PERF_RECORD_AUXTRACE;
    header.misc = PERF_RECORD_MISC_USER;
    PerfRecordAuxtraceData data;
    data.cpu = 1;
    data.idx = 1;
    data.offset = 2;
    data.reference = 2;
    data.reserved__ = 2;
    data.size = 1;
    data.tid = 1;
    uint8_t* p = static_cast<uint8_t*>(malloc(header.size + len));
    EXPECT_EQ(memset_s(p, header.size + len, 0, header.size + len), 0);
    if (memcpy_s(p, sizeof(perf_event_header), reinterpret_cast<const uint8_t *>(&header),
                 sizeof(perf_event_header)) != 0) {
        printf("memcpy_s perf_event_header return failed");
    }
    if (memcpy_s(p + sizeof(perf_event_header), sizeof(PerfRecordAuxtraceData),
                 reinterpret_cast<const uint8_t *>(&data), sizeof(PerfRecordAuxtraceData)) != 0) {
        printf("memcpy_s data return failed");
    }
    if (memcpy_s(p + header.size, len, reinterpret_cast<const uint8_t *>(rawData), len) != 0) {
        printf("memcpy_s rawData return failed");
    }
    PerfRecordAuxtrace record;
    PerfRecordAuxtrace recordCopy;
    record.Init(p);
    std::vector<u8> buf;
    ASSERT_TRUE(record.GetBinary1(buf));
    EXPECT_LT(buf.size(), record.GetSize());
    ASSERT_EQ(CompareByteStream(p, buf.data(), buf.size()), 0);
    recordCopy.Init(buf.data());
    EXPECT_EQ(recordCopy.header_.type, PERF_RECORD_AUXTRACE);
    EXPECT_EQ(recordCopy.header_.misc, PERF_RECORD_MISC_USER);
    EXPECT_EQ(recordCopy.header_.size, sizeof(PerfRecordAuxtraceData) + sizeof(perf_event_header));
    EXPECT_EQ(recordCopy.data_.size, 1);
    EXPECT_EQ(recordCopy.data_.offset, 2);
    EXPECT_EQ(recordCopy.data_.reference, 2);
    EXPECT_EQ(recordCopy.data_.idx, 1);
    EXPECT_EQ(recordCopy.data_.tid, 1);
    EXPECT_EQ(recordCopy.data_.cpu, 1);
    EXPECT_EQ(recordCopy.data_.reserved__, 2);
    free(p);
}

HWTEST_F(PerfEventRecordTest, AuxtraceInitErr, TestSize.Level3)
{
    perf_event_header header;
    header.size = sizeof(PerfRecordAuxtraceData) + sizeof(perf_event_header) - 1;
    header.type = PERF_RECORD_AUXTRACE;
    header.misc = PERF_RECORD_MISC_USER;
    PerfRecordAuxtraceData data;
    uint8_t* p = static_cast<uint8_t*>(malloc(header.size));
    EXPECT_EQ(memset_s(p, header.size, 0, header.size), 0);
    if (memcpy_s(p, sizeof(perf_event_header), reinterpret_cast<const uint8_t *>(&header),
                 sizeof(perf_event_header)) != 0) {
        printf("memcpy_s perf_event_header return failed");
    }
    if (memcpy_s(p + sizeof(perf_event_header), sizeof(PerfRecordAuxtraceData),
                 reinterpret_cast<const uint8_t *>(&data), sizeof(PerfRecordAuxtraceData)) != 0) {
        printf("memcpy_s data return failed");
    }
    PerfRecordAuxtrace record;
    record.Init(p);
    EXPECT_EQ(record.rawData_, nullptr);
    EXPECT_NE(record.header_.size, sizeof(PerfRecordAuxtraceData) + sizeof(perf_event_header));
    free(p);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
