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
#ifndef HIPERF_PERF_EVENT_RECORD_H
#define HIPERF_PERF_EVENT_RECORD_H

#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <stdint.h>
#include <string>
#include <sys/types.h>
#include <unique_fd.h>
#include <variant>
#include <vector>
#include <linux/perf_event.h>
#include <linux/types.h>

#include "debug_logger.h"
#include "dfx_frame.h"
#include "dfx_map.h"
#include "perf_record_format.h"
#include "unique_stack_table.h"
#include "utilities.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
using PerfRecordType = int32_t;

static constexpr uint32_t RECORD_SIZE_LIMIT = 65535;
static constexpr uint32_t RECORD_SIZE_LIMIT_SPE = 524288; // auxMmapPages_ * pageSize_

static const char PERF_RECORD_TYPE_AUXTRACE[] = "auxtrace";
static const char PERF_RECORD_TYPE_SAMPLE[] = "sample";
static const char PERF_RECORD_TYPE_MMAP[] = "mmap";
static const char PERF_RECORD_TYPE_MMAP2[] = "mmap2";
static const char PERF_RECORD_TYPE_LOST[] = "lost";
static const char PERF_RECORD_TYPE_COMM[] = "comm";
static const char PERF_RECORD_TYPE_EXIT[] = "exit";
static const char PERF_RECORD_TYPE_THROTTLE[] = "throttle";
static const char PERF_RECORD_TYPE_UNTHROTTLE[] = "unthrottle";
static const char PERF_RECORD_TYPE_FORK[] = "fork";
static const char PERF_RECORD_TYPE_READ[] = "read";
static const char PERF_RECORD_TYPE_AUX[] = "aux";
static const char PERF_RECORD_TYPE_ITRACESTART[] = "itraceStart";
static const char PERF_RECORD_TYPE_LOSTSAMPLE[] = "lostSamples";
static const char PERF_RECORD_TYPE_SWITCH[] = "switch";
static const char PERF_RECORD_TYPE_SWITCHCPUWIDE[] = "switchCpuWide";

enum perf_event_hiperf_ext_type {
    PERF_RECORD_AUXTRACE = 71,
    PERF_RECORD_HIPERF_CALLSTACK = UINT32_MAX / 2,
};

struct AttrWithId {
    perf_event_attr attr;
    std::vector<uint64_t> ids;
    std::string name; // will be empty in GetAttrSection
};

class PerfEventRecord {
public:
    virtual const char* GetNameP() const;
    virtual void Init(uint8_t *data, const perf_event_attr& attr) = 0;

    virtual ~PerfEventRecord() = default;

    virtual size_t GetSize() const = 0;
    virtual size_t GetHeaderSize() const = 0;
    virtual void GetHeaderBinary(std::vector<uint8_t> &buf) const = 0;

    virtual uint32_t GetType() const = 0;
    virtual uint16_t GetMisc() const = 0;
    virtual bool InKernel() = 0;
    virtual bool InUser() = 0;

    // to support --exclude-hiperf, return sample_id.pid to filter record,
    virtual pid_t GetPid() const = 0;

    virtual bool GetBinary(std::vector<uint8_t> &buf) const = 0;
    virtual void Dump(int indent = 0, std::string outputFilename = "", FILE *outputDump = nullptr) const = 0;
    virtual void DumpData(int indent) const = 0;
    virtual void DumpLog(const std::string &prefix) const = 0;
};

template <typename DataType, const char* RECORD_TYPE_NAME>
class PerfEventRecordTemplate : public PerfEventRecord {
public:
    PerfEventRecordTemplate(const PerfEventRecordTemplate &) = delete;
    PerfEventRecordTemplate &operator=(const PerfEventRecordTemplate &) = delete;

    struct perf_event_header header_ = {};
    DataType data_ = {};
    const char* GetNameP() const override final
    {
        return RECORD_TYPE_NAME;
    }

    PerfEventRecordTemplate() = default;
    void Init(uint8_t *data, const perf_event_attr& = {}) override;

    virtual ~PerfEventRecordTemplate() {}

    virtual size_t GetSize() const override
    {
        return header_.size;
    };
    size_t GetHeaderSize() const override
    {
        return sizeof(header_);
    };
    void GetHeaderBinary(std::vector<uint8_t> &buf) const override;

    uint32_t GetType() const override
    {
        return header_.type;
    };
    uint16_t GetMisc() const override
    {
        return header_.misc;
    };
    bool InKernel() override
    {
        return header_.misc & PERF_RECORD_MISC_KERNEL;
    }
    bool InUser() override
    {
        return header_.misc & PERF_RECORD_MISC_USER;
    }

    // to support --exclude-hiperf, return sample_id.pid to filter record,
    virtual pid_t GetPid() const override
    {
        return 0;
    };

    virtual bool GetBinary(std::vector<uint8_t> &buf) const override = 0;
    void Dump(int indent = 0, std::string outputFilename = "", FILE *outputDump = nullptr) const override;
    virtual void DumpData(int indent) const override = 0;
    virtual void DumpLog(const std::string &prefix) const override;

protected:
    void Init(perf_event_type type, bool inKernel);
    void Init(perf_event_hiperf_ext_type type);
};

// PerfEventRecord
template <typename DataType, const char* NAME>
void PerfEventRecordTemplate<DataType, NAME>::Init(perf_event_type type, bool inKernel)
{
    header_.type = type;
    header_.misc = inKernel ? PERF_RECORD_MISC_KERNEL : PERF_RECORD_MISC_USER;
    header_.size = sizeof(header_);
}

template <typename DataType, const char* NAME>
void PerfEventRecordTemplate<DataType, NAME>::Init(perf_event_hiperf_ext_type type)
{
    header_.type = type;
    header_.misc = PERF_RECORD_MISC_USER;
    header_.size = sizeof(header_);
}

template <typename DataType, const char* NAME>
void PerfEventRecordTemplate<DataType, NAME>::Init(uint8_t *p, const perf_event_attr&)
{
    if (p == nullptr) {
        header_.type = PERF_RECORD_MMAP;
        header_.misc = PERF_RECORD_MISC_USER;
        header_.size = 0;
        return;
    }
    header_ = *(reinterpret_cast<perf_event_header *>(p));

    size_t dataSize = GetSize();
    if (dataSize >= sizeof(header_)) {
        size_t copySize = dataSize - sizeof(header_);
        if (memcpy_s(reinterpret_cast<uint8_t *>(&data_), sizeof(data_), p + sizeof(header_), copySize) != 0) {
            HLOGE("##PerfRecordType## memcpy_s return failed!");
        }
    } else {
        HLOGE("##PerfRecordType## return failed!");
    }
}

template <typename DataType, const char* NAME>
void PerfEventRecordTemplate<DataType, NAME>::GetHeaderBinary(std::vector<uint8_t> &buf) const
{
    if (buf.size() < GetHeaderSize()) {
        buf.resize(GetHeaderSize());
    }
    uint8_t *p = buf.data();
    *(reinterpret_cast<perf_event_header *>(p)) = header_;
}

template <typename DataType, const char* NAME>
void PerfEventRecordTemplate<DataType, NAME>::Dump(int indent, std::string outputFilename, FILE *outputDump) const
{
    if (outputDump != nullptr) {
        g_outputDump = outputDump;
    } else if (!outputFilename.empty() && g_outputDump == nullptr) {
        std::string resolvedPath = CanonicalizeSpecPath(outputFilename.c_str());
        g_outputDump = fopen(resolvedPath.c_str(), "w");
        if (g_outputDump == nullptr) {
            printf("unable open file to '%s' because '%d'\n", outputFilename.c_str(), errno);
            return;
        }
    }
    PRINT_INDENT(indent, "\n");
    PRINT_INDENT(indent, "record %s: type %u, misc %u, size %zu\n", GetNameP(), GetType(),
                 GetMisc(), GetSize());
    DumpData(indent + 1);
}

template <typename DataType, const char* NAME>
void PerfEventRecordTemplate<DataType, NAME>::DumpLog(const std::string &prefix) const
{
    HLOGV("%s: record %s: type %u, misc %u, size %zu\n", prefix.c_str(), GetNameP(),
          GetType(), GetMisc(), GetSize());
}

// define convert from linux/perf_event.h
// description from https://man7.org/linux/man-pages/man2/perf_event_open.2.html
constexpr __u64 SAMPLE_ID = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ID |
                            PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_IDENTIFIER;

constexpr __u64 SAMPLE_TYPE = PERF_SAMPLE_IP | SAMPLE_ID | PERF_SAMPLE_PERIOD;

constexpr __u32 MIN_SAMPLE_STACK_SIZE = 8;
constexpr __u32 MAX_SAMPLE_STACK_SIZE = 65528;

class PerfRecordAuxtrace : public PerfEventRecordTemplate<PerfRecordAuxtraceData, PERF_RECORD_TYPE_AUXTRACE> {
public:
    u8* rawData_ = nullptr;
    PerfRecordAuxtrace() = default;
    PerfRecordAuxtrace(u64 size, u64 offset, u64 reference, u32 idx, u32 tid, u32 cpu, u32 pid);

    bool GetBinary1(std::vector<uint8_t> &buf) const;
    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
    void DumpLog(const std::string &prefix) const override;

    size_t GetSize() const override;
};

class PerfRecordMmap : public PerfEventRecordTemplate<PerfRecordMmapData, PERF_RECORD_TYPE_MMAP> {
public:
    PerfRecordMmap() = default;
    PerfRecordMmap(bool inKernel, u32 pid, u32 tid, u64 addr, u64 len, u64 pgoff,
                   const std::string &filename);

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
    void DumpLog(const std::string &prefix) const override;
};

class PerfRecordMmap2 : public PerfEventRecordTemplate<PerfRecordMmap2Data, PERF_RECORD_TYPE_MMAP> {
public:

    PerfRecordMmap2() = default;

    PerfRecordMmap2(bool inKernel, u32 pid, u32 tid, u64 addr, u64 len, u64 pgoff, u32 maj, u32 min,
                    u64 ino, u32 prot, u32 flags, const std::string &filename);

    PerfRecordMmap2(bool inKernel, u32 pid, u32 tid, std::shared_ptr<HiviewDFX::DfxMap> item);

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
    void DumpLog(const std::string &prefix) const override;
    bool discard_ = false;
};

class PerfRecordLost : public PerfEventRecordTemplate<PerfRecordLostData, PERF_RECORD_TYPE_MMAP> {
public:

    PerfRecordLost() = default;

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;

    // only for UT
    PerfRecordLost(bool inKernel, u64 id, u64 lost);
};

class PerfRecordComm : public PerfEventRecordTemplate<PerfRecordCommData, PERF_RECORD_TYPE_MMAP> {
public:

    PerfRecordComm() = default;


    PerfRecordComm(bool inKernel, u32 pid, u32 tid, const std::string &comm);

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
    void DumpLog(const std::string &prefix) const override;
};

class PerfRecordSample : public PerfEventRecordTemplate<PerfRecordSampleData, PERF_RECORD_TYPE_MMAP> {
public:
    uint64_t sampleType_ = SAMPLE_TYPE;
    uint64_t skipKernel_ = 0;
    uint64_t skipPid_ = 0;
    // extend
    // hold the new ips memory (after unwind)
    // used for data_.ips replace (ReplaceWithCallStack)
    std::vector<u64> ips_;
    std::vector<HiviewDFX::DfxFrame> callFrames_;
    std::vector<pid_t> serverPidMap_;

    PerfRecordSample() = default;
    PerfRecordSample(const PerfRecordSample& sample);
    // referenced input(p) in PerfRecordSample, require caller keep input(p) together
    void Init(uint8_t *data, const perf_event_attr& attr) override;

    StackId stackId_ {0};
    bool removeStack_ {false};
    static void SetDumpRemoveStack(bool dumpRemoveStack);
    static bool IsDumpRemoveStack();
    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent = 0) const override;
    void DumpLog(const std::string &prefix) const override;

    void RecoverCallStack();
    // originalSize is use for expand callstack
    void ReplaceWithCallStack(size_t originalSize = 0);
    pid_t GetPid() const override;

    // only for UT
    PerfRecordSample(bool inKernel, u32 pid, u32 tid, u64 period = 0, u64 time = 0, u64 id = 0);

    pid_t GetUstackServerPid();
    pid_t GetServerPidof(unsigned int ipNr);
private:
    static bool dumpRemoveStack_;
};

class PerfRecordExit : public PerfEventRecordTemplate<PerfRecordExitData, PERF_RECORD_TYPE_MMAP> {
public:
    PerfRecordExit() = default;

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
};

class PerfRecordThrottle : public PerfEventRecordTemplate<PerfRecordThrottleData, PERF_RECORD_TYPE_MMAP> {
public:
    PerfRecordThrottle() = default;

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
};

class PerfRecordUnthrottle : public PerfEventRecordTemplate<PerfRecordThrottleData, PERF_RECORD_TYPE_MMAP> {
public:
    PerfRecordUnthrottle() = default;

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
};

class PerfRecordFork : public PerfEventRecordTemplate<PerfRecordForkData, PERF_RECORD_TYPE_MMAP> {
public:
    PerfRecordFork() = default;

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
};

/*
    This record indicates a read event.
*/
class PerfRecordRead : public PerfEventRecordTemplate<PerfRecordReadData, PERF_RECORD_TYPE_MMAP> {
public:
    PerfRecordRead() = default;

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
};

/*
    This record reports that new data is available in the
    separate AUX buffer region.

    aux_offset
            offset in the AUX mmap region where the new
            data begins.
    aux_size
            size of the data made available.
    flags  describes the AUX update.
            PERF_AUX_FLAG_TRUNCATED
                if set, then the data returned was
                truncated to fit the available buffer
                size.

            PERF_AUX_FLAG_OVERWRITE
                if set, then the data returned has
                overwritten previous data.
*/
class PerfRecordAux : public PerfEventRecordTemplate<PerfRecordAuxData, PERF_RECORD_TYPE_MMAP> {
public:
    uint64_t sampleType_ = SAMPLE_ID;
    PerfRecordAux() = default;

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
};

/*
    This record indicates which process has initiated an
    instruction trace event, allowing tools to properly
    correlate the instruction addresses in the AUX buffer
    with the proper executable.

    pid    process ID of the thread starting an
            instruction trace.
    tid    thread ID of the thread starting an instruction
            trace.
*/
class PerfRecordItraceStart : public PerfEventRecordTemplate<PerfRecordItraceStartData, PERF_RECORD_TYPE_MMAP> {
public:
    PerfRecordItraceStart() = default;

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
};

/*
    When using hardware sampling (such as Intel PEBS) this
    record indicates some number of samples that may have
    been lost.
*/
class PerfRecordLostSamples : public PerfEventRecordTemplate<PerfRecordLostSamplesData, PERF_RECORD_TYPE_MMAP> {
public:
    PerfRecordLostSamples() = default;

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
};

/*
    This record indicates a context switch has happened.
    The PERF_RECORD_MISC_SWITCH_OUT bit in the misc field
    indicates whether it was a context switch into or away
    from the current process.
*/
class PerfRecordSwitch : public PerfEventRecordTemplate<PerfRecordSwitchData, PERF_RECORD_TYPE_MMAP> {
public:
    PerfRecordSwitch() = default;

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int) const override {};
};

/*
    As with PERF_RECORD_SWITCH this record indicates a
    context switch has happened, but it only occurs when
    sampling in CPU-wide mode and provides additional
    information on the process being switched to/from.
    The PERF_RECORD_MISC_SWITCH_OUT bit in the misc field
    indicates whether it was a context switch into or away
    from the current process.

    next_prev_pid
            The process ID of the previous (if switching
            in) or next (if switching out) process on the
            CPU.

    next_prev_tid
            The thread ID of the previous (if switching in)
            or next (if switching out) thread on the CPU.
*/
class PerfRecordSwitchCpuWide : public PerfEventRecordTemplate<PerfRecordSwitchCpuWideData, PERF_RECORD_TYPE_MMAP> {
public:
    PerfRecordSwitchCpuWide() = default;

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
};

class PerfRecordNull : public PerfEventRecordTemplate<PerfRecordSwitchCpuWideData, nullptr> {
public:
    PerfRecordNull() = default;

    bool GetBinary(std::vector<uint8_t>&) const override { return false; };
    void DumpData(int indent) const override {};
};

class PerfEventRecordFactory {
public:
    static PerfEventRecord& GetPerfEventRecord(PerfRecordType type, uint8_t* data,
                                               const perf_event_attr& attr);
private:
    static thread_local std::unordered_map<PerfRecordType, PerfEventRecord*> recordMap_;
};

template<typename T>
void PushToBinary(bool condition, uint8_t *&p, const T &v);

template<typename T1, typename T2>
void PushToBinary2(bool condition, uint8_t *&p, const T1 &v1, const T2 &v2);

template<typename T>
void PopFromBinary(bool condition, uint8_t *&p, T &v);

template<typename T1, typename T2>
void PopFromBinary2(bool condition, uint8_t *&p, T1 &v1, T2 &v2);
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_PERF_EVENT_RECORD_H
