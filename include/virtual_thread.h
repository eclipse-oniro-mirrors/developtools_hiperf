/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef HIPERF_VIRTUAL_THREAD_H
#define HIPERF_VIRTUAL_THREAD_H

#include <cinttypes>
#include <functional>
#include <unordered_set>
#include <unordered_map>

#include "debug_logger.h"
#include "dfx_maps.h"
#include "perf_event_record.h"
#include "symbols_file.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
/*
03284000-03289000 r--p 00000000 b3:05 289        /system/bin/sh
032b7000-032b9000 rw-p 00000000 00:00 0
aff60000-aff96000 r--p 00000000 b3:05 923        /system/lib/libc++.so
affeb000-affed000 rw-p 00000000 00:00 0
b0023000-b0024000 r--p 00000000 b3:05 959        /system/lib/libdl.so
*/
const std::string MMAP_NAME_HEAP = "[heap]";
const std::string MMAP_NAME_ANON = "[anon]";

class VirtualThread {
public:
    VirtualThread(const VirtualThread &) = delete;
    VirtualThread &operator=(const VirtualThread &) = delete;

    VirtualThread(const pid_t pid, const std::vector<std::unique_ptr<SymbolsFile>> &symbolsFiles)
        : pid_(pid),
          tid_(pid),
          symbolsFiles_(symbolsFiles),
          processMemMaps_(),
          memMaps_(processMemMaps_),
          vaddr4kPageCache_(vaddr4kPageCacheOfProc_),
          memMapsIndexs_(processMemMapsIndexs_),
          isRepeat_(),
          hasRepeat_(isRepeat_),
          parent_(*this) {}

    VirtualThread(const pid_t pid, const pid_t tid, VirtualThread &thread,
                  const std::vector<std::unique_ptr<SymbolsFile>> &symbolsFiles)
        : pid_(pid),
          tid_(tid),
          symbolsFiles_(symbolsFiles),
          processMemMaps_(),
          memMaps_(thread.processMemMaps_),
          vaddr4kPageCache_(thread.vaddr4kPageCacheOfProc_),
          memMapsIndexs_(thread.processMemMapsIndexs_),
          isRepeat_(),
          hasRepeat_(thread.isRepeat_),
          parent_(thread)
    {
        HLOG_ASSERT(pid != tid);
        HLOGV("%d %d map from parent size is %zu", pid, tid, memMaps_.size());
    };

    pid_t pid_ = -1;
    pid_t tid_ = -1;
    std::string name_;

    const std::vector<std::shared_ptr<DfxMap>> &GetMaps() const
    {
        return memMaps_;
    }
    void ParseMap();
    void FixHMBundleMap();
    void ParseServiceMap(const std::string &filename);
    void ParseDevhostMap(const pid_t devhost);
    std::shared_ptr<DfxMap> CreateMapItem(const std::string &filename, const uint64_t begin,
                                          const uint64_t len, const uint64_t offset, const uint32_t prot = 0);
    std::shared_ptr<DfxMap> FindMapByAddr(const uint64_t addr) const;
    std::shared_ptr<DfxMap> FindMapByFileInfo(const std::string name, const uint64_t offset) const;
    int64_t FindMapIndexByAddr(const uint64_t addr) const;
    SymbolsFile *FindSymbolsFileByMap(std::shared_ptr<DfxMap> map) const;
    bool ReadRoMemory(const uint64_t vaddr, uint8_t *data, const size_t size) const;
#ifdef HIPERF_DEBUG
    void ReportVaddrMapMiss(const uint64_t vaddr) const;
#endif
    void SetCollectSymbol(bool collecSymbol)
    {
        collectSymbol_ = collecSymbol;
    }
    bool IsCollectSymbol() const
    {
        return collectSymbol_;
    }
    bool IsExistRepeatMaps() const
    {
        return hasRepeat_;
    }
    void ClearMaps();
private:
    void SortMemMaps();
    bool IsRepeatMap(int mapIndex, uint64_t begin, uint64_t end) const;
    std::vector<int> FindRepeatMapIndexs(uint64_t begin, uint64_t end) const;
    void DeleteRepeatMapsByIndex(int index);
    void DeleteRepeatMaps(uint64_t begin, uint64_t end, const std::string filename);
    void ParseDevhostMapEachLine(std::string &filename, std::istringstream &iStringstream, std::string &line);
    VirtualThread& GetParent()
    {
        return parent_;
    }
#ifdef DEBUG_TIME
    bool IsSorted() const;
#endif
    const std::vector<std::unique_ptr<SymbolsFile>> &symbolsFiles_;

    // proc/xx/map
    // use to put the parent thread's map
    // only process have memmap
    std::vector<std::shared_ptr<DfxMap>> processMemMaps_;
    std::unordered_map<uint64_t, uint64_t> vaddr4kPageCacheOfProc_;
    // thread must use ref from process
    std::vector<std::shared_ptr<DfxMap>> &memMaps_;
    std::unordered_map<uint64_t, uint64_t> &vaddr4kPageCache_;
    std::vector<int> processMemMapsIndexs_;
    std::vector<int> &memMapsIndexs_;
    bool collectSymbol_ = true;
    bool isRepeat_ = false;
    bool &hasRepeat_;
    VirtualThread &parent_;
#ifdef HIPERF_DEBUG
    mutable std::unordered_set<uint64_t> missedRuntimeVaddr_;
#endif
#ifdef DEBUG_MISS_SYMBOL
    mutable std::vector<std::string> missedSymbolFile_;
#endif
};
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_VIRTUAL_THREAD_H
