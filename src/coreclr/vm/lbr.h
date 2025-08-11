// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#ifndef LBR_H
#define LBR_H

#ifdef FEATURE_LBR

#if defined(HOST_WINDOWS) && !defined(FEATURE_NATIVEAOT)

#include <wmistr.h>
#include <relogger.h>
#include <thread>

#include "typehashingalgorithms.h"
#include "shash.h"
#include "sarray.h"
#include "class.h"

#include <map>
#include <vector>
#include <tuple>

struct LbrSample {
  __int64 from;
  __int64 to;
  __int64 info;

  bool operator<(const LbrSample &other) const {
    if (from != other.from)
      return from < other.from;
    return to < other.to;
  }
};

struct LbrEvent {
  __int64 timestamp;
  __int32 process;
  __int32 thread;
  __int64 options;
  LbrSample samples[32];
};

class LbrManager;

class LbrEventCallback : public ITraceEventCallback 
{
public:
    LbrEventCallback() : m_lbrMgr(nullptr), m_processId(-1) { }
    LbrEventCallback(LbrManager *lbrMgr, int processId) : m_lbrMgr(lbrMgr), m_processId(processId) { }
    virtual ~LbrEventCallback() { }

    HRESULT STDMETHODCALLTYPE OnBeginProcessTrace(ITraceEvent* header, ITraceRelogger* relogger) override 
    {
      return S_OK;
    }

    HRESULT STDMETHODCALLTYPE OnEvent(ITraceEvent* traceEvent, ITraceRelogger* relogger) override;

    HRESULT STDMETHODCALLTYPE OnFinalizeProcessTrace(ITraceRelogger* relogger) override 
    {
      return S_OK;
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, PVOID* ppObj) override 
    {
      return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override 
    { 
      return 0; 
    }

    ULONG STDMETHODCALLTYPE Release() override 
    { 
      return 0; 
    }

private:
    LbrManager *m_lbrMgr;
    int m_processId;
};


class LbrNativeToSchemaMapping 
{
public:
  LbrNativeToSchemaMapping() = default;
  LbrNativeToSchemaMapping(ICorJitInfo::PgoInstrumentationSchema *pSchema, size_t countSchemaItems, ICorDebugInfo::OffsetMapping *pMap, ULONG32 cMap);

  ~LbrNativeToSchemaMapping();
  int LookupNativeOffset(uint32_t nativeOffset);
  void AlignSample(uint32_t sampleOffset);

  struct IntervalMappingDesc
  {
    union
    {
      struct
      {
        uint32_t low;
        uint32_t high;
      } nativeIntervals;
      size_t nativeOffsetIndex;
    };
    int32_t ilOffset;
    size_t schemaIndex;
    bool isHole;
  };

  uint64_t GetSampleCount(size_t index) const { return m_sampleCounts[index]; }
  const IntervalMappingDesc& GetIntervalMappingDesc(size_t index) const { return m_nativeIntervals[index]; }
  size_t NumIntervals() const { return m_nativeIntervals.size(); }

private:

  void BuildMapping(ICorJitInfo::PgoInstrumentationSchema *pSchema, size_t cSchema, ICorDebugInfo::OffsetMapping *pMap, ULONG32 cMap);

  std::vector<IntervalMappingDesc> m_nativeIntervals;
  std::vector<uint64_t> m_sampleCounts;
};

class LbrManager 
{
public:
    // Setup the initial static instance, which will spawn internal setup
    static void Initialize();
    static void Shutdown();
    static void BuildPGOSchema(MethodDesc *pMD, bool haltSampleCollection);

    LbrManager();

    void ReceiveLbrEvent(LbrEvent *lbrEvent);

    void WriteLBRData();

    // keep a record of how samples were distributed to native/il offsets
    struct LbrRecordData
    {
      std::map<std::tuple<__int64,__int64>,int> sampleHistogram;
      LbrNativeToSchemaMapping nativeToSchemaMap;
      __int64 alignedSamples = 0;
    };

    // temporary pretty blank structure about some sample data we have for a method
    struct Header 
    {
        MethodDesc *method;
        SArray<LbrSample> samples;

        LbrRecordData *record = NULL;
        bool haltSampleCollection = false;

        void Init(MethodDesc *pMD)
        {
          this->method = pMD;
        }

        void InitRecord()
        {
          record = new LbrRecordData();
        }
    };

    struct HeaderList
    {
        HeaderList*  next;
        Header       header;

        MethodDesc*  GetKey() const
        {
            return header.method;
        }
        static COUNT_T Hash(MethodDesc *ptr)
        {
            return MixPointerIntoHash(ptr);
        }
    };


private:
    HRESULT InitializeEtwTrace();
    HRESULT ShutdownEtwTrace();

    void SaveLbrSample(const LbrSample &sample, MethodDesc *pMD);
    void BuildPGOSchemaForMethodDesc(MethodDesc *pMD, bool haltSampleCollection);

    void RetrySamples();

    static LbrManager s_lbrMgr;
    static CrstStatic s_lbrMgrLock;

    ITraceRelogger *m_relogger = NULL;
    LbrEventCallback m_callback;
    std::thread m_callbackThread;
    TRACEHANDLE m_traceHandle;

    //PtrSHash<LbrManager::HeaderList, MethodDesc*> m_lbrDataLookup;
    std::map<MethodDesc*, HeaderList*> m_lbrDataLookup;

    HeaderList* m_lbrHeaderList = NULL;
    Crst m_lock;

    uint64_t m_alignedSamples = 0;
    uint64_t m_missedSamples = 0;
    uint64_t m_numMethodHeadersCreated = 0;

    static ULONG AddPrivilege(LPCTSTR privilege);
    static bool EnableProvider(TRACEHANDLE SessionHandle, LPCGUID ProviderGuid, UCHAR Level = TRACE_LEVEL_VERBOSE, ULONGLONG MatchAnyKeyword = 0, ULONGLONG MatchAllKeyword = 0); 
    static bool DisableProvider(TRACEHANDLE SessionHandle, LPCGUID ProviderGuid);

    // Duplicated from PgoManager for now
    static const char* const         s_PgoFileHeaderString;
    static const char* const         s_PgoFileTrailerString;

    static const char* const         s_LbrFileHeaderString;
    static const char* const         s_LbrFileTrailerString;

    static const char* const         s_MethodHeaderString;

    bool m_shouldWriteLbrData;

    template <class lambda>
    bool EnumerateLbrHeaders(lambda fun)
    {
      HeaderList *pHeaderList = m_lbrHeaderList;
      while (pHeaderList != NULL)
      {
        if (!fun(pHeaderList))
        {
          return false;
        }
        pHeaderList = pHeaderList->next;
      }
      return true;
    }
    

};


#endif

#endif // defined(HOST_WINDOWS)
#endif // LBR_H