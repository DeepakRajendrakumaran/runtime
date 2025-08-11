// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "common.h"
#include "log.h"
#include "lbr.h"
#include "codeman.h"

#ifdef FEATURE_LBR
#if defined(HOST_WINDOWS) && !defined(FEATURE_NATIVEAOT)

#include <io.h>
#include <windows.h>
#include <initguid.h>
#include <winternl.h>
//#include <inttypes.h>
#include <evntcons.h>
#include <thread>
#include <processthreadsapi.h>
#include <winbase.h>
#include <string>
#include <map>

#pragma comment(linker, "/defaultlib:ntdll.lib")

// need to call the undocumented NtSetSystemInformation call
// https://github.com/microsoft/krabsetw/blob/master/krabs/krabs/perfinfo_groupmask.hpp
extern "C" NTSTATUS NTAPI NtSetSystemInformation(_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                                 _In_reads_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                                 _In_ ULONG SystemInformationLength);

constexpr auto SystemPerformanceTraceInformation{static_cast<SYSTEM_INFORMATION_CLASS>(0x1f)};

static const GUID ProviderLastBranchRecordEvent = {
    0x99134383, 0x5248, 0x43fc, {0x83, 0x4b, 0x52, 0x94, 0x54, 0xe7, 0x5d, 0xf3}};

static const GUID LBR_COLLECTOR_GUID = {0xf2e1990, 0x3904, 0x450e, {0x8e, 0x88, 0x7d, 0x68, 0xf4, 0x38, 0xbe, 0x65}};

const wchar_t* TRACE_NAME = L"intel.collector.lbr";

const unsigned MAX_SESSION_NAME_LEN = 1024;
const unsigned MAX_LOGFILE_PATH_LEN = 1024;
typedef struct EventTracePropertiesV2 {
  EVENT_TRACE_PROPERTIES_V2 Properties;
  WCHAR LoggerName[MAX_SESSION_NAME_LEN];
  WCHAR LogFileName[MAX_LOGFILE_PATH_LEN];
} EventTracePropertiesV2;

CrstStatic LbrManager::s_lbrMgrLock;
LbrManager LbrManager::s_lbrMgr;

const char* const         LbrManager::s_PgoFileHeaderString  = "*** START PGO Data, max index = %u ***\n";
const char* const         LbrManager::s_PgoFileTrailerString = "*** END PGO Data ***\n";

const char* const         LbrManager::s_LbrFileHeaderString  = "*** START LBR Data, mapped samples %llu, missed samples %llu, total methods created %llu ***\n";
const char* const         LbrManager::s_LbrFileTrailerString = "*** END LBR Data ***\n";

const char* const         LbrManager::s_MethodHeaderString = "@@@ codehash 0x%08X methodhash 0x%08X ilSize 0x%08X \n";


ULONG PrintSystemError(ULONG result) {
  LPTSTR errorMsg = nullptr;
  FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                result, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&errorMsg, 0, nullptr);

  wprintf(L"%d - %s", result, errorMsg);

  return result;
}

bool StopExistingTraceIfRunning(std::wstring traceName) {
  const unsigned MAX_SESSION_NAME_LEN = 1024;
  const unsigned MAX_LOGFILE_PATH_LEN = 1024;
  typedef struct EventTraceProperties {
    EVENT_TRACE_PROPERTIES Properties;
    WCHAR LoggerName[MAX_SESSION_NAME_LEN];
    WCHAR LogFileName[MAX_LOGFILE_PATH_LEN];
  } EventTraceProperties;

  // Query the status of the ETW trace.
  EventTraceProperties traceProperties = {};
  memset(&traceProperties, 0, sizeof(traceProperties));
  traceProperties.Properties.Wnode.BufferSize = sizeof(traceProperties);

  ULONG status = QueryTrace(0, traceName.c_str(), (EVENT_TRACE_PROPERTIES*)&traceProperties);

  if (status == ERROR_SUCCESS) {
    // The trace is running. Stop it.
    status = ControlTrace(NULL, traceName.c_str(), (EVENT_TRACE_PROPERTIES*)&traceProperties, EVENT_TRACE_CONTROL_STOP);
    if (status != ERROR_SUCCESS) {
      wprintf(L"Failed to stop ETW trace. Error code: %lu\n", status);
      return false;
    } else {
      wprintf(L"ETW trace stopped successfully.\n");
      return true;
    }
  } else if (status == ERROR_WMI_INSTANCE_NOT_FOUND) {
    return false;
  } else {
    // An error occurred.
    wprintf(L"Failed to query ETW trace. Error code: %lu\n", status);
    PrintSystemError(GetLastError());
    return false;
  }
}

LbrNativeToSchemaMapping::LbrNativeToSchemaMapping(ICorJitInfo::PgoInstrumentationSchema *pSchema, size_t cSchema, ICorDebugInfo::OffsetMapping *pMap, ULONG32 cMap)
{
  BuildMapping(pSchema, cSchema, pMap, cMap);
  m_sampleCounts = std::vector<uint64_t>(m_nativeIntervals.size(), 0);
}

LbrNativeToSchemaMapping::~LbrNativeToSchemaMapping() 
{
}

void LbrNativeToSchemaMapping::BuildMapping(ICorJitInfo::PgoInstrumentationSchema *pSchema, size_t cSchema, ICorDebugInfo::OffsetMapping *pMap, ULONG32 cMap)
{
  size_t schemaIndex = 0;
  size_t offsetMapIndex = 1; // first entry is always a -2 offset for the prolog

  while (offsetMapIndex < cMap && schemaIndex < cSchema)
  {
    if (pMap[offsetMapIndex].ilOffset < 0)
    {
      // we have a prolog or epilog, skip it
      offsetMapIndex++;
      continue;
    }

    if (pSchema[schemaIndex].ILOffset == (int32_t)pMap[offsetMapIndex].ilOffset)
    {
      // we have a match, native interval low bound should be the current native offset, and the high bound should
      // be the -1 the next native offset (we can always look up 1 because of epilog special codes)
      IntervalMappingDesc desc;
      desc.nativeIntervals = {pMap[offsetMapIndex].nativeOffset, pMap[offsetMapIndex+1].nativeOffset};
      desc.ilOffset = pSchema[schemaIndex].ILOffset;
      desc.schemaIndex = schemaIndex;
      desc.isHole = false;
      m_nativeIntervals.push_back(desc);
      schemaIndex++;
      offsetMapIndex++;
      continue;
    }

    if (pSchema[schemaIndex].ILOffset < (int32_t)pMap[offsetMapIndex].ilOffset)
    {
      // create a hole to fill in later while we sync back up (we always create a hole when the pSchema offset is lower)
      IntervalMappingDesc desc;
      desc.nativeOffsetIndex = offsetMapIndex;
      desc.ilOffset = pSchema[schemaIndex].ILOffset;
      desc.schemaIndex = schemaIndex;
      desc.isHole = true;
      m_nativeIntervals.push_back(desc);
      schemaIndex++;
    }
    else
    {
      offsetMapIndex++;
    }
  }

  while (schemaIndex < cSchema)
  {
    // create multiple holes to fill in with the algorithm below
    IntervalMappingDesc desc;
    desc.nativeOffsetIndex = offsetMapIndex-2;
    desc.ilOffset = pSchema[schemaIndex].ILOffset;
    desc.schemaIndex = schemaIndex;
    desc.isHole = true;
    m_nativeIntervals.push_back(desc);
    schemaIndex++;
  }

  // cases are offsetMapIndex == schemaIndex
  //           we have extra native offsets (no big deal)
  //           we have extra schema offsets 

  // loop through, and fill the holes
  size_t i = 0;
  while (i < m_nativeIntervals.size())
  {
    if (m_nativeIntervals[i].isHole)
    {
      // find how many holes we have to give the closest native offsets with
      auto j = i + 1;
      while (j < m_nativeIntervals.size() && m_nativeIntervals[j].isHole && m_nativeIntervals[j].nativeOffsetIndex == m_nativeIntervals[i].nativeOffsetIndex)
      {
        j++;
      }

      size_t index = m_nativeIntervals[i].nativeOffsetIndex;
      uint32_t intervalSplit = (pMap[index+1].nativeOffset - pMap[index].nativeOffset) / (uint32_t)(j - i);
      size_t num_holes = j - i;
      for (size_t k = 0; k < num_holes; k++)
      {
        m_nativeIntervals[i].nativeIntervals.low = pMap[index].nativeOffset + (intervalSplit * (uint32_t)(k));
        m_nativeIntervals[i].nativeIntervals.high = pMap[index].nativeOffset + (intervalSplit * (uint32_t)(k + 1));
        i++;
      }
    }
    else
    {
      i++;
    }
  }
}

int LbrNativeToSchemaMapping::LookupNativeOffset(uint32_t nativeOffset)
{
  for (auto i = 0; i < m_nativeIntervals.size(); i++)
  {
    const IntervalMappingDesc &desc = m_nativeIntervals[i];
    if (nativeOffset >= desc.nativeIntervals.low && nativeOffset < desc.nativeIntervals.high)
    {
      return i;
    }
  }
  return -1;
}

void LbrNativeToSchemaMapping::AlignSample(uint32_t sampleOffset)
{
  int descIndex = LookupNativeOffset(sampleOffset);
  if (descIndex != -1)
  {
    m_sampleCounts[descIndex]++;
  }
}

void LbrManager::Initialize()
{
    STANDARD_VM_CONTRACT;

    s_lbrMgrLock.Init(CrstLeafLock, CRST_DEFAULT);



    HRESULT hr = s_lbrMgr.InitializeEtwTrace();
    if (FAILED(hr))
      printf("WARNING: LbrManager did not initialize ETW trace!\n");


}

void LbrManager::Shutdown()
{
    s_lbrMgr.ShutdownEtwTrace();
    s_lbrMgr.WriteLBRData();
}

void LbrManager::BuildPGOSchema(MethodDesc *pMD, bool haltSampleCollection) 
{
    s_lbrMgr.BuildPGOSchemaForMethodDesc(pMD, haltSampleCollection);
}

LbrManager::LbrManager() : m_lock(CrstLbrData, CRST_DEFAULT) 
{
  m_callback = LbrEventCallback(this, GetCurrentProcessId());
  m_shouldWriteLbrData = CLRConfig::GetConfigValue(CLRConfig::INTERNAL_WriteLBRData) == 1;
}

// Relogger should filter and only send lbr events related to dotnet processes
void LbrManager::ReceiveLbrEvent(LbrEvent *lbrEvent) 
{
  for (int i = 0; i < 32; i++)
  {
    bool savedEvent = false;
    const LbrSample &sample = lbrEvent->samples[i];
    EECodeInfo fromInfo(sample.from);
    EECodeInfo toInfo(sample.to);

    if (fromInfo.IsValid())
    {
      MethodDesc *md = fromInfo.GetMethodDesc();
      SaveLbrSample(sample, md);
      savedEvent = true;
    }

    if (toInfo.IsValid())
    {
      MethodDesc *md = toInfo.GetMethodDesc();
      SaveLbrSample(sample, md);
      savedEvent = true;
    }

    if (savedEvent)
    {
      m_alignedSamples++;
    }
    else
    {
      m_missedSamples++;
    }

  }
}

static LPUTF8 NarrowWideChar(__inout_z LPCWSTR str)
{
    if (str != 0) {
        LPCWSTR fromPtr = str;
        LPUTF8 toPtr = (LPUTF8) str;
        LPUTF8 result = toPtr;
        while(*fromPtr != 0)
            *toPtr++ = (char) *fromPtr++;
        *toPtr = 0;
        return result;
    }
    return NULL;
}

void LbrManager::SaveLbrSample(const LbrSample &sample, MethodDesc *pMD)
{
  CrstHolder lock(&m_lock);

  //HeaderList *pHeaderList = m_lbrDataLookup.Lookup(pMD);
  HeaderList *pHeaderList = m_lbrDataLookup[pMD];

  if (pHeaderList == NULL)
  {
    m_numMethodHeadersCreated++;

    //AllocMemTracker loaderHeapAllocation;
    //pHeaderList = (HeaderList*)loaderHeapAllocation.Track(pMD->GetLoaderAllocator()->GetHighFrequencyHeap()->AllocMem(S_SIZE_T(sizeof(HeaderList))));
    pHeaderList = new HeaderList();
    //pHeaderList = (HeaderList*)loaderHeapAllocation.Track(pMD->GetLoaderAllocator()->GetHighFrequencyHeap()->AllocMem(S_SIZE_T(sizeof(HeaderList))));
    memset(pHeaderList, 0, sizeof(HeaderList));
    pHeaderList->header.Init(pMD);

    if (m_shouldWriteLbrData)
    {
      pHeaderList->header.InitRecord();
    }

    pHeaderList->next = m_lbrHeaderList;
    m_lbrHeaderList = pHeaderList;
    //m_lbrDataLookup.Add(pHeaderList);
    m_lbrDataLookup[pMD] = pHeaderList;
    //loaderHeapAllocation.SuppressRelease();

#ifdef DEBUG
    EEClass *pClass = pMD->GetClass();
    printf("INFO (%p): saving initial LBR data for %s::%s with struct:%p key:%p value:%p\n", this, pClass->GetDebugClassName(), pMD->GetName(), &m_lbrDataLookup, pMD, pHeaderList);
#endif
  }

  if (pHeaderList->header.haltSampleCollection)
  {
    return;
  }

  pHeaderList->header.samples.Append(sample);
}

// Helper to use w/ the debug stores.
BYTE* PlaceHolderNew(void * , size_t cBytes)
{
    BYTE * p = new BYTE[cBytes];
    return p;
}

void LbrManager::BuildPGOSchemaForMethodDesc(MethodDesc *pMD, bool haltSampleCollection)
{
  CrstHolder lock(&m_lock);

#ifdef DEBUG
    EEClass *pClass = pMD->GetClass();
    printf("INFO (%p): Building PGO schema for %s::%s\n", this, pClass->GetDebugClassName(), pMD->GetName());
#endif

  //HeaderList *pHeaderList = m_lbrDataLookup.Lookup(pMD);
  HeaderList *pHeaderList = m_lbrDataLookup[pMD];
  if (pHeaderList == NULL)
  {
#ifdef _DEBUG
    EEClass *pClass = pMD->GetClass();
    printf("WARNING: no LBR data for %s::%s with %p:%p\n", pClass->GetDebugClassName(), pMD->GetName(), &m_lbrDataLookup, pMD);
#endif
    return;
  }

  // Get the raw PGO schema to manipulate
  BYTE *pAllocatedData = nullptr; 
  ICorJitInfo::PgoInstrumentationSchema *pSchema = nullptr;
  UINT32 countSchemaItems;
  BYTE *pInstrumentationData = nullptr;
  ICorJitInfo::PgoSource pgoSource;

  HRESULT hr = PgoManager::getPgoInstrumentationResults(pMD, &pAllocatedData, &pSchema, &countSchemaItems, &pInstrumentationData, &pgoSource);
  if (FAILED(hr))
  {
#ifdef DEBUG
    EEClass *pClass = pMD->GetClass();
    printf("WARNING: no PGO data for %s::%s\n", pClass->GetDebugClassName(), pMD->GetName());
    return;
#endif
  }

#ifdef DEBUG
  {
    EEClass *pClass = pMD->GetClass();
    if (!strcmp("DecodeFrom", pMD->GetName()))
    {
      printf("HIT!");
    }
    printf("INFO: creating LBR data for %s::%s with %d samples\n", pClass->GetDebugClassName(), pMD->GetName(), pHeaderList->header.samples.GetCount());
  }

  LPUTF8 lbrDebugMethod;
  CLRConfig::GetConfigValue(CLRConfig::INTERNAL_LBRDump, (LPWSTR*)&lbrDebugMethod);
  lbrDebugMethod = NarrowWideChar((LPWSTR)lbrDebugMethod);
#endif

  // Get debug info
  PCODE nativeCode = pMD->GetNativeCode();
  EECodeInfo info(nativeCode);

  IJitManager *jitMgr = info.GetJitManager();

  // See if we can get some offsets into IL
  DebugInfoRequest request;  
  request.InitFromStartingAddr(pMD, nativeCode);

  // Bounds info.
  ULONG32 cMap = 0;
  ICorDebugInfo::OffsetMapping *pMap = NULL;
  ULONG32 cVars = 0;
  ICorDebugInfo::NativeVarInfo *pVars = NULL;

  BOOL fSuccess = jitMgr->GetBoundariesAndVars(
      request,
      PlaceHolderNew, NULL, // allocator
      &cMap, &pMap,
      &cVars, &pVars);

  LbrNativeToSchemaMapping nativeToSchemaMap(pSchema, countSchemaItems, pMap, cMap);  

  for (uint i = 0; i < pHeaderList->header.samples.GetCount(); i++)
  {
    LbrSample &sample = pHeaderList->header.samples[i];
    EECodeInfo fromInfo(sample.from);
    EECodeInfo toInfo(sample.to);

    if (fromInfo.IsValid() && fromInfo.GetMethodDesc() == pMD) 
    {
      if (pHeaderList->header.record)
      {
        pHeaderList->header.record->sampleHistogram[{sample.from - nativeCode, sample.to - nativeCode}]++;
        pHeaderList->header.record->alignedSamples++;
      }
      nativeToSchemaMap.AlignSample((uint32_t)(sample.from - nativeCode));
    }

    if (toInfo.IsValid() && toInfo.GetMethodDesc() == pMD)
    {
      if (pHeaderList->header.record)
      {
        pHeaderList->header.record->sampleHistogram[{sample.from - nativeCode, sample.to - nativeCode}]++;
        pHeaderList->header.record->alignedSamples++;
      }
      nativeToSchemaMap.AlignSample((uint32_t)(sample.to - nativeCode));
    }
  }

  for (ULONG32 i = 0; i < countSchemaItems; i++)
  {
     *((uint32_t*)(pInstrumentationData + pSchema[i].Offset)) = (uint32_t)nativeToSchemaMap.GetSampleCount(i);
  }

  if (!PgoManager::savePgoInstrumentation(pMD, pSchema, countSchemaItems, pInstrumentationData))
  {
#ifdef DEBUG
    EEClass *pClass = pMD->GetClass();
    printf("Method %s::%s failed to write updated schema", pClass->GetDebugClassName(), pMD->GetName());
#endif
  }


  if (pHeaderList->header.record)
  {
    pHeaderList->header.record->nativeToSchemaMap = std::move(nativeToSchemaMap);
  }

  pHeaderList->header.haltSampleCollection = haltSampleCollection;
}

ULONG LbrManager::AddPrivilege(LPCTSTR privilege) 
{
  HANDLE token;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) 
  {
    return -1;
  }

  TOKEN_PRIVILEGES tp = {};
  LUID luid;

  if (!LookupPrivilegeValueW(NULL, privilege, &luid)) 
  {
    return -1;
  }

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) 
  {
    return -1;
  }

  if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
  {
    return -1;
  }

  return 0;
}

bool LbrManager::EnableProvider(TRACEHANDLE SessionHandle, LPCGUID ProviderGuid, UCHAR Level, ULONGLONG MatchAnyKeyword, ULONGLONG MatchAllKeyword)
{
  ULONG status = ERROR_SUCCESS;

  status = EnableTraceEx2(SessionHandle, ProviderGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, Level, MatchAnyKeyword,
                          MatchAllKeyword, 0, NULL);

  if (status != ERROR_SUCCESS) 
  {
    wprintf(L"EnableTraceEx2 returned %d and failed with GLE: %d\n", status, GetLastError());
    return false;
  }
  return true;
}

bool LbrManager::DisableProvider(TRACEHANDLE SessionHandle, LPCGUID ProviderGuid) 
{
  ULONG status = ERROR_SUCCESS;
  status = EnableTraceEx2(SessionHandle, ProviderGuid, EVENT_CONTROL_CODE_DISABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0,
                          0, 0, NULL);

  if (status != ERROR_SUCCESS) 
  {
    wprintf(L"EnableTraceEx2 returned %d and failed with GLE:%d\n", status, GetLastError());
    return false;
  }
  return true;
}

// Try to encapsulate most of the windows etw related logic/hooks
HRESULT LbrManager::InitializeEtwTrace() 
{
  auto hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  if (FAILED(hr)) 
  {
    wprintf(L"ERROR: Failed to initialize COM: 0x%08x\n", hr);
    return HRESULT_CODE(hr);
  }

  {
    // we need this permissions
    ULONG result = AddPrivilege(SE_SYSTEM_PROFILE_NAME);
    if (result != 0) 
    {
      wprintf(L"ERROR: Failed to add privilege SE_SYSTEM_PROFILE_NAME\n");
      return result;
    }
  }

  StopExistingTraceIfRunning(TRACE_NAME);

  ULONG result = 0;
  TRACEHANDLE traceHandle = {};
  EventTracePropertiesV2 traceProperties = {};

  traceProperties.Properties.VersionNumber = 2;

  traceProperties.Properties.Wnode.BufferSize = sizeof(EventTracePropertiesV2);

  // our GUID
  traceProperties.Properties.Wnode.Guid = LBR_COLLECTOR_GUID;

  // https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header
  // sets the clock resolution to use
  // 1 = Qpc; 2 = System Time; 3 = CPU Cycle Counter
  traceProperties.Properties.Wnode.ClientContext = 1;

  // Flags:               0x00820000
  //                      0x00020000 WNODE_FLAG_TRACED_GUID
  //                      0x00800000 WNODE_FLAG_VERSIONED_PROPERTIES
  traceProperties.Properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID | WNODE_FLAG_VERSIONED_PROPERTIES;

  // BufferSize:          64 kb
  // MinimumBuffers:      32
  // MaximumBuffers:      54
  // traceProperties.Properties.MaximumFileSize = 256; // Mb

  // or use memory buffer 0x00000400  EVENT_TRACE_BUFFERING_MODE
  //
  // EVENT_TRACE_SYSTEM_LOGGER_MODE         0x02000000 // Receive events from
  // SystemTraceProvider EVENT_TRACE_ADDTO_TRIAGE_DUMP          0x80000000 //
  // Add ETW buffers to triage dumps EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN
  // 0x00400000 // Stop on hybrid shutdown
  // EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN 0x00800000 // Persist on hybrid
  // shutdown EVENT_TRACE_INDEPENDENT_SESSION_MODE
  traceProperties.Properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE |
                                           /*EVENT_TRACE_FILE_MODE_CIRCULAR |*/ EVENT_TRACE_SYSTEM_LOGGER_MODE |
                                           EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN;

  // default; not forcing flushes
  // FlushTimer:          0

  traceProperties.Properties.EnableFlags = 0;

    // To ensure least amount of events dropped start with large buffer and minimum buffers.
  traceProperties.Properties.BufferSize = 16384;  // kb - to ensure no events get dropped
  traceProperties.Properties.MinimumBuffers = 64;

  // setup our logger name and filename
  traceProperties.Properties.LoggerNameOffset = offsetof(EventTracePropertiesV2, LoggerName);

  traceProperties.Properties.LogFileNameOffset = offsetof(EventTracePropertiesV2, LogFileName);
  // wcscpy_s(traceProperties.LogFileName, MAX_LOGFILE_PATH_LEN,
  // TRACE_FILEPATH);

  /*
  EVENT_FILTER_TYPE_EXECUTABLE_NAME(0x80000008)
  The executable file name.This is one of the scope filters.
  This is used with EVENT_TRACE_PROPERTIES_V2 for system wide private loggers.
  */
  /*
  auto exeNamesFilter = L"cmd.exe";
  int index = 0;
  EVENT_FILTER_DESCRIPTOR filterDescriptor[4] = {};
  filterDescriptor[index].Ptr = reinterpret_cast<ULONGLONG>(exeNamesFilter);
  filterDescriptor[index].Size = static_cast<ULONG>((wcslen(exeNamesFilter) + 1)
  * sizeof(WCHAR)); filterDescriptor[index].Type =
  EVENT_FILTER_TYPE_EXECUTABLE_NAME; index++;

  traceProperties.Properties.FilterDescCount = index;
  traceProperties.Properties.FilterDesc = (PEVENT_FILTER_DESCRIPTOR)
  &filterDescriptor;
  */

  result = AddPrivilege(SE_SYSTEM_PROFILE_NAME);
  if (result != 0) 
  {
    return result;
  }

  // Set the PMC source to be used for PMC profiling and then the Profiling interval for that source based on the
  // command line provided (or default) This is system-wide setting and hence does not need a trace handle. Later when
  // we enable SystemProfileProviderGuid along with the keyword SYSTEM_PROFILE_KW_PMC_PROFILE, trace will get the
  // PMCSample from the source configured at the profile interval specified by these two calls.

  // set sampling frequency
  ULONG profileInterval = (ULONG) CLRConfig::GetConfigValue(CLRConfig::INTERNAL_LBRSamplingFreq);

  TRACE_PROFILE_INTERVAL traceProfileInterval = {0};
  traceProfileInterval.Source = 30; // BranchInstructionRetired
  traceProfileInterval.Interval = profileInterval;

  result = TraceSetInformation(0, TraceProfileSourceConfigInfo, &traceProfileInterval.Source, sizeof(traceProfileInterval.Source));
  if (result != ERROR_SUCCESS) 
  {
    wprintf(L"TraceSetInformation failed to set TraceProfileSourceConfigInfo with %d\n", result);
    PrintSystemError(result);
  }

  result = TraceSetInformation(0, TraceSampledProfileIntervalInfo, (void*)&traceProfileInterval,
                               sizeof(TRACE_PROFILE_INTERVAL));
  if (FAILED(result))
  {
    printf("TraceSetInformation returned with EC %x\n", result);
  }

  result = StartTrace(&traceHandle,                              // [out]     PTRACEHANDLE TraceHandle,
                      TRACE_NAME,                                // [in]      LPCSTR InstanceName,
                      (EVENT_TRACE_PROPERTIES*)&traceProperties  // [in, out]
                                                                 // PEVENT_TRACE_PROPERTIES
                                                                 // Properties
  );

  if (result != 0) 
  {
    result = StopTrace(0, TRACE_NAME, (EVENT_TRACE_PROPERTIES*) &traceProperties);
    return result;
  }

  m_traceHandle = traceHandle;

  // Enable Process Provider and Image load provider, its the same provider guid but image can be enabled by adding
  // SYSTEM_PROCESS_KW_LOADER keyword
  if (!LbrManager::EnableProvider(m_traceHandle, &SystemProcessProviderGuid, TRACE_LEVEL_INFORMATION,
                      SYSTEM_PROCESS_KW_GENERAL | SYSTEM_PROCESS_KW_LOADER, 0)) 
  {
    wprintf(L"Failed to enable SYSTEM_PROCESS_KW_GENERAL | SYSTEM_PROCESS_KW_LOADER\n");
    StopTrace(m_traceHandle, TRACE_NAME, (EVENT_TRACE_PROPERTIES*)&traceProperties);
    return -1;
  }

  // Enable PerfInfo Provider with pmc_profile events using the keyword SYSTEM_PROFILE_KW_PMC_PROFILE
  // We need the SYSTEM_PROFILE_KW_PMC_PROFILE , as the PMCSample event are not posted by just enabling
  // SYSTEM_PROFILE_KW_GENERAL

  ULONGLONG systemProfileProviderKeyword = SYSTEM_PROFILE_KW_PMC_PROFILE;
  if (traceProfileInterval.Source == 0x0) 
  {  // timer
    systemProfileProviderKeyword = SYSTEM_PROFILE_KW_GENERAL;
  }

  if (!LbrManager::EnableProvider(m_traceHandle, &SystemProfileProviderGuid, TRACE_LEVEL_INFORMATION, systemProfileProviderKeyword, 0)) 
  {
    if (systemProfileProviderKeyword & SYSTEM_PROFILE_KW_GENERAL)
        wprintf(L"Failed to enable SYSTEM_PROFILE_KW_GENERAL\n");

    if (systemProfileProviderKeyword & SYSTEM_PROFILE_KW_PMC_PROFILE)
      wprintf(L"Failed to enable SYSTEM_PROFILE_KW_PMC_PROFILE\n");

    StopTrace(m_traceHandle, TRACE_NAME, (EVENT_TRACE_PROPERTIES*)&traceProperties);
    return -1;
  }

  // Enable LBR collection

  // LbrConfig options:
  //   1h        Kernel   mutually exclusive with User
  //   2h        User     mutually exclusive with Kernel
  //
  //   4h        ConditionalBranches
  //   8h        NearRelativeCalls
  //  10h        NearIndirectCalls
  //  20h        NearReturns
  //  40h        NearIndirectJumps
  //  80h        NearRelativeJumps
  // 100h        FarBranches
  // 200h        StackMode
  ULONG lbrConfig = 1;

  // LbrEventListSource : The event on which we want to capture LBRs.
  // EventListSource is basically a EVENT_GROUP combined with EVENT TYPE, MSFT has long discontinued sharing the
  // constants, reverse engineering from this :
  // https://github.com/microsoft/perfview/blob/a662474c24b228f70429d36963b7730d1be98722/src/TraceEvent/TraceEventSession.cs#L3330

  ULONG lbrEventSource = 0xf2f;  // EVENT_TRACE_GROUP_PERFINFO|PERFINFO_LOG_TYPE_PMC_INTERRUPT
  if (traceProfileInterval.Source == 0x0) 
  {    // timer
    lbrEventSource = 0xf2e;
  }

  ULONG lbrEventListSource[1] = {(lbrEventSource)};

  result = TraceSetInformation(m_traceHandle, TraceLbrConfigurationInfo, &lbrConfig, sizeof(lbrConfig));

  if (result != ERROR_SUCCESS) 
  {
    wprintf(L"TraceSetInformation for TraceLbrConfigurationInfo failed with %d\n", result);
    StopTrace(m_traceHandle, TRACE_NAME, (EVENT_TRACE_PROPERTIES*)&traceProperties);
    return result;
  }

  result = TraceSetInformation(traceHandle, TraceLbrEventListInfo, &lbrEventListSource, sizeof(lbrEventListSource));

  if (result != ERROR_SUCCESS) 
  {
    wprintf(L"TraceSetInformation for TraceLbrEventListInfo failed with %d\n", result);
    StopTrace(m_traceHandle, TRACE_NAME, (EVENT_TRACE_PROPERTIES*)&traceProperties);
    return result;
  }

  // setup our relogger 

  hr = CoCreateInstance(CLSID_TraceRelogger, nullptr, CLSCTX_INPROC_SERVER, __uuidof(ITraceRelogger),
                        reinterpret_cast<LPVOID*>(&m_relogger));
  if (FAILED(hr)) 
  {
    return hr;
  }

  {
    // todo-lbr: not sure if this is needed, Anthony
    //std::lock_guard<std::mutex> lock(relogger_mx);

    hr = m_relogger->SetCompressionMode(TRUE);
    hr = m_relogger->SetOutputFilename(BSTR(L".\\trace.etl"));
    hr = m_relogger->RegisterCallback(&m_callback);
    hr = m_relogger->AddRealtimeTraceStream(BSTR(TRACE_NAME), nullptr, &m_traceHandle);
  }

  m_callbackThread = std::thread([](ITraceRelogger *relogger) {
    relogger->ProcessTrace();
  }, m_relogger);

  return result;
}

HRESULT LbrManager::ShutdownEtwTrace()
{
  EventTracePropertiesV2 traceProperties = {};
  traceProperties.Properties.Wnode.BufferSize = sizeof(EventTracePropertiesV2);
  traceProperties.Properties.Wnode.Guid = LBR_COLLECTOR_GUID;
  traceProperties.Properties.LoggerNameOffset = offsetof(EventTracePropertiesV2, LoggerName);
  traceProperties.Properties.LogFileNameOffset = offsetof(EventTracePropertiesV2, LogFileName);

  HRESULT hr = StopTrace(m_traceHandle, nullptr, (EVENT_TRACE_PROPERTIES*) &traceProperties);
  if (FAILED(hr))
  {
    return hr;
  }

  m_callbackThread.detach();

  return S_OK;
}

void CallFClose2(FILE* file)
{
#if defined(HOST_WINDOWS) && !defined(FEATURE_NATIVEAOT)
    int fd = _fileno(file);
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    FlushFileBuffers(h);    // Flush to disk
#endif
    fclose(file);
}

typedef Holder<FILE*, DoNothing, CallFClose2> FILEHolder;

void LbrManager::WriteLBRData()
{
  if (!m_shouldWriteLbrData)
  {
    return;
  }

  CLRConfigStringHolder fileName(CLRConfig::GetConfigValue(CLRConfig::INTERNAL_LBRDataPath));

  if (fileName == 0)
  {
    printf("LBR: No LBR data path specified\n");
    return;
  }

  const wchar_t *writeFlags = CLRConfig::GetConfigValue(CLRConfig::INTERNAL_AppendLBRData) == 1 ? W("ab") : W("wb");
  FILE* const lbrDataFile = _wfopen(fileName, writeFlags);
  if (lbrDataFile == NULL)
  {
    DWORD err = GetLastError();
    wchar_t* errorMsg = nullptr;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&errorMsg,
        0,
        NULL);
    const wchar_t* fileNameStr = fileName.GetValue();
    wprintf(L"LBR: Error opening file %ls (error %lu: %s)\n", fileNameStr, err, errorMsg ? errorMsg : L"Unknown error");
    if (errorMsg) LocalFree(errorMsg);
    return;
  }

  FILEHolder fileHolder(lbrDataFile);

  int lbrDataCount = 0;
  EnumerateLbrHeaders([&lbrDataCount](HeaderList *lbrData)
  {
    lbrDataCount++;
    return true;
  });

  fprintf(lbrDataFile, s_LbrFileHeaderString, m_alignedSamples, m_missedSamples, m_numMethodHeadersCreated);

  if (lbrDataCount == 0)
  {
    printf("LBR: No LBR data to write\n");
    return;
  }

  // Write the data in two parts: 
  // 1. Some custom tracking for LBR analysis
  // 2. Use existing WritePGOData logic to get a similar schema as what is written for PGO for comparison

  // 1. Write the LBR specific data first

  EnumerateLbrHeaders([lbrDataFile](HeaderList *lbrData)
  {
    if (lbrData->header.samples.GetCount() == 0 || lbrData->header.record->alignedSamples == 0)
    {
      return true;
    }

    //fprintf(lbrDataFile, s_MethodHeaderString, lbrData->header.codehash, lbrData->header.methodhash, lbrData->header.ilSize);
    SString tClass, tMethodName, tMethodSignature;
    lbrData->header.method->GetMethodInfo(tClass, tMethodName, tMethodSignature);

    fprintf(lbrDataFile, "@@@\n");
    fprintf(lbrDataFile, "MethodName: %s.%s\n", tClass.GetUTF8(), tMethodName.GetUTF8());
    fprintf(lbrDataFile, "Signature: %s\n", tMethodSignature.GetUTF8());

    fprintf(lbrDataFile, "** Sample Histogram (%d) **\n", lbrData->header.samples.GetCount());
    for (auto &p : lbrData->header.record->sampleHistogram)
    {
      fprintf(lbrDataFile, "from:%lld to:%lld count:%d\n", std::get<0>(p.first), std::get<1>(p.first) , p.second);
    }

    if (!strcmp("Avx2Decode", tMethodName.GetUTF8()))
    {
      printf("HIT!");
    }

    fprintf(lbrDataFile, "** Block Maps **\n");
    for (size_t i = 0; i < lbrData->header.record->nativeToSchemaMap.NumIntervals(); i++)
    {
      const LbrNativeToSchemaMapping::IntervalMappingDesc &p = lbrData->header.record->nativeToSchemaMap.GetIntervalMappingDesc(i);
      fprintf(lbrDataFile, "nativeOffset:[%d,%d] iLOffset:%d samples:%lld\n", p.nativeIntervals.low, p.nativeIntervals.high, p.ilOffset, lbrData->header.record->nativeToSchemaMap.GetSampleCount(i));
    }

    return true;
  });

  fprintf(lbrDataFile, s_LbrFileTrailerString);
}

HRESULT STDMETHODCALLTYPE LbrEventCallback::OnEvent(ITraceEvent* traceEvent, ITraceRelogger* relogger) 
{
  PEVENT_RECORD eventRecord = nullptr;
  HRESULT hr = traceEvent->GetEventRecord(&eventRecord);
  if (hr == S_OK) 
  {
    const ULONG pid = eventRecord->EventHeader.ProcessId;

    const USHORT eventId = (eventRecord->EventHeader.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER) != 0
                                ? eventRecord->EventHeader.EventDescriptor.Opcode
                                : eventRecord->EventHeader.EventDescriptor.Id;

    // last branch records
    if (memcmp(&(eventRecord->EventHeader.ProviderId), &ProviderLastBranchRecordEvent, sizeof(GUID)) == 0) 
    {
      if (eventRecord->UserDataLength < sizeof(LbrEvent)) 
      {
        return S_OK;
      }

      auto lbrEvent = (LbrEvent*)eventRecord->UserData;

      if (lbrEvent->process != m_processId)
      {
        return S_OK;
      }

      m_lbrMgr->ReceiveLbrEvent(lbrEvent);
    }
  }

  return S_OK;
}


#endif // defined(HOST_WINDOWS) && !defined(FEATURE_NATIVEAOT)
#endif // FEATURE_LBR
