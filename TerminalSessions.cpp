#include "TerminalSessions.h"
#pragma comment(lib, "Wtsapi32.lib")
#include "SysErrorMessage.h"
#include "StringUtils.h"

// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------
// static member functions


/// <summary>
/// Return a collection of all terminal sessions on the current system
/// </summary>
/// <param name="tsList">Output: collection to populate</param>
/// <param name="sErrorInfo">Output: information if an error occurs</param>
/// <returns>true if successful, false otherwise</returns>
bool TerminalSession::GetTerminalSessions(TerminalSessionList_t& tsList, std::wstring& sErrorInfo)
{
    tsList.clear();
    sErrorInfo.clear();

    PWTS_SESSION_INFOW pSessInfo = NULL;
    DWORD dwSessCount = 0;
    BOOL ret = WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessInfo, &dwSessCount);
    if (!ret)
    {
        sErrorInfo = SysErrorMessageWithCode();
        return false;
    }

    for (DWORD ix = 0; ix < dwSessCount; ++ix)
    {
        TerminalSession ts;
        ts.Initialize(pSessInfo[ix], sErrorInfo);
        tsList.push_back(ts);
    }

    WTSFreeMemory(pSessInfo);
    return true;
}

/// <summary>
/// The session identifier of the session that is attached to the physical console. 
/// If there is no session attached to the physical console, (for example, if the physical 
/// console session is in the process of being attached or detached), this 
/// function returns 0xFFFFFFFF.
/// </summary>
DWORD TerminalSession::ActiveConsoleSessionId()
{
    return WTSGetActiveConsoleSessionId();
}

/// <summary>
/// Returns the session ID in which this process is executing.
/// </summary>
/// <param name="dwSessionId">Output: the session ID</param>
/// <param name="sErrorInfo">Output: information if an error occurs</param>
/// <returns>true if successful, false otherwise</returns>
bool TerminalSession::CurrentProcessSessionId(DWORD& dwSessionId, std::wstring& sErrorInfo)
{
    sErrorInfo.clear();
    if (ProcessIdToSessionId(GetCurrentProcessId(), &dwSessionId))
    {
        return true;
    }
    else
    {
        sErrorInfo = SysErrorMessageWithCode();
        return false;
    }
}

/// <summary>
/// Returns true if child sessions are enabled.
/// </summary>
bool TerminalSession::AreChildSessionsEnabled()
{
    // Need to GetProcAddress this function to run on pre-Win8/WS2012, and to build
    // an x86 version, as it appears not to be present in the 32-bit WtsApi32.lib.
    bool ret = false;
    HMODULE hModWts = GetModuleHandleW(L"wtsapi32.dll");
    if (NULL != hModWts)
    {
        // Note: the SDK header file doesn't indicate its a stdcall function, but it seems to be one.
        typedef BOOL (WINAPI *pfn_WTSIsChildSessionsEnabled_t)(_Out_ PBOOL pbEnabled);
        pfn_WTSIsChildSessionsEnabled_t pfn_WTSIsChildSessionsEnabled = (pfn_WTSIsChildSessionsEnabled_t)GetProcAddress(hModWts, "WTSIsChildSessionsEnabled");
        if (pfn_WTSIsChildSessionsEnabled)
        {
            BOOL bEnabled = FALSE;
            if (pfn_WTSIsChildSessionsEnabled(&bEnabled) && bEnabled)
            {
                ret = true;
            }
        }
    }
    return ret;
}

// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------
// Initialization functions


/// <summary>
/// Initialize this object from a WTS_SESSION_INFOW
/// </summary>
bool TerminalSession::Initialize(const WTS_SESSION_INFOW& sessionInfo, std::wstring& sErrorInfo)
{
    sErrorInfo.clear();
    m_dwSessionId = sessionInfo.SessionId;
    m_sSessionName = sessionInfo.pWinStationName ? sessionInfo.pWinStationName : L"(null)";
    m_state = sessionInfo.State;
    return InitWtsInfo(m_dwSessionId, sErrorInfo);
}

/// <summary>
/// Initialize this object from a session ID
/// </summary>
bool TerminalSession::Initialize(DWORD dwSessionId, std::wstring& sErrorInfo)
{
    m_dwSessionId = dwSessionId;
    if (InitWtsInfo(dwSessionId, sErrorInfo))
    {
        m_sSessionName = m_tsInfo.WinStationName;
        m_state = m_tsInfo.SessionState;
        return true;
    }
    else
    {
        return false;
    }
}

/// <summary>
/// Initialize this object from the session associated with the current process
/// </summary>
bool TerminalSession::FromCurrentProcess(std::wstring& sErrorInfo)
{
    sErrorInfo.clear();
    DWORD dwSessionId = 0;
    return (CurrentProcessSessionId(dwSessionId, sErrorInfo) && Initialize(dwSessionId, sErrorInfo));
}

/// <summary>
/// Internal initialization helper function
/// </summary>
bool TerminalSession::InitWtsInfo(DWORD dwSessionId, std::wstring& sErrorInfo)
{
    sErrorInfo.clear();

    PWTSINFOEXW pWtsInfo = nullptr;
    DWORD dwBytesReturned = 0;
    BOOL ret = WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, dwSessionId, WTSSessionInfoEx, (LPWSTR*)&pWtsInfo, &dwBytesReturned);
    if (ret)
    {
        m_tsInfo = pWtsInfo->Data.WTSInfoExLevel1;
    }
    else
    {
        DWORD dwLastErr = GetLastError();
        sErrorInfo = SysErrorMessageWithCode(dwLastErr);
    }
    if (pWtsInfo)
    {
        WTSFreeMemory(pWtsInfo);
    }
    return ret ? true : false;
}

// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------
// Member functions to return attributes about this session:


DWORD TerminalSession::ID() const
{
    return m_dwSessionId;
}

std::wstring TerminalSession::Name() const
{
    return m_tsInfo.WinStationName;
}

std::wstring TerminalSession::State() const
{
    switch (m_tsInfo.SessionState)
    {
    case WTSActive:
        return L"Active";
    case WTSConnected:
        return L"Connected";
    case WTSConnectQuery:
        return L"ConnectQuery";
    case WTSShadow:
        return L"Shadow";
    case WTSDisconnected:
        return L"Disconnected";
    case WTSIdle:
        return L"Idle";
    case WTSListen:
        return L"Listen";
    case WTSReset:
        return L"Reset";
    case WTSDown:
        return L"Down";
    case WTSInit:
        return L"Init";
    default:
        return L"[unexpected]";
    }
}

std::wstring TerminalSession::SessionFlags() const
{
    switch (m_tsInfo.SessionFlags)
    {
    case WTS_SESSIONSTATE_LOCK:
        return L"WTS_SESSIONSTATE_LOCK";
    case WTS_SESSIONSTATE_UNLOCK:
        return L"WTS_SESSIONSTATE_UNLOCK";
    case WTS_SESSIONSTATE_UNKNOWN:
        return L"WTS_SESSIONSTATE_UNKNOWN";
    default:
        return L"[unexpected]";
    }
}

std::wstring TerminalSession::DomainName() const
{
    return m_tsInfo.DomainName;
}

std::wstring TerminalSession::UserName() const
{
    return m_tsInfo.UserName;
}

std::wstring TerminalSession::LogonTime() const
{
    return LargeIntegerToDateTimeString(m_tsInfo.LogonTime);
}

std::wstring TerminalSession::ConnectTime() const
{
    return LargeIntegerToDateTimeString(m_tsInfo.ConnectTime);
}

std::wstring TerminalSession::DisconnectTime() const
{
    return LargeIntegerToDateTimeString(m_tsInfo.DisconnectTime);
}

std::wstring TerminalSession::LastInputTime() const
{
    return LargeIntegerToDateTimeString(m_tsInfo.LastInputTime);
}

std::wstring TerminalSession::CurrentTime() const
{
    return LargeIntegerToDateTimeString(m_tsInfo.CurrentTime);
}

// --------------------------------------------------------------------------------

/// <summary>
/// Get the user token associated with the session. (Must be running as System to do this.)
/// Note that the caller must call CloseHandle on the returned hToken.
/// </summary>
/// <param name="hToken">Output: user token associated with the session, if successful.</param>
/// <param name="sErrorInfo">Output: information if an error occurred.</param>
/// <returns>true if successful, false otherwise</returns>
bool TerminalSession::GetUserToken(HANDLE& hToken, DWORD& dwLastErr) const
{
    if (WTSQueryUserToken(m_dwSessionId, &hToken))
    {
        return true;
    }
    else
    {
        dwLastErr = GetLastError();
        return false;
    }
}

/// <summary>
/// Return a list of all processes associated with the terminal session.
/// </summary>
/// <param name="processList">Output: collection to populate</param>
/// <param name="sErrorInfo">Output: information if an error occurred</param>
/// <returns>true if successful, false otherwise</returns>
bool TerminalSession::GetProcesses(TSProcessInfoList_t& processList, std::wstring& sErrorInfo) const
{
    processList.clear();
    sErrorInfo.clear();

    WTS_PROCESS_INFOW* pProcessesInfo = nullptr;
    DWORD dwProcessCount = 0;
    DWORD dwLevel = 0;
#pragma warning(push)
#pragma warning(disable: 6387) 
    // Disable this false positive:
    // Warning	C6387	'_Param_(1)' could be '0':  this does not adhere to the specification for the function 'WTSEnumerateProcessesExW'.
    BOOL ret = WTSEnumerateProcessesExW(WTS_CURRENT_SERVER_HANDLE, &dwLevel, m_dwSessionId, (LPWSTR*)&pProcessesInfo, &dwProcessCount);
#pragma warning(pop)
    if (!ret)
    {
        sErrorInfo = SysErrorMessageWithCode();
        return false;
    }

    for (size_t ix = 0; ix < dwProcessCount; ++ix)
    {
        WTS_PROCESS_INFOW& wtsCurrProcess = pProcessesInfo[ix];
        TSProcessInfo_t procInfo;
        procInfo.userSid = CSid(wtsCurrProcess.pUserSid);
        procInfo.dwPID = wtsCurrProcess.ProcessId;
        procInfo.sProcessName = (wtsCurrProcess.pProcessName ? wtsCurrProcess.pProcessName : L"[null]");
        processList.push_back(procInfo);
    }

    WTSFreeMemoryExW(WTSTypeProcessInfoLevel0, pProcessesInfo, dwProcessCount);

    return true;
}

