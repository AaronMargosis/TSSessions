#pragma once

#include <Windows.h>
#include <WtsApi32.h>
#include <string>
#include <list>
#include <memory>
#include "CSid.h"

class TerminalSession;
typedef std::list<TerminalSession> TerminalSessionList_t;

struct TSProcessInfo_t
{
	DWORD dwPID = 0;
	std::wstring sProcessName;
	CSid userSid;

	//TODO: Using WTS_PROCESS_INFOW for the above. Could provide a lot more info with WTS_PROCESS_INFO_EXW:
	// https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wts_process_info_exw
};
typedef std::list<TSProcessInfo_t> TSProcessInfoList_t;


//TODO: add feature to enumerate listeners
// https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenumeratelistenersw

/// <summary>
/// Class to encapsulate access to information about Windows Terminal Sessions (a.k.a. "remote desktop")
/// </summary>
class TerminalSession
{
public:
	// static member functions:

	/// <summary>
	/// Return a collection of all terminal sessions on the current system
	/// </summary>
	/// <param name="tsList">Output: collection to populate</param>
	/// <param name="sErrorInfo">Output: information if an error occurs</param>
	/// <returns>true if successful, false otherwise</returns>
	static bool GetTerminalSessions(TerminalSessionList_t& tsList, std::wstring& sErrorInfo);

	/// <summary>
	/// The session identifier of the session that is attached to the physical console. 
	/// If there is no session attached to the physical console, (for example, if the physical 
	/// console session is in the process of being attached or detached), this 
	/// function returns 0xFFFFFFFF.
	/// </summary>
	static DWORD ActiveConsoleSessionId();

	/// <summary>
	/// Returns the session ID in which this process is executing.
	/// </summary>
	/// <param name="dwSessionId">Output: the session ID</param>
	/// <param name="sErrorInfo">Output: information if an error occurs</param>
	/// <returns>true if successful, false otherwise</returns>
	static bool CurrentProcessSessionId(DWORD& dwSessionId, std::wstring& sErrorInfo);

	/// <summary>
	/// Returns true if child sessions are enabled.
	/// </summary>
	static bool AreChildSessionsEnabled();

public:
	// --------------------------------------------------------------------------------
	// ctor, dtor, cctor, assignment - all defaults
	TerminalSession() = default;
	~TerminalSession() = default;
	TerminalSession(const TerminalSession&) = default;
	TerminalSession& operator = (const TerminalSession&) = default;

	// --------------------------------------------------------------------------------
	// Initialization functions

	/// <summary>
	/// Initialize this object from a WTS_SESSION_INFOW
	/// </summary>
	bool Initialize(const WTS_SESSION_INFOW& sessionInfo, std::wstring& sErrorInfo);

	/// <summary>
	/// Initialize this object from a session ID
	/// </summary>
	bool Initialize(DWORD dwSessionId, std::wstring& sErrorInfo);

	/// <summary>
	/// Initialize this object from the session associated with the current process
	/// </summary>
	bool FromCurrentProcess(std::wstring& sErrorInfo);

	// --------------------------------------------------------------------------------
	// Member functions to return attributes about this session.
	// Note that SessionFlags is not reliable on Win7/WS2008R2.

	DWORD ID() const;
	std::wstring Name() const;
	std::wstring State() const;
	std::wstring SessionFlags() const;
	std::wstring DomainName() const;
	std::wstring UserName() const;
	std::wstring LogonTime() const;
	std::wstring ConnectTime() const;
	std::wstring DisconnectTime() const;
	std::wstring LastInputTime() const;
	std::wstring CurrentTime() const;

	/// <summary>
	/// Get the user token associated with the session. (Must be running as System to do this.)
	/// Note that the caller must call CloseHandle on the returned hToken.
	/// </summary>
	/// <param name="hToken">Output: user token associated with the session, if successful.</param>
	/// <param name="sErrorInfo">Output: information if an error occurred.</param>
	/// <returns>true if successful, false otherwise</returns>
	bool GetUserToken(HANDLE& hToken, DWORD& dwLastErr) const;

	/// <summary>
	/// Return a list of all processes associated with the terminal session.
	/// </summary>
	/// <param name="processList">Output: collection to populate</param>
	/// <param name="sErrorInfo">Output: information if an error occurred</param>
	/// <returns>true if successful, false otherwise</returns>
	bool GetProcesses(TSProcessInfoList_t& processList, std::wstring& sErrorInfo) const;

private:
	/// <summary>
	/// Internal initialization helper function
	/// </summary>
	bool InitWtsInfo(DWORD dwSessionId, std::wstring& sErrorInfo);

private:

	DWORD m_dwSessionId = 0xFFFFFFFF;
	std::wstring m_sSessionName;
	WTS_CONNECTSTATE_CLASS m_state = WTS_CONNECTSTATE_CLASS::WTSInit;
	WTSINFOEX_LEVEL1_W m_tsInfo = { 0 };
};

