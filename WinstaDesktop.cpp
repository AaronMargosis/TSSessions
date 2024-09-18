// ----------------------------------------------------------------------------------------------------
// WinstaDesktop.cpp: encapsulation of information about window stations and desktops.

#include <Windows.h>
#include <Psapi.h>
#include <sstream>
#include <sddl.h>
#include "WinstaDesktop.h"
#include "SysErrorMessage.h"
#include "HEX.h"
#include "DbgOut.h"

// Ensure that a static singleton instance is initialized early
static const WindowStation st_OriginalWS(GetProcessWindowStation(), false);
static const Desktop st_OriginalWSDesktop(st_OriginalWS, GetThreadDesktop(GetCurrentThreadId()), false);

// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Copy constructor (does it copy the m_OriginalSD?)
/// </summary>
UserObject::UserObject(const UserObject& other)
{
	m_OpenedName = other.m_OpenedName;
}

/// <summary>
/// Assignment operator (does it copy the m_OriginalSD?)
/// </summary>
UserObject& UserObject::operator=(const UserObject& other)
{
	m_OpenedName = other.m_OpenedName;
	return *this;
}

/// <summary>
/// Internal function to support cctor and assignment
/// </summary>
/// <param name="hObj">Handle to duplicate</param>
/// <returns>Duplicated handle. Caller is responsible for closing it.</returns>
HANDLE UserObject::DuplicateMyHandle(HANDLE hObj)
{
	//TODO: Test whether this correctly duplicates Winsta/Desktop handles
	HANDLE retval = nullptr;
	BOOL ret = DuplicateHandle(GetCurrentProcess(), hObj, GetCurrentProcess(), &retval, 0, FALSE, DUPLICATE_SAME_ACCESS);
	if (ret)
		return retval;
	else
		return nullptr;
}

/// <summary>
/// Encapsulate assigning of object handle and whether it needs to be closed when no longer needed.
/// </summary>
/// <param name="hObjToSet">A reference to the derived-class member variable to set</param>
/// <param name="hSource">The value to set the derived-class member variable to</param>
/// <param name="bNeedsToBeClosed">Whether the handle needs to be closed</param>
void UserObject::AssignUOHandle(HWINSTA& hObjToSet, const HWINSTA hSource, bool bNeedsToBeClosed)
{
	hObjToSet = hSource;
	m_bHandleNeedsToBeClosed = bNeedsToBeClosed;
}

/// <summary>
/// Encapsulate assigning of object handle and whether it needs to be closed when no longer needed.
/// </summary>
/// <param name="hObjToSet">A reference to the derived-class member variable to set</param>
/// <param name="hSource">The value to set the derived-class member variable to</param>
/// <param name="bNeedsToBeClosed">Whether the handle needs to be closed</param>
void UserObject::AssignUOHandle(HDESK& hObjToSet, const HDESK hSource, bool bNeedsToBeClosed)
{
	hObjToSet = hSource;
	m_bHandleNeedsToBeClosed = bNeedsToBeClosed;
}

// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Internal wrapper function for GetUserObjectInformationW
/// </summary>
/// <param name="index">Input: information to retrieve</param>
/// <param name="mem">Output: memory object to put information into</param>
/// <param name="sErrorInfo">Output: information in case of error</param>
/// <returns>Pointer to memory if successful, nullptr otherwise.</returns>
PVOID UserObject::GetUOInfo(int index, HeapMem& mem, std::wstring& sErrorInfo) const
{
	sErrorInfo.clear();
	// Default to 1024 bytes
	const DWORD dwDefaultSize = 1024;
	if (!mem.Alloc(dwDefaultSize, sErrorInfo))
		return nullptr;

	DWORD dwDataLength = 0;
	// Try with a default buffer size; if that fails, create a bigger allocation and try again.
	if (!GetUserObjectInformationW(GetUOHandle(), index, mem.Get(), dwDefaultSize, &dwDataLength))
	{
		if (!mem.Alloc(dwDataLength, sErrorInfo))
			return nullptr;
		if (!GetUserObjectInformationW(GetUOHandle(), index, mem.Get(), dwDataLength, &dwDataLength))
		{
			sErrorInfo = SysErrorMessageWithCode();
			return nullptr;
		}
	}

	return (0 == dwDataLength) ? nullptr : mem.Get();
}


/// <summary>
/// Retrieves the name of the window station or desktop
/// </summary>
bool UserObject::Name(std::wstring& sName, std::wstring& sErrorInfo) const
{
	HeapMem mem;
	const wchar_t* psz = (const wchar_t*)GetUOInfo(UOI_NAME, mem, sErrorInfo);
	if (psz)
	{
		sName = psz;
		return true;
	}
	else
	{
		sName.clear();
		return false;
	}
}

/// <summary>
/// Retrieves the name of the object type
/// </summary>
bool UserObject::Type(std::wstring& sType, std::wstring& sErrorInfo) const
{
	HeapMem mem;
	const wchar_t* psz = (const wchar_t*)GetUOInfo(UOI_TYPE, mem, sErrorInfo);
	if (psz)
	{
		sType = psz;
		return true;
	}
	else
	{
		sType.clear();
		return false;
	}
}

/// <summary>
/// Retrieves the binary flags associated with the window station or desktop
/// </summary>
bool UserObject::Flags(DWORD& dwFlags, std::wstring& sErrorInfo) const
{
	HeapMem mem;
	const USEROBJECTFLAGS* pUOFlags = (const USEROBJECTFLAGS*)GetUOInfo(UOI_FLAGS, mem, sErrorInfo);
	if (pUOFlags)
	{
		dwFlags = pUOFlags->dwFlags;
		return true;
	}
	else
	{
		return false;
	}
}

/// <summary>
/// Retrieves the user SID associated with the object.
/// </summary>
bool UserObject::UserSID(CSid& sid, std::wstring& sErrorInfo) const
{
	HeapMem mem;
	PSID* pSID = (PSID*)GetUOInfo(UOI_USER_SID, mem, sErrorInfo);
	//dbgOut.locked() << L"UserObject::UserSID - GetUOInfo returns " << pSID << L" and " << sErrorInfo << std::endl;
	if (pSID)
	{
		sid = CSid(pSID);
		return true;
	}
	else
	{
		return false;
	}
}

/// <summary>
/// Retrieves the username and SID associated with the object (or "(no user)" if there isn't one).
/// </summary>
/// <returns>true if successful (even if no user), false if an error occurred.</returns>
bool UserObject::UserNameAndSid(std::wstring& sUserNameAndSid, std::wstring& sErrorInfo) const
{
	sUserNameAndSid.clear();
	CSid sid;
	if (UserSID(sid, sErrorInfo))
	{
		std::wstring sUserName = sid.toDomainAndUsername();
		if (sUserName.empty())
			sUserNameAndSid = sid.toSidString();
		else
			sUserNameAndSid = sUserName + L" (" + sid.toSidString() + L")";
		return true;
	}
	else if (sErrorInfo.empty())
	{
		sUserNameAndSid = L"(no user)";
		return true;
	}
	else
	{
		return false;
	}
}

// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Gets the security descriptor associated with the object.
/// </summary>
/// <param name="memSecurityDescriptor">Output: heap-allocation object containing the security descriptor</param>
/// <param name="si"></param>
/// <param name="sErrorInfo">Output: information in the case of an error</param>
/// <returns>true if successful, false otherwise.</returns>
bool UserObject::GetSecurity(SecurityDescriptor& memSecurityDescriptor, SECURITY_INFORMATION si, std::wstring& sErrorInfo) const
{
	memSecurityDescriptor.Dealloc();
	sErrorInfo.clear();
	DWORD nLenNeeded = 0;
	BOOL ret = GetUserObjectSecurity(GetUOHandle(), &si, nullptr, 0, &nLenNeeded);
	DWORD dwLastErr = GetLastError();
	if (ERROR_INSUFFICIENT_BUFFER == dwLastErr)
	{
		if (memSecurityDescriptor.Alloc(nLenNeeded, sErrorInfo))
		{
			ret = GetUserObjectSecurity(GetUOHandle(), &si, memSecurityDescriptor.GetSD(), nLenNeeded, &nLenNeeded);
			if (ret)
				return true;
			else
				sErrorInfo = SysErrorMessageWithCode();
		}
	}
	else
	{
		sErrorInfo = SysErrorMessageWithCode(dwLastErr);
	}
	return false;
}

/// <summary>
/// Sets the security descriptor for the object
/// </summary>
/// <param name="pSD">Input: the security descriptor to apply to the object</param>
/// <param name="si">Input: The security information to apply to the object</param>
/// <param name="sErrorInfo">Output: information in case of an error</param>
/// <returns>true if successful, false otherwise.</returns>
bool UserObject::SetSecurity(PSECURITY_DESCRIPTOR pSD, SECURITY_INFORMATION si, std::wstring& sErrorInfo)
{
	sErrorInfo.clear();
	BOOL ret = SetUserObjectSecurity(GetUOHandle(), &si, pSD);
	if (ret)
	{
		return true;
	}
	else
	{
		sErrorInfo = SysErrorMessageWithCode();
		return false;
	}
}

// ----------------------------------------------------------------------------------------------------
// ----------------------------------------------------------------------------------------------------

WindowStation::WindowStation(HWINSTA hWinsta, bool bNeedsToBeClosed)
{
	AssignUOHandle(m_hObj, hWinsta, bNeedsToBeClosed);
}

WindowStation::~WindowStation()
{
	CloseUOHandle();
}

WindowStation::WindowStation(const WindowStation& other) : UserObject(other)
{
	AssignUOHandle(m_hObj, (HWINSTA)DuplicateMyHandle(other.m_hObj), true);
}

WindowStation& WindowStation::operator=(const WindowStation& other)
{
	CloseUOHandle();
	AssignUOHandle(m_hObj, (HWINSTA)DuplicateMyHandle(other.m_hObj), true);
	return *this;
}

/// <summary>
/// Indicates whether this window station refers to the same WS as "other".
/// Based on window station names. Assumes that they are in the same TS session.
/// </summary>
bool WindowStation::operator==(const WindowStation& other) const
{
	std::wstring sThisName, sOtherName, sErrorInfo;
	bool retval = (
		this->Name(sThisName, sErrorInfo) &&
		other.Name(sOtherName, sErrorInfo) &&
		sThisName == sOtherName);
	return retval;
}

/// <summary>
/// Indicates whether this window station refers to the same WS as "sOther".
/// Based on window station names. Assumes that they are in the same TS session.
/// </summary>
bool WindowStation::operator==(const std::wstring& sOtherName) const
{
	std::wstring sThisName, sErrorInfo;
	bool retval = (
		this->Name(sThisName, sErrorInfo) &&
		sThisName == sOtherName);
	return retval;
}

/// <summary>
/// Static function returns a reference to a WindowStation object referencing the 
/// window station this process started in.
/// </summary>
const WindowStation& WindowStation::Original()
{
	return st_OriginalWS;
}

std::wstring WindowStation::CurrentName(std::wstring& sErrorInfo)
{
	WindowStation wsCurrent;
	std::wstring sName;
	if (
		wsCurrent.InitFromCurrentProcess(sErrorInfo) &&
		wsCurrent.Name(sName, sErrorInfo)
		)
	{
		return sName;
	}
	else
	{
		return L"";
	}
}

/// <summary>
/// Virtual function override to close the object-specific handle
/// </summary>
void WindowStation::CloseUOHandle()
{
	if (m_hObj)
	{
		if (m_bHandleNeedsToBeClosed)
		{
			CloseWindowStation(m_hObj);
		}
		m_hObj = nullptr;
	}
}

// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Open a named window station in the current session.
/// </summary>
/// <param name="szWinSta">Input: name of the window station in the current session to open</param>
/// <param name="dwDesiredAccess">Input: requested access</param>
/// <param name="sErrorInfo">Output: information in case of error</param>
/// <returns>true if successful, false otherwise</returns>
bool WindowStation::Open(const wchar_t* szWinSta, DWORD dwDesiredAccess, std::wstring& sErrorInfo)
{
	sErrorInfo.clear();
	CloseUOHandle();
	m_OpenedName = szWinSta;
	HWINSTA hWinsta = OpenWindowStationW(szWinSta, FALSE, dwDesiredAccess);
	if (hWinsta)
	{
		AssignUOHandle(m_hObj, hWinsta, true);
		return true;
	}
	else
	{
		sErrorInfo = SysErrorMessageWithCode();
		return false;
	}
}

/// <summary>
/// Initialize this WindowStation instance from the window station in which this process is executing.
/// </summary>
/// <param name="sErrorInfo">Output: information in case of error</param>
/// <returns>true if successful, false otherwise</returns>
bool WindowStation::InitFromCurrentProcess(std::wstring& sErrorInfo)
{
	sErrorInfo.clear();
	CloseUOHandle();
	// GetProcessWindowStation: "Do not close the handle returned by this function."
	HWINSTA hWinsta = GetProcessWindowStation();
	if (hWinsta)
	{
		AssignUOHandle(m_hObj, hWinsta, false);
		return true;
	}
	else
	{
		sErrorInfo = SysErrorMessageWithCode();
		return false;
	}
}

/// <summary>
/// Assign the current process to the window station
/// </summary>
/// <param name="sErrorInfo">Output: information in case of error</param>
/// <returns>true if successful, false otherwise</returns>
bool WindowStation::AssignThisProcess(std::wstring& sErrorInfo) const
{
	sErrorInfo.clear();

	std::wstring sName, sForDbgout;
	if (!this->Name(sName, sForDbgout))
		sName = L"***Error: " + sForDbgout;

	if (SetProcessWindowStation(m_hObj))
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
/// Returns an object-specific string representation of the object's flags (override of UserObject pure virtual function)
/// </summary>
bool WindowStation::Flags(std::wstring& sFlags, std::wstring& sErrorInfo) const
{
	DWORD dwFlags;
	if (UserObject::Flags(dwFlags, sErrorInfo))
	{
		std::wstringstream str;
		str << HEX(dwFlags, 8, false, true);
		if (dwFlags & WSF_VISIBLE)
			str << L" WSF_VISIBLE";
		sFlags = str.str();
		return true;
	}
	else
	{
		sFlags.clear();
		return false;
	}
}

// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Structure for passing multiple data items with a single address.
/// </summary>
struct EnumDesktopProcData_t
{
	const WindowStation* pWS;
	DesktopList_t* pDesktopList;
};

/// <summary>
/// Enumeration callback for retrieving information about desktops in a window station
/// </summary>
/// <param name="lpszDesktop">Name of desktop</param>
/// <param name="lParam">Pointer to the window station and the DesktopList_t to populate</param>
static BOOL __stdcall EnumDesktopProcW(LPWSTR lpszDesktop, LPARAM lParam)
{
	EnumDesktopProcData_t* pEnumDeskData = (EnumDesktopProcData_t*)lParam;
	DesktopList_t* pDesktopList = pEnumDeskData->pDesktopList;

	// Initialize a new Desktop object so that it can be added to the list
	Desktop desktop(*(pEnumDeskData->pWS));
	std::wstring sErrorInfo;
	if (desktop.Open(lpszDesktop, MAXIMUM_ALLOWED, sErrorInfo)) // | READ_CONTROL | WRITE_DAC | WRITE_OWNER))
	{
		pDesktopList->push_back(desktop);
	}
	else
	{
		//TODO: Shouldn't be writing to stdout/stderr from here
		std::wcerr << L"OpenDesktop " << lpszDesktop << L": " << sErrorInfo << std::endl;
	}
	return TRUE;
}

/// <summary>
/// Retrieve information about the desktops in this window station
/// </summary>
/// <param name="desktopList">DesktopList_t to populate</param>
/// <param name="sErrorInfo">Output: information in case of error</param>
/// <returns>true if successful, false otherwise</returns>
bool WindowStation::GetDesktops(DesktopList_t& desktopList, std::wstring& sErrorInfo) const
{
	desktopList.clear();
	sErrorInfo.clear();
	bool retval = false;
	// The enumeration callback will try to open the enumerated desktops, which requires that
	// this process be in the corresponding window station.
	std::wstring sSwitchError;
	if (this->AssignThisProcess(sSwitchError))
	{
		EnumDesktopProcData_t enumDeskData = { this, &desktopList };
		retval = (EnumDesktopsW(m_hObj, EnumDesktopProcW, (LPARAM)&enumDeskData) ? true : false);
		if (!retval)
		{
			sErrorInfo = SysErrorMessageWithCode();
		}

		if (!st_OriginalWS.AssignThisProcess(sSwitchError))
		{
			//TODO: can't switch back? What to do?
		}
	}
	else
	{
		sErrorInfo = L"Cannot switch to target window station: " + sSwitchError;
	}
	return retval;
}

/// <summary>
/// Enumeration callback for retrieving names of desktops in a window station
/// </summary>
/// <param name="lpszDesktop">Name of desktop</param>
/// <param name="lParam">Pointer to the DesktopNamesList_t to populate</param>
static BOOL __stdcall EnumDesktopNamesProcW(LPWSTR lpszDesktop, LPARAM lParam)
{
	DesktopNameList_t* pDesktopNameList = (DesktopNameList_t*)lParam;
	if (nullptr != lpszDesktop)
		pDesktopNameList->push_back(lpszDesktop);
	else
		pDesktopNameList->push_back(L"<nullptr>");
	return TRUE;
}

/// <summary>
/// Retrieve a list of the names of the desktops in this window station
/// </summary>
/// <param name="desktopNameList">DesktopNameList_t to populate</param>
/// <param name="sErrorInfo">Output: information in case of error</param>
/// <returns>true if successful, false otherwise</returns>
bool WindowStation::GetDesktopNames(DesktopNameList_t& desktopNameList, std::wstring& sErrorInfo) const
{
	desktopNameList.clear();
	sErrorInfo.clear();
	if (EnumDesktopsW(m_hObj, EnumDesktopNamesProcW, (LPARAM)&desktopNameList))
	{
		return true;
	}
	else
	{
		sErrorInfo = SysErrorMessageWithCode();
		return false;
	}
}

// ----------------------------------------------------------------------------------------------------
// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Enumeration callback for retrieving information about window stations in the current session
/// </summary>
/// <param name="lpszDesktop">Name of window station</param>
/// <param name="lParam">Pointer to the WindowStationList_t to populate</param>
static BOOL __stdcall EnumWindowStationProcW(LPWSTR lpszWinSta, LPARAM lParam)
{
	WindowStationList_t* pWinStaList = (WindowStationList_t*)lParam;
	WindowStation winsta;
	std::wstring sErrorInfo;
	if (winsta.Open(lpszWinSta, MAXIMUM_ALLOWED, sErrorInfo))
	{
		pWinStaList->push_back(winsta);
	}
	else
	{
		//TODO: Shouldn't be writing to stdout/stderr from here
		std::wcerr << L"OpenWindowStation " << lpszWinSta << L": " << sErrorInfo << std::endl;
	}
	return TRUE;
}

/// <summary>
/// Static function that returns information about the window stations in the current session.
/// </summary>
/// <param name="windowStationList">WindowStationList_t to populate</param>
/// <param name="sErrorInfo">Output: information in case of error</param>
/// <returns>true if successful, false otherwise</returns>
bool WindowStation::GetWindowStations(WindowStationList_t& windowStationList, std::wstring& sErrorInfo)
{
	windowStationList.clear();
	sErrorInfo.clear();
	if (EnumWindowStationsW(EnumWindowStationProcW, (LPARAM)&windowStationList))
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
/// Enumeration callback for retrieving the names of window stations in the current session
/// </summary>
/// <param name="lpszDesktop">Name of window station</param>
/// <param name="lParam">Pointer to the pWindowStationNameList to populate</param>
static BOOL __stdcall EnumWindowStationNamesProcW(LPWSTR lpszWinSta, LPARAM lParam)
{
	WindowStationNameList_t* pWindowStationNameList = (WindowStationNameList_t*)lParam;
	if (nullptr != lpszWinSta)
		pWindowStationNameList->push_back(lpszWinSta);
	else
		pWindowStationNameList->push_back(L"<nullptr>");
	return TRUE;
}

/// <summary>
/// Static function that returns the names of the window stations in the current session.
/// </summary>
/// <param name="windowStationList">WindowStationNameList_t to populate</param>
/// <param name="sErrorInfo">Output: information in case of error</param>
/// <returns>true if successful, false otherwise</returns>
bool WindowStation::GetWindowStationNames(WindowStationNameList_t& windowStationNameList, std::wstring& sErrorInfo)
{
	windowStationNameList.clear();
	sErrorInfo.clear();
	if (EnumWindowStationsW(EnumWindowStationNamesProcW, (LPARAM)&windowStationNameList))
	{
		return true;
	}
	else
	{
		sErrorInfo = SysErrorMessageWithCode();
		return false;
	}
}

// ----------------------------------------------------------------------------------------------------
// ----------------------------------------------------------------------------------------------------

Desktop::Desktop(const WindowStation& ws)
	: m_ws(ws)
{
}

Desktop::Desktop(const WindowStation& ws, HDESK hDesk, bool bNeedsToBeClosed)
	: m_ws(ws)
{
	AssignUOHandle(m_hObj, hDesk, bNeedsToBeClosed);
}

Desktop::~Desktop()
{
	CloseUOHandle();
}

Desktop::Desktop(const Desktop& other) : UserObject(other), m_ws(other.m_ws)
{
	AssignUOHandle(m_hObj, (HDESK)DuplicateMyHandle(other.m_hObj), true);
}

Desktop& Desktop::operator=(const Desktop& other)
{
	CloseUOHandle();
	AssignUOHandle(m_hObj, (HDESK)DuplicateMyHandle(other.m_hObj), true);
	m_ws = other.m_ws;
	return *this;
}

/// <summary>
/// Static function returns a reference to a Desktop object referencing the desktop this thread is in.
/// </summary>
const Desktop& Desktop::Original()
{
	return st_OriginalWSDesktop;
}

/// <summary>
/// Virtual function override to close the object-specific handle
/// </summary>
void Desktop::CloseUOHandle()
{
	if (m_hObj)
	{
		if (m_bHandleNeedsToBeClosed)
		{
			CloseDesktop(m_hObj);
		}
		m_hObj = nullptr;
	}
}

// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Open the named desktop. 
/// Temporarily associates this process to the window station associated with this Desktop instance if necessary. 
/// </summary>
/// <param name="szDesktop">Input: name of the desktop to open</param>
/// <param name="dwDesiredAccess">Input: requested access</param>
/// <param name="sErrorInfo">Output: information in case of error</param>
/// <returns>true if successful, false otherwise</returns>
bool Desktop::Open(const wchar_t* szDesktop, DWORD dwDesiredAccess, std::wstring& sErrorInfo)
{
	sErrorInfo.clear();
	CloseUOHandle();

	// Switch to a different window station if process not already running in that WS
	bool bSwitched = false;
	if (!AssignToAssociatedWinstaIfNotThere(bSwitched, sErrorInfo))
		return false;
		
	m_OpenedName = szDesktop;
	HDESK hDesk = OpenDesktopW(szDesktop, 0, FALSE, dwDesiredAccess);
	if (hDesk)
	{
		AssignUOHandle(m_hObj, hDesk, true);
	}
	else
	{
		sErrorInfo = SysErrorMessageWithCode();
	}

	if (bSwitched)
	{
		std::wstring sSwitchError;
		if (!AssignToOriginalWinsta(sSwitchError))
		{
			//TODO: can't switch back? What to do?
		}
	}
	return (m_hObj ? true : false);
}

/// <summary>
/// Initialize this Desktop instance from the desktop with which the current thread is associated.
/// (The process' current window station should be the window station associated with this instance.)
/// </summary>
/// <param name="sErrorInfo">Output: information in case of error</param>
/// <returns>true if successful, false otherwise</returns>
bool Desktop::InitFromCurrentThread(std::wstring& sErrorInfo)
{
	sErrorInfo.clear();
	CloseUOHandle();
	//GetThreadDesktop: "You do not need to call the CloseDesktop function to close the returned handle."
	HDESK hDesk = GetThreadDesktop(GetCurrentThreadId());
	if (hDesk)
	{
		AssignUOHandle(m_hObj, hDesk, false);
		return true;
	}
	else
	{
		sErrorInfo = SysErrorMessageWithCode();
		return false;
	}
}

/// <summary>
/// Initialize this Desktop instance from the desktop which is currently receiving user input.
/// (The process' current window station should be the window station associated with this instance.)
/// </summary>
/// <param name="dwDesiredAccess">Input: requested access</param>
/// <param name="sErrorInfo">Output: information in case of error</param>
/// <returns>true if successful, false otherwise</returns>
bool Desktop::InitFromInputDesktop(DWORD dwDesiredAccess, std::wstring& sErrorInfo)
{
	sErrorInfo.clear();
	CloseUOHandle();
	// OpenInputDesktop: "When you are finished using the handle, call the CloseDesktop function to close it."
	HDESK hDesk = OpenInputDesktop(0, FALSE, dwDesiredAccess);
	if (hDesk)
	{
		AssignUOHandle(m_hObj, hDesk, true);
		return true;
	}
	else
	{
		sErrorInfo = SysErrorMessageWithCode();
		return false;
	}
}

/// <summary>
/// Switch to this desktop and activate it.
/// The process should already be associated with this object's window station.
/// </summary>
/// <param name="sErrorInfo">Output: information in case of error</param>
/// <returns>true if successful, false otherwise</returns>
bool Desktop::SwitchTo(std::wstring& sErrorInfo) const
{
	sErrorInfo.clear();
	if (SwitchDesktop(m_hObj))
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
/// Assign the current thread to this desktop
/// </summary>
/// <param name="sErrorInfo">Output: information in case of error</param>
/// <returns>true if successful, false otherwise</returns>
bool Desktop::AssignThisThread(std::wstring& sErrorInfo) const
{
	sErrorInfo.clear();
	if (SetThreadDesktop(m_hObj))
	{
		return true;
	}
	else
	{
		sErrorInfo = SysErrorMessageWithCode();
		return false;
	}
}

// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Returns the desktop's heap size
/// </summary>
/// <param name="uHeapSize">Output: the desktop's heap size</param>
/// <param name="sErrorInfo">Output: information in case of error</param>
/// <returns>true if successful, false otherwise</returns>
bool Desktop::HeapSize(ULONG& uHeapSize, std::wstring& sErrorInfo) const
{
	sErrorInfo.clear();
	HeapMem mem;
	const ULONG* pUL = (const ULONG*)GetUOInfo(UOI_HEAPSIZE, mem, sErrorInfo);
	if (pUL)
	{
		uHeapSize = *pUL;
		return true;
	}
	else
	{
		return false;
	}
}

/// <summary>
/// Indicates whether this desktop currently receives user input.
/// </summary>
/// <param name="bIsReceivingInput">Output: TRUE if receiving user input; FALSE otherwise.</param>
/// <param name="sErrorInfo">Output: information in case of error</param>
/// <returns>true if successful, false otherwise</returns>
bool Desktop::IsReceivingInput(BOOL& bIsReceivingInput, std::wstring& sErrorInfo) const
{
	sErrorInfo.clear();
	HeapMem mem;
	const BOOL* pBool = (const BOOL*)GetUOInfo(UOI_IO, mem, sErrorInfo);
	if (pBool)
	{
		bIsReceivingInput = *pBool;
		return true;
	}
	else
	{
		return false;
	}
}

/// <summary>
/// Returns an object-specific string representation of the object's flags (override of UserObject pure virtual function)
/// </summary>
bool Desktop::Flags(std::wstring& sFlags, std::wstring& sErrorInfo) const
{
	DWORD dwFlags;
	if (UserObject::Flags(dwFlags, sErrorInfo))
	{
		std::wstringstream str;
		str << HEX(dwFlags, 8, false, true);
		if (dwFlags & DF_ALLOWOTHERACCOUNTHOOK)
			str << L" DF_ALLOWOTHERACCOUNTHOOK";
		sFlags = str.str();
		return true;
	}
	else
	{
		sFlags.clear();
		return false;
	}
}

// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Assign this process to this object's associated window station, if not already associated with it.
/// </summary>
/// <param name="bSwitched">Output: true if a switch was made, false otherwise</param>
/// <param name="sErrorInfo">Output: information in case of error</param>
/// <returns>true if switch made or not needed, false if switch attempted and failed</returns>
bool Desktop::AssignToAssociatedWinstaIfNotThere(bool& bSwitched, std::wstring& sErrorInfo) const
{
	// Switch to a different window station if process not already running in that WS
	bool bNeedToSwitch = !(this->WinSta() == WindowStation::CurrentName(sErrorInfo));
	if (bNeedToSwitch)
	{
		std::wstring sSwitchError;
		bSwitched = m_ws.AssignThisProcess(sSwitchError);
		if (!bSwitched)
		{
			sErrorInfo = L"Cannot switch to target window station: " + sSwitchError;
			return false;
		}
	}
	return true;
}

/// <summary>
/// Assign this process to the object's associated window station and the current thread to this desktop.
/// </summary>
/// <param name="bSwitchedWS">Output: true if winsta assigned; false if error</param>
/// <param name="bSwitchedDesktop">Output: true if desktop assigned; false if error</param>
/// <param name="sErrorInfo">Output: error information</param>
/// <returns>true if winsta and desktop assigned, false otherwise</returns>
bool Desktop::AssignToWinstaDesktop(bool& bSwitchedWS, bool& bSwitchedDesktop, std::wstring& sErrorInfo) const
{
	bSwitchedWS = bSwitchedDesktop = false;
	bSwitchedWS = m_ws.AssignThisProcess(sErrorInfo);
	if (bSwitchedWS)
	{
		bSwitchedDesktop = this->AssignThisThread(sErrorInfo);
	}
	return bSwitchedWS && bSwitchedDesktop;
}

/// <summary>
/// Assign this process to the window station this process was originally associated with.
/// </summary>
/// <param name="sErrorInfo">Output: information in case of error</param>
/// <returns>true if successful, false otherwise</returns>
bool Desktop::AssignToOriginalWinsta(std::wstring& sErrorInfo) const
{
	return st_OriginalWS.AssignThisProcess(sErrorInfo);
}

/// <summary>
/// Assign the current thread to the desktop it was originally associated with.
/// </summary>
/// <param name="sErrorInfo">Output: information in case of error</param>
/// <returns>true if successful, false otherwise</returns>
bool Desktop::AssignToOriginalDesktop(std::wstring& sErrorInfo) const
{
	return st_OriginalWSDesktop.AssignThisThread(sErrorInfo);
}

// ----------------------------------------------------------------------------------------------------
// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Windows enumeration callback function that populates a list of HWNDs
/// </summary>
/// <param name="hwnd">The current HWND being enumerated</param>
/// <param name="lParam">The HwndList_t to populate</param>
static BOOL __stdcall EnumWindowsProc_HwndList(HWND hwnd, LPARAM lParam)
{
	HwndList_t* pHwndList = (HwndList_t*)lParam;
	pHwndList->push_back(hwnd);
	return TRUE;
}

bool Desktop::GetTopLevelWindows(HwndList_t& hwndList, std::wstring& sErrorInfo)
{
	hwndList.clear();
	sErrorInfo.clear();

	bool retval = false;
	bool bSwitchedWS = false, bSwitchedDesktop = false;
	std::wstring sSwitchError;
	if (AssignToWinstaDesktop(bSwitchedWS, bSwitchedDesktop, sSwitchError))
	{
		retval = EnumDesktopWindows((HDESK)GetUOHandle(), EnumWindowsProc_HwndList, (LPARAM)&hwndList);
		if (!retval)
		{
			sErrorInfo = SysErrorMessageWithCode();
		}
	}
	else
	{
		sErrorInfo = L"Could not switch to target winsta/desktop: " + sSwitchError;
	}

	if (bSwitchedWS && !AssignToOriginalWinsta(sSwitchError))
	{
		//TODO: couldn't switch back?!?!? What to do?!?!?
		dbgOut.locked() << L"Couldn't restore original WS: " << sSwitchError << std::endl;
	}
	if (bSwitchedDesktop && !AssignToOriginalDesktop(sSwitchError))
	{
		//TODO: couldn't switch back?!?!? What to do?!?!?
		dbgOut.locked() << L"Couldn't restore original desktop: " << sSwitchError << std::endl;
	}

	return retval;
}

/// <summary>
/// Structure for passing multiple data items to EnumWindowsProc_InfoCollection as a single address
/// </summary>
struct ForEnumWinInfo_t
{
	HeapMem* pHeapMem;
	WindowInfoCollection_t* pWindowInfoCollection;
};
static void AddHwndToCollection(HWND hwnd, WindowInfoCollection_t& windowInfoCollection, HeapMem& buffer);
/// <summary>
/// Windows enumeration callback function that populates a collection of WindowInfo objects.
/// </summary>
/// <param name="hwnd">HWND being enumerated</param>
/// <param name="lParam">params including preallocated memory for doing data collection, and the collection to populate</param>
static BOOL __stdcall EnumWindowsProc_InfoCollection(HWND hwnd, LPARAM lParam)
{
	ForEnumWinInfo_t* pParamsForEnum = (ForEnumWinInfo_t*)lParam;
	HeapMem& buffer = *pParamsForEnum->pHeapMem;
	WindowInfoCollection_t& windowInfoCollection = *pParamsForEnum->pWindowInfoCollection;
	AddHwndToCollection(hwnd, windowInfoCollection, buffer);
	return TRUE;
}

/// <summary>
/// Internal helper function that gathers info about the input HWND and adds that info to a collection.
/// Ignores the HWND if it's NULL or already in the collection.
/// </summary>
/// <param name="hwnd">HWND to add</param>
/// <param name="windowInfoCollection">Collection to populate</param>
/// <param name="buffer">Buffer pre-allocated for data collection</param>
static void AddHwndToCollection(HWND hwnd, WindowInfoCollection_t& windowInfoCollection, HeapMem& buffer)
{
	// Early exit if HWND is null.
	if (NULL == hwnd)
		return;

	// Early exit if the collection already contains this HWND
	if (windowInfoCollection.find(hwnd) != windowInfoCollection.end())
		return;

	DWORD dwBufferSize = (DWORD)buffer.Size();

	WindowInfo_t windowInfo;
	windowInfo.hwnd = hwnd;
	windowInfo.bIsValid = IsWindow(hwnd);
	if (windowInfo.bIsValid)
	{
		windowInfo.bIsVisible = IsWindowVisible(hwnd);
		windowInfo.TID = GetWindowThreadProcessId(hwnd, &windowInfo.PID);
		if (GetClassNameW(hwnd, (wchar_t*)buffer.Get(), dwBufferSize))
			windowInfo.sClassName = (const wchar_t*)buffer.Get();
		if (GetWindowTextW(hwnd, (wchar_t*)buffer.Get(), dwBufferSize) > 0)
			windowInfo.sWindowText = (const wchar_t*)buffer.Get();
		if (0 != windowInfo.PID)
		{
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, windowInfo.PID);
			if (hProcess && GetModuleFileNameExW(hProcess, NULL, (wchar_t*)buffer.Get(), dwBufferSize) > 0)
			{
				windowInfo.sProcessPath = (const wchar_t*)buffer.Get();
			}
			else
			{
				windowInfo.sProcessPath = SysErrorMessageWithCode();
				// Clear the error in this thread now
				SetLastError(0);
			}
			if (hProcess) CloseHandle(hProcess);
		}
	}
	windowInfoCollection[hwnd] = windowInfo;
}

bool Desktop::GetTopLevelWindows(WindowInfoCollection_t& windowInfoCollection, std::wstring& sErrorInfo)
{
	windowInfoCollection.clear();
	sErrorInfo.clear();

	HeapMem buffer;
	if (!buffer.Alloc(4096, sErrorInfo))
		return false;

	bool retval = false;
	bool bSwitchedWS = false, bSwitchedDesktop = false;
	std::wstring sSwitchError;
	if (AssignToWinstaDesktop(bSwitchedWS, bSwitchedDesktop, sSwitchError))
	{
		ForEnumWinInfo_t paramsForEnum = { &buffer, &windowInfoCollection };
		SetLastError(0);
		retval = EnumWindows(EnumWindowsProc_InfoCollection, (LPARAM)&paramsForEnum);
		DWORD dwLastErr = GetLastError();
		if (retval || ERROR_SUCCESS == dwLastErr)
		{
			retval = true;
			// If the collection is empty, try to find items to add.
			if (windowInfoCollection.size() == 0)
			{
				AddHwndToCollection(GetForegroundWindow(), windowInfoCollection, buffer);
				AddHwndToCollection(GetDesktopWindow(), windowInfoCollection, buffer);
				AddHwndToCollection(FindWindowW(nullptr, nullptr), windowInfoCollection, buffer);
				AddHwndToCollection(GetShellWindow(), windowInfoCollection, buffer);
				AddHwndToCollection(GetTopWindow(NULL), windowInfoCollection, buffer);
			}
		}
		else
		{
			sErrorInfo = SysErrorMessageWithCode();
		}
	}
	else
	{
		sErrorInfo = L"Could not switch to target winsta/desktop: " + sSwitchError;
	}

	if (bSwitchedWS && !AssignToOriginalWinsta(sSwitchError))
	{
		//TODO: couldn't switch back?!?!? What to do?!?!?
		dbgOut.locked() << L"Couldn't restore original WS: " << sSwitchError << std::endl;
	}
	if (bSwitchedDesktop && !AssignToOriginalDesktop(sSwitchError))
	{
		//TODO: couldn't switch back?!?!? What to do?!?!?
		dbgOut.locked() << L"Couldn't restore original desktop: " << sSwitchError << std::endl;
	}

	return retval;
}

// ----------------------------------------------------------------------------------------------------
