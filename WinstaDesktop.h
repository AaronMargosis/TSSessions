#pragma once

// WinstaDesktop.h: encapsulation of information about window stations and desktops.

#include <Windows.h>
#include <string>
#include <list>
#include <map>
#include "CSid.h"
#include "HeapMem.h"

// ----------------------------------------------------------------------------------------------------
class Desktop;
class WindowStation;
/// <summary>
/// Structure encapsulating some information about window objects
/// </summary>
struct WindowInfo_t
{
	HWND hwnd = NULL;
	bool bIsValid = false, bIsVisible = false;
	DWORD PID = 0, TID = 0;
	std::wstring sProcessPath, sClassName, sWindowText;
};
typedef std::list<Desktop> DesktopList_t;
typedef std::list<WindowStation> WindowStationList_t;
typedef std::list<std::wstring> DesktopNameList_t;
typedef std::list<std::wstring> WindowStationNameList_t;
typedef std::list<HWND> HwndList_t;
typedef std::map<HWND, WindowInfo_t> WindowInfoCollection_t;

// ----------------------------------------------------------------------------------------------------

class SecurityDescriptor : public HeapMem
{
public:
	SecurityDescriptor() = default;
	~SecurityDescriptor() = default;
	PSECURITY_DESCRIPTOR GetSD() const { return (PSECURITY_DESCRIPTOR)this->Get(); }

private:
	SecurityDescriptor(const SecurityDescriptor&) = delete;
	SecurityDescriptor& operator = (const SecurityDescriptor&) = delete;
};

// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Base object for window stations and desktops
/// </summary>
class UserObject
{
public:
	UserObject() = default;
	virtual ~UserObject() = default;
	//TODO: can these be default too?
	UserObject(const UserObject& other);
	UserObject& operator = (const UserObject& other);

	/// <summary>
	/// The name with which this object was initialized.
	/// </summary>
	const std::wstring& OpenedName() const { return m_OpenedName; }

	/// <summary>
	/// Retrieves the name of the window station or desktop
	/// </summary>
	bool Name(std::wstring& sName, std::wstring& sErrorInfo) const;

	/// <summary>
	/// Retrieves the name of the object type
	/// </summary>
	bool Type(std::wstring& sType, std::wstring& sErrorInfo) const;

	/// <summary>
	/// Retrieves the binary flags associated with the window station or desktop
	/// </summary>
	bool Flags(DWORD& dwFlags, std::wstring& sErrorInfo) const;

	/// <summary>
	/// Returns an object-specific string representation of the object's flags
	/// </summary>
	virtual bool Flags(std::wstring& sFlags, std::wstring& sErrorInfo) const = 0;

	/// <summary>
	/// Retrieves the user SID associated with the object.
	/// </summary>
	bool UserSID(CSid& sid, std::wstring& sErrorInfo) const;

	/// <summary>
	/// Retrieves the username and SID associated with the object (or "(no user)" if there isn't one).
	/// </summary>
	/// <returns>true if successful (even if no user), false if an error occurred.</returns>
	bool UserNameAndSid(std::wstring& sUserSidAndName, std::wstring& sErrorInfo) const;

	/// <summary>
	/// Gets the security descriptor associated with the object.
	/// </summary>
	/// <param name="memSecurityDescriptor">Output: heap-allocation object containing the security descriptor</param>
	/// <param name="si"></param>
	/// <param name="sErrorInfo">Output: information in the case of an error</param>
	/// <returns>true if successful, false otherwise.</returns>
	bool GetSecurity(
		SecurityDescriptor& memSecurityDescriptor,
		SECURITY_INFORMATION si,
		std::wstring& sErrorInfo) const;

	/// <summary>
	/// Sets the security descriptor for the object
	/// </summary>
	/// <param name="pSD">Input: the security descriptor to apply to the object</param>
	/// <param name="si">Input: The security information to apply to the object</param>
	/// <param name="sErrorInfo">Output: information in case of an error</param>
	/// <returns>true if successful, false otherwise.</returns>
	bool SetSecurity(
		PSECURITY_DESCRIPTOR pSD, 
		SECURITY_INFORMATION si,
		std::wstring& sErrorInfo);

protected:
	/// <summary>
	/// The name that the object was opened with. Might be different from what
	/// Windows reports back via the Name() method.
	/// </summary>
	std::wstring m_OpenedName;

	/// <summary>
	/// Internal wrapper function for GetUserObjectInformationW
	/// </summary>
	/// <param name="index">Input: information to retrieve</param>
	/// <param name="mem">Output: memory object to put information into</param>
	/// <param name="sErrorInfo">Output: information in case of error</param>
	/// <returns>Pointer to memory if successful, nullptr otherwise.</returns>
	PVOID GetUOInfo(int index, HeapMem& mem, std::wstring& sErrorInfo) const;

	// ----------------------------------------------------------------------------------------------------
	// Handle management

	//TODO: if typesafe, consider moving m_hObj to the base class as a private member with a read-only accessor,
	// and having member functions in derived classes that cast it to object-specific handle type.
	// Doing so would prevent derived classes from setting m_hObj without also setting m_bHandleNeedsToBeClosed.

	/// <summary>
	/// Encapsulate assigning of object handle and whether it needs to be closed when no longer needed.
	/// </summary>
	/// <param name="hObjToSet">A reference to the derived-class member variable to set</param>
	/// <param name="hSource">The value to set the derived-class member variable to</param>
	/// <param name="bNeedsToBeClosed">Whether the handle needs to be closed</param>
	void AssignUOHandle(HWINSTA& hObjToSet, const HWINSTA hSource, bool bNeedsToBeClosed);
	void AssignUOHandle(HDESK& hObjToSet, const HDESK hSource, bool bNeedsToBeClosed);
	/// <summary>
	/// Member variable that indicates whether the object handle needs to be closed.
	/// </summary>
	bool m_bHandleNeedsToBeClosed = false;

	/// <summary>
	/// Virtual function to get the object-specific handle
	/// </summary>
	virtual HANDLE GetUOHandle() const = 0;

	/// <summary>
	/// Virtual function to close the object-specific handle
	/// </summary>
	virtual void CloseUOHandle() = 0;

	/// <summary>
	/// Internal function to support cctor and assignment
	/// </summary>
	/// <param name="hObj">Handle to duplicate</param>
	/// <returns>Duplicated handle. Caller is responsible for closing it.</returns>
	HANDLE DuplicateMyHandle(HANDLE hObj);
};

// ----------------------------------------------------------------------------------------------------

class WindowStation : public UserObject
{
public:
	// ctor, custom ctor, dtor, cctor, assignment
	WindowStation() = default;
	WindowStation(HWINSTA hWinsta, bool bNeedsToBeClosed);
	virtual ~WindowStation();
	WindowStation(const WindowStation& other);
	WindowStation& operator = (const WindowStation& other);

	/// <summary>
	/// Indicates whether this window station refers to the same WS as "other".
	/// Based on window station names. Assumes that they are in the same TS session.
	/// </summary>
	bool operator == (const WindowStation& other) const;

	/// <summary>
	/// Indicates whether this window station refers to the same WS as "sOther".
	/// Based on window station names. Assumes that they are in the same TS session.
	/// </summary>
	bool operator == (const std::wstring& sOtherName) const;

	/// <summary>
	/// Static function returns a reference to a WindowStation object referencing the 
	/// window station this process started in.
	/// </summary>
	static const WindowStation& Original();

	/// <summary>
	/// Returns the name of the window station this process is currently associated with.
	/// </summary>
	/// <param name="sErrorInfo">Output: information about any error that occurs</param>
	/// <returns>The current window station name if successful; empty string otherwise</returns>
	static std::wstring CurrentName(std::wstring& sErrorInfo);

	/// <summary>
	/// Open a named window station in the current session.
	/// </summary>
	/// <param name="szWinSta">Input: name of the window station in the current session to open</param>
	/// <param name="dwDesiredAccess">Input: requested access</param>
	/// <param name="sErrorInfo">Output: information in case of error</param>
	/// <returns>true if successful, false otherwise</returns>
	bool Open(const wchar_t* szWinSta, DWORD dwDesiredAccess, std::wstring& sErrorInfo);

	/// <summary>
	/// Initialize this WindowStation instance from the window station in which this process is executing.
	/// </summary>
	/// <param name="sErrorInfo">Output: information in case of error</param>
	/// <returns>true if successful, false otherwise</returns>
	bool InitFromCurrentProcess(std::wstring& sErrorInfo);

	/// <summary>
	/// Assign the current process to the window station
	/// </summary>
	/// <param name="sErrorInfo">Output: information in case of error</param>
	/// <returns>true if successful, false otherwise</returns>
	bool AssignThisProcess(std::wstring& sErrorInfo) const;

	/// <summary>
	/// Returns an object-specific string representation of the object's flags (override of UserObject pure virtual function)
	/// </summary>
	virtual bool Flags(std::wstring& sFlags, std::wstring& sErrorInfo) const override;

	/// <summary>
	/// Retrieve information about the desktops in this window station
	/// </summary>
	/// <param name="desktopList">DesktopList_t to populate</param>
	/// <param name="sErrorInfo">Output: information in case of error</param>
	/// <returns>true if successful, false otherwise</returns>
	bool GetDesktops(DesktopList_t& desktopList, std::wstring& sErrorInfo) const;

	/// <summary>
	/// Retrieve a list of the names of the desktops in this window station
	/// </summary>
	/// <param name="desktopNameList">DesktopNameList_t to populate</param>
	/// <param name="sErrorInfo">Output: information in case of error</param>
	/// <returns>true if successful, false otherwise</returns>
	bool GetDesktopNames(DesktopNameList_t& desktopNameList, std::wstring& sErrorInfo) const;

	/// <summary>
	/// Static function that returns information about the window stations in the current session.
	/// </summary>
	/// <param name="windowStationList">WindowStationList_t to populate</param>
	/// <param name="sErrorInfo">Output: information in case of error</param>
	/// <returns>true if successful, false otherwise</returns>
	static bool GetWindowStations(WindowStationList_t& windowStationList, std::wstring& sErrorInfo);

	/// <summary>
	/// Static function that returns the names of the window stations in the current session.
	/// </summary>
	/// <param name="windowStationList">WindowStationNameList_t to populate</param>
	/// <param name="sErrorInfo">Output: information in case of error</param>
	/// <returns>true if successful, false otherwise</returns>
	static bool GetWindowStationNames(WindowStationNameList_t& windowStationNameList, std::wstring& sErrorInfo);

private:
	HWINSTA m_hObj = nullptr;

private:
	/// <summary>
	/// Virtual function override to get the object-specific handle
	/// </summary>
	virtual HANDLE GetUOHandle() const override { return m_hObj; }

	/// <summary>
	/// Virtual function override to close the object-specific handle
	/// </summary>
	virtual void CloseUOHandle() override;
};

// ----------------------------------------------------------------------------------------------------


class Desktop : public UserObject
{
public:
	// ctor, custom ctor dtor, cctor, assignment
	Desktop(const WindowStation& ws);
	Desktop(const WindowStation& ws, HDESK hDesk, bool bNeedsToBeClosed);
	virtual ~Desktop();
	Desktop(const Desktop& other);
	Desktop& operator = (const Desktop& other);

	/// <summary>
	/// Returns a reference to this Desktop's WindowStation
	/// </summary>
	const WindowStation& WinSta() const { return m_ws; }

	/// <summary>
	/// Static function returns a reference to a Desktop object referencing the desktop this process started in.
	/// </summary>
	static const Desktop& Original();

	/// <summary>
	/// Open the named desktop. 
	/// Temporarily associates this process to the window station associated with this Desktop instance if necessary. 
	/// </summary>
	/// <param name="szDesktop">Input: name of the desktop to open</param>
	/// <param name="dwDesiredAccess">Input: requested access</param>
	/// <param name="sErrorInfo">Output: information in case of error</param>
	/// <returns>true if successful, false otherwise</returns>
	bool Open(const wchar_t* szDesktop, DWORD dwDesiredAccess, std::wstring& sErrorInfo);

	/// <summary>
	/// Initialize this Desktop instance from the desktop with which the current thread is associated.
	/// (The process' current window station should be the window station associated with this instance.)
	/// </summary>
	/// <param name="sErrorInfo">Output: information in case of error</param>
	/// <returns>true if successful, false otherwise</returns>
	bool InitFromCurrentThread(std::wstring& sErrorInfo);

	/// <summary>
	/// Initialize this Desktop instance from the desktop which is currently receiving user input.
	/// (The process' current window station should be the window station associated with this instance.)
	/// </summary>
	/// <param name="dwDesiredAccess">Input: requested access</param>
	/// <param name="sErrorInfo">Output: information in case of error</param>
	/// <returns>true if successful, false otherwise</returns>
	bool InitFromInputDesktop(DWORD dwDesiredAccess, std::wstring& sErrorInfo);

	/// <summary>
	/// Switch to this desktop and activate it.
	/// The process should already be associated with this object's window station.
	/// </summary>
	/// <param name="sErrorInfo">Output: information in case of error</param>
	/// <returns>true if successful, false otherwise</returns>
	bool SwitchTo(std::wstring& sErrorInfo) const;

	/// <summary>
	/// Assign the current thread to this desktop
	/// </summary>
	/// <param name="sErrorInfo">Output: information in case of error</param>
	/// <returns>true if successful, false otherwise</returns>
	bool AssignThisThread(std::wstring& sErrorInfo) const;

	/// <summary>
	/// Returns the desktop's heap size
	/// </summary>
	/// <param name="uHeapSize">Output: the desktop's heap size</param>
	/// <param name="sErrorInfo">Output: information in case of error</param>
	/// <returns>true if successful, false otherwise</returns>
	bool HeapSize(ULONG& uHeapSize, std::wstring& sErrorInfo) const;
	
	/// <summary>
	/// Indicates whether this desktop currently receives user input.
	/// </summary>
	/// <param name="bIsReceivingInput">Output: TRUE if receiving user input; FALSE otherwise.</param>
	/// <param name="sErrorInfo">Output: information in case of error</param>
	/// <returns>true if successful, false otherwise</returns>
	bool IsReceivingInput(BOOL& bIsReceivingInput, std::wstring& sErrorInfo) const;

	/// <summary>
	/// Returns an object-specific string representation of the object's flags (override of UserObject pure virtual function)
	/// </summary>
	virtual bool Flags(std::wstring& sFlags, std::wstring& sErrorInfo) const override;

	bool GetTopLevelWindows(HwndList_t& hwndList, std::wstring& sErrorInfo);
	bool GetTopLevelWindows(WindowInfoCollection_t& windowInfoCollection, std::wstring& sErrorInfo);

protected:
	/// <summary>
	/// Assign this process to this object's associated window station, if not already associated with it.
	/// </summary>
	/// <param name="bSwitched">Output: true if a switch was made, false otherwise</param>
	/// <param name="sErrorInfo">Output: information in case of error</param>
	/// <returns>true if switch made or not needed, false if switch attempted and failed</returns>
	bool AssignToAssociatedWinstaIfNotThere(bool& bSwitched, std::wstring& sErrorInfo) const;

	/// <summary>
	/// Assign this process to the object's associated window station and the current thread to this desktop.
	/// </summary>
	/// <param name="bSwitchedWS">Output: true if winsta assigned; false if error</param>
	/// <param name="bSwitchedDesktop">Output: true if desktop assigned; false if error</param>
	/// <param name="sErrorInfo">Output: error information</param>
	/// <returns>true if winsta and desktop assigned, false otherwise</returns>
	bool AssignToWinstaDesktop(bool& bSwitchedWS, bool& bSwitchedDesktop, std::wstring& sErrorInfo) const;

	/// <summary>
	/// Assign this process to the window station this process was originally associated with.
	/// </summary>
	/// <param name="sErrorInfo">Output: information in case of error</param>
	/// <returns>true if successful, false otherwise</returns>
	bool AssignToOriginalWinsta(std::wstring& sErrorInfo) const;

	/// <summary>
	/// Assign the current thread to the desktop it was originally associated with.
	/// </summary>
	/// <param name="sErrorInfo">Output: information in case of error</param>
	/// <returns>true if successful, false otherwise</returns>
	bool AssignToOriginalDesktop(std::wstring& sErrorInfo) const;

private:
	WindowStation m_ws;
	HDESK m_hObj = nullptr;

private:
	/// <summary>
	/// Virtual function override to get the object-specific handle
	/// </summary>
	virtual HANDLE GetUOHandle() const override { return m_hObj; }

	/// <summary>
	/// Virtual function override to close the object-specific handle
	/// </summary>
	virtual void CloseUOHandle() override;
};

// ----------------------------------------------------------------------------------------------------
