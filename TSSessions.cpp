// TSSessions.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <Psapi.h>
#include <io.h>
#include <fcntl.h>
#include <iostream>
#include <algorithm>
#include "TerminalSessions.h"
#include "WinstaDesktop.h"
#include "SecurityDescriptorUtils.h"
#include "SecurityUtils.h"
#include "WhoAmI.h"
#include "SysErrorMessage.h"
#include "HEX.h"
#include "DbgOut.h"
#include "Token.h"
#include "StringUtils.h"
#include "FileOutput.h"

// Undefine macros from the SDK so that we can use the std algorithms.
#undef max
#undef min

//TODO: add ability to create window stations and desktops
// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createwindowstationw
// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createdesktopw

//TODO: incorporate RunInSession0_Framework so it can run as System without needing PsExec.

enum class SecDescOptions_t { None, SecDesc, SDDL };

// ----------------------------------------------------------------------------------------------------
// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Write command-line syntax to stderr (with optional error information) and then exit
/// </summary>
/// <param name="argv0">The program's argv[0] value</param>
/// <param name="szError">Optional: caller-supplied error text</param>
/// <param name="szBadParam">Optional: additional caller-supplied error text (invalid parameter)</param>
static void Usage(const wchar_t* argv0, const wchar_t* szError = nullptr, const wchar_t* szBadParam = nullptr)
{
    std::wstring sExe = GetFileNameFromFilePath(argv0);
    if (szError)
    {
        std::wcerr << szError;
        if (szBadParam)
            std::wcerr << L": " << szBadParam;
        std::wcerr << std::endl << std::endl;
    }
    std::wcerr
        << sExe << L": Enumerate terminal services sessions, window stations, desktops, and more" << std::endl
        << std::endl
        << L"Usage:" << std::endl
        << std::endl
        << L"  " << sExe << L" [-p] [-w|-wv] [-sd|-sddl] [-o outfile]" << std::endl
        << std::endl
        << L"-p         : List the processes associated with each terminal session" << std::endl
        << L"-w         : List the top-level windows associated with each desktop" << std::endl
        << L"-wv        : List the visible top-level windows associated with each desktop" << std::endl
        << L"-sd        : Show the detailed security descriptors of window stations and desktops" << std::endl
        << L"-sddl      : Show the security descriptos of window stations and desktops in Security Descriptor Definition Language" << std::endl
        << L"-o outfile : output to a named UTF-8 file. If -o not used, outputs to stdout." << std::endl
        << std::endl
        ;

    exit(-1);
}

// ----------------------------------------------------------------------------------------------------
// Forward declarations:
static void OutputCurrentInfo(std::wostream& sOut);
static void OutputCurrentUserInputDesktop(std::wostream& sOut);
static void OutputActiveConsoleSessionId(std::wostream& sOut, DWORD dwSessionId);
static void OutputTerminalSessions(std::wostream& sOut, bool bShowProcesses);
static void OutputUserObjectPermissions(std::wostream& sOut, UserObject& obj, bool bWindowStation, SecDescOptions_t secDescOption, size_t indent);
static void OutputDesktopWindows(std::wostream& sOut, Desktop& desktop, bool bVisibleOnly);
static void OutputWinstaDesktopInfo(std::wostream& sOut, bool bShowWindows, bool bShowOnlyVisibleWindows, SecDescOptions_t secDescOption);

// ----------------------------------------------------------------------------------------------------

int wmain(int argc, wchar_t** argv)
{
    //TODO: add support for environment variables to configure dbgOut options.
    dbgOut.WriteToDebugStream(true);

    // Set output mode to UTF8.
    if (_setmode(_fileno(stdout), _O_U8TEXT) == -1 || _setmode(_fileno(stderr), _O_U8TEXT) == -1)
    {
        std::wcerr << L"Unable to set stdout and/or stderr modes to UTF8." << std::endl;
    }

    // ----------------------------------------------------------------------------------------------------
    // Options
    bool bShowProcesses = false;
    bool bShowWindows = false, bShowOnlyVisibleWindows = false;
    SecDescOptions_t secDescOption = SecDescOptions_t::None;
    bool bOut_toFile = false;
    std::wstring sOutFile;

    // ----------------------------------------------------------------------------------------------------
    // Parse command-line options
    int ixArg = 1;
    while (ixArg < argc)
    {
        // Ignore everything past the first -c -- already picked that up in GetTargetCommandLine
        if (0 == _wcsicmp(L"-p", argv[ixArg]))
        {
            bShowProcesses = true;
        }
        else if (0 == _wcsicmp(L"-w", argv[ixArg]))
        {
            bShowWindows = true;
        }
        else if (0 == _wcsicmp(L"-wv", argv[ixArg]))
        {
            bShowWindows = bShowOnlyVisibleWindows = true;
        }
        else if (0 == _wcsicmp(L"-sd", argv[ixArg]))
        {
            secDescOption = SecDescOptions_t::SecDesc;
        }
        else if (0 == _wcsicmp(L"-sddl", argv[ixArg]))
        {
            secDescOption = SecDescOptions_t::SDDL;
        }
        else if (0 == _wcsicmp(L"-o", argv[ixArg]))
        {
            bOut_toFile = true;
            if (++ixArg >= argc)
                Usage(argv[0], L"Missing arg for -o");
            sOutFile = argv[ixArg];
        }
        else if (
            0 == _wcsicmp(L"-h", argv[ixArg]) ||
            0 == _wcsicmp(L"-help", argv[ixArg]) ||
            0 == _wcsicmp(L"-?", argv[ixArg]) ||
            0 == _wcsicmp(L"/?", argv[ixArg])
            )
        {
            Usage(argv[0]);
        }
        else
        {
            Usage(argv[0], L"Unrecognized command-line parameter", argv[ixArg]);
        }
        ++ixArg;
    }

    // ----------------------------------------------------------------------------------------------------
    // Define a wostream output; create a UTF-8 wofstream if sOutFile defined; point it to *pStream otherwise.
    // pStream points to whatever ostream we're writing to.
    // Default to writing to stdout/wcout.
    // If -out specified, open an fstream for writing.
    std::wostream* pStream = &std::wcout;
    std::wofstream fs;
    if (bOut_toFile)
    {
        pStream = &fs;
        if (!CreateFileOutput(sOutFile.c_str(), fs, false))
        {
            // If opening the file for output fails, quit now.
            std::wcerr << L"Cannot open output file " << sOutFile << std::endl;
            Usage(argv[0]);
        }
    }
    std::wostream& sOut = *pStream;

    // ----------------------------------------------------------------------------------------------------
    // Enable Security privilege if possible; ignore if it can't be enabled.
    if (ImpersonateSelf(SecurityImpersonation))
    {
        std::wstring sDummy;
        EnablePrivilege(SE_SECURITY_NAME, sDummy);
    }

    // ----------------------------------------------------------------------------------------------------
    // Do the work

    OutputCurrentInfo(sOut);

    OutputCurrentUserInputDesktop(sOut);

    OutputActiveConsoleSessionId(sOut, TerminalSession::ActiveConsoleSessionId());

    sOut << L"Are child sessions enabled? " << (TerminalSession::AreChildSessionsEnabled() ? L"Yes" : L"No")
        << std::endl
        << std::endl;

    OutputTerminalSessions(sOut, bShowProcesses);

    OutputWinstaDesktopInfo(sOut, bShowWindows, bShowOnlyVisibleWindows, secDescOption);

    RevertToSelf();

    // ------------------------------------------------------------------------------------------
    // If output to a file, close the file.
    if (bOut_toFile)
    {
        fs.close();
    }

    return 0;
}

// ----------------------------------------------------------------------------------------------------

static void OutputCurrentInfo(std::wostream& sOut)
{
    std::wstring sErrorInfo;

    CSid sid;
    DWORD dwSessionId;
    std::wstring sTextData;
    ULONG heapSize = 0;

    sOut << L"This process/thread running in:" << std::endl << std::endl;
    sOut 
        << L"    TS Session:  ";
    if (TerminalSession::CurrentProcessSessionId(dwSessionId, sErrorInfo))
    {
        sOut << dwSessionId << std::endl;
    }
    else
    {
        sOut << sErrorInfo << std::endl;
    }
    sOut << std::endl;

    const Desktop& desktop = Desktop::Original();
    const WindowStation& winsta = desktop.WinSta();

    sOut
        << L"    WinSta:      "
        << (winsta.Name(sTextData, sErrorInfo) ? sTextData : sErrorInfo)
        << std::endl;

    sOut
        << L"    User:        "
        << (winsta.UserNameAndSid(sTextData, sErrorInfo) ? sTextData : sErrorInfo)
        << std::endl;

    //sOut
    //    << L"    Type:        "
    //    << (winsta.Type(sTextData, sErrorInfo) ? sTextData : sErrorInfo)
    //    << std::endl;

    sOut
        << L"    Flags:       "
        << (winsta.Flags(sTextData, sErrorInfo) ? sTextData : sErrorInfo)
        << std::endl;

    sOut << std::endl;

    sOut
        << L"    Desktop:     "
        << (desktop.Name(sTextData, sErrorInfo) ? sTextData : sErrorInfo)
        << std::endl;

    sOut
        << L"    User:        "
        << (desktop.UserNameAndSid(sTextData, sErrorInfo) ? sTextData : sErrorInfo)
        << std::endl;

    //sOut
    //    << L"    Type:        "
    //    << (desktop.Type(sTextData, sErrorInfo) ? sTextData : sErrorInfo)
    //    << std::endl;

    sOut
        << L"    Flags:       "
        << (desktop.Flags(sTextData, sErrorInfo) ? sTextData : sErrorInfo)
        << std::endl;

    sOut
        << L"    Heap size:   ";
    if (desktop.HeapSize(heapSize, sErrorInfo))
    {
        sOut << heapSize << L" KB" << std::endl;
    }
    else
    {
        sOut << sErrorInfo << std::endl;
    }

    sOut << std::endl;

    WhoAmI whoAmI;
    sOut
        << L"    Running as:  "
        << whoAmI.GetUserCSid().toSidString()
        << L" - "
        << whoAmI.GetUserCSid().toDomainAndUsername()
        << std::endl;

    sOut << std::endl;
}

static void OutputCurrentUserInputDesktop(std::wostream& sOut)
{
    std::wstring sErrorInfo, sName;
    Desktop desktop(WindowStation::Original());
    sOut
        << L"Current user input Desktop: ";
    if (desktop.InitFromInputDesktop(MAXIMUM_ALLOWED, sErrorInfo) && desktop.Name(sName, sErrorInfo))
    {
        sOut << sName << std::endl;
    }
    else
    {
        sOut << sErrorInfo << std::endl;
    }
    sOut << std::endl;
}

static void OutputActiveConsoleSessionId(std::wostream& sOut, DWORD dwSessionId)
{
    sOut
        << L"Console Session = ";
    if (0xFFFFFFFF == dwSessionId)
        sOut << L"(transition)" << std::endl << std::endl;
    else
        sOut << dwSessionId << std::endl << std::endl;
}

static void OutputTerminalSessions(std::wostream& sOut, bool bShowProcesses)
{
    TerminalSessionList_t tsList;
    std::wstring sErrorInfo;
    if (!TerminalSession::GetTerminalSessions(tsList, sErrorInfo))
    {
        sOut << L"Unable to enumerate terminal sessions: " << sErrorInfo << std::endl;
        return;
    }

    sOut << L"Terminal sessions: " << tsList.size() << std::endl << std::endl;

    TerminalSessionList_t::const_iterator sessionIter;
    for (sessionIter = tsList.begin(); sessionIter != tsList.end(); sessionIter++)
    {
        sOut
            << L"    Session ID           : " << sessionIter->ID() << std::endl
            << L"    Session Name         : " << sessionIter->Name() << std::endl
            << L"    State                : " << sessionIter->State() << std::endl
            << L"    SessionFlags         : " << sessionIter->SessionFlags() << std::endl
            << L"    DomainName           : " << sessionIter->DomainName() << std::endl
            << L"    UserName             : " << sessionIter->UserName() << std::endl
            << L"    LogonTime            : " << sessionIter->LogonTime() << std::endl
            << L"    ConnectTime          : " << sessionIter->ConnectTime() << std::endl
            << L"    DisconnectTime       : " << sessionIter->DisconnectTime() << std::endl
            << L"    LastInputTime        : " << sessionIter->LastInputTime() << std::endl
            << L"    CurrentTime          : " << sessionIter->CurrentTime() << std::endl
            ;

        HANDLE hToken = NULL, hLinkedToken = NULL;
        DWORD dwLastErr;
        if (sessionIter->GetUserToken(hToken, dwLastErr))
        {
            TokenInfo_t tokenInfo, linkedTokenInfo;
            Token::GetTokenInfo(hToken, tokenInfo, sErrorInfo);
            sOut
                << L"    * User token:" << std::endl
                << L"    Token user SID       : " << tokenInfo.sid.toSidString() << std::endl
                << L"    Token logon session  : " << HEX(tokenInfo.logonSession.HighPart) << L":" << HEX(tokenInfo.logonSession.LowPart) << std::endl
                << L"    Token integrity level: " << tokenInfo.IntegrityLevelName() << std::endl
                ;
            if (Token::GetLinkedToken(hToken, hLinkedToken))
            {
                Token::GetTokenInfo(hLinkedToken, linkedTokenInfo, sErrorInfo);
                sOut
                    << L"    * Linked token:" << std::endl
                    << L"    Token user SID       : " << linkedTokenInfo.sid.toSidString() << std::endl
                    << L"    Token logon session  : " << HEX(linkedTokenInfo.logonSession.HighPart) << L":" << HEX(linkedTokenInfo.logonSession.LowPart) << std::endl
                    << L"    Token integrity level: " << linkedTokenInfo.IntegrityLevelName() << std::endl
                    ;
                CloseHandle(hLinkedToken);
            }
            CloseHandle(hToken);
        }
        else
        {
            switch (dwLastErr)
            {
            case ERROR_PRIVILEGE_NOT_HELD:
                sOut << L"    [Insufficient privilege to retrieve token]" << std::endl;
                break;
            case ERROR_NO_TOKEN:
            case ERROR_FILE_NOT_FOUND: // seeing sessions in Listen state returning ERROR_FILE_NOT_FOUND for some reason
                sOut << L"    No Token" << std::endl;
                break;
            default:
                sOut << L"    Error retrieving token: " << SysErrorMessageWithCode(dwLastErr) << std::endl;
                break;
            }
        }

        if (bShowProcesses)
        {
            TSProcessInfoList_t procList;
            if (sessionIter->GetProcesses(procList, sErrorInfo))
            {
                if (procList.size() > 0)
                {
                    sOut << L"    Processes:" << std::endl;

                    TSProcessInfoList_t::const_iterator procIter;
                    size_t nMaxProcNameLength = 0;
                    for (procIter = procList.begin(); procIter != procList.end(); procIter++)
                    {
                        size_t nProcNameLength = procIter->sProcessName.length();
                        if (nProcNameLength > nMaxProcNameLength)
                            nMaxProcNameLength = nProcNameLength;
                    }
                    for (procIter = procList.begin(); procIter != procList.end(); procIter++)
                    {
                        sOut
                            << L"        "
                            << std::left << std::setw(7) << procIter->dwPID
                            << std::left << std::setw(nMaxProcNameLength + 2) << procIter->sProcessName
                            << procIter->userSid.toDomainAndUsername(true)
                            << std::endl;
                    }
                }
                else
                {
                    sOut << L"    No processes" << std::endl;
                }
            }
            else
            {
                sOut << L"    Error enumerating processes: " << sErrorInfo << std::endl;
            }
        }

        sOut << std::endl;
    }
}

static void OutputUserObjectPermissions(std::wostream& sOut, UserObject& obj, bool bWindowStation, SecDescOptions_t secDescOption, size_t indent)
{
    if (SecDescOptions_t::None != secDescOption)
    {
        std::wstring sErrorInfo, sSDDL;
        bool bWithSacl = false;
        SecurityDescriptor objSD;
        SECURITY_INFORMATION siWithSacl =
            OWNER_SECURITY_INFORMATION |
            GROUP_SECURITY_INFORMATION |
            DACL_SECURITY_INFORMATION |
            LABEL_SECURITY_INFORMATION |
            SACL_SECURITY_INFORMATION;
        SECURITY_INFORMATION siNoSacl =
            OWNER_SECURITY_INFORMATION |
            GROUP_SECURITY_INFORMATION |
            DACL_SECURITY_INFORMATION |
            LABEL_SECURITY_INFORMATION;
        // Try to get SD with SACL; if that fails, try without.
        if (!(bWithSacl = obj.GetSecurity(objSD, siWithSacl, sErrorInfo)) && !obj.GetSecurity(objSD, siNoSacl, sErrorInfo))
        {
            sOut << std::setw(indent) << L"" << L"Sec desc : " << sErrorInfo << std::endl;
        }
        else
        {
            switch (secDescOption)
            {
            case SecDescOptions_t::SDDL:
                sOut << std::setw(indent) << L"" << L"SDDL     : ";
                if (SecDescriptorToSDDL(objSD.GetSD(), (bWithSacl ? siWithSacl : siNoSacl), sSDDL, sErrorInfo))
                {
                    sOut << sSDDL << std::endl;
                }
                else
                {
                    sOut << sErrorInfo << std::endl;
                }
                break;
            case SecDescOptions_t::SecDesc:
                sOut << std::setw(indent) << L"" << L"Security descriptor:" << std::endl;
                OutputSecurityDescriptor(sOut, objSD.GetSD(), bWindowStation ? L"winsta" : L"desktop", true, indent + 2);
                sOut << std::endl;
                break;
            }
        }
    }
}

static void OutputDesktopWindows(std::wostream& sOut, Desktop& desktop, bool bVisibleOnly)
{
    //const wchar_t* const szTab = L"\t";
    const wchar_t* const szIndent = L"          ";

    WindowInfoCollection_t windowInfoCollection;
    std::wstring sErrorInfo;
    if (desktop.GetTopLevelWindows(windowInfoCollection, sErrorInfo))
    {
        if (!sErrorInfo.empty())
        {
            sOut << L"!!! " << sErrorInfo << std::endl;
        }

        size_t numWindows = windowInfoCollection.size();

        if (numWindows == 0)
        {
            sOut << szIndent << L"No top-level windows." << std::endl;
        }
        else
        {
            bool bListingAny = false;
            // iterate through and get the sizes from the data
            size_t lenClassName = 12, lenWindowText = 11, lenPID = 4; // , lenProcessPath = 0;
            WindowInfoCollection_t::const_iterator infoCollIter;
            for (infoCollIter = windowInfoCollection.begin(); infoCollIter != windowInfoCollection.end(); infoCollIter++)
            {
                const WindowInfo_t& windowInfo = infoCollIter->second;
                if (windowInfo.bIsValid && (windowInfo.bIsVisible || !bVisibleOnly))
                {
                    bListingAny = true;
                    lenClassName = std::max(escapeCrLfTabNul(windowInfo.sClassName).size(), lenClassName);
                    lenWindowText = std::max(escapeCrLfTabNul(windowInfo.sWindowText).size(), lenWindowText);
                    //lenProcessPath = std::max(windowInfo.sProcessPath.size(), lenProcessPath);
                    if (windowInfo.PID >= 1000000)
                        lenPID = std::max((size_t)7, lenPID);
                    else if (windowInfo.PID >= 100000)
                        lenPID = std::max((size_t)6, lenPID);
                    else if (windowInfo.PID >= 10000)
                        lenPID = std::max((size_t)5, lenPID);
                }
            }

            // Set some limits
            lenClassName = std::min((size_t)35, lenClassName);
            lenWindowText = std::min((size_t)55, lenWindowText);

            if (!bListingAny)
            {
                sOut << szIndent << L"Top-level windows: " << numWindows << L". None are visible." << std::endl;
            }
            else
            {
                sOut << szIndent << L"Top-level windows: " << numWindows << (bVisibleOnly ? L". Showing visible windows only." : L"") << std::endl;
                // Output headers
                sOut
                    << szIndent << L"  "
                    << std::left << std::setw(9) << L"HWND"
                    << std::left << std::setw(8) << L"IsVis?"
                    << std::left << std::setw(lenClassName + 1) << L"Window class"
                    << std::left << std::setw(lenWindowText + 1) << L"Window text"
                    << std::left << std::setw(lenPID + 1) << L"PID"
                    << L"Process name" << std::endl;

                for (infoCollIter = windowInfoCollection.begin(); infoCollIter != windowInfoCollection.end(); infoCollIter++)
                {
                    const WindowInfo_t& windowInfo = infoCollIter->second;
                    if (windowInfo.bIsValid)
                    {
                        if (windowInfo.bIsVisible || !bVisibleOnly)
                        {
                            // Trim them if necessary
                            std::wstring sClassName = escapeCrLfTabNul(windowInfo.sClassName);
                            std::wstring sWindowText = escapeCrLfTabNul(windowInfo.sWindowText);
                            if (sClassName.length() > lenClassName)
                                sClassName = sClassName.substr(0, lenClassName - 3) + L"...";
                            if (sWindowText.length() > lenWindowText)
                                sWindowText = sWindowText.substr(0, lenWindowText - 3) + L"...";
                            sOut
                                << szIndent << L"  "
                                << std::left << std::setw(9) << HEX((unsigned long long)windowInfo.hwnd, 8, true, false)
                                << std::left << std::setw(8) << (windowInfo.bIsVisible ? L"Visible" : L"Hidden")
                                << std::left << std::setw(lenClassName + 1) << sClassName
                                << std::left << std::setw(lenWindowText + 1) << sWindowText
                                << std::left << std::setw(lenPID + 1) << windowInfo.PID
                                << GetFileNameFromFilePath(windowInfo.sProcessPath) << std::endl;
                        }
                    }
                    else
                    {
                        sOut
                            << szIndent
                            << windowInfo.hwnd
                            << L"(INVALID)"



                            << std::endl;
                    }
                }
            }
        }
    }
    else
    {
        sOut << L"            Unable to enumerate windows: " << sErrorInfo << std::endl;
    }
}

static void OutputWinstaDesktopInfo(std::wostream& sOut, bool bShowWindows, bool bShowOnlyVisibleWindows, SecDescOptions_t secDescOption)
{
    WindowStationNameList_t wsNameList;
    std::wstring sErrorInfo;

    if (WindowStation::GetWindowStationNames(wsNameList, sErrorInfo))
    {
        sOut << L"Window stations in the current session: " << wsNameList.size() << std::endl << std::endl;

        WindowStationNameList_t::iterator wsNameIter;
        for (wsNameIter = wsNameList.begin(); wsNameIter != wsNameList.end(); wsNameIter++)
        {
            sOut << L"    WS name    : " << *wsNameIter << std::endl;
            WindowStation ws;
            if (ws.Open(wsNameIter->c_str(), MAXIMUM_ALLOWED, sErrorInfo))
            {
                std::wstring sName, sFlags, sUserNameAndSid, sSDDL;
                //std::wstring sType;
                sOut
                    //<< L"      Type     : " << (ws.Type(sType, sErrorInfo) ? sType : sErrorInfo) << std::endl
                    << L"      Flags    : " << (ws.Flags(sFlags, sErrorInfo) ? sFlags : sErrorInfo) << std::endl
                    << L"      User     : " << (ws.UserNameAndSid(sUserNameAndSid, sErrorInfo) ? sUserNameAndSid : sErrorInfo) << std::endl
                    ;

                OutputUserObjectPermissions(sOut, ws, true, secDescOption, 6);

                DesktopNameList_t desktopNameList;
                if (ws.GetDesktopNames(desktopNameList, sErrorInfo))
                {
                    sOut << L"      Desktops in WS " << *wsNameIter << L": " << desktopNameList.size() << std::endl << std::endl;
                    DesktopNameList_t::const_iterator desktopNameIter;
                    for (desktopNameIter = desktopNameList.begin(); desktopNameIter != desktopNameList.end(); desktopNameIter++)
                    {
                        sOut << L"        Name : " << *desktopNameIter << std::endl;
                        Desktop desk(ws);

                        if (desk.Open(desktopNameIter->c_str(), MAXIMUM_ALLOWED, sErrorInfo))
                        {
                            ULONG heapSizeKb = 0;
                            BOOL bIsReceivingInput = FALSE;
                            sOut
                                //<< L"          Type     : " << (desk.Type(sType, sErrorInfo) ? sType : sErrorInfo) << std::endl
                                << L"          Flags    : " << (desk.Flags(sFlags, sErrorInfo) ? sFlags : sErrorInfo) << std::endl
                                << L"          User     : " << (desk.UserNameAndSid(sUserNameAndSid, sErrorInfo) ? sUserNameAndSid : sErrorInfo) << std::endl
                                << L"          Heap size: "
                                ;
                            if (desk.HeapSize(heapSizeKb, sErrorInfo))
                            {
                                sOut << heapSizeKb << L" KB" << std::endl;
                            }
                            else
                            {
                                sOut << sErrorInfo << std::endl;
                            }
                            sOut
                                << L"          UserInput: ";
                            if (desk.IsReceivingInput(bIsReceivingInput, sErrorInfo))
                            {
                                sOut << (bIsReceivingInput ? L"Yes" : L"No") << std::endl;
                            }
                            else
                            {
                                sOut << sErrorInfo << std::endl;
                            }

                            OutputUserObjectPermissions(sOut, desk, false, secDescOption, 10);

                            if (bShowWindows)
                            {
                                OutputDesktopWindows(sOut, desk, bShowOnlyVisibleWindows);
                            }
                        }
                        else
                        {
                            sOut << L"          Error: " << sErrorInfo << std::endl;
                        }
                        sOut << std::endl;
                    }
                }
                else
                {
                    sOut << L"      Unable to enumerate desktops: " << sErrorInfo << std::endl;
                }
            }
            else
            {
                sOut << L"    Error: " << sErrorInfo << std::endl;
            }
            sOut << std::endl;
        }
    }
    else
    {
        sOut << L"Unable to enumerate window stations: " << sErrorInfo << std::endl;
    }

}


