#pragma once

#include <Windows.h>
#include <map>
#include <vector>
#include <string>
#include <iostream>

// --------------------------------------------------------------------------------

/// <summary>
/// Output a textual representation of a security descriptor using object-specific permission names.
/// </summary>
/// <param name="sOut">stream to write results into</param>
/// <param name="pSD">Input: the security descriptor to convert to textual representation</param>
/// <param name="szObjType">Input: name of the object type that the SD applies to</param>
/// <param name="bOnePermPerLine">Input: whether to put all the permission names on one line or separate lines</param>
/// <param name="szIndent">Input: base indent at which to start writing text</param>
void OutputSecurityDescriptor(std::wostream& sOut, PSECURITY_DESCRIPTOR pSD, const wchar_t* szObjType, bool bOnePermPerLine = true, size_t indent = 0);

/// <summary>
/// Output a textual representation of a security descriptor using object-specific permission names.
/// </summary>
/// <param name="sOut">stream to write results into</param>
/// <param name="szSDDL">Input: SDDL representing the security descriptor to convert to textual representation</param>
/// <param name="szObjType">Input: name of the object type that the SD applies to</param>
/// <param name="bOnePermPerLine">Input: whether to put all the permission names on one line or separate lines</param>
/// <param name="szIndent">Input: base indent at which to start writing text</param>
void OutputSecurityDescriptor(std::wostream& sOut, const wchar_t* szSDDL, const wchar_t* szObjType, bool bOnePermPerLine = true, size_t indent = 0);

/// <summary>
/// Convert a binary security descriptor to SDDL.
/// </summary>
/// <param name="pSD">Input: security descriptor to convert to SDDL</param>
/// <param name="si">Input: Which security information to incorporate into the SDDL</param>
/// <param name="sSDDL">Output: converted SDDL</param>
/// <param name="sErrorInfo">Output: error information, if the function fails</param>
/// <returns>true if successful, false otherwise</returns>
bool SecDescriptorToSDDL(const PSECURITY_DESCRIPTOR pSD, SECURITY_INFORMATION si, std::wstring& sSDDL, std::wstring& sErrorInfo);

