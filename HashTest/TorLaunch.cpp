#include "stdafx.h"
#include <Windows.h>
#include <iphlpapi.h>
#include <assert.h>
#include <intrin.h>
#include <iostream>
#include <winhttp.h>
#include <jansson.h>
#include "base64.h"
#include <locale.h>
#include <vector>

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "WinHTTP.lib")
#pragma comment(lib, "jansson.lib")

typedef unsigned int _DWORD;
typedef unsigned char _BYTE;
typedef unsigned int uint32_t;

#define _UNICODE

using std::vector;

// BASE 64 END

static void PrintMACaddress(unsigned char MACData[])
{
	printf("%02X-%02X-%02X-%02X-%02X-%02X", 
		MACData[0], MACData[1], MACData[2], MACData[3], MACData[4], MACData[5]);
}

static void GetMACaddress(char* pszTarget, size_t size)
{
  IP_ADAPTER_INFO AdapterInfo[16];       // Allocate information 
                                         // for up to 16 NICs
  DWORD dwBufLen = sizeof(AdapterInfo);  // Save memory size of buffer

  DWORD dwStatus = GetAdaptersInfo(      // Call GetAdapterInfo
    AdapterInfo,                 // [out] buffer to receive data
    &dwBufLen);                  // [in] size of receive data buffer
  assert(dwStatus == ERROR_SUCCESS);  // Verify return value is 
                                      // valid, no buffer overflow

  PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo; // Contains pointer to
                                               // current adapter info
  
  unsigned char* MACData = pAdapterInfo->Address;
  sprintf_s(pszTarget, size, "%02X-%02X-%02X-%02X-%02X-%02X",
		MACData[0], MACData[1], MACData[2], MACData[3], MACData[4], MACData[5]);
}

static unsigned int GetMajorVersion()
{
	OSVERSIONINFOEX osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((OSVERSIONINFO*)&osvi);
	return osvi.dwMajorVersion;
}

static unsigned int GetMinorVersion()
{
	OSVERSIONINFOEX osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((OSVERSIONINFO*)&osvi);
	return osvi.dwMinorVersion;
}

static unsigned int GetServicePackMajorVersion()
{
	OSVERSIONINFOEX osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((OSVERSIONINFO*)&osvi);
	return osvi.wServicePackMajor;
}

static unsigned int GetServicePackMinorVersion()
{
	OSVERSIONINFOEX osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((OSVERSIONINFO*)&osvi);
	return osvi.wServicePackMinor;
}

static void GetVersionString(char* pszDestination, size_t size)
{
	OSVERSIONINFOEX osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((OSVERSIONINFO*)&osvi);

	if (osvi.dwPlatformId)
	{
		if (osvi.dwPlatformId == 1)
		{
			if (osvi.dwMinorVersion)
			{
				if (osvi.dwMinorVersion == 10)
				{
					sprintf_s(pszDestination, size, "Windows 98");
				}
				else if (osvi.dwMinorVersion == 90)
				{
					sprintf_s(pszDestination, size, "Windoes ME");
				}
			} else {
				sprintf_s(pszDestination, size, "Windows 95");
			}
		} else if (osvi.dwPlatformId == 2) {
			if (osvi.dwMajorVersion != 6 || osvi.dwMinorVersion)
			{
				if (osvi.dwMajorVersion == 5)
				{
					if (osvi.dwMinorVersion)
					{
						if (osvi.dwMinorVersion == 1 || osvi.dwMinorVersion == 2)
						{
							sprintf_s(pszDestination, size, "Windows XP %s", osvi.szCSDVersion);
						} else {
							sprintf_s(pszDestination, size, "Windows 2000 %s", osvi.szCSDVersion);
						}
					}
				} else {
					if (osvi.dwMajorVersion > 4)
					{
						sprintf_s(pszDestination, size, "Windows %d.%d  %s", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.szCSDVersion);
					} else {
						sprintf_s(pszDestination, size, "Windows NT %d.%d  %s", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.szCSDVersion);
					}
				}
			} else { 
				if (osvi.wProductType == VER_NT_WORKSTATION) {
					sprintf_s(pszDestination, size, "Windows Vista %s", osvi.szCSDVersion);
				} else {
					sprintf_s(pszDestination, size, "Windows Server 2008 %s", osvi.szCSDVersion);
				}
			}
		} else {
			sprintf_s(pszDestination, size, "Windows ?? %d.%d %s", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.szCSDVersion);
		}
	} else {
		sprintf_s(pszDestination, size, "Windows %d.%d", osvi.dwMajorVersion, osvi.dwMinorVersion);
	}
}

static void GetCPUString(char* pszCPUString, size_t size)
{
	// Get extended ids.
    int CPUInfo[4] = {-1};
    __cpuid(CPUInfo, 0x80000000);
    unsigned int nExIds = CPUInfo[0];

    // Get the information associated with each extended ID.
    char CPUBrandString[0x40] = { 0 };
    for( unsigned int i=0x80000000; i<=nExIds; ++i)
    {
        __cpuid(CPUInfo, i);

        // Interpret CPU brand string and cache information.
        if  (i == 0x80000002)
        {
            memcpy( CPUBrandString,
            CPUInfo,
            sizeof(CPUInfo));
        }
        else if( i == 0x80000003 )
        {
            memcpy( CPUBrandString + 16,
            CPUInfo,
            sizeof(CPUInfo));
        }
        else if( i == 0x80000004 )
        {
            memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));
        }
	}

	sprintf_s(pszCPUString, size, "%s", CPUBrandString);
}


int __cdecl HashFunction(unsigned char* pInputString, unsigned int inputLength, int* hashH, int* hashL)
{
  int result; // eax@17
  int v30; // ST20_4@37
  unsigned int v31; // ST1C_4@37
  int v32; // ST28_4@37
  int v33; // ST1C_4@37
  int v34; // ST20_4@37
  int v35; // ST28_4@37
  int v36; // ST1C_4@37
  int v37; // ST20_4@37
  int v38; // ST28_4@37
  int v39; // ST1C_4@37
  int v40; // ST20_4@37
  unsigned int v41; // ST1C_4@52
  unsigned int v42; // ST28_4@52
  unsigned int v43; // ST20_4@52
  unsigned int v44; // ST1C_4@52
  unsigned int v45; // ST28_4@52
  unsigned int v46; // ST20_4@52
  unsigned char* v47; // [sp+Ch] [bp-20h]@1
  int v51; // [sp+1Ch] [bp-10h]@1
  unsigned int v52; // [sp+20h] [bp-Ch]@1
  int v53; // [sp+28h] [bp-4h]@1

  v52 = inputLength + *(_DWORD *)hashH - 559038737;
  v53 = inputLength + *(_DWORD *)hashH - 559038737;
  v51 = *(_DWORD *)hashL + v52;
  v47 = pInputString;
  while ( inputLength > 0xC )
  {
    v30 = v52
        + *(_BYTE *)(v47 + 4)
        + (*(_BYTE *)(v47 + 5) << 8)
        + (*(_BYTE *)(v47 + 6) << 16)
        + (*(_BYTE *)(v47 + 7) << 24);
    v31 = v51
        + *(_BYTE *)(v47 + 8)
        + (*(_BYTE *)(v47 + 9) << 8)
        + (*(_BYTE *)(v47 + 10) << 16)
        + (*(_BYTE *)(v47 + 11) << 24);
    v32 = (v53
         + *(_BYTE *)v47
         + (*(_BYTE *)(v47 + 1) << 8)
         + (*(_BYTE *)(v47 + 2) << 16)
         + (*(_BYTE *)(v47 + 3) << 24)
         - v31) ^ (v31 >> 28) ^ 16 * v31;
    v33 = v30 + v31;
    v34 = (v30 - v32) ^ ((unsigned int)v32 >> 26) ^ (v32 << 6);
    v35 = v33 + v32;
    v36 = (v33 - v34) ^ ((unsigned int)v34 >> 24) ^ (v34 << 8);
    v37 = v35 + v34;
    v38 = (v35 - v36) ^ ((unsigned int)v36 >> 16) ^ (v36 << 16);
    v39 = v37 + v36;
    v40 = (v37 - v38) ^ ((unsigned int)v38 >> 13) ^ (v38 << 19);
    v53 = v39 + v38;
    v51 = (v39 - v40) ^ ((unsigned int)v40 >> 28) ^ 16 * v40;
    v52 = v53 + v40;
    inputLength -= 12;
    v47 += 12;
  }
  switch ( inputLength )
  {
    case 0xCu:
      v51 += *(_BYTE *)(v47 + 11) << 24;
      goto LABEL_40;
    case 0xBu:
LABEL_40:
      v51 += *(_BYTE *)(v47 + 10) << 16;
      goto LABEL_41;
    case 0xAu:
LABEL_41:
      v51 += *(_BYTE *)(v47 + 9) << 8;
      goto LABEL_42;
    case 9u:
LABEL_42:
      v51 += *(_BYTE *)(v47 + 8);
      goto LABEL_43;
    case 8u:
LABEL_43:
      v52 += *(_BYTE *)(v47 + 7) << 24;
      goto LABEL_44;
    case 7u:
LABEL_44:
      v52 += *(_BYTE *)(v47 + 6) << 16;
      goto LABEL_45;
    case 6u:
LABEL_45:
      v52 += *(_BYTE *)(v47 + 5) << 8;
      goto LABEL_46;
    case 5u:
LABEL_46:
      v52 += *(_BYTE *)(v47 + 4);
      goto LABEL_47;
    case 4u:
LABEL_47:
      v53 += *(_BYTE *)(v47 + 3) << 24;
      goto LABEL_48;
    case 3u:
LABEL_48:
      v53 += *(_BYTE *)(v47 + 2) << 16;
      goto LABEL_49;
    case 2u:
LABEL_49:
      v53 += *(_BYTE *)(v47 + 1) << 8;
      goto LABEL_50;
    case 1u:
LABEL_50:
      v53 += *(_BYTE *)v47;
      goto LABEL_52;
    case 0u:
      result = v51;
      *(_DWORD *)hashH = v51;
      *(_DWORD *)hashL = v52;
      break;
    default:
LABEL_52:
      v41 = (v52 ^ v51) - ((v52 >> 18) ^ (v52 << 14));
      v42 = (v41 ^ v53) - ((v41 >> 21) ^ (v41 << 11));
      v43 = (v42 ^ v52) - ((v42 >> 7) ^ (v42 << 25));
      v44 = (v43 ^ v41) - ((v43 >> 16) ^ (v43 << 16));
      v45 = (v44 ^ v42) - ((v44 >> 28) ^ 16 * v44);
      v46 = (v45 ^ v43) - ((v45 >> 18) ^ (v45 << 14));
      *(_DWORD *)hashH = (v46 ^ v44) - ((v46 >> 8) ^ (v46 << 24));
      result = *hashL;
      *(_DWORD *)hashL = v46;
      break;
  }
  return result;
}

json_t* SendLoginRequest(json_t* data)
{
  DWORD dwSize = 0;
  DWORD dwDownloaded = 0;
  LPSTR pszOutBuffer;
  BOOL  bResults = FALSE;
  HINTERNET  hSession = NULL, 
             hConnect = NULL,
             hRequest = NULL;

  std::vector<unsigned char> v_data;

  // Use WinHttpOpen to obtain a session handle.
  hSession = WinHttpOpen( L"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11",  
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME, 
                          WINHTTP_NO_PROXY_BYPASS, 0 );

  // Specify an HTTP server.
  if( hSession )
    hConnect = WinHttpConnect( hSession, L"launchpad.swtor.com",
                               INTERNET_DEFAULT_HTTPS_PORT, 0 );

  // Create an HTTP request handle.
  if( hConnect )
    hRequest = WinHttpOpenRequest( hConnect, L"POST", L"/launchpad/secure/authenticate",
                                   NULL, WINHTTP_NO_REFERER, 
                                   WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                   WINHTTP_FLAG_SECURE );

  // Send a request.
  if( hRequest )
  {
	char* pRequestData = json_dumps(data, 0);
	// printf("Request JSON: %s Request length: %d\n", pRequestData, strlen(pRequestData));
    bResults = WinHttpSendRequest( hRequest,
                                   L"Content-Type: application/json\r\nx-origin: game\r\nx-token: true\r\n", -1,
                                   pRequestData, strlen(pRequestData) + 1, 
                                   strlen(pRequestData) + 1, 0 );
  }


  // End the request.
  if( bResults )
    bResults = WinHttpReceiveResponse( hRequest, NULL );



  // Keep checking for data until there is nothing left.
  if( bResults )
  {
    do 
    {
      // Check for available data.
      dwSize = 0;
      if( !WinHttpQueryDataAvailable( hRequest, &dwSize ) )
        printf( "Error %u in WinHttpQueryDataAvailable.\n",
                GetLastError( ) );

      // Allocate space for the buffer.
      pszOutBuffer = new char[dwSize+1];
      if( !pszOutBuffer )
      {
        printf( "Out of memory\n" );
        dwSize=0;
      }
      else
      {
        // Read the data.
        ZeroMemory( pszOutBuffer, dwSize+1 );

        if( !WinHttpReadData( hRequest, (LPVOID)pszOutBuffer, 
                              dwSize, &dwDownloaded ) )
          printf( "Error %u in WinHttpReadData.\n", GetLastError( ) );
        // else
        //  printf( "%s", pszOutBuffer );

		
		DWORD dwStatusCode = 0;
		DWORD dwStatusSize = 4;
		WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &dwStatusCode, &dwStatusSize, NULL);

		

		for (unsigned int i = 0; i < dwDownloaded; i++)
		{
			v_data.push_back(pszOutBuffer[i]);
		}


		if (dwStatusCode == 404)
		{
			printf("Error: Invalid password.\n");
			return 0;
		}
        // Free the memory allocated to the buffer.
        delete [] pszOutBuffer;
      }
    } while( dwSize > 0 );

	json_error_t json_error;
	json_t* response = json_loads((const char*)&v_data[0], 0, &json_error);

	if(response)
	{
		printf("[Password]: Accepted!\n");
		return response;
	} else {
		printf("Error: Invalid password.\n");
		return 0;
	}
  }


  // Report any errors.
  if( !bResults )
    printf( "Error %d has occurred.\n", GetLastError( ) );

  // Close any open handles.
  if( hRequest ) WinHttpCloseHandle( hRequest );
  if( hConnect ) WinHttpCloseHandle( hConnect );
  if( hSession ) WinHttpCloseHandle( hSession );

  return 0;
}

void XOR(unsigned char* input, unsigned int inputLength, unsigned char* key, unsigned int keyLength)
{
	for(int i = 0; i < inputLength; i++)
	{
		input[i] = input[i] ^ key[i % keyLength];
	}
}

json_t* GetLoginToken(char* pszLoginTokenOut, size_t size, char* login, json_t* accountInfo)
{
	// Login parameters
	char* pszPassword = 0;
	char* pszMachineSpec = 0;
	json_unpack(accountInfo, "{s:s}", "password", &pszPassword);

	if (!pszPassword)
	{
		printf("Error: No password set for %s\n", login);
	}

	json_unpack(accountInfo, "{s:s}", "machineSpec", &pszMachineSpec);
	if (!pszMachineSpec)
	{
		printf("Error: No machine spec for %s\n", login);
	}

	if (pszMachineSpec && pszPassword)
	{
		json_t* root = json_object();
		json_object_set_new(root, "email", json_string(login));

		json_t* passwordMethod = json_object();
		json_object_set_new(passwordMethod, "method", json_string("PASSWORD"));
		json_object_set_new(passwordMethod, "value", json_string(pszPassword));

		json_t* methodList = json_array();
		json_array_append_new(methodList, passwordMethod);

		json_object_set_new(root, "methodList", methodList);

		json_object_set_new(root, "machineSpec", json_string(pszMachineSpec));
	

		bool bResendRequest;
		json_t* loginResponse = 0;

		do {
			bResendRequest = false;
			// printf("Request JSON: %s\n", json_dumps(root, 0));



			loginResponse = SendLoginRequest(root);

			// printf("Response JSON: %s\n", json_dumps(loginResponse, JSON_INDENT(2)));

			const char* result = 0;
			json_unpack(loginResponse, "{s:s}", "result", &result);

			if (result)
			{
				if (!strcmp(result, "SUCCESS"))
				{
					printf("[Login]: Successfull!\n");
					const char* gameToken = 0;
					json_unpack(loginResponse, "{s:{s:s}}", "token", "gameToken", &gameToken);
					if (gameToken)
					{
						sprintf_s(pszLoginTokenOut, size, "%s", gameToken);
					}
				} else if (!strcmp(result, "REQUIRED")) {
					printf("[Login]: Resubmitting login request with missing field:\n");
					// Add additional fields
					json_t* failures_array;

					json_unpack(loginResponse, "{s:o}", "failures", &failures_array);

					if (!failures_array)
					{
						printf("Error: Could not parse login failures\n");
						return 0;
					}

					size_t failureCount = json_array_size(failures_array);
					for(unsigned int i = 0; i < failureCount; i++)
					{
						json_t* failure = json_array_get(failures_array, i);
						int ID = 0;
						const char* field = 0;
						const char* prompt = 0;
						const char* reason = 0;
						json_unpack(failure, "{s:i, s:s, s:s, s:s}", "id", &ID, "field", &field, "prompt", &prompt, "reason", &reason);
						printf("Field: %s, Prompt: %s\n", field, prompt);

						if (!strcmp(reason, "REQUIRED"))
						{
							if (!strcmp(field, "SECRET_QUESTION"))
							{
								// Get the value for the secret question answer
								const char* secretQuestionAnswer = 0;
								json_unpack(accountInfo, "{s:{s:s}}", "secret-questions", prompt, &secretQuestionAnswer);

								if (!secretQuestionAnswer)
								{
									printf("Could not find answer for secret question: [%s]\nPlease add the answer to config.json\n", prompt);
									return 0;
								}

								json_t* secretMethod = json_object();
								json_object_set_new(secretMethod, "method", json_string("SECRET_QUESTION"));
								json_object_set_new(secretMethod, "id", json_integer(ID));
								json_object_set_new(secretMethod, "value", json_string(secretQuestionAnswer));

								json_array_append_new(methodList, secretMethod);
							}
							printf("Resending login request with additional fields!\n");
							bResendRequest = true;
						}
					}
				}
			} else {
				printf("Failure: Could not log in, check your credentials\n");
				json_decref(root);
				return 0;
			}
		} while (bResendRequest);

		json_decref(root);
		return loginResponse;
	}
	return 0;
}

json_t* loadSettings()
{
	json_error_t error;
	json_t* settings = json_load_file("config.json", 0, &error);
	if (!settings)
	{
		printf("Failed to load config: %s\n", error.text);
	}
	return settings;
}

json_t* loadAccount(json_t* settings, _TCHAR* accountEmail)
{	
	json_error_t error;
	json_t* accountJson = 0;
	json_unpack_ex(settings, &error, 0, "{s:{s:o}}", "accounts", accountEmail, &accountJson);
	if(!accountJson)
	{
		printf("JSON unpack error: %s\n", error.text);
	} else {
		// Check if account has a machine spec
		char* machineSpec = 0;
		json_unpack(accountJson, "{s:s}", "machineSpec", &machineSpec);

		if(!machineSpec)
		{
			unsigned char newMachineSpec[8] = { 0 };
			for (int i = 0; i < 8; i++)
			{
				newMachineSpec[i] = rand() % 256;
			}
			char szMachineSpec[1024] = { 0 };
			sprintf_s(szMachineSpec, sizeof(szMachineSpec), "%u.%u", *(unsigned int*)newMachineSpec, *(unsigned int*)(newMachineSpec + 4));
			printf("Generated machine spec %u.%u for %s\n", *(unsigned int*)newMachineSpec, *(unsigned int*)(newMachineSpec + 4), accountEmail);

			json_object_set(accountJson, "machineSpec", json_string(szMachineSpec));

			json_dump_file(settings, "config.json", JSON_INDENT(2)); 
		} else {
			printf("Using machine spec: %s\n", machineSpec);
		}
	}	
	return accountJson;
}

int _tmain(int argc, _TCHAR* argv[])
{

	srand(time(NULL));
	setlocale(LC_ALL, "");

	if(argc != 2)
	{
		_tprintf(_T("Usage: %s email\n"), argv[0]);
		return -1;
	}

	
	printf("[swtorlauncher by sprite]\n");
	printf("Logging in account: %s\n", argv[1]);


	// Load settings
	json_t* settings = loadSettings();
	json_t* account = loadAccount(settings, argv[1]);

	if (!account)
	{
		_tprintf(_T("Error: Could not find settings for account: %s\n"), argv[1]);
		return -1;
	}

	MEMORYSTATUSEX statex;
	statex.dwLength = sizeof(statex);
	GlobalMemoryStatusEx(&statex);

	char szMACAddress[255] = { 0 };
	GetMACaddress(szMACAddress, sizeof(szMACAddress));
	
	char szVersionString[255] = { 0 };
	GetVersionString(szVersionString, sizeof(szVersionString));
	char szCPUString[50] = { 0 };
	GetCPUString(szCPUString, sizeof(szCPUString));
	char szMachineID[1024] = { 0 };
	sprintf_s(szMachineID, sizeof(szMachineID), "[%d.%d][%d.%d][%s][%s][%s][%I64d]", GetMajorVersion(), GetMinorVersion(), GetServicePackMajorVersion(), GetServicePackMinorVersion(), szVersionString, szCPUString, szMACAddress, statex.ullTotalPhys);
	printf("[Machine ID]: [%d.%d][0.0][%s][%s][%s][%I64d]\n", GetMajorVersion(), GetMinorVersion(), szVersionString, szCPUString, szMACAddress, statex.ullTotalPhys);

	int hashH = 0;
	int hashL = 0;

	HashFunction((unsigned char*)szMachineID, strlen(szMachineID), &hashH, &hashL);
	unsigned char* hashHC = (unsigned char*)&hashH;
	unsigned char* hashLC = (unsigned char*)&hashL;
	printf("[Crypto Hash]: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n", hashHC[0], hashHC[1], hashHC[2], hashHC[3], hashLC[0], hashLC[1], hashLC[2], hashLC[3]);

	char szLoginToken[1024] = { 0 };
	json_t* loginJson = GetLoginToken(szLoginToken, sizeof(szLoginToken), argv[1], account);
	if (loginJson)
	{
		printf("Login response: %s\n", json_dumps(loginJson, JSON_INDENT(2)));


		const char* username = 0;
		json_unpack(loginJson, "{s:{s:s}", "user", "persona", &username);

		if (!username)
		{
			printf("[Error] No username in login response..\n");
			return -1;
		}

		printf("[Login]: Username: %s\n", username);

		unsigned int unTokenLength = strlen(szLoginToken);
		printf("[Token] Received login token [%d bytes]\n", unTokenLength);
		
		printf("[Token]: Encrypting Token\n");
		XOR((unsigned char*)szLoginToken, unTokenLength, (unsigned char*)&hashH, 4);
		printf("[Token]: Encoding Token\n");
		std::string encoded = base64_encode((const unsigned char*)szLoginToken, unTokenLength);

		printf("\nGenerated Login Token:\n\n%s\n\n", encoded.c_str());

		const char* launchPath = 0;
		json_unpack(settings, "{s:s}", "swtor-path", &launchPath);
		if (!launchPath)
		{
			printf("[Error] swtor-path not set in config.json\n");
			return -1;
		}
		
		std::string launchExecutable(launchPath);
		launchExecutable.append("\\swtor.exe");

		std::string launchParams;
		launchParams.append("-set username ");
		launchParams.append(username);
		launchParams.append(" -set password ");
		launchParams.append(encoded.c_str());
		launchParams.append(" -set platform gamepad.swtor.com:443 -set environment swtor -set lang en-us -set torsets main,en-us @swtor_dual.icb");

		printf("[Launching] Star Wars - The Old Republic\n");
		HINSTANCE hInst = ShellExecute(NULL, "open", launchExecutable.c_str(), launchParams.c_str(), launchPath, SW_SHOW);
	}

	// json_decref(settings);
	// json_decref(account);
	return 0;
}