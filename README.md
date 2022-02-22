License Copyleft
Do whatever you want except if your from china


# ahl
Simple AntiDebugging and HWID header lib in c++

to do: add 


	cpu vendor string and disk serial number and product id as shown below. 



	const char* MachineGUID() {
		std::string out;


		HANDLE h = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (h == INVALID_HANDLE_VALUE) return NULL;

		STORAGE_PROPERTY_QUERY storagePropertyQuery{};

		storagePropertyQuery.PropertyId = StorageDeviceProperty;
		storagePropertyQuery.QueryType = PropertyStandardQuery;

		STORAGE_DESCRIPTOR_HEADER storageDescriptorHeader{};

		DWORD dwBytesReturned = 0;

		if (!DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY),
			&storageDescriptorHeader, sizeof(STORAGE_DESCRIPTOR_HEADER), &dwBytesReturned, NULL)) {
			CloseHandle(h);
			return NULL;
		}

		const DWORD dwOutBufferSize = storageDescriptorHeader.Size;

		std::unique_ptr<BYTE[]> bufferb{ new BYTE[dwOutBufferSize]{} };

		if (!DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY),
			bufferb.get(), dwOutBufferSize, &dwBytesReturned, NULL)) {
			CloseHandle(h);
			return NULL;
		}

		STORAGE_DEVICE_DESCRIPTOR* pDeviceDescriptor = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(bufferb.get());

		const DWORD dwSerialNumberOffset = pDeviceDescriptor->SerialNumberOffset;
		const DWORD dwProductIdOffset = pDeviceDescriptor->ProductIdOffset;

		if (dwProductIdOffset == 0) return FALSE;

		const char* productId = reinterpret_cast<const char*>(bufferb.get() + dwProductIdOffset);

		out.append(productId);

		HW_PROFILE_INFO hwProfileInfo;

		if (GetCurrentHwProfileA(&hwProfileInfo))
			out.append(hwProfileInfo.szHwProfileGuid);

		CPUID cpuID(0);

		std::string vendor;
		vendor += std::string((const char*)&cpuID.EBX(), 4);
		vendor += std::string((const char*)&cpuID.EDX(), 4);
		vendor += std::string((const char*)&cpuID.ECX(), 4);

		out.append(vendor);

		DWORD disk_serialINT;
		GetVolumeInformationA(NULL, NULL, NULL, &disk_serialINT, NULL, NULL, NULL, NULL);

		out.append(std::to_string(disk_serialINT));

		CloseHandle(h);

		CPPSHA256 sha256;

		return sha256(out).c_str();
	}
 
//antidebug and hwid header library by Manucod

// simple

// header only

// API

CodeGarbage:
//CODEGARBAGEINIT() and CODEGARBAGE();

AntiDebugging:
//AhlIsDebuggerPresent(bool check) // bool will be true if debugger was found

String Obfuscation:
// (beware basic)
// XorStr( s ) 
// XorStrW(s)


///HWID API

void GetHostInfo(std::string& result); // gets Host Info in Plaintext
void GetGUID(std::string& result);// gets hashed Globally Unique Identifier of the current System. 
///
 
/// DISK

Serial


/// CPU

 GHZ

 Cores


/// GRAPHICSCARD

Model Name


/// RAM

Amount (Physical)

/// 
/// MOTHERBOARD
/// not yet
/// 
/// 
/// 


