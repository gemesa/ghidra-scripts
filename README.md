# ghidra-scripts
Collection of my custom Ghidra scripts.

## `UnorderedCallGraphGenerator.java`

<details>

<summary><code>UnorderedCallGraphGenerator.log</code>(current function)</summary>

```
UnorderedCallGraphGenerator.java> Running...
UnorderedCallGraphGenerator.java> 
mw_heap_alloc_w @ 10001390
 HeapAlloc @ EXTERNAL:0000005b
 GetProcessHeap @ EXTERNAL:00000114

UnorderedCallGraphGenerator.java> Finished!
```

</details>

<details>

<summary><code>UnorderedCallGraphGenerator.log</code>(whole program)</summary>

```
UnorderedCallGraphGenerator.java> Running...
UnorderedCallGraphGenerator.java> 
mw_base64_decode @ 10001000
  mw_memset @ 100014a0
  mw_check_base64_char @ 10001320
mw_heap_alloc_w @ 10001390
  HeapAlloc @ EXTERNAL:0000005b
  GetProcessHeap @ EXTERNAL:00000114
mw_heap_free_w @ 100013d0
  HeapFree @ EXTERNAL:00000115
__allshl @ 10001400
__alloca_probe @ 10001420
mw_memcpy @ 10001450
mw_store_failed_cmd @ 100014e0
  lstrcpyA @ EXTERNAL:0000005c
  mw_heap_alloc_w @ 10001390 [already visited!]
mw_base64_decode_and_xor @ 10001560
  mw_base64_decode @ 10001000 [already visited!]
mw_retry_failed_cmd @ 100015c0
  mw_remove_executed_cmd @ 10001980
    mw_heap_free_w @ 100013d0 [already visited!]
  mw_process_pending_cmd @ 10001740
    mw_heap_free_w @ 100013d0 [already visited!]
  mw_execute_cmd @ 10001630
    mw_execute_shellcode_w @ 10001f60
      mw_execute_shellcode @ 10003880
        CreateRemoteThread @ EXTERNAL:0000005f
        VirtualAllocEx @ EXTERNAL:0000012f
        CloseHandle @ EXTERNAL:0000011e
        VirtualAlloc @ EXTERNAL:0000012d
        CreateThread @ EXTERNAL:0000005e
        mw_launch_svchost @ 10002c40
          CreateProcessA @ EXTERNAL:00000120
          mw_memset @ 100014a0 [already visited!]
          lstrcatA @ EXTERNAL:0000005d
          GetEnvironmentVariableA @ EXTERNAL:0000011f
        WriteProcessMemory @ EXTERNAL:00000130
        mw_thread_start_shellcode @ 100039e0
        mw_memcpy @ 10001450 [already visited!]
      mw_download_pe_file @ 10002230
        mw_decrypt_and_decompress @ 10001d40
          RtlDecompressBuffer @ EXTERNAL:00000059
          mw_heap_alloc_w @ 10001390 [already visited!]
          mw_heap_free_w @ 100013d0 [already visited!]
          mw_memcpy @ 10001450 [already visited!]
        mw_extract_next_url @ 10002720
        mw_handle_http_request @ 10001fe0
          InternetSetOptionA @ EXTERNAL:00000054
          mw_open_connection @ 100024f0
            InternetOpenA @ EXTERNAL:0000004e
          mw_memset @ 100014a0 [already visited!]
          InternetQueryOptionA @ EXTERNAL:00000055
          InternetConnectA @ EXTERNAL:00000057
          InternetCrackUrlA @ EXTERNAL:00000052
          HttpOpenRequestA @ EXTERNAL:00000053
          HttpSendRequestA @ EXTERNAL:0000004f
          InternetReadFile @ EXTERNAL:00000056
          InternetCloseHandle @ EXTERNAL:00000050
          HttpQueryInfoA @ EXTERNAL:00000051
        mw_check_custom_signature @ 10002810
        mw_check_pipe_delimiter @ 10002880
        mw_check_mz_header @ 10002b40
      mw_heap_alloc_w @ 10001390 [already visited!]
      mw_heap_free_w @ 100013d0 [already visited!]
    mw_launch_and_inject_svchost_w @ 10001e80
      mw_download_pe_file @ 10002230 [already visited!]
      mw_heap_alloc_w @ 10001390 [already visited!]
      mw_launch_and_inject_svchost @ 10002b80
        GetProcessId @ EXTERNAL:0000011c
        CloseHandle @ EXTERNAL:0000011e [already visited!]
        mw_inject_and_resume @ 100037e0
          mw_memset @ 100014a0 [already visited!]
          WriteProcessMemory @ EXTERNAL:00000130 [already visited!]
          SetThreadContext @ EXTERNAL:00000136
          GetThreadContext @ EXTERNAL:00000135
          ResumeThread @ EXTERNAL:00000137
        mw_launch_svchost @ 10002c40 [already visited!]
        mw_check_mz_header @ 10002b40 [already visited!]
        mw_inject @ 10003270
          FUN_10003a00 @ 10003a00
            FUN_10003470 @ 10003470
            mw_memcpy @ 10001450 [already visited!]
          VirtualAllocEx @ EXTERNAL:0000012f [already visited!]
          mw_heap_alloc_w @ 10001390 [already visited!]
          WriteProcessMemory @ EXTERNAL:00000130 [already visited!]
          VirtualFreeEx @ EXTERNAL:00000131
          mw_heap_free_w @ 100013d0 [already visited!]
        TerminateProcess @ EXTERNAL:0000011d
      mw_heap_free_w @ 100013d0 [already visited!]
    mw_drop_and_execute_w @ 10001ef0
      mw_download_pe_file @ 10002230 [already visited!]
      mw_heap_alloc_w @ 10001390 [already visited!]
      mw_drop_and_execute @ 10003b30
        GetTempPathA @ EXTERNAL:0000013a
        wsprintfA @ EXTERNAL:00000062
        mw_write_to_file @ 10003ac0
          CloseHandle @ EXTERNAL:0000011e [already visited!]
          CreateFileA @ EXTERNAL:00000138
          WriteFile @ EXTERNAL:00000139
        mw_check_if_dll @ 100033c0
        mw_create_process_w @ 100036c0
          CreateProcessA @ EXTERNAL:00000120 [already visited!]
          mw_memset @ 100014a0 [already visited!]
          CloseHandle @ EXTERNAL:0000011e [already visited!]
        GetTempFileNameA @ EXTERNAL:0000013b
      mw_heap_free_w @ 100013d0 [already visited!]
    mw_execute_pe_w @ 10001e00
      mw_download_pe_file @ 10002230 [already visited!]
      mw_execute_pe @ 10003730
        mw_resolve_imports @ 10003580
          GetModuleHandleA @ EXTERNAL:00000132
          GetProcAddress @ EXTERNAL:00000060
          LoadLibraryA @ EXTERNAL:00000134
        CloseHandle @ EXTERNAL:0000011e [already visited!]
        mw_thread_start @ 100039a0
        CreateThread @ EXTERNAL:0000005e [already visited!]
        mw_check_mz_header @ 10002b40 [already visited!]
        mw_map_pe @ 10003180
          FUN_10003a00 @ 10003a00 [already visited!]
          VirtualAlloc @ EXTERNAL:0000012d [already visited!]
          VirtualFree @ EXTERNAL:0000012e
      mw_heap_alloc_w @ 10001390 [already visited!]
      mw_heap_free_w @ 100013d0 [already visited!]
mw_extract_cmd @ 100017b0
mw_main @ 10001870
  mw_check_cmd @ 100027b0
  mw_retry_failed_cmd @ 100015c0 [already visited!]
  mw_extract_cmd @ 100017b0 [already visited!]
  mw_base64_decode_and_xor @ 10001560 [already visited!]
  mw_store_failed_cmd @ 100014e0 [already visited!]
  mw_heap_alloc_w @ 10001390 [already visited!]
  mw_collect_and_send_info @ 10001aa0
    mw_get_domains @ 100023c0
      DsEnumerateDomainTrustsA @ EXTERNAL:00000118
      lstrcatA @ EXTERNAL:0000005d [already visited!]
    mw_parse_c2_urls @ 10002660
      mw_decrypt_config_w @ 100025b0
        mw_decrypt_config @ 10002cd0
          CryptReleaseContext @ EXTERNAL:00000128
          CryptDestroyKey @ EXTERNAL:00000127
          CryptCreateHash @ EXTERNAL:00000122
          CryptAcquireContextA @ EXTERNAL:00000121
          CryptDeriveKey @ EXTERNAL:00000124
          CryptHashData @ EXTERNAL:00000123
          CryptDestroyHash @ EXTERNAL:00000126
          CryptDecrypt @ EXTERNAL:00000125
        mw_heap_alloc_w @ 10001390 [already visited!]
        mw_memcpy @ 10001450 [already visited!]
    mw_heap_alloc_w @ 10001390 [already visited!]
    GetVersion @ EXTERNAL:00000117
    mw_get_system_info_w @ 10003400
      GetModuleHandleA @ EXTERNAL:00000132 [already visited!]
      mw_memset @ 100014a0 [already visited!]
      GetProcAddress @ EXTERNAL:00000060 [already visited!]
      GetSystemInfo @ EXTERNAL:00000133
    mw_get_computer_and_username @ 100030f0
      GetComputerNameA @ EXTERNAL:0000005a
      mw_get_username @ 10002df0
        lstrcpyA @ EXTERNAL:0000005c [already visited!]
        mw_get_process_username @ 10003000
          OpenProcessToken @ EXTERNAL:0000012a
          GetLastError @ EXTERNAL:0000012c
          LookupAccountSidA @ EXTERNAL:00000063
          mw_heap_alloc_w @ 10001390 [already visited!]
          GetTokenInformation @ EXTERNAL:0000012b
          OpenProcess @ EXTERNAL:00000129
          mw_heap_free_w @ 100013d0 [already visited!]
        mw_get_pid_by_name @ 10002e90
          mw_get_process_file_name @ 10002f30
            lstrcpyA @ EXTERNAL:0000005c [already visited!]
            CloseHandle @ EXTERNAL:0000011e [already visited!]
            K32GetProcessImageFileNameA @ 10003be3
              K32GetProcessImageFileNameA @ EXTERNAL:000000be [already visited!]
            OpenProcess @ EXTERNAL:00000129 [already visited!]
          __alloca_probe @ 10001420 [already visited!]
          K32EnumProcesses @ 10003bdd
            K32EnumProcesses @ EXTERNAL:000000bc [already visited!]
          lstrcmpiA @ EXTERNAL:00000061
        lstrcatA @ EXTERNAL:0000005d [already visited!]
      lstrcatA @ EXTERNAL:0000005d [already visited!]
    wsprintfA @ EXTERNAL:00000062 [already visited!]
    mw_decrypt_config_w @ 100025b0 [already visited!]
    mw_get_mac_and_volume_sn_w @ 10002630
      mw_get_mac_and_volume_sn @ 10001c70
        mw_memset @ 100014a0 [already visited!]
        __allshl @ 10001400 [already visited!]
        mw_get_volume_serial_number @ 10002490
          GetVolumeInformationA @ EXTERNAL:0000011a
          GetWindowsDirectoryA @ EXTERNAL:00000119
        GetAdaptersAddresses @ EXTERNAL:00000058
        mw_heap_alloc_w @ 10001390 [already visited!]
        mw_heap_free_w @ 100013d0 [already visited!]
        mw_memcpy @ 10001450 [already visited!]
    __alloca_probe @ 10001420 [already visited!]
    mw_check_pattern @ 10001a00
      mw_is_uppercase @ 100028b0
    mw_handle_http_request_with_header @ 100028d0
      InternetSetOptionA @ EXTERNAL:00000054 [already visited!]
      mw_open_connection @ 100024f0 [already visited!]
      mw_memset @ 100014a0 [already visited!]
      InternetQueryOptionA @ EXTERNAL:00000055 [already visited!]
      InternetConnectA @ EXTERNAL:00000057 [already visited!]
      lstrlenA @ EXTERNAL:0000011b
      InternetCrackUrlA @ EXTERNAL:00000052 [already visited!]
      HttpOpenRequestA @ EXTERNAL:00000053 [already visited!]
      HttpSendRequestA @ EXTERNAL:0000004f [already visited!]
      InternetReadFile @ EXTERNAL:00000056 [already visited!]
      InternetCloseHandle @ EXTERNAL:00000050 [already visited!]
      HttpQueryInfoA @ EXTERNAL:00000051 [already visited!]
    mw_get_public_ip_w @ 10002520
      lstrcpyA @ EXTERNAL:0000005c [already visited!]
      mw_handle_http_request @ 10001fe0 [already visited!]
  mw_execute_cmd @ 10001630 [already visited!]
  Sleep @ EXTERNAL:00000116
entry @ 100019d0
FCQNEAXPXCR @ 100019e0
  mw_main @ 10001870 [already visited!]

UnorderedCallGraphGenerator.java> Finished!

```
</details>

## `OrderedCallGraphGenerator.java`

<details>

<summary><code>OrderedCallGraphGenerator.log</code>(current function)</summary>

```
OrderedCallGraphGenerator.java> Running...
OrderedCallGraphGenerator.java> 
mw_heap_alloc_w @ 10001390
  GetProcessHeap @ EXTERNAL:00000114
  HeapAlloc @ EXTERNAL:0000005b

OrderedCallGraphGenerator.java> Finished!
```

</details>

<details>

<summary><code>OrderedCallGraphGenerator.log</code>(whole program)</summary>

```
OrderedCallGraphGenerator.java> Running...
OrderedCallGraphGenerator.java>
mw_base64_decode @ 10001000
  mw_memset @ 100014a0
  mw_check_base64_char @ 10001320
mw_heap_alloc_w @ 10001390
  GetProcessHeap @ EXTERNAL:00000114
  HeapAlloc @ EXTERNAL:0000005b
mw_heap_free_w @ 100013d0
  HeapFree @ EXTERNAL:00000115
__allshl @ 10001400
__alloca_probe @ 10001420
mw_memcpy @ 10001450
mw_store_failed_cmd @ 100014e0
  mw_heap_alloc_w @ 10001390 [already visited!]
  lstrcpyA @ EXTERNAL:0000005c
mw_base64_decode_and_xor @ 10001560
  mw_base64_decode @ 10001000 [already visited!]
mw_retry_failed_cmd @ 100015c0
  mw_process_pending_cmd @ 10001740
    mw_heap_free_w @ 100013d0 [already visited!]
  mw_execute_cmd @ 10001630
    mw_drop_and_execute_w @ 10001ef0
      mw_heap_alloc_w @ 10001390 [already visited!]
      mw_download_pe_file @ 10002230
        mw_check_pipe_delimiter @ 10002880
        mw_handle_http_request @ 10001fe0
          mw_memset @ 100014a0 [already visited!]
          InternetCrackUrlA @ EXTERNAL:00000052
          mw_open_connection @ 100024f0
            InternetOpenA @ EXTERNAL:0000004e
          InternetConnectA @ EXTERNAL:00000057
          HttpOpenRequestA @ EXTERNAL:00000053
          InternetCloseHandle @ EXTERNAL:00000050
          InternetQueryOptionA @ EXTERNAL:00000055
          InternetSetOptionA @ EXTERNAL:00000054
          HttpSendRequestA @ EXTERNAL:0000004f
          HttpQueryInfoA @ EXTERNAL:00000051
          InternetReadFile @ EXTERNAL:00000056
        mw_check_custom_signature @ 10002810
        mw_decrypt_and_decompress @ 10001d40
          mw_heap_alloc_w @ 10001390 [already visited!]
          RtlDecompressBuffer @ EXTERNAL:00000059
          mw_memcpy @ 10001450 [already visited!]
          mw_heap_free_w @ 100013d0 [already visited!]
        mw_check_mz_header @ 10002b40
        mw_extract_next_url @ 10002720
      mw_drop_and_execute @ 10003b30
        GetTempPathA @ EXTERNAL:0000013a
        GetTempFileNameA @ EXTERNAL:0000013b
        mw_write_to_file @ 10003ac0
          CreateFileA @ EXTERNAL:00000138
          WriteFile @ EXTERNAL:00000139
          CloseHandle @ EXTERNAL:0000011e
        mw_check_if_dll @ 100033c0
        wsprintfA @ EXTERNAL:00000062
        mw_create_process_w @ 100036c0
          mw_memset @ 100014a0 [already visited!]
          CreateProcessA @ EXTERNAL:00000120
          CloseHandle @ EXTERNAL:0000011e [already visited!]
      mw_heap_free_w @ 100013d0 [already visited!]
    mw_execute_shellcode_w @ 10001f60
      mw_heap_alloc_w @ 10001390 [already visited!]
      mw_download_pe_file @ 10002230 [already visited!]
      mw_execute_shellcode @ 10003880
        mw_launch_svchost @ 10002c40
          mw_memset @ 100014a0 [already visited!]
          GetEnvironmentVariableA @ EXTERNAL:0000011f
          lstrcatA @ EXTERNAL:0000005d
          CreateProcessA @ EXTERNAL:00000120 [already visited!]
        VirtualAllocEx @ EXTERNAL:0000012f
        WriteProcessMemory @ EXTERNAL:00000130
        CreateRemoteThread @ EXTERNAL:0000005f
        CloseHandle @ EXTERNAL:0000011e [already visited!]
        VirtualAlloc @ EXTERNAL:0000012d
        mw_memcpy @ 10001450 [already visited!]
        mw_thread_start_shellcode @ 100039e0
        CreateThread @ EXTERNAL:0000005e
      mw_heap_free_w @ 100013d0 [already visited!]
    mw_execute_pe_w @ 10001e00
      mw_heap_alloc_w @ 10001390 [already visited!]
      mw_download_pe_file @ 10002230 [already visited!]
      mw_execute_pe @ 10003730
        mw_check_mz_header @ 10002b40 [already visited!]
        mw_map_pe @ 10003180
          VirtualAlloc @ EXTERNAL:0000012d [already visited!]
          FUN_10003a00 @ 10003a00
            mw_memcpy @ 10001450 [already visited!]
            FUN_10003470 @ 10003470
          VirtualFree @ EXTERNAL:0000012e
        mw_resolve_imports @ 10003580
          GetModuleHandleA @ EXTERNAL:00000132
          LoadLibraryA @ EXTERNAL:00000134
          GetProcAddress @ EXTERNAL:00000060
        mw_thread_start @ 100039a0
        CreateThread @ EXTERNAL:0000005e [already visited!]
        CloseHandle @ EXTERNAL:0000011e [already visited!]
      mw_heap_free_w @ 100013d0 [already visited!]
    mw_launch_and_inject_svchost_w @ 10001e80
      mw_heap_alloc_w @ 10001390 [already visited!]
      mw_download_pe_file @ 10002230 [already visited!]
      mw_launch_and_inject_svchost @ 10002b80
        mw_check_mz_header @ 10002b40 [already visited!]
        mw_launch_svchost @ 10002c40 [already visited!]
        mw_inject @ 10003270
          VirtualAllocEx @ EXTERNAL:0000012f [already visited!]
          mw_heap_alloc_w @ 10001390 [already visited!]
          FUN_10003a00 @ 10003a00 [already visited!]
          WriteProcessMemory @ EXTERNAL:00000130 [already visited!]
          mw_heap_free_w @ 100013d0 [already visited!]
          VirtualFreeEx @ EXTERNAL:00000131
        mw_inject_and_resume @ 100037e0
          mw_memset @ 100014a0 [already visited!]
          GetThreadContext @ EXTERNAL:00000135
          WriteProcessMemory @ EXTERNAL:00000130 [already visited!]
          SetThreadContext @ EXTERNAL:00000136
          ResumeThread @ EXTERNAL:00000137
        GetProcessId @ EXTERNAL:0000011c
        TerminateProcess @ EXTERNAL:0000011d
        CloseHandle @ EXTERNAL:0000011e [already visited!]
      mw_heap_free_w @ 100013d0 [already visited!]
  mw_remove_executed_cmd @ 10001980
    mw_heap_free_w @ 100013d0 [already visited!]
mw_extract_cmd @ 100017b0
mw_main @ 10001870
  mw_heap_alloc_w @ 10001390 [already visited!]
  mw_collect_and_send_info @ 10001aa0
    __alloca_probe @ 10001420 [already visited!]
    GetVersion @ EXTERNAL:00000117
    mw_get_mac_and_volume_sn_w @ 10002630
      mw_get_mac_and_volume_sn @ 10001c70
        mw_heap_alloc_w @ 10001390 [already visited!]
        GetAdaptersAddresses @ EXTERNAL:00000058
        mw_memset @ 100014a0 [already visited!]
        mw_memcpy @ 10001450 [already visited!]
        mw_heap_free_w @ 100013d0 [already visited!]
        mw_get_volume_serial_number @ 10002490
          GetWindowsDirectoryA @ EXTERNAL:00000119
          GetVolumeInformationA @ EXTERNAL:0000011a
        __allshl @ 10001400 [already visited!]
    mw_get_computer_and_username @ 100030f0
      GetComputerNameA @ EXTERNAL:0000005a
      lstrcatA @ EXTERNAL:0000005d [already visited!]
      mw_get_username @ 10002df0
        mw_get_pid_by_name @ 10002e90
          __alloca_probe @ 10001420 [already visited!]
          K32EnumProcesses @ 10003bdd
            K32EnumProcesses @ EXTERNAL:000000bc [already visited!]
          mw_get_process_file_name @ 10002f30
            OpenProcess @ EXTERNAL:00000129
            K32GetProcessImageFileNameA @ 10003be3
              K32GetProcessImageFileNameA @ EXTERNAL:000000be [already visited!]
            CloseHandle @ EXTERNAL:0000011e [already visited!]
            lstrcpyA @ EXTERNAL:0000005c [already visited!]
          lstrcmpiA @ EXTERNAL:00000061
        mw_get_process_username @ 10003000
          OpenProcess @ EXTERNAL:00000129 [already visited!]
          OpenProcessToken @ EXTERNAL:0000012a
          GetTokenInformation @ EXTERNAL:0000012b
          GetLastError @ EXTERNAL:0000012c
          mw_heap_alloc_w @ 10001390 [already visited!]
          LookupAccountSidA @ EXTERNAL:00000063
          mw_heap_free_w @ 100013d0 [already visited!]
        lstrcpyA @ EXTERNAL:0000005c [already visited!]
        lstrcatA @ EXTERNAL:0000005d [already visited!]
    mw_get_public_ip_w @ 10002520
      lstrcpyA @ EXTERNAL:0000005c [already visited!]
      mw_handle_http_request @ 10001fe0 [already visited!]
    mw_get_domains @ 100023c0
      DsEnumerateDomainTrustsA @ EXTERNAL:00000118
      lstrcatA @ EXTERNAL:0000005d [already visited!]
    mw_get_system_info_w @ 10003400
      mw_memset @ 100014a0 [already visited!]
      GetModuleHandleA @ EXTERNAL:00000132 [already visited!]
      GetProcAddress @ EXTERNAL:00000060 [already visited!]
      GetSystemInfo @ EXTERNAL:00000133
    mw_decrypt_config_w @ 100025b0
      mw_heap_alloc_w @ 10001390 [already visited!]
      mw_memcpy @ 10001450 [already visited!]
      mw_decrypt_config @ 10002cd0
        CryptAcquireContextA @ EXTERNAL:00000121
        CryptCreateHash @ EXTERNAL:00000122
        CryptHashData @ EXTERNAL:00000123
        CryptDeriveKey @ EXTERNAL:00000124
        CryptDecrypt @ EXTERNAL:00000125
        CryptDestroyHash @ EXTERNAL:00000126
        CryptDestroyKey @ EXTERNAL:00000127
        CryptReleaseContext @ EXTERNAL:00000128
    wsprintfA @ EXTERNAL:00000062 [already visited!]
    mw_heap_alloc_w @ 10001390 [already visited!]
    mw_parse_c2_urls @ 10002660
      mw_decrypt_config_w @ 100025b0 [already visited!]
    mw_handle_http_request_with_header @ 100028d0
      mw_memset @ 100014a0 [already visited!]
      lstrlenA @ EXTERNAL:0000011b
      InternetCrackUrlA @ EXTERNAL:00000052 [already visited!]
      mw_open_connection @ 100024f0 [already visited!]
      InternetConnectA @ EXTERNAL:00000057 [already visited!]
      HttpOpenRequestA @ EXTERNAL:00000053 [already visited!]
      InternetCloseHandle @ EXTERNAL:00000050 [already visited!]
      InternetQueryOptionA @ EXTERNAL:00000055 [already visited!]
      InternetSetOptionA @ EXTERNAL:00000054 [already visited!]
      HttpSendRequestA @ EXTERNAL:0000004f [already visited!]
      HttpQueryInfoA @ EXTERNAL:00000051 [already visited!]
      InternetReadFile @ EXTERNAL:00000056 [already visited!]
    mw_check_pattern @ 10001a00
      mw_is_uppercase @ 100028b0
  mw_base64_decode_and_xor @ 10001560 [already visited!]
  mw_extract_cmd @ 100017b0 [already visited!]
  mw_check_cmd @ 100027b0
  mw_execute_cmd @ 10001630 [already visited!]
  mw_store_failed_cmd @ 100014e0 [already visited!]
  Sleep @ EXTERNAL:00000116
  mw_retry_failed_cmd @ 100015c0 [already visited!]
entry @ 100019d0
FCQNEAXPXCR @ 100019e0
  mw_main @ 10001870 [already visited!]

OrderedCallGraphGenerator.java> Finished!

```
</details>
