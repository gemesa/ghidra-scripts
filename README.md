# ghidra-scripts
Collection of my custom Ghidra scripts.

## `HancitorConfigExtractor.java`

<details>

<summary><code>HancitorConfigExtractor.log</code></summary>

```
HancitorConfigExtractor.java> Running...
HancitorConfigExtractor.java> key address: 0x10005010
HancitorConfigExtractor.java> data address: 0x10005018
HancitorConfigExtractor.java> key data: 0xf0da08fe225d0a8f
HancitorConfigExtractor.java> derived key: 0x67f6c6259f
HancitorConfigExtractor.java> decrypted config: 2508_bqplf......http://intakinger.com/8/forum.php|http://idgentexpliet.ru/8/forum.php|http://declassivan.ru/8/forum.php|........................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................
HancitorConfigExtractor.java> Finished!
```

</details>

## `HancitorConfigExtractor2.java`

<details>

<summary><code>HancitorConfigExtractor2.log</code></summary>

```
HancitorConfigExtractor2.java> Running...
HancitorConfigExtractor2.java> key address: 0x10005010
HancitorConfigExtractor2.java> data address: 0x10005018
HancitorConfigExtractor2.java> key data: 0xf0da08fe225d0a8f
HancitorConfigExtractor2.java> derived key: 0x67f6c6259f
HancitorConfigExtractor2.java> decrypted config: 2508_bqplf......http://intakinger.com/8/forum.php|http://idgentexpliet.ru/8/forum.php|http://declassivan.ru/8/forum.php|........................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................
HancitorConfigExtractor2.java> Finished!
```

</details>

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
        mw_memcpy @ 10001450 [already visited!]
        CreateRemoteThread @ EXTERNAL:0000005f
        mw_launch_svchost @ 10002c40
          CreateProcessA @ EXTERNAL:00000120
          mw_memset @ 100014a0 [already visited!]
          lstrcatA @ EXTERNAL:0000005d
          GetEnvironmentVariableA @ EXTERNAL:0000011f
        VirtualAllocEx @ EXTERNAL:0000012f
        mw_thread_start_shellcode @ 100039e0
        WriteProcessMemory @ EXTERNAL:00000130
        CloseHandle @ EXTERNAL:0000011e
        CreateThread @ EXTERNAL:0000005e
        VirtualAlloc @ EXTERNAL:0000012d
      mw_download_pe_file @ 10002230
        mw_check_mz_header @ 10002b40
        mw_handle_http_request @ 10001fe0
          HttpSendRequestA @ EXTERNAL:0000004f
          InternetQueryOptionA @ EXTERNAL:00000055
          InternetReadFile @ EXTERNAL:00000056
          HttpOpenRequestA @ EXTERNAL:00000053
          HttpQueryInfoA @ EXTERNAL:00000051
          mw_memset @ 100014a0 [already visited!]
          InternetSetOptionA @ EXTERNAL:00000054
          InternetCrackUrlA @ EXTERNAL:00000052
          InternetConnectA @ EXTERNAL:00000057
          mw_open_connection @ 100024f0
            InternetOpenA @ EXTERNAL:0000004e
          InternetCloseHandle @ EXTERNAL:00000050
        mw_extract_next_url @ 10002720
        mw_check_custom_signature @ 10002810
        mw_check_pipe_delimiter @ 10002880
        mw_decrypt_and_decompress @ 10001d40
          mw_memcpy @ 10001450 [already visited!]
          mw_heap_free_w @ 100013d0 [already visited!]
          RtlDecompressBuffer @ EXTERNAL:00000059
          mw_heap_alloc_w @ 10001390 [already visited!]
      mw_heap_free_w @ 100013d0 [already visited!]
      mw_heap_alloc_w @ 10001390 [already visited!]
    mw_launch_and_inject_svchost_w @ 10001e80
      mw_heap_free_w @ 100013d0 [already visited!]
      mw_download_pe_file @ 10002230 [already visited!]
      mw_heap_alloc_w @ 10001390 [already visited!]
      mw_launch_and_inject_svchost @ 10002b80
        mw_inject_and_resume @ 100037e0
          GetThreadContext @ EXTERNAL:00000135
          mw_memset @ 100014a0 [already visited!]
          ResumeThread @ EXTERNAL:00000137
          WriteProcessMemory @ EXTERNAL:00000130
          SetThreadContext @ EXTERNAL:00000136
        mw_check_mz_header @ 10002b40 [already visited!]
        GetProcessId @ EXTERNAL:0000011c
        TerminateProcess @ EXTERNAL:0000011d
        mw_launch_svchost @ 10002c40 [already visited!]
        CloseHandle @ EXTERNAL:0000011e
        mw_inject @ 10003270
          mw_heap_free_w @ 100013d0 [already visited!]
          VirtualFreeEx @ EXTERNAL:00000131
          VirtualAllocEx @ EXTERNAL:0000012f
          FUN_10003a00 @ 10003a00
            mw_memcpy @ 10001450 [already visited!]
            FUN_10003470 @ 10003470
          mw_heap_alloc_w @ 10001390 [already visited!]
          WriteProcessMemory @ EXTERNAL:00000130
    mw_drop_and_execute_w @ 10001ef0
      mw_heap_free_w @ 100013d0 [already visited!]
      mw_download_pe_file @ 10002230 [already visited!]
      mw_drop_and_execute @ 10003b30
        wsprintfA @ EXTERNAL:00000062
        mw_check_if_dll @ 100033c0
        mw_write_to_file @ 10003ac0
          CloseHandle @ EXTERNAL:0000011e
          WriteFile @ EXTERNAL:00000139
          CreateFileA @ EXTERNAL:00000138
        GetTempFileNameA @ EXTERNAL:0000013b
        GetTempPathA @ EXTERNAL:0000013a
        mw_create_process_w @ 100036c0
          CreateProcessA @ EXTERNAL:00000120
          mw_memset @ 100014a0 [already visited!]
          CloseHandle @ EXTERNAL:0000011e
      mw_heap_alloc_w @ 10001390 [already visited!]
    mw_execute_pe_w @ 10001e00
      mw_download_pe_file @ 10002230 [already visited!]
      mw_execute_pe @ 10003730
        mw_thread_start @ 100039a0
        mw_check_mz_header @ 10002b40 [already visited!]
        CloseHandle @ EXTERNAL:0000011e
        CreateThread @ EXTERNAL:0000005e
        mw_map_pe @ 10003180
          FUN_10003a00 @ 10003a00 [already visited!]
          VirtualFree @ EXTERNAL:0000012e
          VirtualAlloc @ EXTERNAL:0000012d
        mw_resolve_imports @ 10003580
          GetModuleHandleA @ EXTERNAL:00000132
          LoadLibraryA @ EXTERNAL:00000134
          GetProcAddress @ EXTERNAL:00000060
      mw_heap_free_w @ 100013d0 [already visited!]
      mw_heap_alloc_w @ 10001390 [already visited!]
mw_extract_cmd @ 100017b0
mw_main @ 10001870
  mw_collect_and_send_info @ 10001aa0
    mw_check_pattern @ 10001a00
      mw_is_uppercase @ 100028b0
    mw_handle_http_request_with_header @ 100028d0
      HttpSendRequestA @ EXTERNAL:0000004f
      InternetQueryOptionA @ EXTERNAL:00000055
      InternetReadFile @ EXTERNAL:00000056
      lstrlenA @ EXTERNAL:0000011b
      HttpOpenRequestA @ EXTERNAL:00000053
      HttpQueryInfoA @ EXTERNAL:00000051
      mw_memset @ 100014a0 [already visited!]
      InternetSetOptionA @ EXTERNAL:00000054
      InternetCrackUrlA @ EXTERNAL:00000052
      InternetConnectA @ EXTERNAL:00000057
      mw_open_connection @ 100024f0 [already visited!]
      InternetCloseHandle @ EXTERNAL:00000050
    mw_decrypt_config_w @ 100025b0
      mw_memcpy @ 10001450 [already visited!]
      mw_decrypt_config @ 10002cd0
        CryptDestroyKey @ EXTERNAL:00000127
        CryptAcquireContextA @ EXTERNAL:00000121
        CryptDeriveKey @ EXTERNAL:00000124
        CryptCreateHash @ EXTERNAL:00000122
        CryptHashData @ EXTERNAL:00000123
        CryptDestroyHash @ EXTERNAL:00000126
        CryptDecrypt @ EXTERNAL:00000125
        CryptReleaseContext @ EXTERNAL:00000128
      mw_heap_alloc_w @ 10001390 [already visited!]
    mw_get_public_ip_w @ 10002520
      lstrcpyA @ EXTERNAL:0000005c
      mw_handle_http_request @ 10001fe0 [already visited!]
    mw_get_system_info_w @ 10003400
      GetModuleHandleA @ EXTERNAL:00000132
      GetSystemInfo @ EXTERNAL:00000133
      mw_memset @ 100014a0 [already visited!]
      GetProcAddress @ EXTERNAL:00000060
    mw_heap_alloc_w @ 10001390 [already visited!]
    mw_get_id_from_mac_and_vsn_w @ 10002630
      mw_get_id_from_mac_and_vsn @ 10001c70
        mw_memcpy @ 10001450 [already visited!]
        mw_heap_free_w @ 100013d0 [already visited!]
        mw_memset @ 100014a0 [already visited!]
        __allshl @ 10001400 [already visited!]
        mw_heap_alloc_w @ 10001390 [already visited!]
        mw_get_volume_serial_number @ 10002490
          GetVolumeInformationA @ EXTERNAL:0000011a
          GetWindowsDirectoryA @ EXTERNAL:00000119
        GetAdaptersAddresses @ EXTERNAL:00000058
    wsprintfA @ EXTERNAL:00000062
    mw_get_computer_and_username @ 100030f0
      lstrcatA @ EXTERNAL:0000005d
      GetComputerNameA @ EXTERNAL:0000005a
      mw_get_username @ 10002df0
        lstrcpyA @ EXTERNAL:0000005c
        mw_get_pid_by_name @ 10002e90
          lstrcmpiA @ EXTERNAL:00000061
          __alloca_probe @ 10001420 [already visited!]
          mw_get_process_file_name @ 10002f30
            lstrcpyA @ EXTERNAL:0000005c
            CloseHandle @ EXTERNAL:0000011e
            OpenProcess @ EXTERNAL:00000129
            K32GetProcessImageFileNameA @ 10003be3
              K32GetProcessImageFileNameA @ EXTERNAL:000000be
          K32EnumProcesses @ 10003bdd
            K32EnumProcesses @ EXTERNAL:000000bc
        lstrcatA @ EXTERNAL:0000005d
        mw_get_process_username @ 10003000
          GetTokenInformation @ EXTERNAL:0000012b
          mw_heap_free_w @ 100013d0 [already visited!]
          mw_heap_alloc_w @ 10001390 [already visited!]
          LookupAccountSidA @ EXTERNAL:00000063
          OpenProcess @ EXTERNAL:00000129
          OpenProcessToken @ EXTERNAL:0000012a
          GetLastError @ EXTERNAL:0000012c
    mw_parse_c2_urls @ 10002660
      mw_decrypt_config_w @ 100025b0 [already visited!]
    mw_get_domains @ 100023c0
      lstrcatA @ EXTERNAL:0000005d
      DsEnumerateDomainTrustsA @ EXTERNAL:00000118
    __alloca_probe @ 10001420 [already visited!]
    GetVersion @ EXTERNAL:00000117
  mw_check_cmd @ 100027b0
  mw_heap_alloc_w @ 10001390 [already visited!]
  Sleep @ EXTERNAL:00000116
  mw_retry_failed_cmd @ 100015c0 [already visited!]
  mw_base64_decode_and_xor @ 10001560 [already visited!]
  mw_execute_cmd @ 10001630 [already visited!]
  mw_extract_cmd @ 100017b0 [already visited!]
  mw_store_failed_cmd @ 100014e0 [already visited!]
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
          CloseHandle @ EXTERNAL:0000011e
      mw_heap_free_w @ 100013d0 [already visited!]
    mw_execute_shellcode_w @ 10001f60
      mw_heap_alloc_w @ 10001390 [already visited!]
      mw_download_pe_file @ 10002230 [already visited!]
      mw_execute_shellcode @ 10003880
        mw_launch_svchost @ 10002c40
          mw_memset @ 100014a0 [already visited!]
          GetEnvironmentVariableA @ EXTERNAL:0000011f
          lstrcatA @ EXTERNAL:0000005d
          CreateProcessA @ EXTERNAL:00000120
        VirtualAllocEx @ EXTERNAL:0000012f
        WriteProcessMemory @ EXTERNAL:00000130
        CreateRemoteThread @ EXTERNAL:0000005f
        CloseHandle @ EXTERNAL:0000011e
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
          VirtualAlloc @ EXTERNAL:0000012d
          FUN_10003a00 @ 10003a00
            mw_memcpy @ 10001450 [already visited!]
            FUN_10003470 @ 10003470
          VirtualFree @ EXTERNAL:0000012e
        mw_resolve_imports @ 10003580
          GetModuleHandleA @ EXTERNAL:00000132
          LoadLibraryA @ EXTERNAL:00000134
          GetProcAddress @ EXTERNAL:00000060
        mw_thread_start @ 100039a0
        CreateThread @ EXTERNAL:0000005e
        CloseHandle @ EXTERNAL:0000011e
      mw_heap_free_w @ 100013d0 [already visited!]
    mw_launch_and_inject_svchost_w @ 10001e80
      mw_heap_alloc_w @ 10001390 [already visited!]
      mw_download_pe_file @ 10002230 [already visited!]
      mw_launch_and_inject_svchost @ 10002b80
        mw_check_mz_header @ 10002b40 [already visited!]
        mw_launch_svchost @ 10002c40 [already visited!]
        mw_inject @ 10003270
          VirtualAllocEx @ EXTERNAL:0000012f
          mw_heap_alloc_w @ 10001390 [already visited!]
          FUN_10003a00 @ 10003a00 [already visited!]
          WriteProcessMemory @ EXTERNAL:00000130
          mw_heap_free_w @ 100013d0 [already visited!]
          VirtualFreeEx @ EXTERNAL:00000131
        mw_inject_and_resume @ 100037e0
          mw_memset @ 100014a0 [already visited!]
          GetThreadContext @ EXTERNAL:00000135
          WriteProcessMemory @ EXTERNAL:00000130
          SetThreadContext @ EXTERNAL:00000136
          ResumeThread @ EXTERNAL:00000137
        GetProcessId @ EXTERNAL:0000011c
        TerminateProcess @ EXTERNAL:0000011d
        CloseHandle @ EXTERNAL:0000011e
      mw_heap_free_w @ 100013d0 [already visited!]
  mw_remove_executed_cmd @ 10001980
    mw_heap_free_w @ 100013d0 [already visited!]
mw_extract_cmd @ 100017b0
mw_main @ 10001870
  mw_heap_alloc_w @ 10001390 [already visited!]
  mw_collect_and_send_info @ 10001aa0
    __alloca_probe @ 10001420 [already visited!]
    GetVersion @ EXTERNAL:00000117
    mw_get_id_from_mac_and_vsn_w @ 10002630
      mw_get_id_from_mac_and_vsn @ 10001c70
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
      lstrcatA @ EXTERNAL:0000005d
      mw_get_username @ 10002df0
        mw_get_pid_by_name @ 10002e90
          __alloca_probe @ 10001420 [already visited!]
          K32EnumProcesses @ 10003bdd
            K32EnumProcesses @ EXTERNAL:000000bc
          mw_get_process_file_name @ 10002f30
            OpenProcess @ EXTERNAL:00000129
            K32GetProcessImageFileNameA @ 10003be3
              K32GetProcessImageFileNameA @ EXTERNAL:000000be
            CloseHandle @ EXTERNAL:0000011e
            lstrcpyA @ EXTERNAL:0000005c
          lstrcmpiA @ EXTERNAL:00000061
        mw_get_process_username @ 10003000
          OpenProcess @ EXTERNAL:00000129
          OpenProcessToken @ EXTERNAL:0000012a
          GetTokenInformation @ EXTERNAL:0000012b
          GetLastError @ EXTERNAL:0000012c
          mw_heap_alloc_w @ 10001390 [already visited!]
          LookupAccountSidA @ EXTERNAL:00000063
          mw_heap_free_w @ 100013d0 [already visited!]
        lstrcpyA @ EXTERNAL:0000005c
        lstrcatA @ EXTERNAL:0000005d
    mw_get_public_ip_w @ 10002520
      lstrcpyA @ EXTERNAL:0000005c
      mw_handle_http_request @ 10001fe0 [already visited!]
    mw_get_domains @ 100023c0
      DsEnumerateDomainTrustsA @ EXTERNAL:00000118
      lstrcatA @ EXTERNAL:0000005d
    mw_get_system_info_w @ 10003400
      mw_memset @ 100014a0 [already visited!]
      GetModuleHandleA @ EXTERNAL:00000132
      GetProcAddress @ EXTERNAL:00000060
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
    wsprintfA @ EXTERNAL:00000062
    mw_heap_alloc_w @ 10001390 [already visited!]
    mw_parse_c2_urls @ 10002660
      mw_decrypt_config_w @ 100025b0 [already visited!]
    mw_handle_http_request_with_header @ 100028d0
      mw_memset @ 100014a0 [already visited!]
      lstrlenA @ EXTERNAL:0000011b
      InternetCrackUrlA @ EXTERNAL:00000052
      mw_open_connection @ 100024f0 [already visited!]
      InternetConnectA @ EXTERNAL:00000057
      HttpOpenRequestA @ EXTERNAL:00000053
      InternetCloseHandle @ EXTERNAL:00000050
      InternetQueryOptionA @ EXTERNAL:00000055
      InternetSetOptionA @ EXTERNAL:00000054
      HttpSendRequestA @ EXTERNAL:0000004f
      HttpQueryInfoA @ EXTERNAL:00000051
      InternetReadFile @ EXTERNAL:00000056
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
