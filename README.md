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

Alternatively, you can use the following action: `Function Call Trees` → `Outgoing Calls` → `Copy Formatted`. For more information, see https://github.com/NationalSecurityAgency/ghidra/issues/7417.

## `MiraiCredentialExtractorSORA.java`

<details>

<summary><code>MiraiCredentialExtractorSORA.log</code></summary>

```
MiraiCredentialExtractorSORA.java> Running...
MiraiCredentialExtractorSORA.java> located decryption function: mw_decrypt
MiraiCredentialExtractorSORA.java> "$??"P" : ""??$P"
MiraiCredentialExtractorSORA.java> ""??$P" : "$??"P"
MiraiCredentialExtractorSORA.java> "$??"P" : "null"
MiraiCredentialExtractorSORA.java> "$??"P" : ""
MiraiCredentialExtractorSORA.java> "default" : ""
MiraiCredentialExtractorSORA.java> "default" : "null"
MiraiCredentialExtractorSORA.java> "default" : "altslq"
MiraiCredentialExtractorSORA.java> "default" : "OxhlwSG8"
MiraiCredentialExtractorSORA.java> "default" : "tlJwpbo6"
MiraiCredentialExtractorSORA.java> "default" : "S2fGqNFs"
MiraiCredentialExtractorSORA.java> "root" : "xc3551"
MiraiCredentialExtractorSORA.java> "root" : "vizxv"
MiraiCredentialExtractorSORA.java> "root" : "klv123"
MiraiCredentialExtractorSORA.java> "root" : "admin"
MiraiCredentialExtractorSORA.java> "root" : "zyad1234"
MiraiCredentialExtractorSORA.java> "root" : "zlxx."
MiraiCredentialExtractorSORA.java> "root" : "default"
MiraiCredentialExtractorSORA.java> "root" : "7ujMko0vizxv"
MiraiCredentialExtractorSORA.java> "root" : "7ujMko0admin"
MiraiCredentialExtractorSORA.java> "root" : "hi3518"
MiraiCredentialExtractorSORA.java> "root" : "cat1029"
MiraiCredentialExtractorSORA.java> "root" : "annie2012"
MiraiCredentialExtractorSORA.java> "root" : "changeme"
MiraiCredentialExtractorSORA.java> "guest" : ""
MiraiCredentialExtractorSORA.java> "guest" : "null"
MiraiCredentialExtractorSORA.java> "guest" : "12345z"
MiraiCredentialExtractorSORA.java> "guest" : "123456"
MiraiCredentialExtractorSORA.java> "user" : ""
MiraiCredentialExtractorSORA.java> "user" : "null"
MiraiCredentialExtractorSORA.java> "user" : "123456"
MiraiCredentialExtractorSORA.java> "admin" : ""
MiraiCredentialExtractorSORA.java> "admin" : "null"
MiraiCredentialExtractorSORA.java> "admin" : "pass"
MiraiCredentialExtractorSORA.java> "admin" : "password"
MiraiCredentialExtractorSORA.java> "admin" : "admin1234"
MiraiCredentialExtractorSORA.java> "support" : "null"
MiraiCredentialExtractorSORA.java> "mg3500" : "merlin"
MiraiCredentialExtractorSORA.java> "daemon" : ""
MiraiCredentialExtractorSORA.java> "ubnt" : "null"
MiraiCredentialExtractorSORA.java> "adm" : ""
MiraiCredentialExtractorSORA.java> number of credential pairs: 40
MiraiCredentialExtractorSORA.java> Finished!
```

</details>

## `MiraiConfigExtractorSORA.java`

<details>

<summary><code>MiraiConfigExtractorSORA.log</code></summary>

```
MiraiConfigExtractorSORA.java> Running...
MiraiConfigExtractorSORA.java> located decryption function: mw_encrypt_with_key
MiraiConfigExtractorSORA.java> located config address: 00020e64
MiraiConfigExtractorSORA.java> located copy function: mw_copy
MiraiConfigExtractorSORA.java> located 75 referenced config blocks
MiraiConfigExtractorSORA.java> located 99 total config blocks
MiraiConfigExtractorSORA.java> 000210b4 - 0000004a - 00018098 - 5.........LV....[.....v (35 19 18 18 13 15 02 1F 19 18 4C 56 1D 13 13 06 5B 17 1A 1F 00 13 76)
MiraiConfigExtractorSORA.java> 000210bc - 0000004b - 000180b0 - 7.....LV....Y....Z...........Y.....]...Z...........Y...M.KFXOZ.....Y....Z\Y\M.KFXNv (37 15 15 13 06 02 4C 56 02 13 0E 02 59 1E 02 1B 1A 5A 17 06 06 1A 1F 15 17 02 1F 19 18 59 0E 1E 02 1B 1A 5D 0E 1B 1A 5A 17 06 06 1A 1F 15 17 02 1F 19 18 59 0E 1B 1A 4D 07 4B 46 58 4F 5A 1F 1B 17 11 13 59 01 13 14 06 5A 5C 59 5C 4D 07 4B 46 58 4E 76)
MiraiConfigExtractorSORA.java> 000210c4 - 0000004c - 00018104 - 7.....[:.......LV..[#%Z..M.KFXNv (37 15 15 13 06 02 5B 3A 17 18 11 03 17 11 13 4C 56 13 18 5B 23 25 5A 13 18 4D 07 4B 46 58 4E 76)
MiraiConfigExtractorSORA.java> 000210cc - 0000004d - 00018128 - 5......["...LV...........Y.[...[....[..........v (35 19 18 02 13 18 02 5B 22 0F 06 13 4C 56 17 06 06 1A 1F 15 17 02 1F 19 18 59 0E 5B 01 01 01 5B 10 19 04 1B 5B 03 04 1A 13 18 15 19 12 13 12 76)
MiraiConfigExtractorSORA.java> 00020ecc - 0000000d - 00017d78 - /proc/. (2F 70 72 6F 63 2F 00)
MiraiConfigExtractorSORA.java> 00020ed4 - 0000000e - 00017d80 - /exe. (2F 65 78 65 00)
MiraiConfigExtractorSORA.java> 00020ecc - 0000000d - 00017d78 - /proc/. (2F 70 72 6F 63 2F 00)
MiraiConfigExtractorSORA.java> 00020ecc - 0000000d - 00017d78 - /proc/. (2F 70 72 6F 63 2F 00)
MiraiConfigExtractorSORA.java> 00020ed4 - 0000000e - 00017d80 - /exe. (2F 65 78 65 00)
MiraiConfigExtractorSORA.java> 00020f54 - 0000001e - 00017dbc - .anime. (2E 61 6E 69 6D 65 00)
MiraiConfigExtractorSORA.java> 00020f64 - 00000020 - 00017e60 - ...>.....v (12 00 04 3E 13 1A 06 13 04 76)
MiraiConfigExtractorSORA.java> 00020f6c - 00000021 - 00017e6c - 8.11.$@O..v (38 1F 31 31 13 24 40 4F 0E 12 76)
MiraiConfigExtractorSORA.java> 00020f74 - 00000022 - 00017e78 - GEEA%...:9723$v (47 45 45 41 25 19 04 17 3A 39 37 32 33 24 76)
MiraiConfigExtractorSORA.java> 00020f7c - 00000023 - 00017e88 - 8.11.$.F...GEEAv (38 1F 31 31 13 24 12 46 18 1D 05 47 45 45 41 76)
MiraiConfigExtractorSORA.java> 00020f84 - 00000024 - 00017e9c - .GO?DEOGDB#?#v (2E 47 4F 3F 44 45 4F 47 44 42 23 3F 23 76)
MiraiConfigExtractorSORA.java> 00020f8c - 00000025 - 00017eac - ?./....?..vTGB0.v (3F 03 2F 11 03 1C 13 3F 07 18 76 54 47 42 30 17 76)
MiraiConfigExtractorSORA.java> 00020f94 - 00000026 - 00017eb8 - GB0.v (47 42 30 17 76)
MiraiConfigExtractorSORA.java> 00020f9c - 00000027 - 00017ec0 - ..72v (15 15 37 32 76)
MiraiConfigExtractorSORA.java> 00020fb4 - 0000002a - 00017ec8 - Y....Y...Y.....v (59 06 04 19 15 59 18 13 02 59 04 19 03 02 13 76)
MiraiConfigExtractorSORA.java> 00020fbc - 0000002b - 00017edc - Y....Y.......v (59 06 04 19 15 59 15 06 03 1F 18 10 19 76)
MiraiConfigExtractorSORA.java> 00020fc4 - 0000002c - 00017eec - 4919;?&%v (34 39 31 39 3B 3F 26 25 76)
MiraiConfigExtractorSORA.java> 00020fcc - 0000002d - 00017ef8 - Y...Y..X.Y..X.....v (59 13 02 15 59 04 15 58 12 59 04 15 58 1A 19 15 17 1A 76)
MiraiConfigExtractorSORA.java> 00020fd4 - 0000002e - 00017f0c - .G...B...EC...D...F...v (11 47 17 14 15 42 12 1B 19 45 43 1E 18 06 44 1A 1F 13 46 1D 1C 10 76)
MiraiConfigExtractorSORA.java> 00020fdc - 0000002f - 00017f24 - Y...Y........v (59 12 13 00 59 01 17 02 15 1E 12 19 11 76)
MiraiConfigExtractorSORA.java> 00020fe4 - 00000030 - 00017f34 - Y...Y....Y........v (59 12 13 00 59 1B 1F 05 15 59 01 17 02 15 1E 12 19 11 76)
MiraiConfigExtractorSORA.java> 00020fec - 00000031 - 00017f48 - Y...Y0"!2"GFG)........v (59 12 13 00 59 30 22 21 32 22 47 46 47 29 01 17 02 15 1E 12 19 11 76)
MiraiConfigExtractorSORA.java> 00020ff4 - 00000032 - 00017f60 - Y...Y........Yv (59 12 13 00 59 18 13 02 05 1A 1F 18 1D 59 76)
MiraiConfigExtractorSORA.java> 00020ffc - 00000033 - 00017f70 - &$? ;%1v (26 24 3F 20 3B 25 31 76)
MiraiConfigExtractorSORA.java> 00021004 - 00000034 - 00017f7c - 13":957:?&vT=?::7 (31 33 22 3A 39 35 37 3A 3F 26 76 54 3D 3F 3A 3A 37)
MiraiConfigExtractorSORA.java> 0002100c - 00000035 - 00017f88 - =?::7""=v (3D 3F 3A 3A 37 22 22 3D 76)
MiraiConfigExtractorSORA.java> 00021014 - 00000036 - 00017f94 - 3...Nv (33 17 02 05 4E 76)
MiraiConfigExtractorSORA.java> 0002101c - 00000037 - 00017f9c - .-F.v (00 2D 46 00 76)
MiraiConfigExtractorSORA.java> 0002102c - 00000039 - 00017fa4 - OE9..>,D.v (4F 45 39 10 1C 3E 2C 44 0C 76)
MiraiConfigExtractorSORA.java> 0002103c - 0000003b - 00017fc4 - !.17B60@0v (21 05 31 37 42 36 30 40 30 76)
MiraiConfigExtractorSORA.java> 00021044 - 0000003c - 00017fd0 - 7524v (37 35 32 34 76)
MiraiConfigExtractorSORA.java> 0002104c - 0000003d - 00017fd8 - 7.7.v (37 14 37 12 76)
MiraiConfigExtractorSORA.java> 00021054 - 0000003e - 00017fe0 - ..1.v (1F 17 31 00 76)
MiraiConfigExtractorSORA.java> 00021034 - 0000003a - 00017fb0 - 1....!..>...@@@ (31 1E 19 05 02 21 03 0C 3E 13 04 13 40 40 40)
MiraiConfigExtractorSORA.java> 00020f44 - 0000001c - 00017e48 - 1gba4cdom53nhp12ei0kfj. (31 67 62 61 34 63 64 6F 6D 35 33 6E 68 70 31 32 65 69 30 6B 66 6A 00)
MiraiConfigExtractorSORA.java> 0002119c - 00000067 - 00018788 - ;......YCXFV^!......V8"VGFXFMV!..@BMV.@B_V7....!..=..YCEAXE@V^=>";:ZV....V1...._V5.....Y@DXFXEDFDXOBv (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 21 1F 18 12 19 01 05 56 38 22 56 47 46 58 46 4D 56 21 1F 18 40 42 4D 56 0E 40 42 5F 56 37 06 06 1A 13 21 13 14 3D 1F 02 59 43 45 41 58 45 40 56 5E 3D 3E 22 3B 3A 5A 56 1A 1F 1D 13 56 31 13 15 1D 19 5F 56 35 1E 04 19 1B 13 59 40 44 58 46 58 45 44 46 44 58 4F 42 76)
MiraiConfigExtractorSORA.java> 0002112c - 00000059 - 00018208 - ;......YCXFV^!......V8"VGFXFMV!9!@B_V7....!..=..YCEAXE@V^=>";:ZV....V1...._V5.....YCGXFXDAFBXGFEV%.....YCEAXE@v (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 21 1F 18 12 19 01 05 56 38 22 56 47 46 58 46 4D 56 21 39 21 40 42 5F 56 37 06 06 1A 13 21 13 14 3D 1F 02 59 43 45 41 58 45 40 56 5E 3D 3E 22 3B 3A 5A 56 1A 1F 1D 13 56 31 13 15 1D 19 5F 56 35 1E 04 19 1B 13 59 43 47 58 46 58 44 41 46 42 58 47 46 45 56 25 17 10 17 04 1F 59 43 45 41 58 45 40 76)
MiraiConfigExtractorSORA.java> 00021134 - 0000005a - 00018278 - ;......YCXFV^!......V8"VGFXFMV!9!@B_V7....!..=..YCEAXE@V^=>";:ZV....V1...._V5.....YCDXFXDABEXGG@V%.....YCEAXE@v (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 21 1F 18 12 19 01 05 56 38 22 56 47 46 58 46 4D 56 21 39 21 40 42 5F 56 37 06 06 1A 13 21 13 14 3D 1F 02 59 43 45 41 58 45 40 56 5E 3D 3E 22 3B 3A 5A 56 1A 1F 1D 13 56 31 13 15 1D 19 5F 56 35 1E 04 19 1B 13 59 43 44 58 46 58 44 41 42 45 58 47 47 40 56 25 17 10 17 04 1F 59 43 45 41 58 45 40 76)
MiraiConfigExtractorSORA.java> 0002113c - 0000005b - 000182e8 - ;......YCXFV^!......V8"V@XGMV!9!@B_V7....!..=..YCEAXE@V^=>";:ZV....V1...._V5.....YCGXFXDAFBXGFEV%.....YCEAXE@vT (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 21 1F 18 12 19 01 05 56 38 22 56 40 58 47 4D 56 21 39 21 40 42 5F 56 37 06 06 1A 13 21 13 14 3D 1F 02 59 43 45 41 58 45 40 56 5E 3D 3E 22 3B 3A 5A 56 1A 1F 1D 13 56 31 13 15 1D 19 5F 56 35 1E 04 19 1B 13 59 43 47 58 46 58 44 41 46 42 58 47 46 45 56 25 17 10 17 04 1F 59 43 45 41 58 45 40 76 54)
MiraiConfigExtractorSORA.java> 00021144 - 0000005c - 00018358 - ;......YCXFV^!......V8"V@XGMV!9!@B_V7....!..=..YCEAXE@V^=>";:ZV....V1...._V5.....YCDXFXDABEXGG@V%.....YCEAXE@vT (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 21 1F 18 12 19 01 05 56 38 22 56 40 58 47 4D 56 21 39 21 40 42 5F 56 37 06 06 1A 13 21 13 14 3D 1F 02 59 43 45 41 58 45 40 56 5E 3D 3E 22 3B 3A 5A 56 1A 1F 1D 13 56 31 13 15 1D 19 5F 56 35 1E 04 19 1B 13 59 43 44 58 46 58 44 41 42 45 58 47 47 40 56 25 17 10 17 04 1F 59 43 45 41 58 45 40 76 54)
MiraiConfigExtractorSORA.java> 0002114c - 0000005d - 000183c8 - ;......YCXFV^;........MV?....V;..V9%V.VGF)GG)@_V7....!..=..Y@FGXAXAV^=>";:ZV....V1...._V ......YOXGXDV%.....Y@FGXAXAv (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 3B 17 15 1F 18 02 19 05 1E 4D 56 3F 18 02 13 1A 56 3B 17 15 56 39 25 56 2E 56 47 46 29 47 47 29 40 5F 56 37 06 06 1A 13 21 13 14 3D 1F 02 59 40 46 47 58 41 58 41 56 5E 3D 3E 22 3B 3A 5A 56 1A 1F 1D 13 56 31 13 15 1D 19 5F 56 20 13 04 05 1F 19 18 59 4F 58 47 58 44 56 25 17 10 17 04 1F 59 40 46 47 58 41 58 41 76)
MiraiConfigExtractorSORA.java> 00021154 - 0000005e - 00018440 - ;......YBXFV^..........MV;%?3VOXFMV!......V8"VCXGMV"......YCXF_v (3B 19 0C 1F 1A 1A 17 59 42 58 46 56 5E 15 19 1B 06 17 02 1F 14 1A 13 4D 56 3B 25 3F 33 56 4F 58 46 4D 56 21 1F 18 12 19 01 05 56 38 22 56 43 58 47 4D 56 22 04 1F 12 13 18 02 59 43 58 46 5F 76)
MiraiConfigExtractorSORA.java> 0002115c - 0000005f - 00018484 - ;......YBXFV^..........MV;%?3VOXFMV!......V8"V@XFMV"......YBXFMV1"4AXBMV?...&...XEMV% GMVX83"V5:$VEXBXCEE@FMV!9!@BMV..[#%_v (3B 19 0C 1F 1A 1A 17 59 42 58 46 56 5E 15 19 1B 06 17 02 1F 14 1A 13 4D 56 3B 25 3F 33 56 4F 58 46 4D 56 21 1F 18 12 19 01 05 56 38 22 56 40 58 46 4D 56 22 04 1F 12 13 18 02 59 42 58 46 4D 56 31 22 34 41 58 42 4D 56 3F 18 10 19 26 17 02 1E 58 45 4D 56 25 20 47 4D 56 58 38 33 22 56 35 3A 24 56 45 58 42 58 43 45 45 40 46 4D 56 21 39 21 40 42 4D 56 13 18 5B 23 25 5F 76)
MiraiConfigExtractorSORA.java> 00021164 - 00000060 - 00018500 - ;......YBXFV^..........MV;%?3VOXFMV!......V8"V@XGMV"......YBXFMV02;MV;%?35......MV;....V5.....V&5VCXF_v (3B 19 0C 1F 1A 1A 17 59 42 58 46 56 5E 15 19 1B 06 17 02 1F 14 1A 13 4D 56 3B 25 3F 33 56 4F 58 46 4D 56 21 1F 18 12 19 01 05 56 38 22 56 40 58 47 4D 56 22 04 1F 12 13 18 02 59 42 58 46 4D 56 30 32 3B 4D 56 3B 25 3F 33 35 04 17 01 1A 13 04 4D 56 3B 13 12 1F 17 56 35 13 18 02 13 04 56 26 35 56 43 58 46 5F 76)
MiraiConfigExtractorSORA.java> 0002116c - 00000061 - 00018568 - ;......YBXFV^..........MV;%?3VOXFMV!......V8"V@XGMV"......YBXFMV1"4AXBMV?...&...XDMV% GMVX83"V5:$VBXBXCNAOOMV!9!@BMV..[#%_v (3B 19 0C 1F 1A 1A 17 59 42 58 46 56 5E 15 19 1B 06 17 02 1F 14 1A 13 4D 56 3B 25 3F 33 56 4F 58 46 4D 56 21 1F 18 12 19 01 05 56 38 22 56 40 58 47 4D 56 22 04 1F 12 13 18 02 59 42 58 46 4D 56 31 22 34 41 58 42 4D 56 3F 18 10 19 26 17 02 1E 58 44 4D 56 25 20 47 4D 56 58 38 33 22 56 35 3A 24 56 42 58 42 58 43 4E 41 4F 4F 4D 56 21 39 21 40 42 4D 56 13 18 5B 23 25 5F 76)
MiraiConfigExtractorSORA.java> 00021174 - 00000062 - 000185e4 - ;......YBXFV^..........MV;%?3VOXFMV!......V8"V@XGMV"......YCXFMV0..!..&......._v (3B 19 0C 1F 1A 1A 17 59 42 58 46 56 5E 15 19 1B 06 17 02 1F 14 1A 13 4D 56 3B 25 3F 33 56 4F 58 46 4D 56 21 1F 18 12 19 01 05 56 38 22 56 40 58 47 4D 56 22 04 1F 12 13 18 02 59 43 58 46 4D 56 30 03 18 21 13 14 26 04 19 12 03 15 02 05 5F 76)
MiraiConfigExtractorSORA.java> 0002117c - 00000063 - 00018638 - ;......YCXFV^;........MV?....V;..V9%V.VGFX@MV..LDCXF_V1....YDFGFFGFGV0......YDCXFv (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 3B 17 15 1F 18 02 19 05 1E 4D 56 3F 18 02 13 1A 56 3B 17 15 56 39 25 56 2E 56 47 46 58 40 4D 56 04 00 4C 44 43 58 46 5F 56 31 13 15 1D 19 59 44 46 47 46 46 47 46 47 56 30 1F 04 13 10 19 0E 59 44 43 58 46 76)
MiraiConfigExtractorSORA.java> 00021184 - 00000064 - 0001868c - ;......YCXFV^;........MV?....V;..V9%V.VGFXNMV..LDGXF_V1....YDFGFFGFGV0......YDGXFv (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 3B 17 15 1F 18 02 19 05 1E 4D 56 3F 18 02 13 1A 56 3B 17 15 56 39 25 56 2E 56 47 46 58 4E 4D 56 04 00 4C 44 47 58 46 5F 56 31 13 15 1D 19 59 44 46 47 46 46 47 46 47 56 30 1F 04 13 10 19 0E 59 44 47 58 46 76)
MiraiConfigExtractorSORA.java> 0002118c - 00000065 - 000186e0 - ;......YCXFV^;........MV?....V;..V9%V.VGFXNMV..LDBXF_V1....YDFGFFGFGV0......YDBXFv (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 3B 17 15 1F 18 02 19 05 1E 4D 56 3F 18 02 13 1A 56 3B 17 15 56 39 25 56 2E 56 47 46 58 4E 4D 56 04 00 4C 44 42 58 46 5F 56 31 13 15 1D 19 59 44 46 47 46 46 47 46 47 56 30 1F 04 13 10 19 0E 59 44 42 58 46 76)
MiraiConfigExtractorSORA.java> 00021194 - 00000066 - 00018734 - ;......YCXFV^;........MV?....V;..V9%V.VGF)GFMV..LEEXF_V1....YDFGFFGFGV0......YEEXFv (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 3B 17 15 1F 18 02 19 05 1E 4D 56 3F 18 02 13 1A 56 3B 17 15 56 39 25 56 2E 56 47 46 29 47 46 4D 56 04 00 4C 45 45 58 46 5F 56 31 13 15 1D 19 59 44 46 47 46 46 47 46 47 56 30 1F 04 13 10 19 0E 59 45 45 58 46 76)
MiraiConfigExtractorSORA.java> 00020f34 - 0000001a - 00017e38 - ogin. (6F 67 69 6E 00)
MiraiConfigExtractorSORA.java> 00020f3c - 0000001b - 00017e40 - enter. (65 6E 74 65 72 00)
MiraiConfigExtractorSORA.java> 00020f34 - 0000001a - 00017e38 - ogin. (6F 67 69 6E 00)
MiraiConfigExtractorSORA.java> 00020f3c - 0000001b - 00017e40 - enter. (65 6E 74 65 72 00)
MiraiConfigExtractorSORA.java> 00020f34 - 0000001a - 00017e38 - ogin. (6F 67 69 6E 00)
MiraiConfigExtractorSORA.java> 00020f3c - 0000001b - 00017e40 - enter. (65 6E 74 65 72 00)
MiraiConfigExtractorSORA.java> 00020f2c - 00000019 - 00017e2c - pbbf~cu. (70 62 62 66 7E 63 75 11)
MiraiConfigExtractorSORA.java> 00020f2c - 00000019 - 00017e2c - pbbf~cu. (70 62 62 66 7E 63 75 11)
MiraiConfigExtractorSORA.java> 00020f2c - 00000019 - 00017e2c - pbbf~cu. (70 62 62 66 7E 63 75 11)
MiraiConfigExtractorSORA.java> 00020e8c - 00000005 - 00017d00 - enable. (65 6E 61 62 6C 65 00)
MiraiConfigExtractorSORA.java> 00020e94 - 00000006 - 00017d08 - system. (73 79 73 74 65 6D 00)
MiraiConfigExtractorSORA.java> 00020e9c - 00000007 - 00017d10 - sh. (73 68 00)
MiraiConfigExtractorSORA.java> 00020e84 - 00000004 - 00017cf8 - shell. (73 68 65 6C 6C 00)
MiraiConfigExtractorSORA.java> 00020eb4 - 0000000a - 00017d40 - ncorrect. (6E 63 6F 72 72 65 63 74 00)
MiraiConfigExtractorSORA.java> 00020eb4 - 0000000a - 00017d40 - ncorrect. (6E 63 6F 72 72 65 63 74 00)
MiraiConfigExtractorSORA.java> 00020eac - 00000009 - 00017d28 - SORA: applet not found. (53 4F 52 41 3A 20 61 70 70 6C 65 74 20 6E 6F 74 20 66 6F 75 6E 64 00)
MiraiConfigExtractorSORA.java> 00020ea4 - 00000008 - 00017d14 - /bin/busybox SORA. (2F 62 69 6E 2F 62 75 73 79 62 6F 78 20 53 4F 52 41 00)
MiraiConfigExtractorSORA.java> 00020e7c - 00000003 - 000187f0 - Connected To CNC. (43 6F 6E 6E 65 63 74 65 64 20 54 6F 20 43 4E 43 00)
MiraiConfigExtractorSORA.java> 00020f1c - 00000017 - 00017e08 - /dev/watchdog. (2F 64 65 76 2F 77 61 74 63 68 64 6F 67 00)
MiraiConfigExtractorSORA.java> 00020f24 - 00000018 - 00017e18 - /dev/misc/watchdog. (2F 64 65 76 2F 6D 69 73 63 2F 77 61 74 63 68 64 6F 67 00)
MiraiConfigExtractorSORA.java> 00020e6c - 00000001 - 00017cf0 - .  (05 20)
MiraiConfigExtractorSORA.java> Finished!
```

</details>
