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

## `MiraiCredentialExtractorSORAArm.java`

<details>

<summary><code>MiraiCredentialExtractorSORAArm.log</code></summary>

```
MiraiCredentialExtractorSORAArm.java> Running...
MiraiCredentialExtractorSORAArm.java> located decryption function: mw_decrypt
MiraiCredentialExtractorSORAArm.java> found 40 credential pairs
MiraiCredentialExtractorSORAArm.java> credential pairs (username : password):
MiraiCredentialExtractorSORAArm.java> ("$??"P" : ""??$P")
MiraiCredentialExtractorSORAArm.java> (""??$P" : "$??"P")
MiraiCredentialExtractorSORAArm.java> ("$??"P" : "$??"P")
MiraiCredentialExtractorSORAArm.java> ("$??"P" : "")
MiraiCredentialExtractorSORAArm.java> ("default" : "")
MiraiCredentialExtractorSORAArm.java> ("default" : "default")
MiraiCredentialExtractorSORAArm.java> ("default" : "altslq")
MiraiCredentialExtractorSORAArm.java> ("default" : "OxhlwSG8")
MiraiCredentialExtractorSORAArm.java> ("default" : "tlJwpbo6")
MiraiCredentialExtractorSORAArm.java> ("default" : "S2fGqNFs")
MiraiCredentialExtractorSORAArm.java> ("root" : "xc3551")
MiraiCredentialExtractorSORAArm.java> ("root" : "vizxv")
MiraiCredentialExtractorSORAArm.java> ("root" : "klv123")
MiraiCredentialExtractorSORAArm.java> ("root" : "admin")
MiraiCredentialExtractorSORAArm.java> ("root" : "zyad1234")
MiraiCredentialExtractorSORAArm.java> ("root" : "zlxx.")
MiraiCredentialExtractorSORAArm.java> ("root" : "default")
MiraiCredentialExtractorSORAArm.java> ("root" : "7ujMko0vizxv")
MiraiCredentialExtractorSORAArm.java> ("root" : "7ujMko0admin")
MiraiCredentialExtractorSORAArm.java> ("root" : "hi3518")
MiraiCredentialExtractorSORAArm.java> ("root" : "cat1029")
MiraiCredentialExtractorSORAArm.java> ("root" : "annie2012")
MiraiCredentialExtractorSORAArm.java> ("root" : "changeme")
MiraiCredentialExtractorSORAArm.java> ("guest" : "")
MiraiCredentialExtractorSORAArm.java> ("guest" : "guest")
MiraiCredentialExtractorSORAArm.java> ("guest" : "12345z")
MiraiCredentialExtractorSORAArm.java> ("guest" : "123456")
MiraiCredentialExtractorSORAArm.java> ("user" : "")
MiraiCredentialExtractorSORAArm.java> ("user" : "user")
MiraiCredentialExtractorSORAArm.java> ("user" : "123456")
MiraiCredentialExtractorSORAArm.java> ("admin" : "")
MiraiCredentialExtractorSORAArm.java> ("admin" : "admin")
MiraiCredentialExtractorSORAArm.java> ("admin" : "pass")
MiraiCredentialExtractorSORAArm.java> ("admin" : "password")
MiraiCredentialExtractorSORAArm.java> ("admin" : "admin1234")
MiraiCredentialExtractorSORAArm.java> ("support" : "support")
MiraiCredentialExtractorSORAArm.java> ("mg3500" : "merlin")
MiraiCredentialExtractorSORAArm.java> ("daemon" : "")
MiraiCredentialExtractorSORAArm.java> ("ubnt" : "ubnt")
MiraiCredentialExtractorSORAArm.java> ("adm" : "")
MiraiCredentialExtractorSORAArm.java> Finished!
```

</details>

## `MiraiConfigExtractorSORAArm.java`

<details>

<summary><code>MiraiConfigExtractorSORAArm.log</code> (key: <code>0xdedefbaf</code>)</summary>

```
MiraiConfigExtractorSORAArm.java> Running...
MiraiConfigExtractorSORAArm.java> located decryption function: mw_encrypt_with_key
MiraiConfigExtractorSORAArm.java> located config address: 00020e64
MiraiConfigExtractorSORAArm.java> located copy function: mw_copy
MiraiConfigExtractorSORAArm.java> located 65 referenced config blocks
MiraiConfigExtractorSORAArm.java> located 99 total config blocks
MiraiConfigExtractorSORAArm.java> referenced config blocks (.bss address - config ID - .rodata address - string (hex bytes)):
MiraiConfigExtractorSORAArm.java> 000210b4 - 0000004a - 00018098 - 5.........LV....[.....v (35 19 18 18 13 15 02 1F 19 18 4C 56 1D 13 13 06 5B 17 1A 1F 00 13 76)
MiraiConfigExtractorSORAArm.java> 000210bc - 0000004b - 000180b0 - 7.....LV....Y....Z...........Y.....]...Z...........Y...M.KFXOZ.....Y....Z\Y\M.KFXNv (37 15 15 13 06 02 4C 56 02 13 0E 02 59 1E 02 1B 1A 5A 17 06 06 1A 1F 15 17 02 1F 19 18 59 0E 1E 02 1B 1A 5D 0E 1B 1A 5A 17 06 06 1A 1F 15 17 02 1F 19 18 59 0E 1B 1A 4D 07 4B 46 58 4F 5A 1F 1B 17 11 13 59 01 13 14 06 5A 5C 59 5C 4D 07 4B 46 58 4E 76)
MiraiConfigExtractorSORAArm.java> 000210c4 - 0000004c - 00018104 - 7.....[:.......LV..[#%Z..M.KFXNv (37 15 15 13 06 02 5B 3A 17 18 11 03 17 11 13 4C 56 13 18 5B 23 25 5A 13 18 4D 07 4B 46 58 4E 76)
MiraiConfigExtractorSORAArm.java> 000210cc - 0000004d - 00018128 - 5......["...LV...........Y.[...[....[..........v (35 19 18 02 13 18 02 5B 22 0F 06 13 4C 56 17 06 06 1A 1F 15 17 02 1F 19 18 59 0E 5B 01 01 01 5B 10 19 04 1B 5B 03 04 1A 13 18 15 19 12 13 12 76)
MiraiConfigExtractorSORAArm.java> 00020ecc - 0000000d - 00017d78 - /proc/. (2F 70 72 6F 63 2F 00)
MiraiConfigExtractorSORAArm.java> 00020ed4 - 0000000e - 00017d80 - /exe. (2F 65 78 65 00)
MiraiConfigExtractorSORAArm.java> 00020f54 - 0000001e - 00017dbc - .anime. (2E 61 6E 69 6D 65 00)
MiraiConfigExtractorSORAArm.java> 00020f64 - 00000020 - 00017e60 - ...>.....v (12 00 04 3E 13 1A 06 13 04 76)
MiraiConfigExtractorSORAArm.java> 00020f6c - 00000021 - 00017e6c - 8.11.$@O..v (38 1F 31 31 13 24 40 4F 0E 12 76)
MiraiConfigExtractorSORAArm.java> 00020f74 - 00000022 - 00017e78 - GEEA%...:9723$v (47 45 45 41 25 19 04 17 3A 39 37 32 33 24 76)
MiraiConfigExtractorSORAArm.java> 00020f7c - 00000023 - 00017e88 - 8.11.$.F...GEEAv (38 1F 31 31 13 24 12 46 18 1D 05 47 45 45 41 76)
MiraiConfigExtractorSORAArm.java> 00020f84 - 00000024 - 00017e9c - .GO?DEOGDB#?#v (2E 47 4F 3F 44 45 4F 47 44 42 23 3F 23 76)
MiraiConfigExtractorSORAArm.java> 00020f8c - 00000025 - 00017eac - ?./....?..vTGB0.v (3F 03 2F 11 03 1C 13 3F 07 18 76 54 47 42 30 17 76)
MiraiConfigExtractorSORAArm.java> 00020f94 - 00000026 - 00017eb8 - GB0.v (47 42 30 17 76)
MiraiConfigExtractorSORAArm.java> 00020f9c - 00000027 - 00017ec0 - ..72v (15 15 37 32 76)
MiraiConfigExtractorSORAArm.java> 00020fb4 - 0000002a - 00017ec8 - Y....Y...Y.....v (59 06 04 19 15 59 18 13 02 59 04 19 03 02 13 76)
MiraiConfigExtractorSORAArm.java> 00020fbc - 0000002b - 00017edc - Y....Y.......v (59 06 04 19 15 59 15 06 03 1F 18 10 19 76)
MiraiConfigExtractorSORAArm.java> 00020fc4 - 0000002c - 00017eec - 4919;?&%v (34 39 31 39 3B 3F 26 25 76)
MiraiConfigExtractorSORAArm.java> 00020fcc - 0000002d - 00017ef8 - Y...Y..X.Y..X.....v (59 13 02 15 59 04 15 58 12 59 04 15 58 1A 19 15 17 1A 76)
MiraiConfigExtractorSORAArm.java> 00020fd4 - 0000002e - 00017f0c - .G...B...EC...D...F...v (11 47 17 14 15 42 12 1B 19 45 43 1E 18 06 44 1A 1F 13 46 1D 1C 10 76)
MiraiConfigExtractorSORAArm.java> 00020fdc - 0000002f - 00017f24 - Y...Y........v (59 12 13 00 59 01 17 02 15 1E 12 19 11 76)
MiraiConfigExtractorSORAArm.java> 00020fe4 - 00000030 - 00017f34 - Y...Y....Y........v (59 12 13 00 59 1B 1F 05 15 59 01 17 02 15 1E 12 19 11 76)
MiraiConfigExtractorSORAArm.java> 00020fec - 00000031 - 00017f48 - Y...Y0"!2"GFG)........v (59 12 13 00 59 30 22 21 32 22 47 46 47 29 01 17 02 15 1E 12 19 11 76)
MiraiConfigExtractorSORAArm.java> 00020ff4 - 00000032 - 00017f60 - Y...Y........Yv (59 12 13 00 59 18 13 02 05 1A 1F 18 1D 59 76)
MiraiConfigExtractorSORAArm.java> 00020ffc - 00000033 - 00017f70 - &$? ;%1v (26 24 3F 20 3B 25 31 76)
MiraiConfigExtractorSORAArm.java> 00021004 - 00000034 - 00017f7c - 13":957:?&vT=?::7 (31 33 22 3A 39 35 37 3A 3F 26 76 54 3D 3F 3A 3A 37)
MiraiConfigExtractorSORAArm.java> 0002100c - 00000035 - 00017f88 - =?::7""=v (3D 3F 3A 3A 37 22 22 3D 76)
MiraiConfigExtractorSORAArm.java> 00021014 - 00000036 - 00017f94 - 3...Nv (33 17 02 05 4E 76)
MiraiConfigExtractorSORAArm.java> 0002101c - 00000037 - 00017f9c - .-F.v (00 2D 46 00 76)
MiraiConfigExtractorSORAArm.java> 0002102c - 00000039 - 00017fa4 - OE9..>,D.v (4F 45 39 10 1C 3E 2C 44 0C 76)
MiraiConfigExtractorSORAArm.java> 0002103c - 0000003b - 00017fc4 - !.17B60@0v (21 05 31 37 42 36 30 40 30 76)
MiraiConfigExtractorSORAArm.java> 00021044 - 0000003c - 00017fd0 - 7524v (37 35 32 34 76)
MiraiConfigExtractorSORAArm.java> 0002104c - 0000003d - 00017fd8 - 7.7.v (37 14 37 12 76)
MiraiConfigExtractorSORAArm.java> 00021054 - 0000003e - 00017fe0 - ..1.v (1F 17 31 00 76)
MiraiConfigExtractorSORAArm.java> 00021034 - 0000003a - 00017fb0 - 1....!..>...@@@ (31 1E 19 05 02 21 03 0C 3E 13 04 13 40 40 40)
MiraiConfigExtractorSORAArm.java> 00020f44 - 0000001c - 00017e48 - 1gba4cdom53nhp12ei0kfj. (31 67 62 61 34 63 64 6F 6D 35 33 6E 68 70 31 32 65 69 30 6B 66 6A 00)
MiraiConfigExtractorSORAArm.java> 0002119c - 00000067 - 00018788 - ;......YCXFV^!......V8"VGFXFMV!..@BMV.@B_V7....!..=..YCEAXE@V^=>";:ZV....V1...._V5.....Y@DXFXEDFDXOBv (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 21 1F 18 12 19 01 05 56 38 22 56 47 46 58 46 4D 56 21 1F 18 40 42 4D 56 0E 40 42 5F 56 37 06 06 1A 13 21 13 14 3D 1F 02 59 43 45 41 58 45 40 56 5E 3D 3E 22 3B 3A 5A 56 1A 1F 1D 13 56 31 13 15 1D 19 5F 56 35 1E 04 19 1B 13 59 40 44 58 46 58 45 44 46 44 58 4F 42 76)
MiraiConfigExtractorSORAArm.java> 0002112c - 00000059 - 00018208 - ;......YCXFV^!......V8"VGFXFMV!9!@B_V7....!..=..YCEAXE@V^=>";:ZV....V1...._V5.....YCGXFXDAFBXGFEV%.....YCEAXE@v (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 21 1F 18 12 19 01 05 56 38 22 56 47 46 58 46 4D 56 21 39 21 40 42 5F 56 37 06 06 1A 13 21 13 14 3D 1F 02 59 43 45 41 58 45 40 56 5E 3D 3E 22 3B 3A 5A 56 1A 1F 1D 13 56 31 13 15 1D 19 5F 56 35 1E 04 19 1B 13 59 43 47 58 46 58 44 41 46 42 58 47 46 45 56 25 17 10 17 04 1F 59 43 45 41 58 45 40 76)
MiraiConfigExtractorSORAArm.java> 00021134 - 0000005a - 00018278 - ;......YCXFV^!......V8"VGFXFMV!9!@B_V7....!..=..YCEAXE@V^=>";:ZV....V1...._V5.....YCDXFXDABEXGG@V%.....YCEAXE@v (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 21 1F 18 12 19 01 05 56 38 22 56 47 46 58 46 4D 56 21 39 21 40 42 5F 56 37 06 06 1A 13 21 13 14 3D 1F 02 59 43 45 41 58 45 40 56 5E 3D 3E 22 3B 3A 5A 56 1A 1F 1D 13 56 31 13 15 1D 19 5F 56 35 1E 04 19 1B 13 59 43 44 58 46 58 44 41 42 45 58 47 47 40 56 25 17 10 17 04 1F 59 43 45 41 58 45 40 76)
MiraiConfigExtractorSORAArm.java> 0002113c - 0000005b - 000182e8 - ;......YCXFV^!......V8"V@XGMV!9!@B_V7....!..=..YCEAXE@V^=>";:ZV....V1...._V5.....YCGXFXDAFBXGFEV%.....YCEAXE@vT (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 21 1F 18 12 19 01 05 56 38 22 56 40 58 47 4D 56 21 39 21 40 42 5F 56 37 06 06 1A 13 21 13 14 3D 1F 02 59 43 45 41 58 45 40 56 5E 3D 3E 22 3B 3A 5A 56 1A 1F 1D 13 56 31 13 15 1D 19 5F 56 35 1E 04 19 1B 13 59 43 47 58 46 58 44 41 46 42 58 47 46 45 56 25 17 10 17 04 1F 59 43 45 41 58 45 40 76 54)
MiraiConfigExtractorSORAArm.java> 00021144 - 0000005c - 00018358 - ;......YCXFV^!......V8"V@XGMV!9!@B_V7....!..=..YCEAXE@V^=>";:ZV....V1...._V5.....YCDXFXDABEXGG@V%.....YCEAXE@vT (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 21 1F 18 12 19 01 05 56 38 22 56 40 58 47 4D 56 21 39 21 40 42 5F 56 37 06 06 1A 13 21 13 14 3D 1F 02 59 43 45 41 58 45 40 56 5E 3D 3E 22 3B 3A 5A 56 1A 1F 1D 13 56 31 13 15 1D 19 5F 56 35 1E 04 19 1B 13 59 43 44 58 46 58 44 41 42 45 58 47 47 40 56 25 17 10 17 04 1F 59 43 45 41 58 45 40 76 54)
MiraiConfigExtractorSORAArm.java> 0002114c - 0000005d - 000183c8 - ;......YCXFV^;........MV?....V;..V9%V.VGF)GG)@_V7....!..=..Y@FGXAXAV^=>";:ZV....V1...._V ......YOXGXDV%.....Y@FGXAXAv (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 3B 17 15 1F 18 02 19 05 1E 4D 56 3F 18 02 13 1A 56 3B 17 15 56 39 25 56 2E 56 47 46 29 47 47 29 40 5F 56 37 06 06 1A 13 21 13 14 3D 1F 02 59 40 46 47 58 41 58 41 56 5E 3D 3E 22 3B 3A 5A 56 1A 1F 1D 13 56 31 13 15 1D 19 5F 56 20 13 04 05 1F 19 18 59 4F 58 47 58 44 56 25 17 10 17 04 1F 59 40 46 47 58 41 58 41 76)
MiraiConfigExtractorSORAArm.java> 00021154 - 0000005e - 00018440 - ;......YBXFV^..........MV;%?3VOXFMV!......V8"VCXGMV"......YCXF_v (3B 19 0C 1F 1A 1A 17 59 42 58 46 56 5E 15 19 1B 06 17 02 1F 14 1A 13 4D 56 3B 25 3F 33 56 4F 58 46 4D 56 21 1F 18 12 19 01 05 56 38 22 56 43 58 47 4D 56 22 04 1F 12 13 18 02 59 43 58 46 5F 76)
MiraiConfigExtractorSORAArm.java> 0002115c - 0000005f - 00018484 - ;......YBXFV^..........MV;%?3VOXFMV!......V8"V@XFMV"......YBXFMV1"4AXBMV?...&...XEMV% GMVX83"V5:$VEXBXCEE@FMV!9!@BMV..[#%_v (3B 19 0C 1F 1A 1A 17 59 42 58 46 56 5E 15 19 1B 06 17 02 1F 14 1A 13 4D 56 3B 25 3F 33 56 4F 58 46 4D 56 21 1F 18 12 19 01 05 56 38 22 56 40 58 46 4D 56 22 04 1F 12 13 18 02 59 42 58 46 4D 56 31 22 34 41 58 42 4D 56 3F 18 10 19 26 17 02 1E 58 45 4D 56 25 20 47 4D 56 58 38 33 22 56 35 3A 24 56 45 58 42 58 43 45 45 40 46 4D 56 21 39 21 40 42 4D 56 13 18 5B 23 25 5F 76)
MiraiConfigExtractorSORAArm.java> 00021164 - 00000060 - 00018500 - ;......YBXFV^..........MV;%?3VOXFMV!......V8"V@XGMV"......YBXFMV02;MV;%?35......MV;....V5.....V&5VCXF_v (3B 19 0C 1F 1A 1A 17 59 42 58 46 56 5E 15 19 1B 06 17 02 1F 14 1A 13 4D 56 3B 25 3F 33 56 4F 58 46 4D 56 21 1F 18 12 19 01 05 56 38 22 56 40 58 47 4D 56 22 04 1F 12 13 18 02 59 42 58 46 4D 56 30 32 3B 4D 56 3B 25 3F 33 35 04 17 01 1A 13 04 4D 56 3B 13 12 1F 17 56 35 13 18 02 13 04 56 26 35 56 43 58 46 5F 76)
MiraiConfigExtractorSORAArm.java> 0002116c - 00000061 - 00018568 - ;......YBXFV^..........MV;%?3VOXFMV!......V8"V@XGMV"......YBXFMV1"4AXBMV?...&...XDMV% GMVX83"V5:$VBXBXCNAOOMV!9!@BMV..[#%_v (3B 19 0C 1F 1A 1A 17 59 42 58 46 56 5E 15 19 1B 06 17 02 1F 14 1A 13 4D 56 3B 25 3F 33 56 4F 58 46 4D 56 21 1F 18 12 19 01 05 56 38 22 56 40 58 47 4D 56 22 04 1F 12 13 18 02 59 42 58 46 4D 56 31 22 34 41 58 42 4D 56 3F 18 10 19 26 17 02 1E 58 44 4D 56 25 20 47 4D 56 58 38 33 22 56 35 3A 24 56 42 58 42 58 43 4E 41 4F 4F 4D 56 21 39 21 40 42 4D 56 13 18 5B 23 25 5F 76)
MiraiConfigExtractorSORAArm.java> 00021174 - 00000062 - 000185e4 - ;......YBXFV^..........MV;%?3VOXFMV!......V8"V@XGMV"......YCXFMV0..!..&......._v (3B 19 0C 1F 1A 1A 17 59 42 58 46 56 5E 15 19 1B 06 17 02 1F 14 1A 13 4D 56 3B 25 3F 33 56 4F 58 46 4D 56 21 1F 18 12 19 01 05 56 38 22 56 40 58 47 4D 56 22 04 1F 12 13 18 02 59 43 58 46 4D 56 30 03 18 21 13 14 26 04 19 12 03 15 02 05 5F 76)
MiraiConfigExtractorSORAArm.java> 0002117c - 00000063 - 00018638 - ;......YCXFV^;........MV?....V;..V9%V.VGFX@MV..LDCXF_V1....YDFGFFGFGV0......YDCXFv (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 3B 17 15 1F 18 02 19 05 1E 4D 56 3F 18 02 13 1A 56 3B 17 15 56 39 25 56 2E 56 47 46 58 40 4D 56 04 00 4C 44 43 58 46 5F 56 31 13 15 1D 19 59 44 46 47 46 46 47 46 47 56 30 1F 04 13 10 19 0E 59 44 43 58 46 76)
MiraiConfigExtractorSORAArm.java> 00021184 - 00000064 - 0001868c - ;......YCXFV^;........MV?....V;..V9%V.VGFXNMV..LDGXF_V1....YDFGFFGFGV0......YDGXFv (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 3B 17 15 1F 18 02 19 05 1E 4D 56 3F 18 02 13 1A 56 3B 17 15 56 39 25 56 2E 56 47 46 58 4E 4D 56 04 00 4C 44 47 58 46 5F 56 31 13 15 1D 19 59 44 46 47 46 46 47 46 47 56 30 1F 04 13 10 19 0E 59 44 47 58 46 76)
MiraiConfigExtractorSORAArm.java> 0002118c - 00000065 - 000186e0 - ;......YCXFV^;........MV?....V;..V9%V.VGFXNMV..LDBXF_V1....YDFGFFGFGV0......YDBXFv (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 3B 17 15 1F 18 02 19 05 1E 4D 56 3F 18 02 13 1A 56 3B 17 15 56 39 25 56 2E 56 47 46 58 4E 4D 56 04 00 4C 44 42 58 46 5F 56 31 13 15 1D 19 59 44 46 47 46 46 47 46 47 56 30 1F 04 13 10 19 0E 59 44 42 58 46 76)
MiraiConfigExtractorSORAArm.java> 00021194 - 00000066 - 00018734 - ;......YCXFV^;........MV?....V;..V9%V.VGF)GFMV..LEEXF_V1....YDFGFFGFGV0......YEEXFv (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 3B 17 15 1F 18 02 19 05 1E 4D 56 3F 18 02 13 1A 56 3B 17 15 56 39 25 56 2E 56 47 46 29 47 46 4D 56 04 00 4C 45 45 58 46 5F 56 31 13 15 1D 19 59 44 46 47 46 46 47 46 47 56 30 1F 04 13 10 19 0E 59 45 45 58 46 76)
MiraiConfigExtractorSORAArm.java> 00020f34 - 0000001a - 00017e38 - ogin. (6F 67 69 6E 00)
MiraiConfigExtractorSORAArm.java> 00020f3c - 0000001b - 00017e40 - enter. (65 6E 74 65 72 00)
MiraiConfigExtractorSORAArm.java> 00020f2c - 00000019 - 00017e2c - pbbf~cu. (70 62 62 66 7E 63 75 11)
MiraiConfigExtractorSORAArm.java> 00020e8c - 00000005 - 00017d00 - enable. (65 6E 61 62 6C 65 00)
MiraiConfigExtractorSORAArm.java> 00020e94 - 00000006 - 00017d08 - system. (73 79 73 74 65 6D 00)
MiraiConfigExtractorSORAArm.java> 00020e9c - 00000007 - 00017d10 - sh. (73 68 00)
MiraiConfigExtractorSORAArm.java> 00020e84 - 00000004 - 00017cf8 - shell. (73 68 65 6C 6C 00)
MiraiConfigExtractorSORAArm.java> 00020eb4 - 0000000a - 00017d40 - ncorrect. (6E 63 6F 72 72 65 63 74 00)
MiraiConfigExtractorSORAArm.java> 00020eac - 00000009 - 00017d28 - SORA: applet not found. (53 4F 52 41 3A 20 61 70 70 6C 65 74 20 6E 6F 74 20 66 6F 75 6E 64 00)
MiraiConfigExtractorSORAArm.java> 00020ea4 - 00000008 - 00017d14 - /bin/busybox SORA. (2F 62 69 6E 2F 62 75 73 79 62 6F 78 20 53 4F 52 41 00)
MiraiConfigExtractorSORAArm.java> 00020e7c - 00000003 - 000187f0 - Connected To CNC. (43 6F 6E 6E 65 63 74 65 64 20 54 6F 20 43 4E 43 00)
MiraiConfigExtractorSORAArm.java> 00020f1c - 00000017 - 00017e08 - /dev/watchdog. (2F 64 65 76 2F 77 61 74 63 68 64 6F 67 00)
MiraiConfigExtractorSORAArm.java> 00020f24 - 00000018 - 00017e18 - /dev/misc/watchdog. (2F 64 65 76 2F 6D 69 73 63 2F 77 61 74 63 68 64 6F 67 00)
MiraiConfigExtractorSORAArm.java> 00020e6c - 00000001 - 00017cf0 - .  (05 20)
MiraiConfigExtractorSORAArm.java> Finished!
```

</details>

<details>

<summary><code>MiraiConfigExtractorSORAArm.log</code> (key: <code>0xdeadbeef</code>)</summary>

```
MiraiConfigExtractorSORAArm.java> Running...
MiraiConfigExtractorSORAArm.java> located decryption function: mw_encrypt_with_key
MiraiConfigExtractorSORAArm.java> located config address: 00020e64
MiraiConfigExtractorSORAArm.java> located copy function: mw_copy
MiraiConfigExtractorSORAArm.java> located 65 referenced config blocks
MiraiConfigExtractorSORAArm.java> located 99 total config blocks
MiraiConfigExtractorSORAArm.java> referenced config blocks (.bss address - config ID - .rodata address - string (hex bytes)):
MiraiConfigExtractorSORAArm.java> 000210b4 - 0000004a - 00018098 - Connection: keep-alive. (43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 6B 65 65 70 2D 61 6C 69 76 65 00)
MiraiConfigExtractorSORAArm.java> 000210bc - 0000004b - 000180b0 - Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8. (41 63 63 65 70 74 3A 20 74 65 78 74 2F 68 74 6D 6C 2C 61 70 70 6C 69 63 61 74 69 6F 6E 2F 78 68 74 6D 6C 2B 78 6D 6C 2C 61 70 70 6C 69 63 61 74 69 6F 6E 2F 78 6D 6C 3B 71 3D 30 2E 39 2C 69 6D 61 67 65 2F 77 65 62 70 2C 2A 2F 2A 3B 71 3D 30 2E 38 00)
MiraiConfigExtractorSORAArm.java> 000210c4 - 0000004c - 00018104 - Accept-Language: en-US,en;q=0.8. (41 63 63 65 70 74 2D 4C 61 6E 67 75 61 67 65 3A 20 65 6E 2D 55 53 2C 65 6E 3B 71 3D 30 2E 38 00)
MiraiConfigExtractorSORAArm.java> 000210cc - 0000004d - 00018128 - Content-Type: application/x-www-form-urlencoded. (43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E 2F 78 2D 77 77 77 2D 66 6F 72 6D 2D 75 72 6C 65 6E 63 6F 64 65 64 00)
MiraiConfigExtractorSORAArm.java> 00020ecc - 0000000d - 00017d78 - Y....Yv (59 06 04 19 15 59 76)
MiraiConfigExtractorSORAArm.java> 00020ed4 - 0000000e - 00017d80 - Y...v (59 13 0E 13 76)
MiraiConfigExtractorSORAArm.java> 00020f54 - 0000001e - 00017dbc - X.....v (58 17 18 1F 1B 13 76)
MiraiConfigExtractorSORAArm.java> 00020f64 - 00000020 - 00017e60 - dvrHelper. (64 76 72 48 65 6C 70 65 72 00)
MiraiConfigExtractorSORAArm.java> 00020f6c - 00000021 - 00017e6c - <censored>
MiraiConfigExtractorSORAArm.java> 00020f74 - 00000022 - 00017e78 - 1337SoraLOADER. (31 33 33 37 53 6F 72 61 4C 4F 41 44 45 52 00)
MiraiConfigExtractorSORAArm.java> 00020f7c - 00000023 - 00017e88 - <censored>
MiraiConfigExtractorSORAArm.java> 00020f84 - 00000024 - 00017e9c - X19I239124UIU. (58 31 39 49 32 33 39 31 32 34 55 49 55 00)
MiraiConfigExtractorSORAArm.java> 00020f8c - 00000025 - 00017eac - IuYgujeIqn."14Fa. (49 75 59 67 75 6A 65 49 71 6E 00 22 31 34 46 61 00)
MiraiConfigExtractorSORAArm.java> 00020f94 - 00000026 - 00017eb8 - 14Fa. (31 34 46 61 00)
MiraiConfigExtractorSORAArm.java> 00020f9c - 00000027 - 00017ec0 - ccAD. (63 63 41 44 00)
MiraiConfigExtractorSORAArm.java> 00020fb4 - 0000002a - 00017ec8 - /proc/net/route. (2F 70 72 6F 63 2F 6E 65 74 2F 72 6F 75 74 65 00)
MiraiConfigExtractorSORAArm.java> 00020fbc - 0000002b - 00017edc - /proc/cpuinfo. (2F 70 72 6F 63 2F 63 70 75 69 6E 66 6F 00)
MiraiConfigExtractorSORAArm.java> 00020fc4 - 0000002c - 00017eec - BOGOMIPS. (42 4F 47 4F 4D 49 50 53 00)
MiraiConfigExtractorSORAArm.java> 00020fcc - 0000002d - 00017ef8 - /etc/rc.d/rc.local. (2F 65 74 63 2F 72 63 2E 64 2F 72 63 2E 6C 6F 63 61 6C 00)
MiraiConfigExtractorSORAArm.java> 00020fd4 - 0000002e - 00017f0c - g1abc4dmo35hnp2lie0kjf. (67 31 61 62 63 34 64 6D 6F 33 35 68 6E 70 32 6C 69 65 30 6B 6A 66 00)
MiraiConfigExtractorSORAArm.java> 00020fdc - 0000002f - 00017f24 - /dev/watchdog. (2F 64 65 76 2F 77 61 74 63 68 64 6F 67 00)
MiraiConfigExtractorSORAArm.java> 00020fe4 - 00000030 - 00017f34 - /dev/misc/watchdog. (2F 64 65 76 2F 6D 69 73 63 2F 77 61 74 63 68 64 6F 67 00)
MiraiConfigExtractorSORAArm.java> 00020fec - 00000031 - 00017f48 - /dev/FTWDT101_watchdog. (2F 64 65 76 2F 46 54 57 44 54 31 30 31 5F 77 61 74 63 68 64 6F 67 00)
MiraiConfigExtractorSORAArm.java> 00020ff4 - 00000032 - 00017f60 - /dev/netslink/. (2F 64 65 76 2F 6E 65 74 73 6C 69 6E 6B 2F 00)
MiraiConfigExtractorSORAArm.java> 00020ffc - 00000033 - 00017f70 - PRIVMSG. (50 52 49 56 4D 53 47 00)
MiraiConfigExtractorSORAArm.java> 00021004 - 00000034 - 00017f7c - GETLOCALIP."KILLA (47 45 54 4C 4F 43 41 4C 49 50 00 22 4B 49 4C 4C 41)
MiraiConfigExtractorSORAArm.java> 0002100c - 00000035 - 00017f88 - KILLATTK. (4B 49 4C 4C 41 54 54 4B 00)
MiraiConfigExtractorSORAArm.java> 00021014 - 00000036 - 00017f94 - Eats8. (45 61 74 73 38 00)
MiraiConfigExtractorSORAArm.java> 0002101c - 00000037 - 00017f9c - v[0v. (76 5B 30 76 00)
MiraiConfigExtractorSORAArm.java> 0002102c - 00000039 - 00017fa4 - 93OfjHZ2z. (39 33 4F 66 6A 48 5A 32 7A 00)
MiraiConfigExtractorSORAArm.java> 0002103c - 0000003b - 00017fc4 - WsGA4@F6F. (57 73 47 41 34 40 46 36 46 00)
MiraiConfigExtractorSORAArm.java> 00021044 - 0000003c - 00017fd0 - ACDB. (41 43 44 42 00)
MiraiConfigExtractorSORAArm.java> 0002104c - 0000003d - 00017fd8 - AbAd. (41 62 41 64 00)
MiraiConfigExtractorSORAArm.java> 00021054 - 0000003e - 00017fe0 - iaGv. (69 61 47 76 00)
MiraiConfigExtractorSORAArm.java> 00021034 - 0000003a - 00017fb0 - GhostWuzHere666 (47 68 6F 73 74 57 75 7A 48 65 72 65 36 36 36)
MiraiConfigExtractorSORAArm.java> 00020f44 - 0000001c - 00017e48 - G...B....CE...GD..F...v (47 11 14 17 42 15 12 19 1B 43 45 18 1E 06 47 44 13 1F 46 1D 10 1C 76)
MiraiConfigExtractorSORAArm.java> 0002119c - 00000067 - 00018788 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94. (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 3B 20 57 69 6E 36 34 3B 20 78 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 36 32 2E 30 2E 33 32 30 32 2E 39 34 00)
MiraiConfigExtractorSORAArm.java> 0002112c - 00000059 - 00018208 - Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36. (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 3B 20 57 4F 57 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 35 31 2E 30 2E 32 37 30 34 2E 31 30 33 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 00)
MiraiConfigExtractorSORAArm.java> 00021134 - 0000005a - 00018278 - Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36. (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 3B 20 57 4F 57 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 35 32 2E 30 2E 32 37 34 33 2E 31 31 36 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 00)
MiraiConfigExtractorSORAArm.java> 0002113c - 0000005b - 000182e8 - Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36." (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 31 3B 20 57 4F 57 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 35 31 2E 30 2E 32 37 30 34 2E 31 30 33 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 00 22)
MiraiConfigExtractorSORAArm.java> 00021144 - 0000005c - 00018358 - Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36." (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 31 3B 20 57 4F 57 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 35 32 2E 30 2E 32 37 34 33 2E 31 31 36 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 00 22)
MiraiConfigExtractorSORAArm.java> 0002114c - 0000005d - 000183c8 - Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.7 (KHTML, like Gecko) Version/9.1.2 Safari/601.7.7. (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 4D 61 63 69 6E 74 6F 73 68 3B 20 49 6E 74 65 6C 20 4D 61 63 20 4F 53 20 58 20 31 30 5F 31 31 5F 36 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 36 30 31 2E 37 2E 37 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 56 65 72 73 69 6F 6E 2F 39 2E 31 2E 32 20 53 61 66 61 72 69 2F 36 30 31 2E 37 2E 37 00)
MiraiConfigExtractorSORAArm.java> 00021154 - 0000005e - 00018440 - Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0). (4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 39 2E 30 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 35 2E 31 3B 20 54 72 69 64 65 6E 74 2F 35 2E 30 29 00)
MiraiConfigExtractorSORAArm.java> 0002115c - 0000005f - 00018484 - Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/4.0; GTB7.4; InfoPath.3; SV1; .NET CLR 3.4.53360; WOW64; en-US). (4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 39 2E 30 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 30 3B 20 54 72 69 64 65 6E 74 2F 34 2E 30 3B 20 47 54 42 37 2E 34 3B 20 49 6E 66 6F 50 61 74 68 2E 33 3B 20 53 56 31 3B 20 2E 4E 45 54 20 43 4C 52 20 33 2E 34 2E 35 33 33 36 30 3B 20 57 4F 57 36 34 3B 20 65 6E 2D 55 53 29 00)
MiraiConfigExtractorSORAArm.java> 00021164 - 00000060 - 00018500 - Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; FDM; MSIECrawler; Media Center PC 5.0). (4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 39 2E 30 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 31 3B 20 54 72 69 64 65 6E 74 2F 34 2E 30 3B 20 46 44 4D 3B 20 4D 53 49 45 43 72 61 77 6C 65 72 3B 20 4D 65 64 69 61 20 43 65 6E 74 65 72 20 50 43 20 35 2E 30 29 00)
MiraiConfigExtractorSORAArm.java> 0002116c - 00000061 - 00018568 - Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 4.4.58799; WOW64; en-US). (4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 39 2E 30 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 31 3B 20 54 72 69 64 65 6E 74 2F 34 2E 30 3B 20 47 54 42 37 2E 34 3B 20 49 6E 66 6F 50 61 74 68 2E 32 3B 20 53 56 31 3B 20 2E 4E 45 54 20 43 4C 52 20 34 2E 34 2E 35 38 37 39 39 3B 20 57 4F 57 36 34 3B 20 65 6E 2D 55 53 29 00)
MiraiConfigExtractorSORAArm.java> 00021174 - 00000062 - 000185e4 - Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; FunWebProducts). (4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 39 2E 30 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 31 3B 20 54 72 69 64 65 6E 74 2F 35 2E 30 3B 20 46 75 6E 57 65 62 50 72 6F 64 75 63 74 73 29 00)
MiraiConfigExtractorSORAArm.java> 0002117c - 00000063 - 00018638 - Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:25.0) Gecko/20100101 Firefox/25.0. (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 4D 61 63 69 6E 74 6F 73 68 3B 20 49 6E 74 65 6C 20 4D 61 63 20 4F 53 20 58 20 31 30 2E 36 3B 20 72 76 3A 32 35 2E 30 29 20 47 65 63 6B 6F 2F 32 30 31 30 30 31 30 31 20 46 69 72 65 66 6F 78 2F 32 35 2E 30 00)
MiraiConfigExtractorSORAArm.java> 00021184 - 00000064 - 0001868c - Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:21.0) Gecko/20100101 Firefox/21.0. (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 4D 61 63 69 6E 74 6F 73 68 3B 20 49 6E 74 65 6C 20 4D 61 63 20 4F 53 20 58 20 31 30 2E 38 3B 20 72 76 3A 32 31 2E 30 29 20 47 65 63 6B 6F 2F 32 30 31 30 30 31 30 31 20 46 69 72 65 66 6F 78 2F 32 31 2E 30 00)
MiraiConfigExtractorSORAArm.java> 0002118c - 00000065 - 000186e0 - Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0. (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 4D 61 63 69 6E 74 6F 73 68 3B 20 49 6E 74 65 6C 20 4D 61 63 20 4F 53 20 58 20 31 30 2E 38 3B 20 72 76 3A 32 34 2E 30 29 20 47 65 63 6B 6F 2F 32 30 31 30 30 31 30 31 20 46 69 72 65 66 6F 78 2F 32 34 2E 30 00)
MiraiConfigExtractorSORAArm.java> 00021194 - 00000066 - 00018734 - Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0. (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 4D 61 63 69 6E 74 6F 73 68 3B 20 49 6E 74 65 6C 20 4D 61 63 20 4F 53 20 58 20 31 30 5F 31 30 3B 20 72 76 3A 33 33 2E 30 29 20 47 65 63 6B 6F 2F 32 30 31 30 30 31 30 31 20 46 69 72 65 66 6F 78 2F 33 33 2E 30 00)
MiraiConfigExtractorSORAArm.java> 00020f34 - 0000001a - 00017e38 - ....v (19 11 1F 18 76)
MiraiConfigExtractorSORAArm.java> 00020f3c - 0000001b - 00017e40 - .....v (13 18 02 13 04 76)
MiraiConfigExtractorSORAArm.java> 00020f2c - 00000019 - 00017e2c - .......g (06 14 14 10 08 15 03 67)
MiraiConfigExtractorSORAArm.java> 00020e8c - 00000005 - 00017d00 - ......v (13 18 17 14 1A 13 76)
MiraiConfigExtractorSORAArm.java> 00020e94 - 00000006 - 00017d08 - ......v (05 0F 05 02 13 1B 76)
MiraiConfigExtractorSORAArm.java> 00020e9c - 00000007 - 00017d10 - ..v (05 1E 76)
MiraiConfigExtractorSORAArm.java> 00020e84 - 00000004 - 00017cf8 - .....v (05 1E 13 1A 1A 76)
MiraiConfigExtractorSORAArm.java> 00020eb4 - 0000000a - 00017d40 - ........v (18 15 19 04 04 13 15 02 76)
MiraiConfigExtractorSORAArm.java> 00020eac - 00000009 - 00017d28 - %9$7LV......V...V.....v (25 39 24 37 4C 56 17 06 06 1A 13 02 56 18 19 02 56 10 19 03 18 12 76)
MiraiConfigExtractorSORAArm.java> 00020ea4 - 00000008 - 00017d14 - Y...Y.......V%9$7v (59 14 1F 18 59 14 03 05 0F 14 19 0E 56 25 39 24 37 76)
MiraiConfigExtractorSORAArm.java> 00020e7c - 00000003 - 000187f0 - 5........V".V585v (35 19 18 18 13 15 02 13 12 56 22 19 56 35 38 35 76)
MiraiConfigExtractorSORAArm.java> 00020f1c - 00000017 - 00017e08 - Y...Y........v (59 12 13 00 59 01 17 02 15 1E 12 19 11 76)
MiraiConfigExtractorSORAArm.java> 00020f24 - 00000018 - 00017e18 - Y...Y....Y........v (59 12 13 00 59 1B 1F 05 15 59 01 17 02 15 1E 12 19 11 76)
MiraiConfigExtractorSORAArm.java> 00020e6c - 00000001 - 00017cf0 - sV (73 56)
MiraiConfigExtractorSORAArm.java> Finished!
```

</details>

## `mirai_config_extractor_sora_arm_qiling.py`

<details>

<summary><code>mirai_config_extractor_sora_arm_qiling.log</code> (key: <code>0xdedefbaf</code>)</summary>

```
mirai_config_extractor_sora_arm_qiling.py> Running...
located decryption function: FUN_00013218
encrypted data (14): bytearray(b'\x00\x07;!&71t\x11:3=:1t\x05!1&-T')
decrypted data (14): bytearray(b'TSource Engine Query\x00')
encrypted data (4e): bytearray(b'QGVaMMIKG\n\x05"')
decrypted data (4e): bytearray(b'\x05\x13\x025\x19\x19\x1d\x1f\x13^Qv')
encrypted data (4f): bytearray(b'PGDPGQJ\x18"')
decrypted data (4f): bytearray(b'\x04\x13\x10\x04\x13\x05\x1eLv')
encrypted data (50): bytearray(b'NMACVKML\x18"')
decrypted data (50): bytearray(b'\x1a\x19\x15\x17\x02\x1f\x19\x18Lv')
encrypted data (51): bytearray(b'QGV\x0fAMMIKG\x18"')
decrypted data (51): bytearray(b'\x05\x13\x02[\x15\x19\x19\x1d\x1f\x13Lv')
encrypted data (52): bytearray(b'AMLVGLV\x0fNGLEVJ\x18"')
decrypted data (52): bytearray(b'\x15\x19\x18\x02\x13\x18\x02[\x1a\x13\x18\x11\x02\x1eLv')
encrypted data (53): bytearray(b'VPCLQDGP\x0fGLAMFKLE\x18"')
decrypted data (53): bytearray(b'\x02\x04\x17\x18\x05\x10\x13\x04[\x13\x18\x15\x19\x12\x1f\x18\x11Lv')
encrypted data (54): bytearray(b'AJWLIGF"')
decrypted data (54): bytearray(b'\x15\x1e\x03\x18\x1d\x13\x12v')
encrypted data (55): bytearray(b'IGGR\x0fCNKTG"')
decrypted data (55): bytearray(b'\x1d\x13\x13\x06[\x17\x1a\x1f\x00\x13v')
encrypted data (56): bytearray(b'AMLLGAVKML\x18"')
decrypted data (56): bytearray(b'\x15\x19\x18\x18\x13\x15\x02\x1f\x19\x18Lv')
encrypted data (57): bytearray(b'QGPTGP\x18\x02FMQCPPGQV"')
decrypted data (57): bytearray(b'\x05\x13\x04\x00\x13\x04LV\x12\x19\x05\x17\x04\x04\x13\x05\x02v')
encrypted data (4a): bytearray(b'aMLLGAVKML\x18\x02IGGR\x0fCNKTG"')
decrypted data (4a): bytearray(b'5\x19\x18\x18\x13\x15\x02\x1f\x19\x18LV\x1d\x13\x13\x06[\x17\x1a\x1f\x00\x13v')
encrypted data (4b): bytearray(b'cAAGRV\x18\x02VGZV\rJVON\x0eCRRNKACVKML\rZJVON\tZON\x0eCRRNKACVKML\rZON\x19S\x1f\x12\x0c\x1b\x0eKOCEG\rUG@R\x0e\x08\r\x08\x19S\x1f\x12\x0c\x1a"')
decrypted data (4b): bytearray(b'7\x15\x15\x13\x06\x02LV\x02\x13\x0e\x02Y\x1e\x02\x1b\x1aZ\x17\x06\x06\x1a\x1f\x15\x17\x02\x1f\x19\x18Y\x0e\x1e\x02\x1b\x1a]\x0e\x1b\x1aZ\x17\x06\x06\x1a\x1f\x15\x17\x02\x1f\x19\x18Y\x0e\x1b\x1aM\x07KFXOZ\x1f\x1b\x17\x11\x13Y\x01\x13\x14\x06Z\\Y\\M\x07KFXNv')
encrypted data (4c): bytearray(b'cAAGRV\x0fnCLEWCEG\x18\x02GL\x0fwq\x0eGL\x19S\x1f\x12\x0c\x1a"')
decrypted data (4c): bytearray(b'7\x15\x15\x13\x06\x02[:\x17\x18\x11\x03\x17\x11\x13LV\x13\x18[#%Z\x13\x18M\x07KFXNv')
encrypted data (4d): bytearray(b'aMLVGLV\x0fv[RG\x18\x02CRRNKACVKML\rZ\x0fUUU\x0fDMPO\x0fWPNGLAMFGF"')
decrypted data (4d): bytearray(b'5\x19\x18\x02\x13\x18\x02["\x0f\x06\x13LV\x17\x06\x06\x1a\x1f\x15\x17\x02\x1f\x19\x18Y\x0e[\x01\x01\x01[\x10\x19\x04\x1b[\x03\x04\x1a\x13\x18\x15\x19\x12\x13\x12v')
encrypted data (e): bytearray(b'{1,1T')
decrypted data (e): bytearray(b'/exe\x00')
encrypted data (d): bytearray(b'{$&;7{T')
decrypted data (d): bytearray(b'/proc/\x00')
encrypted data (d): bytearray(b'/proc/\x00')
decrypted data (d): bytearray(b'{$&;7{T')
encrypted data (e): bytearray(b'/exe\x00')
decrypted data (e): bytearray(b'{1,1T')
encrypted data (1e): bytearray(b'z5:=91T')
decrypted data (1e): bytearray(b'.anime\x00')
encrypted data (20): bytearray(b'FTPjGNRGP"')
decrypted data (20): bytearray(b'\x12\x00\x04>\x13\x1a\x06\x13\x04v')
encrypted data (21): bytearray(b'lKeeGp\x14\x1bZF"')
decrypted data (21): bytearray(b'8\x1f11\x13$@O\x0e\x12v')
encrypted data (22): bytearray(b'\x13\x11\x11\x15qMPCnmcfgp"')
decrypted data (22): bytearray(b'GEEA%\x19\x04\x17:9723$v')
encrypted data (23): bytearray(b'lKeeGpF\x12LIQ\x13\x11\x11\x15"')
decrypted data (23): bytearray(b'8\x1f11\x13$\x12F\x18\x1d\x05GEEAv')
encrypted data (24): bytearray(b'z\x13\x1bk\x10\x11\x1b\x13\x10\x16wkw"')
decrypted data (24): bytearray(b'.GO?DEOGDB#?#v')
encrypted data (25): bytearray(b'kW{EWHGkSL"')
decrypted data (25): bytearray(b'?\x03/\x11\x03\x1c\x13?\x07\x18v')
encrypted data (26): bytearray(b'\x13\x16dC"')
decrypted data (26): bytearray(b'GB0\x17v')
encrypted data (27): bytearray(b'AAcf"')
decrypted data (27): bytearray(b'\x15\x1572v')
encrypted data (2a): bytearray(b'\rRPMA\rLGV\rPMWVG"')
decrypted data (2a): bytearray(b'Y\x06\x04\x19\x15Y\x18\x13\x02Y\x04\x19\x03\x02\x13v')
encrypted data (2b): bytearray(b'\rRPMA\rARWKLDM"')
decrypted data (2b): bytearray(b'Y\x06\x04\x19\x15Y\x15\x06\x03\x1f\x18\x10\x19v')
encrypted data (2c): bytearray(b'`memokrq"')
decrypted data (2c): bytearray(b'4919;?&%v')
encrypted data (2d): bytearray(b'\rGVA\rPA\x0cF\rPA\x0cNMACN"')
decrypted data (2d): bytearray(b'Y\x13\x02\x15Y\x04\x15X\x12Y\x04\x15X\x1a\x19\x15\x17\x1av')
encrypted data (2e): bytearray(b'E\x13C@A\x16FOM\x11\x17JLR\x10NKG\x12IHD"')
decrypted data (2e): bytearray(b'\x11G\x17\x14\x15B\x12\x1b\x19EC\x1e\x18\x06D\x1a\x1f\x13F\x1d\x1c\x10v')
encrypted data (2f): bytearray(b'\rFGT\rUCVAJFME"')
decrypted data (2f): bytearray(b'Y\x12\x13\x00Y\x01\x17\x02\x15\x1e\x12\x19\x11v')
encrypted data (30): bytearray(b'\rFGT\rOKQA\rUCVAJFME"')
decrypted data (30): bytearray(b'Y\x12\x13\x00Y\x1b\x1f\x05\x15Y\x01\x17\x02\x15\x1e\x12\x19\x11v')
encrypted data (31): bytearray(b'\rFGT\rdvufv\x13\x12\x13}UCVAJFME"')
decrypted data (31): bytearray(b'Y\x12\x13\x00Y0"!2"GFG)\x01\x17\x02\x15\x1e\x12\x19\x11v')
encrypted data (32): bytearray(b'\rFGT\rLGVQNKLI\r"')
decrypted data (32): bytearray(b'Y\x12\x13\x00Y\x18\x13\x02\x05\x1a\x1f\x18\x1dYv')
encrypted data (33): bytearray(b'rpktoqe"')
decrypted data (33): bytearray(b'&$? ;%1v')
encrypted data (34): bytearray(b'egvnmacnkr"')
decrypted data (34): bytearray(b'13":957:?&v')
encrypted data (35): bytearray(b'iknncvvi"')
decrypted data (35): bytearray(b'=?::7""=v')
encrypted data (36): bytearray(b'gCVQ\x1a"')
decrypted data (36): bytearray(b'3\x17\x02\x05Nv')
encrypted data (37): bytearray(b'Ty\x12T"')
decrypted data (37): bytearray(b'\x00-F\x00v')
encrypted data (39): bytearray(b'\x1b\x11mDHjx\x10X"')
decrypted data (39): bytearray(b'OE9\x10\x1c>,D\x0cv')
encrypted data (3b): bytearray(b'uQec\x16bd\x14d"')
decrypted data (3b): bytearray(b'!\x0517B60@0v')
encrypted data (3c): bytearray(b'caf`"')
decrypted data (3c): bytearray(b'7524v')
encrypted data (3d): bytearray(b'c@cF"')
decrypted data (3d): bytearray(b'7\x147\x12v')
encrypted data (3e): bytearray(b'KCeT"')
decrypted data (3e): bytearray(b'\x1f\x171\x00v')
encrypted data (3a): bytearray(b'eJMQVuWXjGPG\x14\x14\x14')
decrypted data (3a): bytearray(b'1\x1e\x19\x05\x02!\x03\x0c>\x13\x04\x13@@@')
encrypted data (67): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\nuKLFMUQ\x02lv\x02\x13\x12\x0c\x12\x19\x02uKL\x14\x16\x19\x02Z\x14\x16\x0b\x02cRRNGuG@iKV\r\x17\x11\x15\x0c\x11\x14\x02\nijvon\x0e\x02NKIG\x02eGAIM\x0b\x02aJPMOG\r\x14\x10\x0c\x12\x0c\x11\x10\x12\x10\x0c\x1b\x16"')
decrypted data (67): bytearray(b';\x19\x0c\x1f\x1a\x1a\x17YCXFV^!\x1f\x18\x12\x19\x01\x05V8"VGFXFMV!\x1f\x18@BMV\x0e@B_V7\x06\x06\x1a\x13!\x13\x14=\x1f\x02YCEAXE@V^=>";:ZV\x1a\x1f\x1d\x13V1\x13\x15\x1d\x19_V5\x1e\x04\x19\x1b\x13Y@DXFXEDFDXOBv')
encrypted data (59): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\nuKLFMUQ\x02lv\x02\x13\x12\x0c\x12\x19\x02umu\x14\x16\x0b\x02cRRNGuG@iKV\r\x17\x11\x15\x0c\x11\x14\x02\nijvon\x0e\x02NKIG\x02eGAIM\x0b\x02aJPMOG\r\x17\x13\x0c\x12\x0c\x10\x15\x12\x16\x0c\x13\x12\x11\x02qCDCPK\r\x17\x11\x15\x0c\x11\x14"')
decrypted data (59): bytearray(b';\x19\x0c\x1f\x1a\x1a\x17YCXFV^!\x1f\x18\x12\x19\x01\x05V8"VGFXFMV!9!@B_V7\x06\x06\x1a\x13!\x13\x14=\x1f\x02YCEAXE@V^=>";:ZV\x1a\x1f\x1d\x13V1\x13\x15\x1d\x19_V5\x1e\x04\x19\x1b\x13YCGXFXDAFBXGFEV%\x17\x10\x17\x04\x1fYCEAXE@v')
encrypted data (5a): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\nuKLFMUQ\x02lv\x02\x13\x12\x0c\x12\x19\x02umu\x14\x16\x0b\x02cRRNGuG@iKV\r\x17\x11\x15\x0c\x11\x14\x02\nijvon\x0e\x02NKIG\x02eGAIM\x0b\x02aJPMOG\r\x17\x10\x0c\x12\x0c\x10\x15\x16\x11\x0c\x13\x13\x14\x02qCDCPK\r\x17\x11\x15\x0c\x11\x14"')
decrypted data (5a): bytearray(b';\x19\x0c\x1f\x1a\x1a\x17YCXFV^!\x1f\x18\x12\x19\x01\x05V8"VGFXFMV!9!@B_V7\x06\x06\x1a\x13!\x13\x14=\x1f\x02YCEAXE@V^=>";:ZV\x1a\x1f\x1d\x13V1\x13\x15\x1d\x19_V5\x1e\x04\x19\x1b\x13YCDXFXDABEXGG@V%\x17\x10\x17\x04\x1fYCEAXE@v')
encrypted data (5b): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\nuKLFMUQ\x02lv\x02\x14\x0c\x13\x19\x02umu\x14\x16\x0b\x02cRRNGuG@iKV\r\x17\x11\x15\x0c\x11\x14\x02\nijvon\x0e\x02NKIG\x02eGAIM\x0b\x02aJPMOG\r\x17\x13\x0c\x12\x0c\x10\x15\x12\x16\x0c\x13\x12\x11\x02qCDCPK\r\x17\x11\x15\x0c\x11\x14"')
decrypted data (5b): bytearray(b';\x19\x0c\x1f\x1a\x1a\x17YCXFV^!\x1f\x18\x12\x19\x01\x05V8"V@XGMV!9!@B_V7\x06\x06\x1a\x13!\x13\x14=\x1f\x02YCEAXE@V^=>";:ZV\x1a\x1f\x1d\x13V1\x13\x15\x1d\x19_V5\x1e\x04\x19\x1b\x13YCGXFXDAFBXGFEV%\x17\x10\x17\x04\x1fYCEAXE@v')
encrypted data (5c): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\nuKLFMUQ\x02lv\x02\x14\x0c\x13\x19\x02umu\x14\x16\x0b\x02cRRNGuG@iKV\r\x17\x11\x15\x0c\x11\x14\x02\nijvon\x0e\x02NKIG\x02eGAIM\x0b\x02aJPMOG\r\x17\x10\x0c\x12\x0c\x10\x15\x16\x11\x0c\x13\x13\x14\x02qCDCPK\r\x17\x11\x15\x0c\x11\x14"')
decrypted data (5c): bytearray(b';\x19\x0c\x1f\x1a\x1a\x17YCXFV^!\x1f\x18\x12\x19\x01\x05V8"V@XGMV!9!@B_V7\x06\x06\x1a\x13!\x13\x14=\x1f\x02YCEAXE@V^=>";:ZV\x1a\x1f\x1d\x13V1\x13\x15\x1d\x19_V5\x1e\x04\x19\x1b\x13YCDXFXDABEXGG@V%\x17\x10\x17\x04\x1fYCEAXE@v')
encrypted data (5d): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\noCAKLVMQJ\x19\x02kLVGN\x02oCA\x02mq\x02z\x02\x13\x12}\x13\x13}\x14\x0b\x02cRRNGuG@iKV\r\x14\x12\x13\x0c\x15\x0c\x15\x02\nijvon\x0e\x02NKIG\x02eGAIM\x0b\x02tGPQKML\r\x1b\x0c\x13\x0c\x10\x02qCDCPK\r\x14\x12\x13\x0c\x15\x0c\x15"')
decrypted data (5d): bytearray(b';\x19\x0c\x1f\x1a\x1a\x17YCXFV^;\x17\x15\x1f\x18\x02\x19\x05\x1eMV?\x18\x02\x13\x1aV;\x17\x15V9%V.VGF)GG)@_V7\x06\x06\x1a\x13!\x13\x14=\x1f\x02Y@FGXAXAV^=>";:ZV\x1a\x1f\x1d\x13V1\x13\x15\x1d\x19_V \x13\x04\x05\x1f\x19\x18YOXGXDV%\x17\x10\x17\x04\x1fY@FGXAXAv')
encrypted data (5e): bytearray(b'oMXKNNC\r\x16\x0c\x12\x02\nAMORCVK@NG\x19\x02oqkg\x02\x1b\x0c\x12\x19\x02uKLFMUQ\x02lv\x02\x17\x0c\x13\x19\x02vPKFGLV\r\x17\x0c\x12\x0b"')
decrypted data (5e): bytearray(b';\x19\x0c\x1f\x1a\x1a\x17YBXFV^\x15\x19\x1b\x06\x17\x02\x1f\x14\x1a\x13MV;%?3VOXFMV!\x1f\x18\x12\x19\x01\x05V8"VCXGMV"\x04\x1f\x12\x13\x18\x02YCXF_v')
encrypted data (5f): bytearray(b'oMXKNNC\r\x16\x0c\x12\x02\nAMORCVK@NG\x19\x02oqkg\x02\x1b\x0c\x12\x19\x02uKLFMUQ\x02lv\x02\x14\x0c\x12\x19\x02vPKFGLV\r\x16\x0c\x12\x19\x02ev`\x15\x0c\x16\x19\x02kLDMrCVJ\x0c\x11\x19\x02qt\x13\x19\x02\x0clgv\x02anp\x02\x11\x0c\x16\x0c\x17\x11\x11\x14\x12\x19\x02umu\x14\x16\x19\x02GL\x0fwq\x0b"')
decrypted data (5f): bytearray(b';\x19\x0c\x1f\x1a\x1a\x17YBXFV^\x15\x19\x1b\x06\x17\x02\x1f\x14\x1a\x13MV;%?3VOXFMV!\x1f\x18\x12\x19\x01\x05V8"V@XFMV"\x04\x1f\x12\x13\x18\x02YBXFMV1"4AXBMV?\x18\x10\x19&\x17\x02\x1eXEMV% GMVX83"V5:$VEXBXCEE@FMV!9!@BMV\x13\x18[#%_v')
encrypted data (60): bytearray(b'oMXKNNC\r\x16\x0c\x12\x02\nAMORCVK@NG\x19\x02oqkg\x02\x1b\x0c\x12\x19\x02uKLFMUQ\x02lv\x02\x14\x0c\x13\x19\x02vPKFGLV\r\x16\x0c\x12\x19\x02dfo\x19\x02oqkgaPCUNGP\x19\x02oGFKC\x02aGLVGP\x02ra\x02\x17\x0c\x12\x0b"')
decrypted data (60): bytearray(b';\x19\x0c\x1f\x1a\x1a\x17YBXFV^\x15\x19\x1b\x06\x17\x02\x1f\x14\x1a\x13MV;%?3VOXFMV!\x1f\x18\x12\x19\x01\x05V8"V@XGMV"\x04\x1f\x12\x13\x18\x02YBXFMV02;MV;%?35\x04\x17\x01\x1a\x13\x04MV;\x13\x12\x1f\x17V5\x13\x18\x02\x13\x04V&5VCXF_v')
encrypted data (61): bytearray(b'oMXKNNC\r\x16\x0c\x12\x02\nAMORCVK@NG\x19\x02oqkg\x02\x1b\x0c\x12\x19\x02uKLFMUQ\x02lv\x02\x14\x0c\x13\x19\x02vPKFGLV\r\x16\x0c\x12\x19\x02ev`\x15\x0c\x16\x19\x02kLDMrCVJ\x0c\x10\x19\x02qt\x13\x19\x02\x0clgv\x02anp\x02\x16\x0c\x16\x0c\x17\x1a\x15\x1b\x1b\x19\x02umu\x14\x16\x19\x02GL\x0fwq\x0b"')
decrypted data (61): bytearray(b';\x19\x0c\x1f\x1a\x1a\x17YBXFV^\x15\x19\x1b\x06\x17\x02\x1f\x14\x1a\x13MV;%?3VOXFMV!\x1f\x18\x12\x19\x01\x05V8"V@XGMV"\x04\x1f\x12\x13\x18\x02YBXFMV1"4AXBMV?\x18\x10\x19&\x17\x02\x1eXDMV% GMVX83"V5:$VBXBXCNAOOMV!9!@BMV\x13\x18[#%_v')
encrypted data (62): bytearray(b'oMXKNNC\r\x16\x0c\x12\x02\nAMORCVK@NG\x19\x02oqkg\x02\x1b\x0c\x12\x19\x02uKLFMUQ\x02lv\x02\x14\x0c\x13\x19\x02vPKFGLV\r\x17\x0c\x12\x19\x02dWLuG@rPMFWAVQ\x0b"')
decrypted data (62): bytearray(b';\x19\x0c\x1f\x1a\x1a\x17YBXFV^\x15\x19\x1b\x06\x17\x02\x1f\x14\x1a\x13MV;%?3VOXFMV!\x1f\x18\x12\x19\x01\x05V8"V@XGMV"\x04\x1f\x12\x13\x18\x02YCXFMV0\x03\x18!\x13\x14&\x04\x19\x12\x03\x15\x02\x05_v')
encrypted data (63): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\noCAKLVMQJ\x19\x02kLVGN\x02oCA\x02mq\x02z\x02\x13\x12\x0c\x14\x19\x02PT\x18\x10\x17\x0c\x12\x0b\x02eGAIM\r\x10\x12\x13\x12\x12\x13\x12\x13\x02dKPGDMZ\r\x10\x17\x0c\x12"')
decrypted data (63): bytearray(b';\x19\x0c\x1f\x1a\x1a\x17YCXFV^;\x17\x15\x1f\x18\x02\x19\x05\x1eMV?\x18\x02\x13\x1aV;\x17\x15V9%V.VGFX@MV\x04\x00LDCXF_V1\x13\x15\x1d\x19YDFGFFGFGV0\x1f\x04\x13\x10\x19\x0eYDCXFv')
encrypted data (64): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\noCAKLVMQJ\x19\x02kLVGN\x02oCA\x02mq\x02z\x02\x13\x12\x0c\x1a\x19\x02PT\x18\x10\x13\x0c\x12\x0b\x02eGAIM\r\x10\x12\x13\x12\x12\x13\x12\x13\x02dKPGDMZ\r\x10\x13\x0c\x12"')
decrypted data (64): bytearray(b';\x19\x0c\x1f\x1a\x1a\x17YCXFV^;\x17\x15\x1f\x18\x02\x19\x05\x1eMV?\x18\x02\x13\x1aV;\x17\x15V9%V.VGFXNMV\x04\x00LDGXF_V1\x13\x15\x1d\x19YDFGFFGFGV0\x1f\x04\x13\x10\x19\x0eYDGXFv')
encrypted data (65): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\noCAKLVMQJ\x19\x02kLVGN\x02oCA\x02mq\x02z\x02\x13\x12\x0c\x1a\x19\x02PT\x18\x10\x16\x0c\x12\x0b\x02eGAIM\r\x10\x12\x13\x12\x12\x13\x12\x13\x02dKPGDMZ\r\x10\x16\x0c\x12"')
decrypted data (65): bytearray(b';\x19\x0c\x1f\x1a\x1a\x17YCXFV^;\x17\x15\x1f\x18\x02\x19\x05\x1eMV?\x18\x02\x13\x1aV;\x17\x15V9%V.VGFXNMV\x04\x00LDBXF_V1\x13\x15\x1d\x19YDFGFFGFGV0\x1f\x04\x13\x10\x19\x0eYDBXFv')
encrypted data (66): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\noCAKLVMQJ\x19\x02kLVGN\x02oCA\x02mq\x02z\x02\x13\x12}\x13\x12\x19\x02PT\x18\x11\x11\x0c\x12\x0b\x02eGAIM\r\x10\x12\x13\x12\x12\x13\x12\x13\x02dKPGDMZ\r\x11\x11\x0c\x12"')
decrypted data (66): bytearray(b';\x19\x0c\x1f\x1a\x1a\x17YCXFV^;\x17\x15\x1f\x18\x02\x19\x05\x1eMV?\x18\x02\x13\x1aV;\x17\x15V9%V.VGF)GFMV\x04\x00LEEXF_V1\x13\x15\x1d\x19YDFGFFGFGV0\x1f\x04\x13\x10\x19\x0eYEEXFv')
encrypted data (1a): bytearray(b';3=:T')
decrypted data (1a): bytearray(b'ogin\x00')
encrypted data (1b): bytearray(b'1: 1&T')
decrypted data (1b): bytearray(b'enter\x00')
encrypted data (19): bytearray(b'$662*7!E')
decrypted data (19): bytearray(b'pbbf~cu\x11')
encrypted data (5): bytearray(b'1:5681T')
decrypted data (5): bytearray(b'enable\x00')
encrypted data (6): bytearray(b"\'-\' 19T")
decrypted data (6): bytearray(b'system\x00')
encrypted data (7): bytearray(b"\'<T")
decrypted data (7): bytearray(b'sh\x00')
encrypted data (4): bytearray(b"\'<188T")
decrypted data (4): bytearray(b'shell\x00')
encrypted data (a): bytearray(b':7;&&17 T')
decrypted data (a): bytearray(b'ncorrect\x00')
encrypted data (9): bytearray(b'\x07\x1b\x06\x15nt5$$81 t:; t2;!:0T')
decrypted data (9): bytearray(b'SORA: applet not found\x00')
encrypted data (2): bytearray(b'[\x1c')
decrypted data (2): bytearray(b'\x0fH')
encrypted data (8): bytearray(b"{6=:{6!\'-6;,t\x07\x1b\x06\x15T")
decrypted data (8): bytearray(b'/bin/busybox SORA\x00')
encrypted data (3): bytearray(b'\x17;::17 10t\x00;t\x17\x1a\x17T')
decrypted data (3): bytearray(b'Connected To CNC\x00')
encrypted data (18): bytearray(b'{01"{9=\'7{#5 7<0;3T')
decrypted data (18): bytearray(b'/dev/misc/watchdog\x00')
encrypted data (1): bytearray(b'Qt')
decrypted data (1): bytearray(b'\x05 ')
mirai_config_extractor_sora_arm_qiling.py> Finished!
```

</details>

<details>

<summary><code>mirai_config_extractor_sora_arm_qiling.log</code> (key: <code>0xdeadbeef</code>)</summary>

```
mirai_config_extractor_sora_arm_qiling.py> Running...
located decryption function: FUN_00013218
encrypted data (14): bytearray(b'\x00\x07;!&71t\x11:3=:1t\x05!1&-T')
decrypted data (14): bytearray(b'"%\x19\x03\x04\x15\x13V3\x18\x11\x1f\x18\x13V\'\x03\x13\x04\x0fv')
encrypted data (4e): bytearray(b'QGVaMMIKG\n\x05"')
decrypted data (4e): bytearray(b"setCookie(\'\x00")
encrypted data (4f): bytearray(b'PGDPGQJ\x18"')
decrypted data (4f): bytearray(b'refresh:\x00')
encrypted data (50): bytearray(b'NMACVKML\x18"')
decrypted data (50): bytearray(b'location:\x00')
encrypted data (51): bytearray(b'QGV\x0fAMMIKG\x18"')
decrypted data (51): bytearray(b'set-cookie:\x00')
encrypted data (52): bytearray(b'AMLVGLV\x0fNGLEVJ\x18"')
decrypted data (52): bytearray(b'content-length:\x00')
encrypted data (53): bytearray(b'VPCLQDGP\x0fGLAMFKLE\x18"')
decrypted data (53): bytearray(b'transfer-encoding:\x00')
encrypted data (54): bytearray(b'AJWLIGF"')
decrypted data (54): bytearray(b'chunked\x00')
encrypted data (55): bytearray(b'IGGR\x0fCNKTG"')
decrypted data (55): bytearray(b'keep-alive\x00')
encrypted data (56): bytearray(b'AMLLGAVKML\x18"')
decrypted data (56): bytearray(b'connection:\x00')
encrypted data (57): bytearray(b'QGPTGP\x18\x02FMQCPPGQV"')
decrypted data (57): bytearray(b'server: dosarrest\x00')
encrypted data (4a): bytearray(b'aMLLGAVKML\x18\x02IGGR\x0fCNKTG"')
decrypted data (4a): bytearray(b'Connection: keep-alive\x00')
encrypted data (4b): bytearray(b'cAAGRV\x18\x02VGZV\rJVON\x0eCRRNKACVKML\rZJVON\tZON\x0eCRRNKACVKML\rZON\x19S\x1f\x12\x0c\x1b\x0eKOCEG\rUG@R\x0e\x08\r\x08\x19S\x1f\x12\x0c\x1a"')
decrypted data (4b): bytearray(b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\x00')
encrypted data (4c): bytearray(b'cAAGRV\x0fnCLEWCEG\x18\x02GL\x0fwq\x0eGL\x19S\x1f\x12\x0c\x1a"')
decrypted data (4c): bytearray(b'Accept-Language: en-US,en;q=0.8\x00')
encrypted data (4d): bytearray(b'aMLVGLV\x0fv[RG\x18\x02CRRNKACVKML\rZ\x0fUUU\x0fDMPO\x0fWPNGLAMFGF"')
decrypted data (4d): bytearray(b'Content-Type: application/x-www-form-urlencoded\x00')
encrypted data (e): bytearray(b'{1,1T')
decrypted data (e): bytearray(b'Y\x13\x0e\x13v')
encrypted data (d): bytearray(b'{$&;7{T')
decrypted data (d): bytearray(b'Y\x06\x04\x19\x15Yv')
encrypted data (d): bytearray(b'Y\x06\x04\x19\x15Yv')
decrypted data (d): bytearray(b'{$&;7{T')
encrypted data (e): bytearray(b'Y\x13\x0e\x13v')
decrypted data (e): bytearray(b'{1,1T')
encrypted data (1e): bytearray(b'z5:=91T')
decrypted data (1e): bytearray(b'X\x17\x18\x1f\x1b\x13v')
encrypted data (20): bytearray(b'FTPjGNRGP"')
decrypted data (20): bytearray(b'dvrHelper\x00')
encrypted data (21): bytearray(b'lKeeGp\x14\x1bZF"')
decrypted data (21): <censored>
encrypted data (22): bytearray(b'\x13\x11\x11\x15qMPCnmcfgp"')
decrypted data (22): bytearray(b'1337SoraLOADER\x00')
encrypted data (23): bytearray(b'lKeeGpF\x12LIQ\x13\x11\x11\x15"')
decrypted data (23): <censored>
encrypted data (24): bytearray(b'z\x13\x1bk\x10\x11\x1b\x13\x10\x16wkw"')
decrypted data (24): bytearray(b'X19I239124UIU\x00')
encrypted data (25): bytearray(b'kW{EWHGkSL"')
decrypted data (25): bytearray(b'IuYgujeIqn\x00')
encrypted data (26): bytearray(b'\x13\x16dC"')
decrypted data (26): bytearray(b'14Fa\x00')
encrypted data (27): bytearray(b'AAcf"')
decrypted data (27): bytearray(b'ccAD\x00')
encrypted data (2a): bytearray(b'\rRPMA\rLGV\rPMWVG"')
decrypted data (2a): bytearray(b'/proc/net/route\x00')
encrypted data (2b): bytearray(b'\rRPMA\rARWKLDM"')
decrypted data (2b): bytearray(b'/proc/cpuinfo\x00')
encrypted data (2c): bytearray(b'`memokrq"')
decrypted data (2c): bytearray(b'BOGOMIPS\x00')
encrypted data (2d): bytearray(b'\rGVA\rPA\x0cF\rPA\x0cNMACN"')
decrypted data (2d): bytearray(b'/etc/rc.d/rc.local\x00')
encrypted data (2e): bytearray(b'E\x13C@A\x16FOM\x11\x17JLR\x10NKG\x12IHD"')
decrypted data (2e): bytearray(b'g1abc4dmo35hnp2lie0kjf\x00')
encrypted data (2f): bytearray(b'\rFGT\rUCVAJFME"')
decrypted data (2f): bytearray(b'/dev/watchdog\x00')
encrypted data (30): bytearray(b'\rFGT\rOKQA\rUCVAJFME"')
decrypted data (30): bytearray(b'/dev/misc/watchdog\x00')
encrypted data (31): bytearray(b'\rFGT\rdvufv\x13\x12\x13}UCVAJFME"')
decrypted data (31): bytearray(b'/dev/FTWDT101_watchdog\x00')
encrypted data (32): bytearray(b'\rFGT\rLGVQNKLI\r"')
decrypted data (32): bytearray(b'/dev/netslink/\x00')
encrypted data (33): bytearray(b'rpktoqe"')
decrypted data (33): bytearray(b'PRIVMSG\x00')
encrypted data (34): bytearray(b'egvnmacnkr"')
decrypted data (34): bytearray(b'GETLOCALIP\x00')
encrypted data (35): bytearray(b'iknncvvi"')
decrypted data (35): bytearray(b'KILLATTK\x00')
encrypted data (36): bytearray(b'gCVQ\x1a"')
decrypted data (36): bytearray(b'Eats8\x00')
encrypted data (37): bytearray(b'Ty\x12T"')
decrypted data (37): bytearray(b'v[0v\x00')
encrypted data (39): bytearray(b'\x1b\x11mDHjx\x10X"')
decrypted data (39): bytearray(b'93OfjHZ2z\x00')
encrypted data (3b): bytearray(b'uQec\x16bd\x14d"')
decrypted data (3b): bytearray(b'WsGA4@F6F\x00')
encrypted data (3c): bytearray(b'caf`"')
decrypted data (3c): bytearray(b'ACDB\x00')
encrypted data (3d): bytearray(b'c@cF"')
decrypted data (3d): bytearray(b'AbAd\x00')
encrypted data (3e): bytearray(b'KCeT"')
decrypted data (3e): bytearray(b'iaGv\x00')
encrypted data (3a): bytearray(b'eJMQVuWXjGPG\x14\x14\x14')
decrypted data (3a): bytearray(b'GhostWuzHere666')
encrypted data (67): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\nuKLFMUQ\x02lv\x02\x13\x12\x0c\x12\x19\x02uKL\x14\x16\x19\x02Z\x14\x16\x0b\x02cRRNGuG@iKV\r\x17\x11\x15\x0c\x11\x14\x02\nijvon\x0e\x02NKIG\x02eGAIM\x0b\x02aJPMOG\r\x14\x10\x0c\x12\x0c\x11\x10\x12\x10\x0c\x1b\x16"')
decrypted data (67): bytearray(b'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94\x00')
encrypted data (59): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\nuKLFMUQ\x02lv\x02\x13\x12\x0c\x12\x19\x02umu\x14\x16\x0b\x02cRRNGuG@iKV\r\x17\x11\x15\x0c\x11\x14\x02\nijvon\x0e\x02NKIG\x02eGAIM\x0b\x02aJPMOG\r\x17\x13\x0c\x12\x0c\x10\x15\x12\x16\x0c\x13\x12\x11\x02qCDCPK\r\x17\x11\x15\x0c\x11\x14"')
decrypted data (59): bytearray(b'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36\x00')
encrypted data (5a): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\nuKLFMUQ\x02lv\x02\x13\x12\x0c\x12\x19\x02umu\x14\x16\x0b\x02cRRNGuG@iKV\r\x17\x11\x15\x0c\x11\x14\x02\nijvon\x0e\x02NKIG\x02eGAIM\x0b\x02aJPMOG\r\x17\x10\x0c\x12\x0c\x10\x15\x16\x11\x0c\x13\x13\x14\x02qCDCPK\r\x17\x11\x15\x0c\x11\x14"')
decrypted data (5a): bytearray(b'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36\x00')
encrypted data (5b): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\nuKLFMUQ\x02lv\x02\x14\x0c\x13\x19\x02umu\x14\x16\x0b\x02cRRNGuG@iKV\r\x17\x11\x15\x0c\x11\x14\x02\nijvon\x0e\x02NKIG\x02eGAIM\x0b\x02aJPMOG\r\x17\x13\x0c\x12\x0c\x10\x15\x12\x16\x0c\x13\x12\x11\x02qCDCPK\r\x17\x11\x15\x0c\x11\x14"')
decrypted data (5b): bytearray(b'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36\x00')
encrypted data (5c): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\nuKLFMUQ\x02lv\x02\x14\x0c\x13\x19\x02umu\x14\x16\x0b\x02cRRNGuG@iKV\r\x17\x11\x15\x0c\x11\x14\x02\nijvon\x0e\x02NKIG\x02eGAIM\x0b\x02aJPMOG\r\x17\x10\x0c\x12\x0c\x10\x15\x16\x11\x0c\x13\x13\x14\x02qCDCPK\r\x17\x11\x15\x0c\x11\x14"')
decrypted data (5c): bytearray(b'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36\x00')
encrypted data (5d): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\noCAKLVMQJ\x19\x02kLVGN\x02oCA\x02mq\x02z\x02\x13\x12}\x13\x13}\x14\x0b\x02cRRNGuG@iKV\r\x14\x12\x13\x0c\x15\x0c\x15\x02\nijvon\x0e\x02NKIG\x02eGAIM\x0b\x02tGPQKML\r\x1b\x0c\x13\x0c\x10\x02qCDCPK\r\x14\x12\x13\x0c\x15\x0c\x15"')
decrypted data (5d): bytearray(b'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.7 (KHTML, like Gecko) Version/9.1.2 Safari/601.7.7\x00')
encrypted data (5e): bytearray(b'oMXKNNC\r\x16\x0c\x12\x02\nAMORCVK@NG\x19\x02oqkg\x02\x1b\x0c\x12\x19\x02uKLFMUQ\x02lv\x02\x17\x0c\x13\x19\x02vPKFGLV\r\x17\x0c\x12\x0b"')
decrypted data (5e): bytearray(b'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)\x00')
encrypted data (5f): bytearray(b'oMXKNNC\r\x16\x0c\x12\x02\nAMORCVK@NG\x19\x02oqkg\x02\x1b\x0c\x12\x19\x02uKLFMUQ\x02lv\x02\x14\x0c\x12\x19\x02vPKFGLV\r\x16\x0c\x12\x19\x02ev`\x15\x0c\x16\x19\x02kLDMrCVJ\x0c\x11\x19\x02qt\x13\x19\x02\x0clgv\x02anp\x02\x11\x0c\x16\x0c\x17\x11\x11\x14\x12\x19\x02umu\x14\x16\x19\x02GL\x0fwq\x0b"')
decrypted data (5f): bytearray(b'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/4.0; GTB7.4; InfoPath.3; SV1; .NET CLR 3.4.53360; WOW64; en-US)\x00')
encrypted data (60): bytearray(b'oMXKNNC\r\x16\x0c\x12\x02\nAMORCVK@NG\x19\x02oqkg\x02\x1b\x0c\x12\x19\x02uKLFMUQ\x02lv\x02\x14\x0c\x13\x19\x02vPKFGLV\r\x16\x0c\x12\x19\x02dfo\x19\x02oqkgaPCUNGP\x19\x02oGFKC\x02aGLVGP\x02ra\x02\x17\x0c\x12\x0b"')
decrypted data (60): bytearray(b'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; FDM; MSIECrawler; Media Center PC 5.0)\x00')
encrypted data (61): bytearray(b'oMXKNNC\r\x16\x0c\x12\x02\nAMORCVK@NG\x19\x02oqkg\x02\x1b\x0c\x12\x19\x02uKLFMUQ\x02lv\x02\x14\x0c\x13\x19\x02vPKFGLV\r\x16\x0c\x12\x19\x02ev`\x15\x0c\x16\x19\x02kLDMrCVJ\x0c\x10\x19\x02qt\x13\x19\x02\x0clgv\x02anp\x02\x16\x0c\x16\x0c\x17\x1a\x15\x1b\x1b\x19\x02umu\x14\x16\x19\x02GL\x0fwq\x0b"')
decrypted data (61): bytearray(b'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 4.4.58799; WOW64; en-US)\x00')
encrypted data (62): bytearray(b'oMXKNNC\r\x16\x0c\x12\x02\nAMORCVK@NG\x19\x02oqkg\x02\x1b\x0c\x12\x19\x02uKLFMUQ\x02lv\x02\x14\x0c\x13\x19\x02vPKFGLV\r\x17\x0c\x12\x19\x02dWLuG@rPMFWAVQ\x0b"')
decrypted data (62): bytearray(b'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; FunWebProducts)\x00')
encrypted data (63): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\noCAKLVMQJ\x19\x02kLVGN\x02oCA\x02mq\x02z\x02\x13\x12\x0c\x14\x19\x02PT\x18\x10\x17\x0c\x12\x0b\x02eGAIM\r\x10\x12\x13\x12\x12\x13\x12\x13\x02dKPGDMZ\r\x10\x17\x0c\x12"')
decrypted data (63): bytearray(b'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:25.0) Gecko/20100101 Firefox/25.0\x00')
encrypted data (64): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\noCAKLVMQJ\x19\x02kLVGN\x02oCA\x02mq\x02z\x02\x13\x12\x0c\x1a\x19\x02PT\x18\x10\x13\x0c\x12\x0b\x02eGAIM\r\x10\x12\x13\x12\x12\x13\x12\x13\x02dKPGDMZ\r\x10\x13\x0c\x12"')
decrypted data (64): bytearray(b'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:21.0) Gecko/20100101 Firefox/21.0\x00')
encrypted data (65): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\noCAKLVMQJ\x19\x02kLVGN\x02oCA\x02mq\x02z\x02\x13\x12\x0c\x1a\x19\x02PT\x18\x10\x16\x0c\x12\x0b\x02eGAIM\r\x10\x12\x13\x12\x12\x13\x12\x13\x02dKPGDMZ\r\x10\x16\x0c\x12"')
decrypted data (65): bytearray(b'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0\x00')
encrypted data (66): bytearray(b'oMXKNNC\r\x17\x0c\x12\x02\noCAKLVMQJ\x19\x02kLVGN\x02oCA\x02mq\x02z\x02\x13\x12}\x13\x12\x19\x02PT\x18\x11\x11\x0c\x12\x0b\x02eGAIM\r\x10\x12\x13\x12\x12\x13\x12\x13\x02dKPGDMZ\r\x11\x11\x0c\x12"')
decrypted data (66): bytearray(b'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0\x00')
encrypted data (1a): bytearray(b';3=:T')
decrypted data (1a): bytearray(b'\x19\x11\x1f\x18v')
encrypted data (1b): bytearray(b'1: 1&T')
decrypted data (1b): bytearray(b'\x13\x18\x02\x13\x04v')
encrypted data (19): bytearray(b'$662*7!E')
decrypted data (19): bytearray(b'\x06\x14\x14\x10\x08\x15\x03g')
encrypted data (5): bytearray(b'1:5681T')
decrypted data (5): bytearray(b'\x13\x18\x17\x14\x1a\x13v')
encrypted data (6): bytearray(b"\'-\' 19T")
decrypted data (6): bytearray(b'\x05\x0f\x05\x02\x13\x1bv')
encrypted data (7): bytearray(b"\'<T")
decrypted data (7): bytearray(b'\x05\x1ev')
encrypted data (4): bytearray(b"\'<188T")
decrypted data (4): bytearray(b'\x05\x1e\x13\x1a\x1av')
encrypted data (a): bytearray(b':7;&&17 T')
decrypted data (a): bytearray(b'\x18\x15\x19\x04\x04\x13\x15\x02v')
encrypted data (9): bytearray(b'\x07\x1b\x06\x15nt5$$81 t:; t2;!:0T')
decrypted data (9): bytearray(b'%9$7LV\x17\x06\x06\x1a\x13\x02V\x18\x19\x02V\x10\x19\x03\x18\x12v')
encrypted data (2): bytearray(b'[\x1c')
decrypted data (2): bytearray(b'y>')
encrypted data (8): bytearray(b"{6=:{6!\'-6;,t\x07\x1b\x06\x15T")
decrypted data (8): bytearray(b'Y\x14\x1f\x18Y\x14\x03\x05\x0f\x14\x19\x0eV%9$7v')
encrypted data (3): bytearray(b'\x17;::17 10t\x00;t\x17\x1a\x17T')
decrypted data (3): bytearray(b'5\x19\x18\x18\x13\x15\x02\x13\x12V"\x19V585v')
encrypted data (18): bytearray(b'{01"{9=\'7{#5 7<0;3T')
decrypted data (18): bytearray(b'Y\x12\x13\x00Y\x1b\x1f\x05\x15Y\x01\x17\x02\x15\x1e\x12\x19\x11v')
encrypted data (1): bytearray(b'Qt')
decrypted data (1): bytearray(b'sV')
mirai_config_extractor_sora_arm_qiling.py> Finished!
```
</details>
