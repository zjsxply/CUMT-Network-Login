@echo off

REM 本项目地址：https://github.com/zjsxply/CUMT-Network-Login

REM 请求管理员权限
@%1 mshta vbscript:CreateObject("Shell.Application").ShellExecute("cmd.exe","/c %~s0 ::","","runas",1)(window.close)&&exit  
@cd /d "%~dp0"

REM 获取应用程序目录
set APPDIR=%APPDATA%\CUMT
if not exist "%APPDIR%" mkdir "%APPDIR%" > nul

REM 将 Powershell 脚本文件写入磁盘
if exist "%APPDIR%"\LoginNetwork.ps1 del "%APPDIR%"\LoginNetwork.ps1 > nul
certutil -decode "%~f0" %APPDIR%\LoginNetwork.ps1 > nul

REM 执行 Powershell 脚本
powershell -ExecutionPolicy Bypass -File "%APPDIR%\LoginNetwork.ps1"

exit /b 1


REM 以下是本 bat 文件内嵌的 Powershell 脚本文件
-----BEGIN CERTIFICATE-----
IyC2qNLltcfCvLqvyv0NCmZ1bmN0aW9uIExvZ2luLUNhbXB1c05ldHdvcmsgew0K
ICAgIHBhcmFtICgNCiAgICAgICAgW3N0cmluZ10kU3R1ZGVudElELA0KICAgICAg
ICBbc3RyaW5nXSRQYXNzd29yZCwNCiAgICAgICAgW3N0cmluZ10kQ2FycmllciwN
CgkJW2Jvb2xdJFRlc3QgPSAkZmFsc2UNCiAgICApDQoNCiAgICAjILzssuIgSVAg
MTAuMi40LjIgyse38b/J0tQgUGluZyDNqA0KICAgIGlmICgtbm90ICRUZXN0KSB7
DQoJCSRwaW5nUmVzdWx0ID0gVGVzdC1Db25uZWN0aW9uIC1Db21wdXRlck5hbWUg
IjEwLjIuNC4yIiAtUXVpZXQgLUJ1ZmZlclNpemUgMSAtQ291bnQgMQ0KCQlpZiAo
JHBpbmdSZXN1bHQpIHsNCgkJCSRwaW5nUmVzdWx0VGV4dCA9ICLN+MLntKbT2sGs
zajXtMysIg0KCQl9DQoJCWVsc2Ugew0KCQkJJHBpbmdSZXN1bHRUZXh0ID0gIs34
wufOtMGszaijrL/JxNy19M/fu/K41cGsvdPN+MLno7vWtNDQtcfCvDogIg0KCQl9
DQoJfQ0KCQ0KCSMgsuLK1NTy0ru2qLeiy821x8K8x+vH8w0KICAgIGlmICgkVGVz
dCAtb3IgLW5vdCAkcGluZ1Jlc3VsdCkgew0KICAgICAgICBpZiAoW2Jvb2xdJENh
cnJpZXIpIHsNCgkJCSRDYXJyaWVyID0gIkAkKCRDYXJyaWVyKSINCiAgICAgICAg
fQ0KCQkkdXJsID0gImh0dHA6Ly8xMC4yLjUuMjUxOjgwMS9lcG9ydGFsLz9jPVBv
cnRhbCZhPWxvZ2luJmxvZ2luX21ldGhvZD0xJnVzZXJfYWNjb3VudD0kKCRTdHVk
ZW50SUQpJCgkQ2FycmllcikmdXNlcl9wYXNzd29yZD0kKCRQYXNzd29yZCkiDQoJ
CSRyZXNwb25zZSA9IEludm9rZS1XZWJSZXF1ZXN0IC1VcmkgJHVybA0KCQkkcmVz
cFRleHQgPSAkcmVzcG9uc2UuQ29udGVudC5UcmltU3RhcnQoJygnKS5UcmltRW5k
KCcpJykNCgkJJHJlc3BKc29uID0gQ29udmVydEZyb20tSnNvbiAkcmVzcFRleHQN
CgkJDQogICAgICAgIHN3aXRjaCAoJHJlc3BKc29uLnJlc3VsdCkgew0KICAgICAg
ICAgICAgMSB7DQogICAgICAgICAgICAgICAgJG5vdGlmaWNhdGlvbiA9ICK1x8K8
s8m5piINCiAgICAgICAgICAgIH0NCiAgICAgICAgICAgIDAgew0KCQkJCXN3aXRj
aCAoJHJlc3BKc29uLnJldF9jb2RlKSB7DQoJCQkJCTEgew0KCQkJCQkJJGJ5dGVz
ID0gW1N5c3RlbS5Db252ZXJ0XTo6RnJvbUJhc2U2NFN0cmluZygkcmVzcEpzb24u
bXNnKQ0KCQkJCQkJJG1zZyA9IFtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OlVURjgu
R2V0U3RyaW5nKCRieXRlcykNCgkJCQkJCXN3aXRjaCAoJG1zZykgew0KCQkJCQkJ
CSJ1c2VyaWQgZXJyb3IxIiB7DQoJCQkJCQkJCSRub3RpZmljYXRpb24gPSAi1cu6
xbK7tObU2iINCgkJCQkJCQl9DQoJCQkJCQkJImF1dGggZXJyb3I4MCIgew0KCQkJ
CQkJCQkkbm90aWZpY2F0aW9uID0gIrG+yrG2zr371rnJz834Ig0KCQkJCQkJCX0N
CgkJCQkJCQkiUmFkOlVzZXJOYW1lX0VyciIgew0KCQkJCQkJCQkkbm90aWZpY2F0
aW9uID0gIrDztqi1xNTL06rJzNXLusW07c7zo6zH68Gqz7XUy9Oqycy6y8q1u/LI
pdTL06rJzNCj1LDTqtK1zPy9+NDQsPO2qKGjIg0KCQkJCQkJCX0NCgkJCQkJCQki
QXV0aGVudGljYXRpb24gRmFpbCBFcnJDb2RlPTE2IiB7DQoJCQkJCQkJCSRub3Rp
ZmljYXRpb24gPSAisb7KsbbOsrvUytDtyc/N+CINCgkJCQkJCQl9DQoJCQkJCQkJ
Ik1hYywgSVAsIE5BU2lwLCBQT1JUIGVycigyKSEiIHsNCgkJCQkJCQkJJG5vdGlm
aWNhdGlvbiA9ICLE+rXE1cu6xbK71MrQ7dTatMvN+MLnyrnTw6Osx+u87LLpvdPI
67XEyscgQ1VNVF9TdHUgu7nKxyBDVU1UX1RlYyDN+MLnIg0KCQkJCQkJCX0NCgkJ
CQkJCQkiUmFkOlN0YXR1c19FcnIiIHsNCgkJCQkJCQkJJG5vdGlmaWNhdGlvbiA9
ICLE+rDztqi1xNTL06rJzNXLusXXtMys0uyzo6Osx+vBqs+1ttTTptTL06rJzLSm
wO2hoyINCgkJCQkJCQl9DQoJCQkJCQkJIlJhZDpMaW1pdCBVc2VycyBFcnIiIHsN
CgkJCQkJCQkJJG5vdGlmaWNhdGlvbiA9ICLE+rXEtcfCvbOsz96jrMfr1NrX1Lf+
zvEgaHR0cDovLzIwMi4xMTkuMTk2LjY6ODA4MC9TZWxmIM/Cz9/W1bbLoaMiDQoJ
CQkJCQkJfQ0KCQkJCQkJCSJsZGFwIGF1dGggZXJyb3IiIHsNCgkJCQkJCQkJJG5v
dGlmaWNhdGlvbiA9ICLNs9K7ye233cjP1qTTw7unw/vD3MLrtO3O86OhIg0KCQkJ
CQkJCX0NCgkJCQkJCQlkZWZhdWx0IHsNCgkJCQkJCQkJJG5vdGlmaWNhdGlvbiA9
ICLOtNaqtO3O86O6JCgkbXNnKSINCgkJCQkJCQkJDQoJCQkJCQkJfQ0KCQkJCQkJ
fQ0KCQkJCQl9DQoJCQkJCTIgew0KCQkJCQkJJG5vdGlmaWNhdGlvbiA9ICLE+tLR
vq20ptPatcfCvNe0zKwiDQoJCQkJCX0NCgkJCQkJMyB7DQoJCQkJCQkkbm90aWZp
Y2F0aW9uID0gIs601qq07c7zo6y07c7ztPrC66O6MyINCgkJCQkJfQ0KCQkJCX0N
CiAgICAgICAgICAgIH0NCiAgICAgICAgICAgIGRlZmF1bHQgew0KICAgICAgICAg
ICAgICAgICRub3RpZmljYXRpb24gPSAizrTWqr3hufujuiQoJHJlc3BKc29uKSIN
CgkJCQkNCiAgICAgICAgICAgIH0NCiAgICAgICAgfQ0KDQogICAgICAgICMgta+z
9s+1zbPNqNaqz/vPog0KCQkjIE5ldy1CdXJudFRvYXN0Tm90aWZpY2F0aW9uIC1U
ZXh0ICLS0bOiytS1x8K80KPUsM34IiwgJG5vdGlmaWNhdGlvbg0KICAgIH0NCgkJ
DQoJcmV0dXJuICRwaW5nUmVzdWx0VGV4dCArICRub3RpZmljYXRpb24NCn0NCg0K
IyC2qNLl16LP+rqvyv0NCmZ1bmN0aW9uIExvZ291dC1DYW1wdXNOZXR3b3JrIHsN
CgkkdXJsID0gImh0dHA6Ly8xMC4yLjUuMjUxOjgwMS9lcG9ydGFsLz9jPVBvcnRh
bCZhPWxvZ291dCINCgkkcmVzcG9uc2UgPSBJbnZva2UtV2ViUmVxdWVzdCAtVXJp
ICR1cmwNCn0NCg0KIyC2qNLlssO89MjV1r68x8K8uq/K/Q0KZnVuY3Rpb24gQ3V0
LUZpbGVMb2cgew0KICAgIHBhcmFtICgNCiAgICAgICAgW3N0cmluZ1tdXSRmaWxl
Q29udGVudCwNCgkJW3N0cmluZ1tdXSRzLA0KICAgICAgICBbaW50XSRudW0gPSAx
MDANCiAgICApDQoNCgkjILfWsfC2qNLlw7+49tfWt/u0rrD8uqy1xNDQyv3OqiAw
o6y31rHwtqjS5bTmtKLDv7j219a3+7Su0NDK/bXEyv3X6Q0KCSRjb3VudHMgPSBA
e30NCgkkbGluZXMgPSBAe30NCglmb3JlYWNoICgkc3RyIGluICRzKSB7DQoJCSRj
b3VudHNbJHN0cl0gPSAwDQoJCSRsaW5lc1skc3RyXSA9IEAoKQ0KCX0NCg0KCSMg
0a27t7HpwPrDv9K70NCjrLzHwryw/Lqsw7+49tfWt/u0rrXE0NDK/bKivavG5LTm
tKK1vc/g06a1xMr91+nW0A0KCWZvcmVhY2ggKCRsaW5lIGluICRmaWxlQ29udGVu
dCkgew0KCQlmb3JlYWNoICgkc3RyIGluICRzKSB7DQoJCQlpZiAoJGxpbmUgLW1h
dGNoICRzdHIpIHsNCgkJCQkkY291bnRzWyRzdHJdKysNCgkJCQkkbGluZXNbJHN0
cl0gKz0gJGxpbmUNCgkJCQlpZiAoJGNvdW50c1skc3RyXSAtZ3QgJG51bSkgew0K
CQkJCQkkbGluZXNbJHN0cl0gPSAkbGluZXNbJHN0cl0gfCBTZWxlY3QtT2JqZWN0
IC1MYXN0ICRudW0NCgkJCQkJJGNvdW50c1skc3RyXSA9ICRudW0NCgkJCQl9DQoJ
CQkJYnJlYWsNCgkJCX0NCgkJfQ0KCX0NCg0KCSMgsLTV1dStz8i1xMuz0PLW2NDC
1+m6z87EvP7E2sjdo6yyore1u9gNCgkkbmV3RmlsZUNvbnRlbnQgPSBAKCkNCglm
b3JlYWNoICgkbGluZSBpbiAkZmlsZUNvbnRlbnQpIHsNCgkJZm9yZWFjaCAoJHN0
ciBpbiAkcykgew0KCQkJaWYgKCRsaW5lIC1pbiAkbGluZXNbJHN0cl0pIHsNCgkJ
CQkkbmV3RmlsZUNvbnRlbnQgKz0gJGxpbmUNCgkJCQlicmVhaw0KCQkJfQ0KCQl9
DQoJfQ0KCXJldHVybiAkbmV3RmlsZUNvbnRlbnQNCg0KfQ0KDQojILao0uXIocjV
1r7OxLz+wre+trqvyv0NCmZ1bmN0aW9uIEdldC1GaWxlTG9nLVBhdGggew0KCSRs
b2dGaWxlID0gSm9pbi1QYXRoICRQU1NjcmlwdFJvb3QgIkxvZ2luTmV0d29yay5s
b2ciDQoJaWYgKC1ub3QgKFRlc3QtUGF0aCAkbG9nRmlsZSkpIHsNCgkJTmV3LUl0
ZW0gLVBhdGggJGxvZ0ZpbGUgLUl0ZW1UeXBlIEZpbGUgLUZvcmNlDQoJfQ0KCXJl
dHVybiAkbG9nRmlsZQ0KfQ0KDQojILao0uW8x8K8yNXWvrqvyv0NCmZ1bmN0aW9u
IFdyaXRlLUZpbGVMb2cgew0KICAgIHBhcmFtICgNCiAgICAgICAgW3N0cmluZ10k
TG9nLA0KCQlbc3RyaW5nXSRjYWxsZXINCiAgICApDQoJDQoJIyDJ6NbDyNXWvs7E
vP7Ct762DQoJJGxvZ0ZpbGUgPSBHZXQtRmlsZUxvZy1QYXRoDQoJDQoJIyDJ6NbD
0qrM7bzTtb3I1da+zsS8/tbQtcTOxLG+19a3+7SuDQoJJGxvZ0Zvcm1hdCA9ICJb
ezA6eXl5eS1NTS1kZCBISDptbTpzc31dIHsxfSAtIHsyfSINCgkkdGltZXN0YW1w
ID0gR2V0LURhdGUNCgkkbG9nRW50cnkgPSAkbG9nRm9ybWF0IC1mICR0aW1lc3Rh
bXAsICRjYWxsZXIsICRMb2cNCgkNCgkjIMztvNPQwsjV1r7E2sjdtb3I1da+zsS8
/sSpzrINCglBZGQtQ29udGVudCAkbG9nRmlsZSAtVmFsdWUgJGxvZ0VudHJ5DQoN
CgkjIMjnufvI1da+zPXK/bOsuf0gMTAwIMz1o6zU8ta7saPB9Nfu0MK1xCAxMDAg
zPUNCgkkbG9nQ29udGVudCA9IEdldC1Db250ZW50ICRsb2dGaWxlDQoJU2V0LUNv
bnRlbnQgJGxvZ0ZpbGUgKEN1dC1GaWxlTG9nICRsb2dDb250ZW50IEAoIk1vbml0
b3IiLCAiVHJpZ2dlciIpKQ0KDQp9DQoNCiMgw/zB7tDQv8m908rVIDUguPayzsr9
o7rRp7rFIMPcwusg1MvTqsnMIMrHt/Gy4srUtcfCvCDKx7fxzqq84LLiDQojILzG
u67Izs7x1rTQ0LXHwrwNCmlmICgkYXJncykgew0KCQ0KCSMgyOe5+8rHvOCy4qOs
1PI3OjA1ILW9IDIzOjUwINauzeK1xMqxvOTS1CAxIC8gMjAgtcS4xcLK1rTQ0LXH
wrwNCgkkY3VycmVudERhdGUgPSBHZXQtRGF0ZQ0KCWlmICgkYXJnc1s0XSkgew0K
CQkkY2FsbGVyID0gIk1vbml0b3IiDQoJCSRpc0FmdGVyN18wNSA9ICRjdXJyZW50
RGF0ZS5Ib3VyIC1ndCA3IC1vciAoJGN1cnJlbnREYXRlLkhvdXIgLWdlIDcgLWFu
ZCAkY3VycmVudERhdGUuTWludXRlIC1nZSAwNSkNCgkJJGlzQmVmb3JlMjNfNTAg
PSAkY3VycmVudERhdGUuSG91ciAtbHQgMjMgLW9yICgkY3VycmVudERhdGUuSG91
ciAtZXEgMjMgLWFuZCAkY3VycmVudERhdGUuTWludXRlIC1sZSA1MCkNCgkJaWYg
KC1ub3QgKCRpc0FmdGVyN18wNSAtYW5kICRpc0JlZm9yZTIzXzUwKSl7DQoJCQkk
cmVzdWx0ID0gIrK71NogNzowNS0yMzo1MCDWrrzkLCDS1CAxLzIwILjFwsq0pbei
tcfCvNCj1LDN+DsgIg0KCQkJaWYgKEdldC1SYW5kb20gLU1heGltdW0gMjApIHsN
CgkJCQkkcmVzdWx0ICs9ICLOtLSlt6LWtNDQIg0KCQkJfQ0KCQkJZWxzZSB7DQoJ
CQkJJHJlc3VsdCArPSAitKW3ota00NCjrL3hufs6ICINCgkJCQkkcmVzdWx0ICs9
IExvZ2luLUNhbXB1c05ldHdvcmsgLVN0dWRlbnRJRCAkYXJnc1swXSAtUGFzc3dv
cmQgJGFyZ3NbMV0gLUNhcnJpZXIgJGFyZ3NbMl0NCgkJCX0NCgkJfQ0KCQllbHNl
IHsNCgkJCSRyZXN1bHQgPSBMb2dpbi1DYW1wdXNOZXR3b3JrIC1TdHVkZW50SUQg
JGFyZ3NbMF0gLVBhc3N3b3JkICRhcmdzWzFdIC1DYXJyaWVyICRhcmdzWzJdDQoJ
CX0NCgl9IGVsc2Ugew0KCQkkY2FsbGVyID0gIlRyaWdnZXIiDQoJCSRyZXN1bHQg
PSBMb2dpbi1DYW1wdXNOZXR3b3JrIC1TdHVkZW50SUQgJGFyZ3NbMF0gLVBhc3N3
b3JkICRhcmdzWzFdIC1DYXJyaWVyICRhcmdzWzJdDQoJfQ0KCVdyaXRlLUZpbGVM
b2cgJHJlc3VsdCAkY2FsbGVyDQoJRXhpdA0KfQ0KDQojINKqx/O53MDt1LHIqM/e
DQokcm9sZSA9IFtTZWN1cml0eS5QcmluY2lwYWwuV2luZG93c1ByaW5jaXBhbF1b
U2VjdXJpdHkuUHJpbmNpcGFsLldpbmRvd3NJZGVudGl0eV06OkdldEN1cnJlbnQo
KQ0KJGlzQWRtaW4gPSAkcm9sZS5Jc0luUm9sZShbU2VjdXJpdHkuUHJpbmNpcGFs
LldpbmRvd3NCdWlsdEluUm9sZV0gIkFkbWluaXN0cmF0b3IiKSAtb3IgW2Jvb2xd
JHJvbGUuSXNTeXN0ZW0NCmlmICgtbm90ICRpc0FkbWluKSB7DQoJV3JpdGUtSG9z
dCAi0OjSqrncwO3Uscioz96jrMfrx/PIqM/e1tAuLi4iIC1Gb3JlZ3JvdW5kQ29s
b3IgWWVsbG93DQogICAgU3RhcnQtUHJvY2VzcyBwb3dlcnNoZWxsLmV4ZSAiLU5v
UHJvZmlsZSAtRXhlY3V0aW9uUG9saWN5IEJ5cGFzcyAtRmlsZSBgIiRQU0NvbW1h
bmRQYXRoYCIiIC1WZXJiIFJ1bkFzDQogICAgRXhpdA0KfQ0KDQojIMrks/a149Xz
19YNCldyaXRlLUhvc3QgQCINCg0KoaGhoaGhofSh9KH0ofSh9KH0oaGhoaH0ofSh
9KH0oaGh9KH0ofSh9KGhofSh9KH0ofShoaGhoaGhoaH0ofSh9KGhofSh9KH0ofSh
9KH0ofSh9KH0oaENCqGhoaGh9KH0ofShoaGhofSh9KGhoaGhoaH0ofShoaGhoaGh
9KH0oaGhoaGhofSh9KH0oaGhoaGhoaGh9KH0oaGhoaH0ofShoaGhofShoaGhofSh
9KGhDQqhoaGhofSh9KGhoaGhoaGhofSh9KGhoaGh9KGhoaGhoaGhoaGh9KGhoaGh
oaGhofSh9KH0oaGhoaH0ofSh9KGhoaGh9KH0oaGhoaH0oaGhoaH0ofShoQ0KoaGh
oaH0ofShoaGhoaGhoaGhoaGhoaGhofShoaGhoaGhoaGhofShoaGhoaGhoaH0ofSh
9KGhoaGh9KH0ofShoaGhoaGhoaGhoaGh9KGhoaGhoaGhoaENCqGhofSh9KH0oaGh
oaGhoaGhoaGhoaGhoaH0oaGhoaGhoaGhoaH0oaGhoaGhoaGh9KH0ofSh9KGhofSh
oaH0oaGhoaGhoaGhoaGhofShoaGhoaGhoaGhDQqhoaH0ofSh9KGhoaGhoaGhoaGh
oaGhoaGh9KGhoaGhoaGhoaGh9KGhoaGhoaGhofShoaH0ofSh9KH0oaGh9KGhoaGh
oaGhoaGhoaH0oaGhoaGhoaGhoQ0KoaGhoaH0ofShoaGhoaGhoaH0ofShoaGhofSh
9KGhoaGhoaH0ofShoaGhoaGhoaH0oaGh9KH0ofShoaGhofShoaGhoaGhoaGhoaGh
9KGhoaGhoaGhoaENCqGhoaGh9KH0ofShoaGhofSh9KH0oaGhoaH0ofShoaGhoaGh
9KH0oaGhoaGhoaGh9KGhoaGh9KH0oaGhoaH0oaGhoaGhoaGhoaGhofShoaGhoaGh
oaGhDQqhoaGhoaGh9KH0ofSh9KH0ofShoaGhoaGh9KH0ofSh9KH0ofSh9KGhoaGh
9KH0ofSh9KGhofSh9KH0ofSh9KH0oaGhoaGhofSh9KH0ofSh9KGhoaGhoQ0KDQoi
QCAtRm9yZWdyb3VuZENvbG9yIEJsdWUNCg0KIyC9xbG+venJ3A0KV3JpdGUtSG9z
dCBAIg0K1eLKx9K7uPa/ydLUyejWwyBDVU1UINCj1LDN+NfUtq+1x8K8tcSzzNDy
oaPUy9PDtuDW1rSlt6LG96Os1qez1tLUz8K5psTco7oNCqHMIMGsvdMgQ1VNVF9T
dHUgu/IgQ1VNVF9UZWMgV2lGaSDKsdfUtq+1x8K8DQqhzCDBrL3TIENVTVRfU3R1
IM34z98gKNLUzKvN+CkgyrHX1LavtcfCvA0KocwgveLL+L34yOu158TUyrHX1Lav
tcfCvA0Kocwgw7/M7MnPzucgNzoyMiAtIDc6MjUg19S2r7XHwrwNCqHMICi/ydGh
KSDRrbu3vOyy4qOstfTP39fUtq/W2LXHDQq24NbWt73KvbGj1qTE+rXEx+G/7MnP
zfjM5dHpo6ENCrDmsb6junYyMDIzMDQxNg0KDQoiQCAtRm9yZWdyb3VuZENvbG9y
IEN5YW4NCg0KPCMgIyCwstewIEJ1cm50VG9hc3QNCldyaXRlLUhvc3QgItLUz8LI
9NGvzsqwstewxKO/6cfryuTI6yB5ILKiu9iztSINCldyaXRlLUhvc3QgItX91Nq8
7LLpy/nSwMC1tcTPtc2zzajWqsSjv+kuLi4iDQpJbnN0YWxsLU1vZHVsZSBCdXJu
dFRvYXN0DQpXcml0ZS1Ib3N0ICLS0bCy17DL+dLAwLW1xMSjv+kiDQpXcml0ZS1I
b3N0ICIiICM+DQoNCiMgyei2qLzGu67Izs7xw/uzxg0KJHRhc2tOYW1lID0gIkNV
TVTX1LavtcfCvNCj1LDN+CINCiR0YXNrTmFtZTIgPSAiQ1VNVNfUtq+1x8K80KPU
sM34oaqhqrzgsuIiDQoNCiMgyPS8xruuyM7O8dLRtObU2qOs1PLRodTxyb6z/bu5
yse4srjHDQokdGFza0V4aXN0cyA9IEdldC1TY2hlZHVsZWRUYXNrIHwgV2hlcmUt
T2JqZWN0IHsgJF8uVGFza05hbWUgLWVxICR0YXNrTmFtZSB9DQokdGFza0V4aXN0
czIgPSBHZXQtU2NoZWR1bGVkVGFzayB8IFdoZXJlLU9iamVjdCB7ICRfLlRhc2tO
YW1lIC1lcSAkdGFza05hbWUyIH0NCmlmICgkdGFza0V4aXN0cyAtb3IgJHRhc2tF
eGlzdHMyKSB7DQoJV3JpdGUtSG9zdCAiz7XNs7zssuK1vdLRyejWw7n919S2r7XH
wryhoyIgLUZvcmVncm91bmRDb2xvciBZZWxsb3cNCgkNCgkkbG9nQ29udGVudCA9
IEdldC1Db250ZW50IChHZXQtRmlsZUxvZy1QYXRoKQ0KCVdyaXRlLUhvc3QgIiIN
CglXcml0ZS1Ib3N0ICLX7r38tcTWtNDQyNXWvsjnz8KjuiINCglXcml0ZS1Ib3N0
ICgoQ3V0LUZpbGVMb2cgJGxvZ0NvbnRlbnQgQCgnTW9uaXRvcicsICdUcmlnZ2Vy
JykgNSkgLWpvaW4gImBuIikNCglXcml0ZS1Ib3N0ICIiDQoJDQoJZG8gew0KCQkk
cmVzcG9uc2UgPSBSZWFkLUhvc3QgIsfr0aHU8aO6yb6z/cno1sMgLyC4srjH1K3J
6NbD1tjQwsno1sOjvyjJvrP9IFkgLyDW2NDCyejWwyBOo6zErMjPIE6jqSINCgl9
IHdoaWxlICgkcmVzcG9uc2UgLW5vdG1hdGNoICJeW3luWU5dJCIgLWFuZCAkcmVz
cG9uc2UgLW5lICcnKQ0KDQoJaWYgKCR0YXNrRXhpc3RzKSB7DQoJCVVucmVnaXN0
ZXItU2NoZWR1bGVkVGFzayAtVGFza05hbWUgJHRhc2tOYW1lIC1Db25maXJtOiRm
YWxzZQ0KCX0NCglpZiAoJHRhc2tFeGlzdHMyKSB7DQoJCVVucmVnaXN0ZXItU2No
ZWR1bGVkVGFzayAtVGFza05hbWUgJHRhc2tOYW1lMiAtQ29uZmlybTokZmFsc2UN
Cgl9DQoJDQoJaWYgKCRyZXNwb25zZSAtaW1hdGNoICJeW3lZXSQiKSB7DQoJCVdy
aXRlLUhvc3QgItLR0saz/dCj1LDN+NfUtq+1x8K8uabE3KOsu7bTrcT6z8K0zsq5
08OjoSIgLUZvcmVncm91bmRDb2xvciBHcmVlbg0KCQlXcml0ZS1Ib3N0ICKwtMjO
0uK8/M3Ls/YuLi4iDQoJCSRIb3N0LlVJLlJhd1VJLlJlYWRLZXkoIk5vRWNobyxJ
bmNsdWRlS2V5RG93biIpID4gJG51bGwNCgkJRXhpdA0KCX0NCgllbHNlIHsNCgkJ
V3JpdGUtSG9zdCAiIg0KCX0NCn0NCg0KIyDH68fz08O7p8rkyOujrLKi0enWpNXL
u6cNCldyaXRlLUhvc3QgIr3Tz8LAtKOsx+vK5MjrxPq1xNXLu6fQxc+io6zIu7rz
sLS72LO1vPwiIC1Gb3JlZ3JvdW5kQ29sb3IgR3JlZW4NCmRvIHsNCglXcml0ZS1I
b3N0ICIiDQoJZG8gew0KCQkkU3R1ZGVudElEID0gUmVhZC1Ib3N0ICLH68rkyOvE
+rXE0ae6xSINCgl9IHdoaWxlICgtbm90ICRTdHVkZW50SUQpDQoJZG8gew0KCQkk
c2VjdXJlUGFzc3dvcmQgPSBSZWFkLUhvc3QgLVByb21wdCAix+vK5MjrxPq1xMPc
wusiIC1Bc1NlY3VyZVN0cmluZw0KCX0gd2hpbGUgKC1ub3QgJHNlY3VyZVBhc3N3
b3JkKQ0KCSRQYXNzd29yZCA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2Vydmlj
ZXMuTWFyc2hhbF06OlB0clRvU3RyaW5nQXV0byhbU3lzdGVtLlJ1bnRpbWUuSW50
ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTZWN1cmVTdHJpbmdUb0JTVFIoJHNlY3Vy
ZVBhc3N3b3JkKSkNCglkbyB7DQoJCSRDYXJyaWVyID0gUmVhZC1Ib3N0ICLH68rk
yOvE+rXE1MvTqsnMo6jH68rk0PK6xaO6MS7SxravIDIuwarNqCAzLrXn0MUgMC7Q
o9SwzfggLyBUZWMg1cu6xaOpIg0KCX0gd2hpbGUgKC1ub3QgJENhcnJpZXIpDQoJ
c3dpdGNoICgkQ2Fycmllcikgew0KCQkiMCIgew0KCQkJJENhcnJpZXIgPSAiIg0K
CQl9DQoJCSIxIiB7DQoJCQkkQ2FycmllciA9ICJjbWNjIg0KCQl9DQoJCSIyIiB7
DQoJCQkkQ2FycmllciA9ICJ1bmljb20iDQoJCX0NCgkJIjMiIHsNCgkJCSRDYXJy
aWVyID0gInRlbGVjb20iDQoJCX0NCgkJItCj1LDN+CIgew0KCQkJJENhcnJpZXIg
PSAiIg0KCQl9DQoJCSLQo9SwIiB7DQoJCQkkQ2FycmllciA9ICIiDQoJCX0NCgkJ
IiIgew0KCQkJJENhcnJpZXIgPSAiIg0KCQl9DQoJCSLSxravIiB7DQoJCQkkQ2Fy
cmllciA9ICJjbWNjIg0KCQl9DQoJCSLBqs2oIiB7DQoJCQkkQ2FycmllciA9ICJ1
bmljb20iDQoJCX0NCgkJIrXn0MUiIHsNCgkJCSRDYXJyaWVyID0gInRlbGVjb20i
DQoJCX0NCgkJInRlbGVjb20iIHsNCgkJCSRDYXJyaWVyID0gInRlbGVjb20iDQoJ
CX0NCgkJImNtY2MiIHsNCgkJCSRDYXJyaWVyID0gImNtY2MiDQoJCX0NCgkJInVu
aWNvbSIgew0KCQkJJENhcnJpZXIgPSAidW5pY29tIg0KCQl9DQoJCWRlZmF1bHQg
ew0KCQkJV3JpdGUtSG9zdCAivq+45qO6zrTWqrXE1MvTqsnMo6y/ycTctbzWwrXH
wrzKp7DcIiAtRm9yZWdyb3VuZENvbG9yIFllbGxvdw0KCQl9DQoJfQ0KDQoJZG8g
ew0KCQlXcml0ZS1Ib3N0ICIiDQoJCVdyaXRlLUhvc3QgIsfryLexo8T6z9bU2tLR
way909Cj1LDN+KGjIiAtTm9OZXdsaW5lIC1Gb3JlZ3JvdW5kQ29sb3IgR3JlZW4N
CgkJV3JpdGUtSG9zdCAi1f3U2rOiytS1x8K8Li4uICAiIC1Ob05ld2xpbmUgLUZv
cmVncm91bmRDb2xvciBHcmVlbg0KCQkkcmVzdWx0ID0gTG9naW4tQ2FtcHVzTmV0
d29yayAtU3R1ZGVudElEICRTdHVkZW50SUQgLVBhc3N3b3JkICRQYXNzd29yZCAt
Q2FycmllciAkQ2FycmllciAtVGVzdCAkdHJ1ZQ0KCQlXcml0ZS1Ib3N0ICK1x8K8
veG5+6O6JHJlc3VsdCINCgkJaWYgKCRyZXN1bHQgLWVxICLE+tLRvq20ptPatcfC
vNe0zKwiKSB7DQoJCQlXcml0ZS1Ib3N0ICK1x8K817TMrM/Czt63qNHp1qTE47XE
1cu7p9DFz6KhoyIgLUZvcmVncm91bmRDb2xvciBZZWxsb3cNCgkJCWRvIHsNCgkJ
CQkkcmVzcG9uc2UgPSBSZWFkLUhvc3QgIsrHt/HPyNeiz/q1x8K8o6zU2dbY0MK1
x8K80tTR6dak0MXPosrHt/HV/ci3o78oWSAvIE4sIL2o0unR6dak0tTD4tfUtq+1
x8K81rTQ0MqnsNyjrMSsyM8gWaOpIg0KCQkJfSB3aGlsZSAoJHJlc3BvbnNlIC1u
b3RtYXRjaCAiXlt5bllOXSQiIC1hbmQgJHJlc3BvbnNlIC1uZSAnJykNCg0KCQkJ
aWYgKCRyZXNwb25zZSAtaW1hdGNoICJeW3lZXSQiIC1vciAkcmVzcG9uc2UgLWVx
ICcnKSB7DQoJCQkJJGZsYWcyID0gJHRydWUNCgkJCQkkZmxhZyA9ICR0cnVlDQoJ
CQkJTG9nb3V0LUNhbXB1c05ldHdvcmsNCgkJCQlXcml0ZS1Ib3N0ICLS0deiz/rQ
o9SwzfgiIC1Gb3JlZ3JvdW5kQ29sb3IgR3JlZW4NCgkJCX0gZWxzZSB7DQoJCQkJ
JGZsYWcyID0gJGZhbHNlDQoJCQkJJGZsYWcgPSAkZmFsc2UNCgkJCX0NCgkJfQ0K
CQllbHNlaWYgKCRyZXN1bHQgLWVxICK1x8K8s8m5piIpIHsNCgkJCSRmbGFnMiA9
ICRmYWxzZQ0KCQkJJGZsYWcgPSAkZmFsc2UNCgkJfQ0KCQllbHNlaWYgKCRyZXN1
bHQgLWVxICLNs9K7ye233cjP1qTTw7unw/vD3MLrtO3O86OhIikgew0KCQkJV3Jp
dGUtSG9zdCAiIg0KCQkJJGZsYWcyID0gJGZhbHNlDQoJCQkkZmxhZyA9ICR0cnVl
DQoJCX0NCgkJZWxzZSB7DQoJCQlkbyB7DQoJCQkJJHJlc3BvbnNlID0gUmVhZC1I
b3N0ICLH69Gh1PHKx7fx1tjQwszu0LTQxc+io6zU2bTOs6LK1LXHwrzS1NHp1qTQ
xc+iyse38dX9yLejvyhZIC8gTiwgvajS6dHp1qTS1MPi19S2r7XHwrzWtNDQyqew
3KOsxKzIzyBZo6kiDQoJCQl9IHdoaWxlICgkcmVzcG9uc2UgLW5vdG1hdGNoICJe
W3luWU5dJCIgLWFuZCAkcmVzcG9uc2UgLW5lICcnKQ0KDQoJCQlpZiAoJHJlc3Bv
bnNlIC1pbWF0Y2ggIl5beVldJCIgLW9yICRyZXNwb25zZSAtZXEgJycpIHsNCgkJ
CQkkZmxhZzIgPSAkZmFsc2UNCgkJCQkkZmxhZyA9ICR0cnVlDQoJCQl9IGVsc2Ug
ew0KCQkJCSRmbGFnMiA9ICRmYWxzZQ0KCQkJCSRmbGFnID0gJGZhbHNlDQoJCQl9
DQoJCX0NCgl9IHdoaWxlICgkZmxhZzIpDQp9IHdoaWxlICgkZmxhZykNCg0KV3Jp
dGUtSG9zdCAiIg0KDQojILX0z9/X1Lav1ti1xw0KZG8gew0KCXRyeSB7DQoJCSRy
ZWNvbm5lY3QgPSBSZWFkLUhvc3QgIsrHt/G/qsb00a27t7zssuKjrLX0z9/X1Lav
1ti1x6O/KMj00OjSqsfryuTI69Gtu7e87LLivOS49LfW1tPK/aO70ruw47K70OjS
qqOs1rG907vYs7UpIg0KCQlpZiAoJHJlY29ubmVjdCAtZXEgJycpIHsNCgkJCSRy
ZWNvbm5lY3QgPSAwDQoJCX0NCgkJZWxzZSB7DQoJCQlbaW50XSRyZWNvbm5lY3Qg
PSAkcmVjb25uZWN0DQoJCX0NCgkJJGZsYWcgPSAkdHJ1ZQ0KCX0gY2F0Y2ggew0K
CQlXcml0ZS1Ib3N0ICLK5Mjrzt7Qp6Osx+vK5Mjr0ru49tX7yv2hoyIgLUZvcmVn
cm91bmRDb2xvciBSZWQNCgl9DQp9IHdoaWxlICgtbm90ICRmbGFnKQ0KDQpXcml0
ZS1Ib3N0ICLV/dTayejWw73iy/i158TUus3Dv8zsyc/O5yA3OjIyIC0gNzoyNSDK
sdfUtq+1x8K8Li4uIiAtRm9yZWdyb3VuZENvbG9yIEdyZWVuDQoNCiMgsaO05rWx
x7C9xbG+tcTN6tX7wre+tg0KJHNjcmlwdFBhdGggPSAkTXlJbnZvY2F0aW9uLk15
Q29tbWFuZC5QYXRoDQoNCiMgtLS9qLzGu67Izs7xDQokdHJpZ2dlckxvZ2luID0g
TmV3LVNjaGVkdWxlZFRhc2tUcmlnZ2VyIC1BdExvZ09uDQokdHJpZ2dlckRhaWx5
ID0gTmV3LVNjaGVkdWxlZFRhc2tUcmlnZ2VyIC1BdCAiNzoyMiIgLURhaWx5DQok
YWN0aW9uID0gTmV3LVNjaGVkdWxlZFRhc2tBY3Rpb24gLUV4ZWN1dGUgJ1Bvd2Vy
c2hlbGwuZXhlJyAtQXJndW1lbnQgIi1Ob1Byb2ZpbGUgLUV4ZWN1dGlvblBvbGlj
eSBCeXBhc3MgYCIkKCRzY3JpcHRQYXRoKWAiICQoJFN0dWRlbnRJRCkgJCgkUGFz
c3dvcmQpICQoJENhcnJpZXIpIg0KJGFjdGlvbjIgPSBOZXctU2NoZWR1bGVkVGFz
a0FjdGlvbiAtRXhlY3V0ZSAnUG93ZXJzaGVsbC5leGUnIC1Bcmd1bWVudCAiLU5v
UHJvZmlsZSAtRXhlY3V0aW9uUG9saWN5IEJ5cGFzcyBgIiQoJHNjcmlwdFBhdGgp
YCIgJCgkU3R1ZGVudElEKSAkKCRQYXNzd29yZCkgJCgkQ2FycmllcikgJGZhbHNl
ICR0cnVlIg0KJHNldHRpbmdzID0gTmV3LVNjaGVkdWxlZFRhc2tTZXR0aW5nc1Nl
dCAtRG9udFN0b3BPbklkbGVFbmQgLUFsbG93U3RhcnRJZk9uQmF0dGVyaWVzDQoN
CiR0ZW1wID0gUmVnaXN0ZXItU2NoZWR1bGVkVGFzayAtVGFza05hbWUgJHRhc2tO
YW1lIC1UcmlnZ2VyIEAoJHRyaWdnZXJMb2dpbiwgJHRyaWdnZXJEYWlseSkgLUFj
dGlvbiAkYWN0aW9uIC1Vc2VyICJTWVNURU0iIC1TZXR0aW5ncyAkc2V0dGluZ3Mg
LVJ1bkxldmVsIEhpZ2hlc3QgLUZvcmNlDQoNCmlmICgkcmVjb25uZWN0KSB7DQoJ
V3JpdGUtSG9zdCAi1f3U2sno1sPDvyAkcmVjb25uZWN0ILfW1tPRrbu3vOyy4i4u
LiIgLUZvcmVncm91bmRDb2xvciBHcmVlbg0KCSR0cmlnZ2VyVGltZSA9IE5ldy1T
Y2hlZHVsZWRUYXNrVHJpZ2dlciAtQXQgIjA6MDAiIC1PbmNlIC1SZXBldGl0aW9u
SW50ZXJ2YWwgKE5ldy1UaW1lU3BhbiAtTWludXRlcyAkcmVjb25uZWN0KQ0KCSR0
ZW1wID0gUmVnaXN0ZXItU2NoZWR1bGVkVGFzayAtVGFza05hbWUgJHRhc2tOYW1l
MiAtVHJpZ2dlciAkdHJpZ2dlclRpbWUgLUFjdGlvbiAkYWN0aW9uMiAtVXNlciAi
U1lTVEVNIiAtU2V0dGluZ3MgJHNldHRpbmdzIC1SdW5MZXZlbCBIaWdoZXN0IC1G
b3JjZQ0KfQ0KDQpXcml0ZS1Ib3N0ICLV/dTayejWw9TaIFdpRmkgLyDS1MyrzfjB
rL3TyrG1x8K8Li4uIiAtRm9yZWdyb3VuZENvbG9yIEdyZWVuDQoNCiMgzqq8xruu
yM7O8cztvNMgV2lGaSAvINLUzKvN+CDBrL3TysK8/qOozai5/dDeuMQgeG1so6kN
CmZ1bmN0aW9uIEFkZC1OZXR3b3JrLUV2ZW50IHsNCiAgICBwYXJhbSAoDQogICAg
ICAgIFtzdHJpbmddJHRhc2tOYW1lDQogICAgKQ0KDQoJIyC2wcihyM7O8bzGu66z
zNDytcQgWE1MIMXk1sPOxLz+DQoJJHRhc2tYbWwgPSBOZXctT2JqZWN0IFhNTA0K
CSR4bWxUZXh0ID0gRXhwb3J0LVNjaGVkdWxlZFRhc2sgLVRhc2tOYW1lICR0YXNr
TmFtZQ0KCSR0YXNrWG1sLkxvYWRYbWwoJHhtbFRleHQpDQoNCgkjILS0vaggTmV0
d29yayDKwrz+tKW3osb3vdq14w0KCSRuZXdFdmVudFRyaWdnZXIgPSAkdGFza1ht
bC5DcmVhdGVFbGVtZW50KCJFdmVudFRyaWdnZXIiLCAkdGFza1htbC5Eb2N1bWVu
dEVsZW1lbnQuTmFtZXNwYWNlVVJJKQ0KDQoJIyDM7bzTIEVuYWJsZWQgvdq14w0K
CSRuZXdFbmFibGVkID0gJHRhc2tYbWwuQ3JlYXRlRWxlbWVudCgiRW5hYmxlZCIs
ICR0YXNrWG1sLkRvY3VtZW50RWxlbWVudC5OYW1lc3BhY2VVUkkpDQoJJG5ld0Vu
YWJsZWQuSW5uZXJUZXh0ID0gInRydWUiDQoJJHRlbXAgPSAkbmV3RXZlbnRUcmln
Z2VyLkFwcGVuZENoaWxkKCRuZXdFbmFibGVkKQ0KDQoJIyDM7bzTIFN1YnNjcmlw
dGlvbiC92rXjDQoJJG5ld1N1YnNjcmlwdGlvbiA9ICR0YXNrWG1sLkNyZWF0ZUVs
ZW1lbnQoIlN1YnNjcmlwdGlvbiIsICR0YXNrWG1sLkRvY3VtZW50RWxlbWVudC5O
YW1lc3BhY2VVUkkpDQoJPCMgJG5ld1N1YnNjcmlwdGlvbi5Jbm5lclhtbCA9ICcm
bHQ7UXVlcnlMaXN0Jmd0OyZsdDtRdWVyeSBJZD0iMCIgUGF0aD0iU3lzdGVtIiZn
dDsmbHQ7U2VsZWN0IFBhdGg9Ik1pY3Jvc29mdC1XaW5kb3dzLVdMQU4tQXV0b0Nv
bmZpZy9PcGVyYXRpb25hbCImZ3Q7KltTeXN0ZW1bUHJvdmlkZXJbQE5hbWU9Ik1p
Y3Jvc29mdC1XaW5kb3dzLVdMQU4tQXV0b0NvbmZpZyJdIGFuZCAoRXZlbnRJRD04
MDAxKV1dDQoJW0V2ZW50RGF0YVtEYXRhW0BOYW1lPSJTU0lEIl09IkNVTVRfU3R1
Il0gb3IgRXZlbnREYXRhW0RhdGFbQE5hbWU9IlNTSUQiXT0iQ1VNVF9UZWMiXV0N
CgkmbHQ7L1NlbGVjdCZndDsmbHQ7L1F1ZXJ5Jmd0OyZsdDsvUXVlcnlMaXN0Jmd0
OycgIz4NCgkkbmV3U3Vic2NyaXB0aW9uLklubmVyWG1sID0gJyZsdDtRdWVyeUxp
c3QmZ3Q7Jmx0O1F1ZXJ5IElkPSIwIiBQYXRoPSJTeXN0ZW0iJmd0OyZsdDtTZWxl
Y3QgUGF0aD0iTWljcm9zb2Z0LVdpbmRvd3MtV0xBTi1BdXRvQ29uZmlnL09wZXJh
dGlvbmFsIiZndDsqW1N5c3RlbVtQcm92aWRlcltATmFtZT0iTWljcm9zb2Z0LVdp
bmRvd3MtV0xBTi1BdXRvQ29uZmlnIl0gYW5kIChFdmVudElEPTgwMDEpXV0NCglb
RXZlbnREYXRhW0RhdGFbQE5hbWU9IlNTSUQiXT0iQ1VNVF9TdHUiXSBvciBFdmVu
dERhdGFbRGF0YVtATmFtZT0iU1NJRCJdPSJDVU1UX1RlYyJdXQ0KCSZsdDsvU2Vs
ZWN0Jmd0OyZsdDsvUXVlcnkmZ3Q7Jmx0O1F1ZXJ5IElkPSIxIiBQYXRoPSJTeXN0
ZW0iJmd0OyZsdDtTZWxlY3QgUGF0aD0iTWljcm9zb2Z0LVdpbmRvd3MtTmV0d29y
a1Byb2ZpbGUvT3BlcmF0aW9uYWwiJmd0OypbU3lzdGVtW1Byb3ZpZGVyW0BOYW1l
PSJNaWNyb3NvZnQtV2luZG93cy1OZXR3b3JrUHJvZmlsZSJdIGFuZCAoRXZlbnRJ
RD0xMDAwMCldXQ0KCVtFdmVudERhdGFbRGF0YVtATmFtZT0iTmFtZSJdPSJDVU1U
X1N0dSJdIG9yIEV2ZW50RGF0YVtEYXRhW0BOYW1lPSJOYW1lIl09IkNVTVRfVGVj
Il1dDQoJJmx0Oy9TZWxlY3QmZ3Q7Jmx0Oy9RdWVyeSZndDsmbHQ7L1F1ZXJ5TGlz
dCZndDsnDQoJJHRlbXAgPSAkbmV3RXZlbnRUcmlnZ2VyLkFwcGVuZENoaWxkKCRu
ZXdTdWJzY3JpcHRpb24pDQoNCgkjIMztvNPKwrz+tKW3osb3vdq147W9yM7O8bzG
u66zzNDyIFhNTCDF5NbD1tANCgkkdGVtcCA9ICR0YXNrWG1sLlRhc2suVHJpZ2dl
cnMuQXBwZW5kQ2hpbGQoJG5ld0V2ZW50VHJpZ2dlcikNCg0KCSMgobCyu7nc08O7
p8rHt/G1x8K8trzSqtTL0NChsQ0KCTwjICRuZXdMb2dvblR5cGUgPSAkdGFza1ht
bC5DcmVhdGVFbGVtZW50KCJMb2dvblR5cGUiLCAkdGFza1htbC5Eb2N1bWVudEVs
ZW1lbnQuTmFtZXNwYWNlVVJJKQ0KCSRuZXdMb2dvblR5cGUuSW5uZXJUZXh0ID0g
IlBhc3N3b3JkIg0KCSR0ZW1wID0gJHRhc2tYbWwuVGFzay5QcmluY2lwYWxzLlBy
aW5jaXBhbC5BcHBlbmRDaGlsZCgkbmV3TG9nb25UeXBlKSAjPg0KDQoJIyC4/NDC
yM7O8bzGu66zzNDytcQgWE1MIMXk1sMNCglVbnJlZ2lzdGVyLVNjaGVkdWxlZFRh
c2sgLVRhc2tOYW1lICR0YXNrTmFtZSAtQ29uZmlybTokZmFsc2UNCgkkdGVtcCA9
IFJlZ2lzdGVyLVNjaGVkdWxlZFRhc2sgLVRhc2tOYW1lICR0YXNrTmFtZSAtWG1s
ICR0YXNrWG1sLk91dGVyWG1sDQoJDQp9DQoNCkFkZC1OZXR3b3JrLUV2ZW50ICR0
YXNrTmFtZQ0KDQojIMztvNPL5rv60dPKsQ0KZnVuY3Rpb24gQWRkLVJhbmRvbS1E
ZWxheSB7DQogICAgcGFyYW0gKA0KICAgICAgICBbc3RyaW5nXSR0YXNrTmFtZSwN
CgkJW3N0cmluZ10kZGVsYXksDQoJCVtib29sXSRmbGFnDQogICAgKQ0KDQoJIyC2
wcihyM7O8bzGu66zzNDytcQgWE1MIMXk1sPOxLz+DQoJJHRhc2tYbWwgPSBOZXct
T2JqZWN0IFhNTA0KCSR4bWxUZXh0ID0gRXhwb3J0LVNjaGVkdWxlZFRhc2sgLVRh
c2tOYW1lICR0YXNrTmFtZQ0KCSR0YXNrWG1sLkxvYWRYbWwoJHhtbFRleHQpDQoN
CgkjIMvmu/rR08qxDQoJJG5ld1JhbmRvbURlbGF5ID0gJHRhc2tYbWwuQ3JlYXRl
RWxlbWVudCgiUmFuZG9tRGVsYXkiLCAkdGFza1htbC5Eb2N1bWVudEVsZW1lbnQu
TmFtZXNwYWNlVVJJKQ0KCWlmICgkZmxhZykgew0KCQkkbmV3UmFuZG9tRGVsYXku
SW5uZXJUZXh0ID0gJGRlbGF5DQoJCSR0ZW1wID0gJHRhc2tYbWwuVGFzay5Ucmln
Z2Vycy5UaW1lVHJpZ2dlci5BcHBlbmRDaGlsZCgkbmV3UmFuZG9tRGVsYXkpDQoJ
fQ0KCWVsc2Ugew0KCQkkbmV3UmFuZG9tRGVsYXkuSW5uZXJUZXh0ID0gJGRlbGF5
DQoJCSR0ZW1wID0gJHRhc2tYbWwuVGFzay5UcmlnZ2Vycy5DYWxlbmRhclRyaWdn
ZXIuQXBwZW5kQ2hpbGQoJG5ld1JhbmRvbURlbGF5KQ0KCX0NCg0KCSMguPzQwsjO
zvG8xruus8zQ8rXEIFhNTCDF5NbDDQoJVW5yZWdpc3Rlci1TY2hlZHVsZWRUYXNr
IC1UYXNrTmFtZSAkdGFza05hbWUgLUNvbmZpcm06JGZhbHNlDQoJJHRlbXAgPSBS
ZWdpc3Rlci1TY2hlZHVsZWRUYXNrIC1UYXNrTmFtZSAkdGFza05hbWUgLVhtbCAk
dGFza1htbC5PdXRlclhtbA0KCQ0KfQ0KDQpBZGQtUmFuZG9tLURlbGF5ICR0YXNr
TmFtZSAiUFQzTSIgJGZhbHNlDQppZiAoJHJlY29ubmVjdCkgew0KCUFkZC1SYW5k
b20tRGVsYXkgJHRhc2tOYW1lMiAiUFQkKFtNYXRoXTo6Q2VpbGluZygkcmVjb25u
ZWN0LzMpKU0iICR0cnVlDQp9DQoNCiMgyuSz9sno1sOzybmm0MXPog0KV3JpdGUt
SG9zdCBAIg0KDQqhzCDJ6NbDzeqzyaOhyPTOtLP2z9a67NfWtO3O88zhyr6jrNTy
xPq1xNfUtq+1x8K8uabE3NLRvq3J+tCnoaMNCqHMIMT6tcS158TU0tS688GsvdPQ
o9SwzfjKsb2r19S2r7XHwryjrM7e0OjE+tTZtPK/qrG+s8zQ8qGjxPrP1tTav8nS
1LnYsdWxvrPM0PKhow0K08nT2rG+s8zQ8rvhyKvX1LavtcfCvKOsyOfE+tP2tb21
x8K8yeixuLOsz961yMfpv/bQ6NKq16LP+sqxo6wNCsfryta2r7Tyv6ogMTAuMi41
LjI1MaOotcfCvNKzw+ajqaOsu/K1x8K819S3/s7xz7XNsyAyMDIuMTE5LjE5Ni42
OjgwODAvU2VsZiC9+NDQstnX96GjDQrI59Do0N64xMno1sPQxc+io6zWu9Do1tjQ
wtTL0NCxvrPM0PKhow0KyPSz9s/WuuzX1rGotO2jrMfrs6LK1NbY0MLUy9DQsb6z
zNDyoaMNCg0KIkAgLUZvcmVncm91bmRDb2xvciBHcmVlbg0KDQojIMrks/bP7sS/
0MXPog0KV3JpdGUtSG9zdCBAIg0Ksb7P7sS/wbS906O6aHR0cHM6Ly9naXRodWIu
Y29tL3pqc3hwbHkvQ1VNVC1OZXR3b3JrLUxvZ2luDQqxvs/uxL/A+sqx1LwgMTIg
0KHKscnPz9+jrMbavOS1w7W9wcsgR1BULTQgtcS088G/sO/W+qOhDQrI57bUIEdQ
VCDT0NDLyKSjrLu2062808jro7q/87TzIENoYXRHUFQgvbvB98i6IDY0Njc0NTgw
OA0KDQrB7bi9uPfRp9S6w/G85NfK1LS31s/tyLqjusr90acgNDU0MTYyMjM3o6y7
r7mkIDgwODcyNzMwMaOo0rvIuqOpIDI0MDQ5NDg1o6i2/si6o6kNCrzGy+O7+iA5
MTY0ODM1NDWjrLu3suIgOTA5ODkzMjM4o6zQxb/YIDQ2NDExMjE2OKOsu/q15yA3
MTcxNzY3NzOjrLXnwaYgODMwNjA0NTk5DQoNCiJAIC1Gb3JlZ3JvdW5kQ29sb3Ig
Q3lhbg0KDQokdGVtcCA9IFJlYWQtSG9zdCAisLS72LO1vPzNy7P2Li4uIg0KPCMg
V3JpdGUtSG9zdCAisLTIztLivPzNy7P2Li4uIg0KDQojILXItP3Tw7unsLTPwsjO
0uK8/KOs0tSx49TavcWxvta00NC94cr4uvOxo8H0IFBvd2VyU2hlbGwgtLC/2tLU
sum/tMrks/YNCiRIb3N0LlVJLlJhd1VJLlJlYWRLZXkoIk5vRWNobyxJbmNsdWRl
S2V5RG93biIpID4gJG51bGwgIz4NCg==
-----END CERTIFICATE-----
