@echo off

REM 本项目地址：https://github.com/zjsxply/CUMT-Network-Login

REM 判断是否安装 Powershell
setlocal
set "version="
for /f "delims=" %%i in ('powershell "[string]$PSVersionTable.PSVersion"') do set "version=%%i"
if not defined version (
    echo 此电脑上没有安装本程序运行所需的 PowerShell。您需要先安装 PowerShell，然后再次运行本程序。
	pause
) else (
	set "version=%version:PSVersion=%"
    REM echo 本地 PowerShell 版本：%version: =% 
)

REM 请求管理员权限
@%1 echo 正在请求管理员权限...&&mshta vbscript:CreateObject("Shell.Application").ShellExecute("cmd.exe","/c %~s0 ::","","runas",1)(window.close)&&exit
@cd /d "%~dp0"

REM 获取应用程序目录
set APPDIR=%APPDATA%\CUMT
if not exist "%APPDIR%" mkdir "%APPDIR%" > nul

REM 将 Powershell 脚本文件写入磁盘
if exist "%APPDIR%\LoginNetwork.ps1" del "%APPDIR%\LoginNetwork.ps1" > nul
certutil -decode "%~f0" "%APPDIR%\LoginNetwork.ps1" > nul

REM 执行 Powershell 脚本
powershell -ExecutionPolicy Bypass -File "%APPDIR%\LoginNetwork.ps1"

REM 执行完毕，等候两秒退出
timeout /t 2 >nul
exit /b 1


REM 以下是本 bat 文件内嵌的 Powershell 脚本文件
-----BEGIN CERTIFICATE-----
IyC2qNLltcfCvLqvyv0NCmZ1bmN0aW9uIFNlbmQtTG9naW4tUmVxdWVzdCB7DQog
ICAgcGFyYW0gKA0KICAgICAgICBbc3RyaW5nXSRTdHVkZW50SUQsDQogICAgICAg
IFtzdHJpbmddJFBhc3N3b3JkLA0KICAgICAgICBbc3RyaW5nXSRDYXJyaWVyDQog
ICAgKQ0KCQkNCglpZiAoW2Jvb2xdJENhcnJpZXIpIHsNCgkJJENhcnJpZXIgPSAi
QCQoJENhcnJpZXIpIg0KCX0NCgkkdXJsID0gImh0dHA6Ly8xMC4yLjUuMjUxOjgw
MS9lcG9ydGFsLz9jPVBvcnRhbCZhPWxvZ2luJmxvZ2luX21ldGhvZD0xJnVzZXJf
YWNjb3VudD0kKCRTdHVkZW50SUQpJCgkQ2FycmllcikmdXNlcl9wYXNzd29yZD0k
KCRQYXNzd29yZCkiDQoJJHJlc3BvbnNlID0gSW52b2tlLVdlYlJlcXVlc3QgLVVy
aSAkdXJsIC1Vc2VCYXNpY1BhcnNpbmcNCgkkcmVzcFRleHQgPSAkcmVzcG9uc2Uu
Q29udGVudC5UcmltU3RhcnQoJygnKS5UcmltRW5kKCcpJykNCgkkcmVzcEpzb24g
PSBDb252ZXJ0RnJvbS1Kc29uICRyZXNwVGV4dA0KCQ0KCXN3aXRjaCAoJHJlc3BK
c29uLnJlc3VsdCkgew0KCQkxIHsNCgkJCSRub3RpZmljYXRpb24gPSAitcfCvLPJ
uaYiDQoJCX0NCgkJMCB7DQoJCQlzd2l0Y2ggKCRyZXNwSnNvbi5yZXRfY29kZSkg
ew0KCQkJCTEgew0KCQkJCQkkYnl0ZXMgPSBbU3lzdGVtLkNvbnZlcnRdOjpGcm9t
QmFzZTY0U3RyaW5nKCRyZXNwSnNvbi5tc2cpDQoJCQkJCSRtc2cgPSBbU3lzdGVt
LlRleHQuRW5jb2RpbmddOjpVVEY4LkdldFN0cmluZygkYnl0ZXMpDQoJCQkJCXN3
aXRjaCAoJG1zZykgew0KCQkJCQkJInVzZXJpZCBlcnJvcjEiIHsNCgkJCQkJCQkk
bm90aWZpY2F0aW9uID0gItXLusWyu7Tm1NoiDQoJCQkJCQl9DQoJCQkJCQkiYXV0
aCBlcnJvcjgwIiB7DQoJCQkJCQkJJG5vdGlmaWNhdGlvbiA9ICKxvsqxts69+9a5
yc/N+CINCgkJCQkJCX0NCgkJCQkJCSJSYWQ6VXNlck5hbWVfRXJyIiB7DQoJCQkJ
CQkJJG5vdGlmaWNhdGlvbiA9ICKw87aotcTUy9OqyczVy7rFtO3O86Osx+vBqs+1
1MvTqsnMusvKtbvyyKXUy9OqyczQo9Sw06rStcz8vfjQ0LDztqihoyINCgkJCQkJ
CX0NCgkJCQkJCSJBdXRoZW50aWNhdGlvbiBGYWlsIEVyckNvZGU9MTYiIHsNCgkJ
CQkJCQkkbm90aWZpY2F0aW9uID0gIrG+yrG2zrK71MrQ7cnPzfgiDQoJCQkJCQl9
DQoJCQkJCQkiTWFjLCBJUCwgTkFTaXAsIFBPUlQgZXJyKDIpISIgew0KCQkJCQkJ
CSRub3RpZmljYXRpb24gPSAixPq1xNXLusWyu9TK0O3U2rTLzfjC58q508OjrMfr
vOyy6b3TyOu1xMrHIENVTVRfU3R1ILu5yscgQ1VNVF9UZWMgzfjC5yINCgkJCQkJ
CX0NCgkJCQkJCSJSYWQ6U3RhdHVzX0VyciIgew0KCQkJCQkJCSRub3RpZmljYXRp
b24gPSAixPqw87aotcTUy9OqyczVy7rF17TMrNLss6OjrMfrwarPtbbU06bUy9Oq
ycy0psDtoaMiDQoJCQkJCQl9DQoJCQkJCQkiUmFkOkxpbWl0IFVzZXJzIEVyciIg
ew0KCQkJCQkJCSRub3RpZmljYXRpb24gPSAixPq1xLXHwr2zrM/eo6zH69Ta19S3
/s7xIGh0dHA6Ly8yMDIuMTE5LjE5Ni42OjgwODAvU2VsZiDPws/f1tW2y6GjIg0K
CQkJCQkJfQ0KCQkJCQkJImxkYXAgYXV0aCBlcnJvciIgew0KCQkJCQkJCSRub3Rp
ZmljYXRpb24gPSAizbPSu8ntt93Iz9ak08O7p8P7w9zC67TtzvOjoSINCgkJCQkJ
CX0NCgkJCQkJCWRlZmF1bHQgew0KCQkJCQkJCSRub3RpZmljYXRpb24gPSAizrTW
qrTtzvOjuiQoJG1zZykiDQoJCQkJCQkJDQoJCQkJCQl9DQoJCQkJCX0NCgkJCQl9
DQoJCQkJMiB7DQoJCQkJCSRub3RpZmljYXRpb24gPSAixPrS0b6ttKbT2rXHwrzX
tMysIg0KCQkJCX0NCgkJCQkzIHsNCgkJCQkJJG5vdGlmaWNhdGlvbiA9ICLOtNaq
tO3O86OstO3O87T6wuujujMiDQoJCQkJfQ0KCQkJfQ0KCQl9DQoJCWRlZmF1bHQg
ew0KCQkJJG5vdGlmaWNhdGlvbiA9ICLOtNaqveG5+6O6JCgkcmVzcEpzb24pIg0K
CQkJDQoJCX0NCgl9DQoJDQoJcmV0dXJuICRub3RpZmljYXRpb24NCn0NCg0KIyC2
qNLltcfCvLqvyv0NCmZ1bmN0aW9uIExvZ2luLUNhbXB1c05ldHdvcmsgew0KICAg
IHBhcmFtICgNCiAgICAgICAgW3N0cmluZ10kU3R1ZGVudElELA0KICAgICAgICBb
c3RyaW5nXSRQYXNzd29yZCwNCiAgICAgICAgW3N0cmluZ10kQ2FycmllciwNCgkJ
W2Jvb2xdJFRlc3QgPSAkZmFsc2UNCiAgICApDQoNCiAgICAjILzssuIgSVAgMTAu
Mi40LjIgyse38b/J0tQgUGluZyDNqA0KICAgIGlmICgtbm90ICRUZXN0KSB7DQoJ
CSRwaW5nUmVzdWx0ID0gVGVzdC1Db25uZWN0aW9uIC1Db21wdXRlck5hbWUgIjEw
LjIuNC4yIiAtUXVpZXQgLUJ1ZmZlclNpemUgMSAtQ291bnQgMQ0KCQlpZiAoJHBp
bmdSZXN1bHQpIHsNCgkJCSRwaW5nUmVzdWx0VGV4dCA9ICLN+MLntKbT2sGszajX
tMysIg0KCQl9DQoJCWVsc2Ugew0KCQkJJHBpbmdSZXN1bHRUZXh0ID0gIs34wufO
tMGszaijrL/JxNy19M/fu/K41cGsvdPN+MLno7vWtNDQtcfCvDogIg0KCQl9DQoJ
fQ0KCQ0KCSMgsuLK1NTy0ru2qLeiy821x8K8x+vH8w0KICAgIGlmICgkVGVzdCAt
b3IgLW5vdCAkcGluZ1Jlc3VsdCkgew0KCQkkcGluZ1Jlc3VsdCA9IFRlc3QtQ29u
bmVjdGlvbiAtQ29tcHV0ZXJOYW1lICIxMC4yLjUuMjUxIiAtUXVpZXQgLUJ1ZmZl
clNpemUgMSAtQ291bnQgMQ0KCQlpZiAoLW5vdCAkcGluZ1Jlc3VsdCkgew0KCQkJ
JG5vdGlmaWNhdGlvbiA9ICK3x9Cj1LDN+Lu3vrMiDQoJCX0NCgkJZWxzZSB7DQoJ
CQkkbm90aWZpY2F0aW9uID0gU2VuZC1Mb2dpbi1SZXF1ZXN0ICRTdHVkZW50SUQg
JFBhc3N3b3JkICRDYXJyaWVyDQoJCQkNCgkJCSMgta+z9s+1zbPNqNaqz/vPog0K
CQkJIyBOZXctQnVybnRUb2FzdE5vdGlmaWNhdGlvbiAtVGV4dCAi0tGzosrUtcfC
vNCj1LDN+CIsICRub3RpZmljYXRpb24NCgkJfQ0KCQkNCiAgICB9DQoJCQ0KCXJl
dHVybiAkcGluZ1Jlc3VsdFRleHQgKyAkbm90aWZpY2F0aW9uDQp9DQoNCiMgtqjS
5deiz/q6r8r9DQpmdW5jdGlvbiBMb2dvdXQtQ2FtcHVzTmV0d29yayB7DQoJJHVy
bCA9ICJodHRwOi8vMTAuMi41LjI1MTo4MDEvZXBvcnRhbC8/Yz1Qb3J0YWwmYT1s
b2dvdXQiDQoJJHJlc3BvbnNlID0gSW52b2tlLVdlYlJlcXVlc3QgLVVyaSAkdXJs
IC1Vc2VCYXNpY1BhcnNpbmcNCn0NCg0KIyC2qNLlssO89MjV1r68x8K8uq/K/Q0K
ZnVuY3Rpb24gQ3V0LUZpbGVMb2cgew0KICAgIHBhcmFtICgNCiAgICAgICAgW3N0
cmluZ1tdXSRmaWxlQ29udGVudCwNCgkJW3N0cmluZ1tdXSRzLA0KICAgICAgICBb
aW50XSRudW0gPSAxMDANCiAgICApDQoNCgkjILfWsfC2qNLlw7+49tfWt/u0rrD8
uqy1xNDQyv3OqiAwo6y31rHwtqjS5bTmtKLDv7j219a3+7Su0NDK/bXEyv3X6Q0K
CSRjb3VudHMgPSBAe30NCgkkbGluZXMgPSBAe30NCglmb3JlYWNoICgkc3RyIGlu
ICRzKSB7DQoJCSRjb3VudHNbJHN0cl0gPSAwDQoJCSRsaW5lc1skc3RyXSA9IEAo
KQ0KCX0NCg0KCSMg0a27t7HpwPrDv9K70NCjrLzHwryw/Lqsw7+49tfWt/u0rrXE
0NDK/bKivavG5LTmtKK1vc/g06a1xMr91+nW0A0KCWZvcmVhY2ggKCRsaW5lIGlu
ICRmaWxlQ29udGVudCkgew0KCQlmb3JlYWNoICgkc3RyIGluICRzKSB7DQoJCQlp
ZiAoJGxpbmUgLW1hdGNoICRzdHIpIHsNCgkJCQkkY291bnRzWyRzdHJdKysNCgkJ
CQkkbGluZXNbJHN0cl0gKz0gJGxpbmUNCgkJCQlpZiAoJGNvdW50c1skc3RyXSAt
Z3QgJG51bSkgew0KCQkJCQkkbGluZXNbJHN0cl0gPSAkbGluZXNbJHN0cl0gfCBT
ZWxlY3QtT2JqZWN0IC1MYXN0ICRudW0NCgkJCQkJJGNvdW50c1skc3RyXSA9ICRu
dW0NCgkJCQl9DQoJCQkJYnJlYWsNCgkJCX0NCgkJfQ0KCX0NCg0KCSMgsLTV1dSt
z8i1xMuz0PLW2NDC1+m6z87EvP7E2sjdo6yyore1u9gNCgkkbmV3RmlsZUNvbnRl
bnQgPSBAKCkNCglmb3JlYWNoICgkbGluZSBpbiAkZmlsZUNvbnRlbnQpIHsNCgkJ
Zm9yZWFjaCAoJHN0ciBpbiAkcykgew0KCQkJaWYgKCRsaW5lIC1pbiAkbGluZXNb
JHN0cl0pIHsNCgkJCQkkbmV3RmlsZUNvbnRlbnQgKz0gJGxpbmUNCgkJCQlicmVh
aw0KCQkJfQ0KCQl9DQoJfQ0KCXJldHVybiAkbmV3RmlsZUNvbnRlbnQNCg0KfQ0K
DQojILao0uXIocjV1r7OxLz+wre+trqvyv0NCmZ1bmN0aW9uIEdldC1GaWxlTG9n
LVBhdGggew0KCSRsb2dGaWxlID0gSm9pbi1QYXRoICRQU1NjcmlwdFJvb3QgIkxv
Z2luTmV0d29yay5sb2ciDQoJaWYgKC1ub3QgKFRlc3QtUGF0aCAkbG9nRmlsZSkp
IHsNCgkJTmV3LUl0ZW0gLVBhdGggJGxvZ0ZpbGUgLUl0ZW1UeXBlIEZpbGUgLUZv
cmNlDQoJfQ0KCXJldHVybiAkbG9nRmlsZQ0KfQ0KDQojILao0uW8x8K8yNXWvrqv
yv0NCmZ1bmN0aW9uIFdyaXRlLUZpbGVMb2cgew0KICAgIHBhcmFtICgNCiAgICAg
ICAgW3N0cmluZ10kTG9nLA0KCQlbc3RyaW5nXSRjYWxsZXINCiAgICApDQoJDQoJ
IyDJ6NbDyNXWvs7EvP7Ct762DQoJJGxvZ0ZpbGUgPSBHZXQtRmlsZUxvZy1QYXRo
DQoJDQoJIyDJ6NbD0qrM7bzTtb3I1da+zsS8/tbQtcTOxLG+19a3+7SuDQoJJGxv
Z0Zvcm1hdCA9ICJbezA6eXl5eS1NTS1kZCBISDptbTpzc31dIHsxfSAtIHsyfSIN
CgkkdGltZXN0YW1wID0gR2V0LURhdGUNCgkkbG9nRW50cnkgPSAkbG9nRm9ybWF0
IC1mICR0aW1lc3RhbXAsICRjYWxsZXIsICRMb2cNCgkNCgkjIMztvNPQwsjV1r7E
2sjdtb3I1da+zsS8/sSpzrINCglBZGQtQ29udGVudCAkbG9nRmlsZSAtVmFsdWUg
JGxvZ0VudHJ5DQoNCgkjIMjnufvI1da+zPXK/bOsuf0gMTAwIMz1o6zU8ta7saPB
9Nfu0MK1xCAxMDAgzPUNCgkkbG9nQ29udGVudCA9IEdldC1Db250ZW50ICRsb2dG
aWxlDQoJU2V0LUNvbnRlbnQgJGxvZ0ZpbGUgKEN1dC1GaWxlTG9nICRsb2dDb250
ZW50IEAoIk1vbml0b3IiLCAiVHJpZ2dlciIpKQ0KDQp9DQoNCiMgw/zB7tDQv8m9
08rVIDUguPayzsr9o7rRp7rFIMPcwusg1MvTqsnMIMrHt/Gy4srUtcfCvCDKx7fx
zqq84LLiDQojILzGu67Izs7x1rTQ0LXHwrwNCmlmICgkYXJncykgew0KCQ0KCSMg
yOe5+8rHvOCy4qOs1PI3OjA1ILW9IDIzOjUwINauzeK1xMqxvOTS1CAxIC8gMjAg
tcS4xcLK1rTQ0LXHwrwNCgkkY3VycmVudERhdGUgPSBHZXQtRGF0ZQ0KCWlmICgk
YXJnc1s0XSkgew0KCQkkY2FsbGVyID0gIk1vbml0b3IiDQoJCSRpc0FmdGVyN18w
NSA9ICRjdXJyZW50RGF0ZS5Ib3VyIC1ndCA3IC1vciAoJGN1cnJlbnREYXRlLkhv
dXIgLWdlIDcgLWFuZCAkY3VycmVudERhdGUuTWludXRlIC1nZSAwNSkNCgkJJGlz
QmVmb3JlMjNfNTAgPSAkY3VycmVudERhdGUuSG91ciAtbHQgMjMgLW9yICgkY3Vy
cmVudERhdGUuSG91ciAtZXEgMjMgLWFuZCAkY3VycmVudERhdGUuTWludXRlIC1s
ZSA1MCkNCgkJaWYgKC1ub3QgKCRpc0FmdGVyN18wNSAtYW5kICRpc0JlZm9yZTIz
XzUwKSl7DQoJCQkkcmVzdWx0ID0gIrK71NogNzowNS0yMzo1MCDWrrzkLCDS1CAx
LzIwILjFwsq0pbeitcfCvNCj1LDN+DsgIg0KCQkJaWYgKEdldC1SYW5kb20gLU1h
eGltdW0gMjApIHsNCgkJCQkkcmVzdWx0ICs9ICLOtLSlt6LWtNDQIg0KCQkJfQ0K
CQkJZWxzZSB7DQoJCQkJJHJlc3VsdCArPSAitKW3ota00NCjrL3hufs6ICINCgkJ
CQkkcmVzdWx0ICs9IExvZ2luLUNhbXB1c05ldHdvcmsgLVN0dWRlbnRJRCAkYXJn
c1swXSAtUGFzc3dvcmQgJGFyZ3NbMV0gLUNhcnJpZXIgJGFyZ3NbMl0NCgkJCX0N
CgkJfQ0KCQllbHNlIHsNCgkJCSRyZXN1bHQgPSBMb2dpbi1DYW1wdXNOZXR3b3Jr
IC1TdHVkZW50SUQgJGFyZ3NbMF0gLVBhc3N3b3JkICRhcmdzWzFdIC1DYXJyaWVy
ICRhcmdzWzJdDQoJCX0NCgl9IGVsc2Ugew0KCQkkY2FsbGVyID0gIlRyaWdnZXIi
DQoJCSRyZXN1bHQgPSBMb2dpbi1DYW1wdXNOZXR3b3JrIC1TdHVkZW50SUQgJGFy
Z3NbMF0gLVBhc3N3b3JkICRhcmdzWzFdIC1DYXJyaWVyICRhcmdzWzJdDQoJfQ0K
CVdyaXRlLUZpbGVMb2cgJHJlc3VsdCAkY2FsbGVyDQoJRXhpdA0KfQ0KDQojINKq
x/O53MDt1LHIqM/eDQokcm9sZSA9IFtTZWN1cml0eS5QcmluY2lwYWwuV2luZG93
c1ByaW5jaXBhbF1bU2VjdXJpdHkuUHJpbmNpcGFsLldpbmRvd3NJZGVudGl0eV06
OkdldEN1cnJlbnQoKQ0KJGlzQWRtaW4gPSAkcm9sZS5Jc0luUm9sZShbU2VjdXJp
dHkuUHJpbmNpcGFsLldpbmRvd3NCdWlsdEluUm9sZV0gIkFkbWluaXN0cmF0b3Ii
KSAtb3IgW2Jvb2xdJHJvbGUuSXNTeXN0ZW0NCmlmICgtbm90ICRpc0FkbWluKSB7
DQoJV3JpdGUtSG9zdCAi0OjSqrncwO3Uscioz96jrMfrx/PIqM/e1tAuLi4iIC1G
b3JlZ3JvdW5kQ29sb3IgWWVsbG93DQogICAgU3RhcnQtUHJvY2VzcyBwb3dlcnNo
ZWxsLmV4ZSAiLU5vUHJvZmlsZSAtRXhlY3V0aW9uUG9saWN5IEJ5cGFzcyAtRmls
ZSBgIiRQU0NvbW1hbmRQYXRoYCIiIC1WZXJiIFJ1bkFzDQogICAgRXhpdA0KfQ0K
DQojIMrks/a149Xz19YNCldyaXRlLUhvc3QgQCINCg0KoaGhoaGhofSh9KH0ofSh
9KH0oaGhoaH0ofSh9KH0oaGh9KH0ofSh9KGhofSh9KH0ofShoaGhoaGhoaH0ofSh
9KGhofSh9KH0ofSh9KH0ofSh9KH0oaENCqGhoaGh9KH0ofShoaGhofSh9KGhoaGh
oaH0ofShoaGhoaGh9KH0oaGhoaGhofSh9KH0oaGhoaGhoaGh9KH0oaGhoaH0ofSh
oaGhofShoaGhofSh9KGhDQqhoaGhofSh9KGhoaGhoaGhofSh9KGhoaGh9KGhoaGh
oaGhoaGh9KGhoaGhoaGhofSh9KH0oaGhoaH0ofSh9KGhoaGh9KH0oaGhoaH0oaGh
oaH0ofShoQ0KoaGhoaH0ofShoaGhoaGhoaGhoaGhoaGhofShoaGhoaGhoaGhofSh
oaGhoaGhoaH0ofSh9KGhoaGh9KH0ofShoaGhoaGhoaGhoaGh9KGhoaGhoaGhoaEN
CqGhofSh9KH0oaGhoaGhoaGhoaGhoaGhoaH0oaGhoaGhoaGhoaH0oaGhoaGhoaGh
9KH0ofSh9KGhofShoaH0oaGhoaGhoaGhoaGhofShoaGhoaGhoaGhDQqhoaH0ofSh
9KGhoaGhoaGhoaGhoaGhoaGh9KGhoaGhoaGhoaGh9KGhoaGhoaGhofShoaH0ofSh
9KH0oaGh9KGhoaGhoaGhoaGhoaH0oaGhoaGhoaGhoQ0KoaGhoaH0ofShoaGhoaGh
oaH0ofShoaGhofSh9KGhoaGhoaH0ofShoaGhoaGhoaH0oaGh9KH0ofShoaGhofSh
oaGhoaGhoaGhoaGh9KGhoaGhoaGhoaENCqGhoaGh9KH0ofShoaGhofSh9KH0oaGh
oaH0ofShoaGhoaGh9KH0oaGhoaGhoaGh9KGhoaGh9KH0oaGhoaH0oaGhoaGhoaGh
oaGhofShoaGhoaGhoaGhDQqhoaGhoaGh9KH0ofSh9KH0ofShoaGhoaGh9KH0ofSh
9KH0ofSh9KGhoaGh9KH0ofSh9KGhofSh9KH0ofSh9KH0oaGhoaGhofSh9KH0ofSh
9KGhoaGhoQ0KDQoiQCAtRm9yZWdyb3VuZENvbG9yIEJsdWUNCg0KIyC9xbG+venJ
3A0KV3JpdGUtSG9zdCBAIg0K1eLKx9K7uPa/ydLUyejWwyBDVU1UINCj1LDN+NfU
tq+1x8K8tcSzzNDyoaPUy9PDtuDW1rSlt6LG96Os1qez1tLUz8K5psTco7oNCqHM
IMGsvdMgQ1VNVF9TdHUgu/IgQ1VNVF9UZWMgV2lGaSDKsdfUtq+1x8K8DQqhzCDB
rL3TIENVTVRfU3R1IM34z98gKNLUzKvN+CkgyrHX1LavtcfCvA0KocwgveLL+L34
yOu158TUyrHX1LavtcfCvA0Kocwgw7/M7MnPzucgNzoyMiAtIDc6MjUg19S2r7XH
wrwNCqHMICi/ydGhKSDRrbu3vOyy4qOstfTP39fUtq/W2LXHDQq24NbWt73KvbGj
1qTE+rXEx+G/7MnPzfjM5dHpo6ENCrDmsb6junYyMDIzMDQyMg0KDQoiQCAtRm9y
ZWdyb3VuZENvbG9yIEN5YW4NCg0KPCMgIyCwstewIEJ1cm50VG9hc3QNCldyaXRl
LUhvc3QgItLUz8LI9NGvzsqwstewxKO/6cfryuTI6yB5ILKiu9iztSINCldyaXRl
LUhvc3QgItX91Nq87LLpy/nSwMC1tcTPtc2zzajWqsSjv+kuLi4iDQpJbnN0YWxs
LU1vZHVsZSBCdXJudFRvYXN0DQpXcml0ZS1Ib3N0ICLS0bCy17DL+dLAwLW1xMSj
v+kiDQpXcml0ZS1Ib3N0ICIiICM+DQoNCiMgyei2qLzGu67Izs7xw/uzxg0KJHRh
c2tOYW1lID0gIkNVTVTX1LavtcfCvNCj1LDN+CINCiR0YXNrTmFtZTIgPSAiQ1VN
VNfUtq+1x8K80KPUsM34oaqhqrzgsuIiDQoNCiMgyPS8xruuyM7O8dLRtObU2qOs
1PLRodTxyb6z/bu5yse4srjHDQokdGFza0V4aXN0cyA9IEdldC1TY2hlZHVsZWRU
YXNrIHwgV2hlcmUtT2JqZWN0IHsgJF8uVGFza05hbWUgLWVxICR0YXNrTmFtZSB9
DQokdGFza0V4aXN0czIgPSBHZXQtU2NoZWR1bGVkVGFzayB8IFdoZXJlLU9iamVj
dCB7ICRfLlRhc2tOYW1lIC1lcSAkdGFza05hbWUyIH0NCmlmICgkdGFza0V4aXN0
cyAtb3IgJHRhc2tFeGlzdHMyKSB7DQoJV3JpdGUtSG9zdCAiz7XNs7zssuK1vdLR
yejWw7n919S2r7XHwryhoyIgLUZvcmVncm91bmRDb2xvciBZZWxsb3cNCgkNCgkk
bG9nQ29udGVudCA9IEdldC1Db250ZW50IChHZXQtRmlsZUxvZy1QYXRoKQ0KCVdy
aXRlLUhvc3QgIiINCglXcml0ZS1Ib3N0ICLX7r38tcTWtNDQyNXWvsjnz8KjuiIN
CglXcml0ZS1Ib3N0ICgoQ3V0LUZpbGVMb2cgJGxvZ0NvbnRlbnQgQCgnTW9uaXRv
cicsICdUcmlnZ2VyJykgNSkgLWpvaW4gImBuIikNCglXcml0ZS1Ib3N0ICIiDQoJ
DQoJZG8gew0KCQkkcmVzcG9uc2UgPSBSZWFkLUhvc3QgIsfr0aHU8aO6yb6z/cno
1sMgLyC4srjH1K3J6NbD1tjQwsno1sOjvyjJvrP9IFkgLyDW2NDCyejWwyBOo6zE
rMjPIE6jqSINCgl9IHdoaWxlICgkcmVzcG9uc2UgLW5vdG1hdGNoICJeW3luWU5d
JCIgLWFuZCAkcmVzcG9uc2UgLW5lICcnKQ0KDQoJaWYgKCR0YXNrRXhpc3RzKSB7
DQoJCVVucmVnaXN0ZXItU2NoZWR1bGVkVGFzayAtVGFza05hbWUgJHRhc2tOYW1l
IC1Db25maXJtOiRmYWxzZQ0KCX0NCglpZiAoJHRhc2tFeGlzdHMyKSB7DQoJCVVu
cmVnaXN0ZXItU2NoZWR1bGVkVGFzayAtVGFza05hbWUgJHRhc2tOYW1lMiAtQ29u
ZmlybTokZmFsc2UNCgl9DQoJDQoJaWYgKCRyZXNwb25zZSAtaW1hdGNoICJeW3lZ
XSQiKSB7DQoJCVdyaXRlLUhvc3QgItLR0saz/dCj1LDN+NfUtq+1x8K8uabE3KOs
u7bTrcT6z8K0zsq508OjoSIgLUZvcmVncm91bmRDb2xvciBHcmVlbg0KCQlXcml0
ZS1Ib3N0ICKwtMjO0uK8/M3Ls/YuLi4iDQoJCSRIb3N0LlVJLlJhd1VJLlJlYWRL
ZXkoIk5vRWNobyxJbmNsdWRlS2V5RG93biIpID4gJG51bGwNCgkJRXhpdA0KCX0N
CgllbHNlIHsNCgkJV3JpdGUtSG9zdCAiIg0KCX0NCn0NCg0KIyDH68fz08O7p8rk
yOujrLKi0enWpNXLu6cNCldyaXRlLUhvc3QgIr3Tz8LAtKOsx+vK5MjrxPq1xNXL
u6fQxc+io6zIu7rzsLS72LO1vPwiIC1Gb3JlZ3JvdW5kQ29sb3IgR3JlZW4NCmRv
IHsNCglXcml0ZS1Ib3N0ICIiDQoJZG8gew0KCQkkU3R1ZGVudElEID0gUmVhZC1I
b3N0ICLH68rkyOvE+rXE0ae6xSINCgl9IHdoaWxlICgtbm90ICRTdHVkZW50SUQp
DQoJZG8gew0KCQkkc2VjdXJlUGFzc3dvcmQgPSBSZWFkLUhvc3QgLVByb21wdCAi
x+vK5MjrxPq1xMPcwusiIC1Bc1NlY3VyZVN0cmluZw0KCX0gd2hpbGUgKC1ub3Qg
JHNlY3VyZVBhc3N3b3JkKQ0KCSRQYXNzd29yZCA9IFtTeXN0ZW0uUnVudGltZS5J
bnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlB0clRvU3RyaW5nQXV0byhbU3lzdGVt
LlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTZWN1cmVTdHJpbmdU
b0JTVFIoJHNlY3VyZVBhc3N3b3JkKSkNCglkbyB7DQoJCSRDYXJyaWVyID0gUmVh
ZC1Ib3N0ICLH68rkyOvE+rXE1MvTqsnMo6jH68rk0PK6xaO6MS7SxravIDIuwarN
qCAzLrXn0MUgMC7Qo9SwzfggLyBUZWMg1cu6xaOpIg0KCX0gd2hpbGUgKC1ub3Qg
JENhcnJpZXIpDQoJc3dpdGNoICgkQ2Fycmllcikgew0KCQkiMCIgew0KCQkJJENh
cnJpZXIgPSAiIg0KCQl9DQoJCSIxIiB7DQoJCQkkQ2FycmllciA9ICJjbWNjIg0K
CQl9DQoJCSIyIiB7DQoJCQkkQ2FycmllciA9ICJ1bmljb20iDQoJCX0NCgkJIjMi
IHsNCgkJCSRDYXJyaWVyID0gInRlbGVjb20iDQoJCX0NCgkJItCj1LDN+CIgew0K
CQkJJENhcnJpZXIgPSAiIg0KCQl9DQoJCSLQo9SwIiB7DQoJCQkkQ2FycmllciA9
ICIiDQoJCX0NCgkJIiIgew0KCQkJJENhcnJpZXIgPSAiIg0KCQl9DQoJCSLSxrav
IiB7DQoJCQkkQ2FycmllciA9ICJjbWNjIg0KCQl9DQoJCSLBqs2oIiB7DQoJCQkk
Q2FycmllciA9ICJ1bmljb20iDQoJCX0NCgkJIrXn0MUiIHsNCgkJCSRDYXJyaWVy
ID0gInRlbGVjb20iDQoJCX0NCgkJInRlbGVjb20iIHsNCgkJCSRDYXJyaWVyID0g
InRlbGVjb20iDQoJCX0NCgkJImNtY2MiIHsNCgkJCSRDYXJyaWVyID0gImNtY2Mi
DQoJCX0NCgkJInVuaWNvbSIgew0KCQkJJENhcnJpZXIgPSAidW5pY29tIg0KCQl9
DQoJCWRlZmF1bHQgew0KCQkJV3JpdGUtSG9zdCAivq+45qO6zrTWqrXE1MvTqsnM
o6y/ycTctbzWwrXHwrzKp7DcIiAtRm9yZWdyb3VuZENvbG9yIFllbGxvdw0KCQl9
DQoJfQ0KDQoJZG8gew0KCQlXcml0ZS1Ib3N0ICIiDQoJCVdyaXRlLUhvc3QgIsfr
yLexo8T6z9bU2tLRway909Cj1LDN+KGjIiAtTm9OZXdsaW5lIC1Gb3JlZ3JvdW5k
Q29sb3IgR3JlZW4NCgkJV3JpdGUtSG9zdCAi1f3U2rOiytS1x8K8Li4uICAiIC1O
b05ld2xpbmUgLUZvcmVncm91bmRDb2xvciBHcmVlbg0KCQkkcmVzdWx0ID0gTG9n
aW4tQ2FtcHVzTmV0d29yayAtU3R1ZGVudElEICRTdHVkZW50SUQgLVBhc3N3b3Jk
ICRQYXNzd29yZCAtQ2FycmllciAkQ2FycmllciAtVGVzdCAkdHJ1ZQ0KCQlXcml0
ZS1Ib3N0ICK1x8K8veG5+6O6JHJlc3VsdCINCgkJaWYgKCRyZXN1bHQgLWVxICLE
+tLRvq20ptPatcfCvNe0zKwiKSB7DQoJCQlXcml0ZS1Ib3N0ICK1x8K817TMrM/C
zt63qNHp1qTE47XE1cu7p9DFz6KhoyIgLUZvcmVncm91bmRDb2xvciBZZWxsb3cN
CgkJCWRvIHsNCgkJCQkkcmVzcG9uc2UgPSBSZWFkLUhvc3QgIsrHt/HPyNeiz/q1
x8K8o6zU2dbY0MK1x8K80tTR6dak0MXPosrHt/HV/ci3o78oWSAvIE4sIL2o0unR
6dak0tTD4tfUtq+1x8K81rTQ0MqnsNyjrMSsyM8gWaOpIg0KCQkJfSB3aGlsZSAo
JHJlc3BvbnNlIC1ub3RtYXRjaCAiXlt5bllOXSQiIC1hbmQgJHJlc3BvbnNlIC1u
ZSAnJykNCg0KCQkJaWYgKCRyZXNwb25zZSAtaW1hdGNoICJeW3lZXSQiIC1vciAk
cmVzcG9uc2UgLWVxICcnKSB7DQoJCQkJJGZsYWcyID0gJHRydWUNCgkJCQkkZmxh
ZyA9ICR0cnVlDQoJCQkJTG9nb3V0LUNhbXB1c05ldHdvcmsNCgkJCQlXcml0ZS1I
b3N0ICLS0deiz/rQo9SwzfgiIC1Gb3JlZ3JvdW5kQ29sb3IgR3JlZW4NCgkJCX0g
ZWxzZSB7DQoJCQkJJGZsYWcyID0gJGZhbHNlDQoJCQkJJGZsYWcgPSAkZmFsc2UN
CgkJCX0NCgkJfQ0KCQllbHNlaWYgKCRyZXN1bHQgLWVxICK1x8K8s8m5piIpIHsN
CgkJCSRmbGFnMiA9ICRmYWxzZQ0KCQkJJGZsYWcgPSAkZmFsc2UNCgkJfQ0KCQll
bHNlaWYgKCRyZXN1bHQgLWVxICLNs9K7ye233cjP1qTTw7unw/vD3MLrtO3O86Oh
Iikgew0KCQkJV3JpdGUtSG9zdCAiIg0KCQkJJGZsYWcyID0gJGZhbHNlDQoJCQkk
ZmxhZyA9ICR0cnVlDQoJCX0NCgkJZWxzZSB7DQoJCQlkbyB7DQoJCQkJJHJlc3Bv
bnNlID0gUmVhZC1Ib3N0ICLH69Gh1PHKx7fx1tjQwszu0LTQxc+io6zU2bTOs6LK
1LXHwrzS1NHp1qTQxc+iyse38dX9yLejvyhZIC8gTiwgvajS6dHp1qTS1MPi19S2
r7XHwrzWtNDQyqew3KOsxKzIzyBZo6kiDQoJCQl9IHdoaWxlICgkcmVzcG9uc2Ug
LW5vdG1hdGNoICJeW3luWU5dJCIgLWFuZCAkcmVzcG9uc2UgLW5lICcnKQ0KDQoJ
CQlpZiAoJHJlc3BvbnNlIC1pbWF0Y2ggIl5beVldJCIgLW9yICRyZXNwb25zZSAt
ZXEgJycpIHsNCgkJCQkkZmxhZzIgPSAkZmFsc2UNCgkJCQkkZmxhZyA9ICR0cnVl
DQoJCQl9IGVsc2Ugew0KCQkJCSRmbGFnMiA9ICRmYWxzZQ0KCQkJCSRmbGFnID0g
JGZhbHNlDQoJCQl9DQoJCX0NCgl9IHdoaWxlICgkZmxhZzIpDQp9IHdoaWxlICgk
ZmxhZykNCg0KV3JpdGUtSG9zdCAiIg0KDQojILX0z9/X1Lav1ti1xw0KZG8gew0K
CXRyeSB7DQoJCSRyZWNvbm5lY3QgPSBSZWFkLUhvc3QgIsrHt/G/qsb00a27t7zs
suKjrLX0z9/X1Lav1ti1x6O/KMj00OjSqsfryuTI69Gtu7e87LLivOS49LfW1tPK
/aO70ruw47K70OjSqqOs1rG907vYs7UpIg0KCQlpZiAoJHJlY29ubmVjdCAtZXEg
JycpIHsNCgkJCSRyZWNvbm5lY3QgPSAwDQoJCX0NCgkJZWxzZSB7DQoJCQlbaW50
XSRyZWNvbm5lY3QgPSAkcmVjb25uZWN0DQoJCX0NCgkJJGZsYWcgPSAkdHJ1ZQ0K
CX0gY2F0Y2ggew0KCQlXcml0ZS1Ib3N0ICLK5Mjrzt7Qp6Osx+vK5Mjr0ru49tX7
yv2hoyIgLUZvcmVncm91bmRDb2xvciBSZWQNCgl9DQp9IHdoaWxlICgtbm90ICRm
bGFnKQ0KDQpXcml0ZS1Ib3N0ICLV/dTayejWw73iy/i158TUus3Dv8zsyc/O5yA3
OjIyIC0gNzoyNSDKsdfUtq+1x8K8Li4uIiAtRm9yZWdyb3VuZENvbG9yIEdyZWVu
DQoNCiMgsaO05rWxx7C9xbG+tcTN6tX7wre+tg0KJHNjcmlwdFBhdGggPSAkTXlJ
bnZvY2F0aW9uLk15Q29tbWFuZC5QYXRoDQoNCiMgtLS9qLzGu67Izs7xDQokdHJp
Z2dlckxvZ2luID0gTmV3LVNjaGVkdWxlZFRhc2tUcmlnZ2VyIC1BdExvZ09uDQok
dHJpZ2dlckRhaWx5ID0gTmV3LVNjaGVkdWxlZFRhc2tUcmlnZ2VyIC1BdCAiNzoy
MiIgLURhaWx5DQokYWN0aW9uID0gTmV3LVNjaGVkdWxlZFRhc2tBY3Rpb24gLUV4
ZWN1dGUgJ1Bvd2Vyc2hlbGwuZXhlJyAtQXJndW1lbnQgIi1Ob1Byb2ZpbGUgLUV4
ZWN1dGlvblBvbGljeSBCeXBhc3MgYCIkKCRzY3JpcHRQYXRoKWAiICQoJFN0dWRl
bnRJRCkgJCgkUGFzc3dvcmQpICQoJENhcnJpZXIpIg0KJGFjdGlvbjIgPSBOZXct
U2NoZWR1bGVkVGFza0FjdGlvbiAtRXhlY3V0ZSAnUG93ZXJzaGVsbC5leGUnIC1B
cmd1bWVudCAiLU5vUHJvZmlsZSAtRXhlY3V0aW9uUG9saWN5IEJ5cGFzcyBgIiQo
JHNjcmlwdFBhdGgpYCIgJCgkU3R1ZGVudElEKSAkKCRQYXNzd29yZCkgJCgkQ2Fy
cmllcikgJGZhbHNlICR0cnVlIg0KJHNldHRpbmdzID0gTmV3LVNjaGVkdWxlZFRh
c2tTZXR0aW5nc1NldCAtRG9udFN0b3BPbklkbGVFbmQgLUFsbG93U3RhcnRJZk9u
QmF0dGVyaWVzDQoNCiR0ZW1wID0gUmVnaXN0ZXItU2NoZWR1bGVkVGFzayAtVGFz
a05hbWUgJHRhc2tOYW1lIC1UcmlnZ2VyIEAoJHRyaWdnZXJMb2dpbiwgJHRyaWdn
ZXJEYWlseSkgLUFjdGlvbiAkYWN0aW9uIC1Vc2VyICJTWVNURU0iIC1TZXR0aW5n
cyAkc2V0dGluZ3MgLVJ1bkxldmVsIEhpZ2hlc3QgLUZvcmNlDQoNCmlmICgkcmVj
b25uZWN0KSB7DQoJV3JpdGUtSG9zdCAi1f3U2sno1sPDvyAkcmVjb25uZWN0ILfW
1tPRrbu3vOyy4i4uLiIgLUZvcmVncm91bmRDb2xvciBHcmVlbg0KCSR0cmlnZ2Vy
VGltZSA9IE5ldy1TY2hlZHVsZWRUYXNrVHJpZ2dlciAtQXQgIjA6MDAiIC1PbmNl
IC1SZXBldGl0aW9uSW50ZXJ2YWwgKE5ldy1UaW1lU3BhbiAtTWludXRlcyAkcmVj
b25uZWN0KQ0KCSR0ZW1wID0gUmVnaXN0ZXItU2NoZWR1bGVkVGFzayAtVGFza05h
bWUgJHRhc2tOYW1lMiAtVHJpZ2dlciAkdHJpZ2dlclRpbWUgLUFjdGlvbiAkYWN0
aW9uMiAtVXNlciAiU1lTVEVNIiAtU2V0dGluZ3MgJHNldHRpbmdzIC1SdW5MZXZl
bCBIaWdoZXN0IC1Gb3JjZQ0KfQ0KDQpXcml0ZS1Ib3N0ICLV/dTayejWw9TaIFdp
RmkgLyDS1MyrzfjBrL3TyrG1x8K8Li4uIiAtRm9yZWdyb3VuZENvbG9yIEdyZWVu
DQoNCiMgzqq8xruuyM7O8cztvNMgV2lGaSAvINLUzKvN+CDBrL3TysK8/qOozai5
/dDeuMQgeG1so6kNCmZ1bmN0aW9uIEFkZC1OZXR3b3JrLUV2ZW50IHsNCiAgICBw
YXJhbSAoDQogICAgICAgIFtzdHJpbmddJHRhc2tOYW1lDQogICAgKQ0KDQoJIyC2
wcihyM7O8bzGu66zzNDytcQgWE1MIMXk1sPOxLz+DQoJJHRhc2tYbWwgPSBOZXct
T2JqZWN0IFhNTA0KCSR4bWxUZXh0ID0gRXhwb3J0LVNjaGVkdWxlZFRhc2sgLVRh
c2tOYW1lICR0YXNrTmFtZQ0KCSR0YXNrWG1sLkxvYWRYbWwoJHhtbFRleHQpDQoN
CgkjILS0vaggTmV0d29yayDKwrz+tKW3osb3vdq14w0KCSRuZXdFdmVudFRyaWdn
ZXIgPSAkdGFza1htbC5DcmVhdGVFbGVtZW50KCJFdmVudFRyaWdnZXIiLCAkdGFz
a1htbC5Eb2N1bWVudEVsZW1lbnQuTmFtZXNwYWNlVVJJKQ0KDQoJIyDM7bzTIEVu
YWJsZWQgvdq14w0KCSRuZXdFbmFibGVkID0gJHRhc2tYbWwuQ3JlYXRlRWxlbWVu
dCgiRW5hYmxlZCIsICR0YXNrWG1sLkRvY3VtZW50RWxlbWVudC5OYW1lc3BhY2VV
UkkpDQoJJG5ld0VuYWJsZWQuSW5uZXJUZXh0ID0gInRydWUiDQoJJHRlbXAgPSAk
bmV3RXZlbnRUcmlnZ2VyLkFwcGVuZENoaWxkKCRuZXdFbmFibGVkKQ0KDQoJIyDM
7bzTIFN1YnNjcmlwdGlvbiC92rXjDQoJJG5ld1N1YnNjcmlwdGlvbiA9ICR0YXNr
WG1sLkNyZWF0ZUVsZW1lbnQoIlN1YnNjcmlwdGlvbiIsICR0YXNrWG1sLkRvY3Vt
ZW50RWxlbWVudC5OYW1lc3BhY2VVUkkpDQoJPCMgJG5ld1N1YnNjcmlwdGlvbi5J
bm5lclhtbCA9ICcmbHQ7UXVlcnlMaXN0Jmd0OyZsdDtRdWVyeSBJZD0iMCIgUGF0
aD0iU3lzdGVtIiZndDsmbHQ7U2VsZWN0IFBhdGg9Ik1pY3Jvc29mdC1XaW5kb3dz
LVdMQU4tQXV0b0NvbmZpZy9PcGVyYXRpb25hbCImZ3Q7KltTeXN0ZW1bUHJvdmlk
ZXJbQE5hbWU9Ik1pY3Jvc29mdC1XaW5kb3dzLVdMQU4tQXV0b0NvbmZpZyJdIGFu
ZCAoRXZlbnRJRD04MDAxKV1dDQoJW0V2ZW50RGF0YVtEYXRhW0BOYW1lPSJTU0lE
Il09IkNVTVRfU3R1Il0gb3IgRXZlbnREYXRhW0RhdGFbQE5hbWU9IlNTSUQiXT0i
Q1VNVF9UZWMiXV0NCgkmbHQ7L1NlbGVjdCZndDsmbHQ7L1F1ZXJ5Jmd0OyZsdDsv
UXVlcnlMaXN0Jmd0OycgIz4NCgkkbmV3U3Vic2NyaXB0aW9uLklubmVyWG1sID0g
JyZsdDtRdWVyeUxpc3QmZ3Q7Jmx0O1F1ZXJ5IElkPSIwIiBQYXRoPSJTeXN0ZW0i
Jmd0OyZsdDtTZWxlY3QgUGF0aD0iTWljcm9zb2Z0LVdpbmRvd3MtV0xBTi1BdXRv
Q29uZmlnL09wZXJhdGlvbmFsIiZndDsqW1N5c3RlbVtQcm92aWRlcltATmFtZT0i
TWljcm9zb2Z0LVdpbmRvd3MtV0xBTi1BdXRvQ29uZmlnIl0gYW5kIChFdmVudElE
PTgwMDEpXV0NCglbRXZlbnREYXRhW0RhdGFbQE5hbWU9IlNTSUQiXT0iQ1VNVF9T
dHUiXSBvciBFdmVudERhdGFbRGF0YVtATmFtZT0iU1NJRCJdPSJDVU1UX1RlYyJd
XQ0KCSZsdDsvU2VsZWN0Jmd0OyZsdDsvUXVlcnkmZ3Q7Jmx0O1F1ZXJ5IElkPSIx
IiBQYXRoPSJTeXN0ZW0iJmd0OyZsdDtTZWxlY3QgUGF0aD0iTWljcm9zb2Z0LVdp
bmRvd3MtTmV0d29ya1Byb2ZpbGUvT3BlcmF0aW9uYWwiJmd0OypbU3lzdGVtW1By
b3ZpZGVyW0BOYW1lPSJNaWNyb3NvZnQtV2luZG93cy1OZXR3b3JrUHJvZmlsZSJd
IGFuZCAoRXZlbnRJRD0xMDAwMCldXQ0KCVtFdmVudERhdGFbRGF0YVtATmFtZT0i
TmFtZSJdPSJDVU1UX1N0dSJdIG9yIEV2ZW50RGF0YVtEYXRhW0BOYW1lPSJOYW1l
Il09IkNVTVRfVGVjIl1dDQoJJmx0Oy9TZWxlY3QmZ3Q7Jmx0Oy9RdWVyeSZndDsm
bHQ7L1F1ZXJ5TGlzdCZndDsnDQoJJHRlbXAgPSAkbmV3RXZlbnRUcmlnZ2VyLkFw
cGVuZENoaWxkKCRuZXdTdWJzY3JpcHRpb24pDQoNCgkjIMztvNPKwrz+tKW3osb3
vdq147W9yM7O8bzGu66zzNDyIFhNTCDF5NbD1tANCgkkdGVtcCA9ICR0YXNrWG1s
LlRhc2suVHJpZ2dlcnMuQXBwZW5kQ2hpbGQoJG5ld0V2ZW50VHJpZ2dlcikNCg0K
CSMgobCyu7nc08O7p8rHt/G1x8K8trzSqtTL0NChsQ0KCTwjICRuZXdMb2dvblR5
cGUgPSAkdGFza1htbC5DcmVhdGVFbGVtZW50KCJMb2dvblR5cGUiLCAkdGFza1ht
bC5Eb2N1bWVudEVsZW1lbnQuTmFtZXNwYWNlVVJJKQ0KCSRuZXdMb2dvblR5cGUu
SW5uZXJUZXh0ID0gIlBhc3N3b3JkIg0KCSR0ZW1wID0gJHRhc2tYbWwuVGFzay5Q
cmluY2lwYWxzLlByaW5jaXBhbC5BcHBlbmRDaGlsZCgkbmV3TG9nb25UeXBlKSAj
Pg0KDQoJIyC4/NDCyM7O8bzGu66zzNDytcQgWE1MIMXk1sMNCglVbnJlZ2lzdGVy
LVNjaGVkdWxlZFRhc2sgLVRhc2tOYW1lICR0YXNrTmFtZSAtQ29uZmlybTokZmFs
c2UNCgkkdGVtcCA9IFJlZ2lzdGVyLVNjaGVkdWxlZFRhc2sgLVRhc2tOYW1lICR0
YXNrTmFtZSAtWG1sICR0YXNrWG1sLk91dGVyWG1sDQoJDQp9DQoNCkFkZC1OZXR3
b3JrLUV2ZW50ICR0YXNrTmFtZQ0KDQojIMztvNPL5rv60dPKsQ0KZnVuY3Rpb24g
QWRkLVJhbmRvbS1EZWxheSB7DQogICAgcGFyYW0gKA0KICAgICAgICBbc3RyaW5n
XSR0YXNrTmFtZSwNCgkJW3N0cmluZ10kZGVsYXksDQoJCVtib29sXSRmbGFnDQog
ICAgKQ0KDQoJIyC2wcihyM7O8bzGu66zzNDytcQgWE1MIMXk1sPOxLz+DQoJJHRh
c2tYbWwgPSBOZXctT2JqZWN0IFhNTA0KCSR4bWxUZXh0ID0gRXhwb3J0LVNjaGVk
dWxlZFRhc2sgLVRhc2tOYW1lICR0YXNrTmFtZQ0KCSR0YXNrWG1sLkxvYWRYbWwo
JHhtbFRleHQpDQoNCgkjIMvmu/rR08qxDQoJJG5ld1JhbmRvbURlbGF5ID0gJHRh
c2tYbWwuQ3JlYXRlRWxlbWVudCgiUmFuZG9tRGVsYXkiLCAkdGFza1htbC5Eb2N1
bWVudEVsZW1lbnQuTmFtZXNwYWNlVVJJKQ0KCWlmICgkZmxhZykgew0KCQkkbmV3
UmFuZG9tRGVsYXkuSW5uZXJUZXh0ID0gJGRlbGF5DQoJCSR0ZW1wID0gJHRhc2tY
bWwuVGFzay5UcmlnZ2Vycy5UaW1lVHJpZ2dlci5BcHBlbmRDaGlsZCgkbmV3UmFu
ZG9tRGVsYXkpDQoJfQ0KCWVsc2Ugew0KCQkkbmV3UmFuZG9tRGVsYXkuSW5uZXJU
ZXh0ID0gJGRlbGF5DQoJCSR0ZW1wID0gJHRhc2tYbWwuVGFzay5UcmlnZ2Vycy5D
YWxlbmRhclRyaWdnZXIuQXBwZW5kQ2hpbGQoJG5ld1JhbmRvbURlbGF5KQ0KCX0N
Cg0KCSMguPzQwsjOzvG8xruus8zQ8rXEIFhNTCDF5NbDDQoJVW5yZWdpc3Rlci1T
Y2hlZHVsZWRUYXNrIC1UYXNrTmFtZSAkdGFza05hbWUgLUNvbmZpcm06JGZhbHNl
DQoJJHRlbXAgPSBSZWdpc3Rlci1TY2hlZHVsZWRUYXNrIC1UYXNrTmFtZSAkdGFz
a05hbWUgLVhtbCAkdGFza1htbC5PdXRlclhtbA0KCQ0KfQ0KDQpBZGQtUmFuZG9t
LURlbGF5ICR0YXNrTmFtZSAiUFQzTSIgJGZhbHNlDQppZiAoJHJlY29ubmVjdCkg
ew0KCUFkZC1SYW5kb20tRGVsYXkgJHRhc2tOYW1lMiAiUFQkKFtNYXRoXTo6Q2Vp
bGluZygkcmVjb25uZWN0LzMpKU0iICR0cnVlDQp9DQoNCiMgyuSz9sno1sOzybmm
0MXPog0KV3JpdGUtSG9zdCBAIg0KDQqhzCDJ6NbDzeqzyaOhyPTOtLP2z9a67NfW
tO3O88zhyr6jrNTyxPq1xNfUtq+1x8K8uabE3NLRvq3J+tCnoaMNCqHMIMT6tcS1
58TU0tS688GsvdPQo9SwzfjKsb2r19S2r7XHwryjrM7e0OjE+tTZtPK/qrG+s8zQ
8qGjxPrP1tTav8nS1LnYsdWxvrPM0PKhow0K08nT2rG+s8zQ8rvhyKvX1LavtcfC
vKOsyOfE+tP2tb21x8K8yeixuLOsz961yMfpv/bQ6NKq16LP+sqxo6wNCsfryta2
r7Tyv6ogMTAuMi41LjI1MaOotcfCvNKzw+ajqaOsu/K1x8K819S3/s7xz7XNsyAy
MDIuMTE5LjE5Ni42OjgwODAvU2VsZiC9+NDQstnX96GjDQrI59Do0N64xMno1sPQ
xc+io6zWu9Do1tjQwtTL0NCxvrPM0PKhow0KyPSz9s/WuuzX1rGotO2jrMfrs6LK
1NbY0MLUy9DQsb6zzNDyoaMNCg0KIkAgLUZvcmVncm91bmRDb2xvciBHcmVlbg0K
DQojIMrks/bP7sS/0MXPog0KV3JpdGUtSG9zdCBAIg0Ksb7P7sS/wbS906O6aHR0
cHM6Ly9naXRodWIuY29tL3pqc3hwbHkvQ1VNVC1OZXR3b3JrLUxvZ2luDQqxvs/u
xL/A+sqx1LwgMTIg0KHKscnPz9+jrMbavOS1w7W9wcsgR1BULTQgtcS088G/sO/W
+qOhDQrI57bUIEdQVCDT0NDLyKSjrLu2062808jro7q/87TzIENoYXRHUFQgvbvB
98i6IDY0Njc0NTgwOA0KDQrB7bi9uPfRp9S6w/G85NfK1LS31s/tyLqjusr90acg
NDU0MTYyMjM3o6y7r7mkIDgwODcyNzMwMaOo0rvIuqOpIDI0MDQ5NDg1o6i2/si6
o6kNCrzGy+O7+iA5MTY0ODM1NDWjrLu3suIgOTA5ODkzMjM4o6zQxb/YIDQ2NDEx
MjE2OKOsu/q15yA3MTcxNzY3NzOjrLXnwaYgODMwNjA0NTk5DQoNCiJAIC1Gb3Jl
Z3JvdW5kQ29sb3IgQ3lhbg0KDQokdGVtcCA9IFJlYWQtSG9zdCAisLS72LO1vPzN
y7P2Li4uIg0KPCMgV3JpdGUtSG9zdCAisLTIztLivPzNy7P2Li4uIg0KDQojILXI
tP3Tw7unsLTPwsjO0uK8/KOs0tSx49TavcWxvta00NC94cr4uvOxo8H0IFBvd2Vy
U2hlbGwgtLC/2tLUsum/tMrks/YNCiRIb3N0LlVJLlJhd1VJLlJlYWRLZXkoIk5v
RWNobyxJbmNsdWRlS2V5RG93biIpID4gJG51bGwgIz4NCg==
-----END CERTIFICATE-----
