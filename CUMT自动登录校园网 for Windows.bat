@echo off

REM 请求管理员权限
>nul 2>&1 "%SYSTEMROOT%\system32\icacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo 需要管理员权限，正在请求...
    goto UACPrompt
) else (goto gotAdmin)

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

REM 获取应用程序目录
set APPDIR=%APPDATA%\CUMT
if not exist "%APPDIR%" mkdir "%APPDIR%" > nul

REM 将 Powershell 脚本写入磁盘
if exist "%APPDIR%"\LoginNetwork.ps1 del "%APPDIR%"\LoginNetwork.ps1 > nul
certutil -decode "%~f0" %APPDIR%\LoginNetwork.ps1 > nul

REM 执行 PS1 文件
powershell -ExecutionPolicy Bypass -File "%APPDIR%\LoginNetwork.ps1"

exit /b 1


-----BEGIN CERTIFICATE-----
IyC2qNLltcfCvLqvyv0NCmZ1bmN0aW9uIExvZ2luLUNhbXB1c05ldHdvcmsgew0K
ICAgIHBhcmFtICgNCiAgICAgICAgW3N0cmluZ10kU3R1ZGVudElELA0KICAgICAg
ICBbc3RyaW5nXSRQYXNzd29yZCwNCiAgICAgICAgW3N0cmluZ10kQ2FycmllciwN
CgkJW2Jvb2xdJFRlc3QgPSAkZmFsc2UNCiAgICApDQoNCiAgICAjILzssuIgSVAg
MTAuMi40LjIgyse38b/J0tQgUGluZyDNqA0KICAgIGlmICgtbm90ICRUZXN0KSB7
DQoJCSRwaW5nUmVzdWx0ID0gVGVzdC1Db25uZWN0aW9uIC1Db21wdXRlck5hbWUg
IjEwLjIuNC4yIiAtUXVpZXQgLUJ1ZmZlclNpemUgMSAtQ291bnQgMQ0KCX0NCg0K
ICAgIGlmICgkVGVzdCAtb3IgLW5vdCAkcGluZ1Jlc3VsdCkgew0KICAgICAgICBp
ZiAoW2Jvb2xdJENhcnJpZXIpIHsNCgkJCSR1cmwgPSAiaHR0cDovLzEwLjIuNS4y
NTE6ODAxL2Vwb3J0YWwvP2M9UG9ydGFsJmE9bG9naW4mbG9naW5fbWV0aG9kPTEm
dXNlcl9hY2NvdW50PSQoJFN0dWRlbnRJRClAJCgkQ2FycmllcikmdXNlcl9wYXNz
d29yZD0kKCRQYXNzd29yZCkiDQogICAgICAgIH0NCgkJZWxzZSB7DQoJCQkkdXJs
ID0gImh0dHA6Ly8xMC4yLjUuMjUxOjgwMS9lcG9ydGFsLz9jPVBvcnRhbCZhPWxv
Z2luJmxvZ2luX21ldGhvZD0xJnVzZXJfYWNjb3VudD0kKCRTdHVkZW50SUQpJnVz
ZXJfcGFzc3dvcmQ9JCgkUGFzc3dvcmQpIg0KCQl9DQoJCSRyZXNwb25zZSA9IElu
dm9rZS1XZWJSZXF1ZXN0IC1VcmkgJHVybA0KCQkkcmVzcFRleHQgPSAkcmVzcG9u
c2UuQ29udGVudC5UcmltU3RhcnQoJygnKS5UcmltRW5kKCcpJykNCgkJJHJlc3BK
c29uID0gQ29udmVydEZyb20tSnNvbiAkcmVzcFRleHQNCgkJDQogICAgICAgIHN3
aXRjaCAoJHJlc3BKc29uLnJlc3VsdCkgew0KICAgICAgICAgICAgMSB7DQogICAg
ICAgICAgICAgICAgJG5vdGlmaWNhdGlvbiA9ICK1x8K8s8m5piINCiAgICAgICAg
ICAgIH0NCiAgICAgICAgICAgIDAgew0KCQkJCXN3aXRjaCAoJHJlc3BKc29uLnJl
dF9jb2RlKSB7DQoJCQkJCTEgew0KCQkJCQkJc3dpdGNoICgkcmVzcEpzb24ubXNn
KSB7DQoJCQkJCQkJImJHUmhjQ0JoZFhSb0lHVnljbTl5IiB7DQoJCQkJCQkJCSRu
b3RpZmljYXRpb24gPSAi1cu6xaGiw9zC67vy1MvTqsnMtO3O8yINCgkJCQkJCQl9
DQoJCQkJCQkJIlVtRmtPbFZ6WlhKT1lXMWxYMFZ5Y2c9PSIgew0KCQkJCQkJCQkk
bm90aWZpY2F0aW9uID0gItXLusWyu7Tm1NoiDQoJCQkJCQkJfQ0KCQkJCQkJCSJU
V0ZqTENCSlVDd2dUa0ZUYVhBc0lGQlBVbFFnWlhKeUtESXBJUT09IiB7DQoJCQkJ
CQkJCSRub3RpZmljYXRpb24gPSAixPq1xNXLusWyu9TK0O3U2rTLzfjC58q508Mi
DQoJCQkJCQkJfQ0KCQkJCQkJfQ0KCQkJCQl9DQoJCQkJCTIgew0KCQkJCQkJJG5v
dGlmaWNhdGlvbiA9ICLE+tLRvq20ptPatcfCvNe0zKwiDQoJCQkJCX0NCgkJCQkJ
MyB7DQoJCQkJCQkkbm90aWZpY2F0aW9uID0gIs601qq07c7zo6y07c7ztPrC66O6
MyINCgkJCQkJfQ0KCQkJCX0NCiAgICAgICAgICAgIH0NCiAgICAgICAgICAgIGRl
ZmF1bHQgew0KICAgICAgICAgICAgICAgICRub3RpZmljYXRpb24gPSAizrTWqr3h
ufsiDQoJCQkJDQogICAgICAgICAgICB9DQogICAgICAgIH0NCg0KICAgICAgICAj
ILWvs/bPtc2zzajWqs/7z6INCgkJIyBOZXctQnVybnRUb2FzdE5vdGlmaWNhdGlv
biAtVGV4dCAi0tGzosrUtcfCvNCj1LDN+CIsICRub3RpZmljYXRpb24NCgkJDQoJ
CXJldHVybiAkbm90aWZpY2F0aW9uDQogICAgfQ0KfQ0KDQojILao0uXXos/6uq/K
/Q0KZnVuY3Rpb24gTG9nb3V0LUNhbXB1c05ldHdvcmsgew0KCSR1cmwgPSAiaHR0
cDovLzEwLjIuNS4yNTE6ODAxL2Vwb3J0YWwvP2M9UG9ydGFsJmE9bG9nb3V0Ig0K
CSRyZXNwb25zZSA9IEludm9rZS1XZWJSZXF1ZXN0IC1VcmkgJHVybA0KfQ0KDQoj
IMP8we7Q0L/JvdPK1SA1ILj2ss7K/aO60ae6xSDD3MLrINTL06rJzCDKx7fxsuLK
1LXHwrwgyse38c6qvOCy4g0KIyC8xruuyM7O8da00NC1x8K8DQppZiAoW2Jvb2xd
JGFyZ3MpIHsNCgkNCgkjIMjnufvKx7zgsuKjrNTyNzowNSC1vSAyMzo1MCDWrs3i
tcTKsbzk0tQgMSAvIDIwILXEuMXCyta00NC1x8K8DQoJJGN1cnJlbnREYXRlID0g
R2V0LURhdGUNCglpZiAoJGFyZ3NbNF0gLWFuZCAtbm90ICgkY3VycmVudERhdGUu
SG91ciAtZ3QgNyAtb3IgKCRjdXJyZW50RGF0ZS5Ib3VyIC1nZSA3IC1hbmQgJGN1
cnJlbnREYXRlLk1pbnV0ZSAtZ2UgMDUpKSAtYW5kICgkY3VycmVudERhdGUuSG91
ciAtbHQgMjMgLW9yICgkY3VycmVudERhdGUuSG91ciAtZXEgMjMgLWFuZCAkY3Vy
cmVudERhdGUuTWludXRlIC1sZSA1MCkpKSB7DQoJCWlmIChHZXQtUmFuZG9tIC1N
YXhpbXVtIDIwIC1NaW5pbXVtIDEgLUluY2x1ZGVNaW5pbXVtKSB7DQoJCQlMb2dp
bi1DYW1wdXNOZXR3b3JrIC1TdHVkZW50SUQgJGFyZ3NbMF0gLVBhc3N3b3JkICRh
cmdzWzFdIC1DYXJyaWVyICRhcmdzWzJdDQoJCX0NCgl9IGVsc2Ugew0KCQlMb2dp
bi1DYW1wdXNOZXR3b3JrIC1TdHVkZW50SUQgJGFyZ3NbMF0gLVBhc3N3b3JkICRh
cmdzWzFdIC1DYXJyaWVyICRhcmdzWzJdDQoJfQ0KCUV4aXQNCn0NCg0KIyDSqsfz
udzA7dSxyKjP3g0KJHJvbGUgPSBbU2VjdXJpdHkuUHJpbmNpcGFsLldpbmRvd3NQ
cmluY2lwYWxdW1NlY3VyaXR5LlByaW5jaXBhbC5XaW5kb3dzSWRlbnRpdHldOjpH
ZXRDdXJyZW50KCkNCiRpc0FkbWluID0gJHJvbGUuSXNJblJvbGUoW1NlY3VyaXR5
LlByaW5jaXBhbC5XaW5kb3dzQnVpbHRJblJvbGVdICJBZG1pbmlzdHJhdG9yIikg
LW9yIFtib29sXSRyb2xlLklzU3lzdGVtDQppZiAoLW5vdCAkaXNBZG1pbikgew0K
CVdyaXRlLUhvc3QgItDo0qq53MDt1LHIqM/eo6zH68fzyKjP3tbQLi4uIiAtRm9y
ZWdyb3VuZENvbG9yIFllbGxvdw0KICAgIFN0YXJ0LVByb2Nlc3MgcG93ZXJzaGVs
bC5leGUgIi1Ob1Byb2ZpbGUgLUV4ZWN1dGlvblBvbGljeSBCeXBhc3MgLUZpbGUg
YCIkUFNDb21tYW5kUGF0aGAiIiAtVmVyYiBSdW5Bcw0KICAgIEV4aXQNCn0NCg0K
IyDK5LP2tePV89fWDQpXcml0ZS1Ib3N0IEAiDQqhoaGhoaGhoaGhoaGhoaGhoaGh
oaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGh
oaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGh
oaGhoaENCqGhoaGhoaH0ofSh9KH0ofSh9KGhoaGh9KH0ofSh9KGhofSh9KH0ofSh
oaH0ofSh9KH0oaGhoaGhoaGh9KH0ofShoaH0ofSh9KH0ofSh9KH0ofSh9KGhDQqh
oaGhofSh9KH0oaGhoaH0ofShoaGhoaGh9KH0oaGhoaGhofSh9KGhoaGhoaH0ofSh
9KGhoaGhoaGhofSh9KGhoaGh9KH0oaGhoaH0oaGhoaH0ofShoQ0KoaGhoaH0ofSh
oaGhoaGhoaH0ofShoaGhofShoaGhoaGhoaGhofShoaGhoaGhoaH0ofSh9KGhoaGh
9KH0ofShoaGhofSh9KGhoaGh9KGhoaGh9KH0oaENCqGhoaGh9KH0oaGhoaGhoaGh
oaGhoaGhoaH0oaGhoaGhoaGhoaH0oaGhoaGhoaGh9KH0ofShoaGhofSh9KH0oaGh
oaGhoaGhoaGhofShoaGhoaGhoaGhDQqhoaH0ofSh9KGhoaGhoaGhoaGhoaGhoaGh
9KGhoaGhoaGhoaGh9KGhoaGhoaGhofSh9KH0ofShoaH0oaGh9KGhoaGhoaGhoaGh
oaH0oaGhoaGhoaGhoQ0KoaGh9KH0ofShoaGhoaGhoaGhoaGhoaGhofShoaGhoaGh
oaGhofShoaGhoaGhoaH0oaGh9KH0ofSh9KGhofShoaGhoaGhoaGhoaGh9KGhoaGh
oaGhoaENCqGhoaGh9KH0oaGhoaGhoaGh9KH0oaGhoaH0ofShoaGhoaGh9KH0oaGh
oaGhoaGh9KGhofSh9KH0oaGhoaH0oaGhoaGhoaGhoaGhofShoaGhoaGhoaGhDQqh
oaGhofSh9KH0oaGhoaH0ofSh9KGhoaGh9KH0oaGhoaGhofSh9KGhoaGhoaGhofSh
oaGhofSh9KGhoaGh9KGhoaGhoaGhoaGhoaH0oaGhoaGhoaGhoQ0KoaGhoaGhofSh
9KH0ofSh9KH0oaGhoaGhofSh9KH0ofSh9KH0ofShoaGhofSh9KH0ofShoaH0ofSh
9KH0ofSh9KGhoaGhoaH0ofSh9KH0ofShoaGhoaENCg0KDQoNCiJAIC1Gb3JlZ3Jv
dW5kQ29sb3IgQmx1ZQ0KDQojIL3Fsb696cncDQpXcml0ZS1Ib3N0ICLV4srH0ru4
9sXk1sPX1LavtcfCvCBDVU1UINCj1LDN+LXEs8zQ8qOsvt+xuNLUz8K5psTco7oi
IC1Gb3JlZ3JvdW5kQ29sb3IgQ3lhbg0KV3JpdGUtSG9zdCAiocwgtefE1L3iy/i6
89fUtq+1x8K8IiAtRm9yZWdyb3VuZENvbG9yIEN5YW4NCldyaXRlLUhvc3QgIqHM
IMGsvdMgQ1VNVF9TdHUgu/IgQ1VNVF9UZWMgV2lGaSC689fUtq+1x8K8IiAtRm9y
ZWdyb3VuZENvbG9yIEN5YW4NCldyaXRlLUhvc3QgIqHMIMGsvdPN+M/fo6jS1Myr
zfijqbrz19S2r7XHwrwiIC1Gb3JlZ3JvdW5kQ29sb3IgQ3lhbg0KV3JpdGUtSG9z
dCAiocwgw7/M7CA3OjIyIEFNINfUtq+1x8K8IiAtRm9yZWdyb3VuZENvbG9yIEN5
YW4NCldyaXRlLUhvc3QgIqHMICi/ydGhKSC19M/fuvPX1Lav1tjBrKOo1LzDvyA1
ILfW1tO87LLi0ru0zqOpIiAtRm9yZWdyb3VuZENvbG9yIEN5YW4NCldyaXRlLUhv
c3QgIrDmsb6junYyMDIzMDQwMSIgLUZvcmVncm91bmRDb2xvciBDeWFuDQpXcml0
ZS1Ib3N0ICIiDQoNCjwjICMgsLLXsCBCdXJudFRvYXN0DQpXcml0ZS1Ib3N0ICLS
1M/CyPTRr87KsLLXsMSjv+nH68rkyOsgeSCyorvYs7UiDQpXcml0ZS1Ib3N0ICLV
/dTavOyy6cv50sDAtbXEz7XNs82o1qrEo7/pLi4uIg0KSW5zdGFsbC1Nb2R1bGUg
QnVybnRUb2FzdA0KV3JpdGUtSG9zdCAi0tGwstewy/nSwMC1tcTEo7/pIg0KV3Jp
dGUtSG9zdCAiIiAjPg0KDQojIMnotqi8xruuyM7O8cP7s8YNCiR0YXNrTmFtZSA9
ICJDVU1U19S2r7XHwrzQo9SwzfgiDQokdGFza05hbWUyID0gIkNVTVTX1LavtcfC
vNCj1LDN+KGqoaq84LLiIg0KDQojIMj0vMa7rsjOzvHS0bTm1NqjrNTy0aHU8cm+
s/27ucrHuLK4xw0KJHRhc2tFeGlzdHMgPSBHZXQtU2NoZWR1bGVkVGFzayB8IFdo
ZXJlLU9iamVjdCB7ICRfLlRhc2tOYW1lIC1lcSAkdGFza05hbWUgfQ0KJHRhc2tF
eGlzdHMyID0gR2V0LVNjaGVkdWxlZFRhc2sgfCBXaGVyZS1PYmplY3QgeyAkXy5U
YXNrTmFtZSAtZXEgJHRhc2tOYW1lMiB9DQppZiAoJHRhc2tFeGlzdHMgLW9yICR0
YXNrRXhpc3RzMikgew0KCVdyaXRlLUhvc3QgIs+1zbO87LLitb3S0cXk1sO5/dfU
tq+1x8K8oaMiIC1Gb3JlZ3JvdW5kQ29sb3IgWWVsbG93DQoJZG8gew0KCQkkcmVz
cG9uc2UgPSBSZWFkLUhvc3QgIsfr0aHU8aO6yb6z/cXk1sMgLyC4srjH1K3F5NbD
1tjQwsXk1sOjvyjJvrP9IFkgLyDW2NDCxeTWwyBOo6zErMjPINbY0MLF5NbDo6ki
DQoJfSB3aGlsZSAoJHJlc3BvbnNlIC1ub3RtYXRjaCAiXlt5bllOXSQiIC1hbmQg
JHJlc3BvbnNlIC1uZSAnJykNCg0KCWlmICgkdGFza0V4aXN0cykgew0KCQlVbnJl
Z2lzdGVyLVNjaGVkdWxlZFRhc2sgLVRhc2tOYW1lICR0YXNrTmFtZSAtQ29uZmly
bTokZmFsc2UNCgl9DQoJaWYgKCR0YXNrRXhpc3RzMikgew0KCQlVbnJlZ2lzdGVy
LVNjaGVkdWxlZFRhc2sgLVRhc2tOYW1lICR0YXNrTmFtZTIgLUNvbmZpcm06JGZh
bHNlDQoJfQ0KCQ0KCWlmICgkcmVzcG9uc2UgLWltYXRjaCAiXlt5WV0kIikgew0K
CQlXcml0ZS1Ib3N0ICLS0dLGs/3Qo9SwzfjX1LavtcfCvLmmxNyjrMbatP3E+tTZ
tM7KudPDo6EiIC1Gb3JlZ3JvdW5kQ29sb3IgR3JlZW4NCgkJV3JpdGUtSG9zdCAi
sLTIztLivPzNy7P2Li4uIg0KCQkkSG9zdC5VSS5SYXdVSS5SZWFkS2V5KCJOb0Vj
aG8sSW5jbHVkZUtleURvd24iKSA+ICRudWxsDQoJCUV4aXQNCgl9DQoJZWxzZSB7
DQoJCVdyaXRlLUhvc3QgIiINCgl9DQp9DQoNCiMgx+vH89PDu6fK5Mjro6yyotHp
1qTVy7unDQpXcml0ZS1Ib3N0ICK908/CwLSjrMfryuTI68T6tcTVy7un0MXPoqOs
yLu687C0u9iztbz8IiAtRm9yZWdyb3VuZENvbG9yIEdyZWVuDQpkbyB7DQoJV3Jp
dGUtSG9zdCAiIg0KCSRTdHVkZW50SUQgPSBSZWFkLUhvc3QgIsfryuTI68T6tcTR
p7rFIg0KCSRzZWN1cmVQYXNzd29yZCA9IFJlYWQtSG9zdCAtUHJvbXB0ICLH68rk
yOvE+rXEw9zC6yIgLUFzU2VjdXJlU3RyaW5nDQoJJFBhc3N3b3JkID0gW1N5c3Rl
bS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6UHRyVG9TdHJpbmdB
dXRvKFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlNl
Y3VyZVN0cmluZ1RvQlNUUigkc2VjdXJlUGFzc3dvcmQpKQ0KCSRDYXJyaWVyID0g
UmVhZC1Ib3N0ICLH68rkyOvE+rXE1MvTqsnMo6jSxravIGNtY2OjrMGqzaggdW5p
Y29to6y159DFIHRlbGVjb22jrNCj1LDN+CDB9L/Vo6kiDQoNCglkbyB7DQoJCVdy
aXRlLUhvc3QgIiINCgkJV3JpdGUtSG9zdCAi1f3U2rOiytS1x8K8Li4uICAiIC1O
b05ld2xpbmUgLUZvcmVncm91bmRDb2xvciBHcmVlbg0KCQkkcmVzdWx0ID0gTG9n
aW4tQ2FtcHVzTmV0d29yayAtU3R1ZGVudElEICRTdHVkZW50SUQgLVBhc3N3b3Jk
ICRQYXNzd29yZCAtQ2FycmllciAkQ2FycmllciAtVGVzdCAkdHJ1ZQ0KCQlXcml0
ZS1Ib3N0ICK1x8K8veG5+6O6JHJlc3VsdCINCgkJaWYgKCRyZXN1bHQgLWVxICLE
+tLRvq20ptPatcfCvNe0zKwiKSB7DQoJCQlXcml0ZS1Ib3N0ICK1x8K817TMrM/C
zt63qNHp1qTE47XE1cu7p9DFz6KhoyIgLUZvcmVncm91bmRDb2xvciBZZWxsb3cN
CgkJCWRvIHsNCgkJCQkkcmVzcG9uc2UgPSBSZWFkLUhvc3QgIsrHt/HPyNeiz/q1
x8K8o6zU2dbY0MK1x8K80tTR6dak0MXPosrHt/HV/ci3o78oWSAvIE4sIMSsyM8g
WaOpIg0KCQkJfSB3aGlsZSAoJHJlc3BvbnNlIC1ub3RtYXRjaCAiXlt5bllOXSQi
IC1hbmQgJHJlc3BvbnNlIC1uZSAnJykNCg0KCQkJaWYgKCRyZXNwb25zZSAtaW1h
dGNoICJeW3lZXSQiIC1vciAkcmVzcG9uc2UgLWVxICcnKSB7DQoJCQkJJGZsYWcy
ID0gJHRydWUNCgkJCQkkZmxhZyA9ICR0cnVlDQoJCQkJTG9nb3V0LUNhbXB1c05l
dHdvcmsNCgkJCQlXcml0ZS1Ib3N0ICLS0deiz/rQo9SwzfgiIC1Gb3JlZ3JvdW5k
Q29sb3IgR3JlZW4NCgkJCX0gZWxzZSB7DQoJCQkJJGZsYWcyID0gJGZhbHNlDQoJ
CQkJJGZsYWcgPSAkZmFsc2UNCgkJCX0NCgkJfQ0KCQllbHNlaWYgKCRyZXN1bHQg
LWVxICK1x8K8s8m5piIpIHsNCgkJCSRmbGFnMiA9ICRmYWxzZQ0KCQkJJGZsYWcg
PSAkZmFsc2UNCgkJfQ0KCQllbHNlIHsNCgkJCVdyaXRlLUhvc3QgIiINCgkJCSRm
bGFnMiA9ICRmYWxzZQ0KCQkJJGZsYWcgPSAkdHJ1ZQ0KCQl9DQoJfSB3aGlsZSAo
JGZsYWcyKQ0KfSB3aGlsZSAoJGZsYWcpDQoNCldyaXRlLUhvc3QgIiINCg0KIyDK
x7fxtfTP39fUtq/W2LXHDQpkbyB7DQoJJHJlc3BvbnNlID0gUmVhZC1Ib3N0ICLK
x7fxv6rG9LX0z9/X1Lav1tjBrLmmxNyjrNS8w78gNSC31tbTvOyy4tK7tM6jvyhZ
IC8gTqOs0ruw47K70OjSqqOsxKzIzyBOKSINCn0gd2hpbGUgKCRyZXNwb25zZSAt
bm90bWF0Y2ggIl5beW5ZTl0kIiAtYW5kICRyZXNwb25zZSAtbmUgJycpDQokcmVj
b25uZWN0ID0gJHJlc3BvbnNlIC1pbWF0Y2ggIl5beVldJCINCg0KV3JpdGUtSG9z
dCAi1f3U2sno1sPX1LavtcfCvC4uLiIgLUZvcmVncm91bmRDb2xvciBHcmVlbg0K
DQojILGjtOa1scewvcWxvrXEzerV+8K3vrYNCiRzY3JpcHRQYXRoID0gJE15SW52
b2NhdGlvbi5NeUNvbW1hbmQuUGF0aA0KDQojILS0vai8xruuyM7O8Q0KJHRyaWdn
ZXJMb2dpbiA9IE5ldy1TY2hlZHVsZWRUYXNrVHJpZ2dlciAtQXRMb2dPbg0KJHRy
aWdnZXJEYWlseSA9IE5ldy1TY2hlZHVsZWRUYXNrVHJpZ2dlciAtQXQgIjc6MjIi
IC1EYWlseQ0KJHRyaWdnZXJUaW1lID0gTmV3LVNjaGVkdWxlZFRhc2tUcmlnZ2Vy
IC1BdCAiNzoyMiIgLU9uY2UgLVJlcGV0aXRpb25JbnRlcnZhbCAoTmV3LVRpbWVT
cGFuIC1NaW51dGVzIDUpDQokYWN0aW9uID0gTmV3LVNjaGVkdWxlZFRhc2tBY3Rp
b24gLUV4ZWN1dGUgJ1Bvd2Vyc2hlbGwuZXhlJyAtQXJndW1lbnQgIi1Ob1Byb2Zp
bGUgLUV4ZWN1dGlvblBvbGljeSBCeXBhc3MgYCIkKCRzY3JpcHRQYXRoKWAiICQo
JFN0dWRlbnRJRCkgJCgkUGFzc3dvcmQpICQoJENhcnJpZXIpIg0KJGFjdGlvbjIg
PSBOZXctU2NoZWR1bGVkVGFza0FjdGlvbiAtRXhlY3V0ZSAnUG93ZXJzaGVsbC5l
eGUnIC1Bcmd1bWVudCAiLU5vUHJvZmlsZSAtRXhlY3V0aW9uUG9saWN5IEJ5cGFz
cyBgIiQoJHNjcmlwdFBhdGgpYCIgJCgkU3R1ZGVudElEKSAkKCRQYXNzd29yZCkg
JCgkQ2FycmllcikgJGZhbHNlICR0cnVlIg0KJHNldHRpbmdzID0gTmV3LVNjaGVk
dWxlZFRhc2tTZXR0aW5nc1NldCAtRG9udFN0b3BPbklkbGVFbmQgLUFsbG93U3Rh
cnRJZk9uQmF0dGVyaWVzDQoNCiR0ZW1wID0gUmVnaXN0ZXItU2NoZWR1bGVkVGFz
ayAtVGFza05hbWUgJHRhc2tOYW1lIC1UcmlnZ2VyIEAoJHRyaWdnZXJMb2dpbiwg
JHRyaWdnZXJEYWlseSkgLUFjdGlvbiAkYWN0aW9uIC1Vc2VyICJTWVNURU0iIC1T
ZXR0aW5ncyAkc2V0dGluZ3MgLVJ1bkxldmVsIEhpZ2hlc3QgLUZvcmNlDQoNCmlm
ICgkcmVjb25uZWN0KSB7DQoJJHRlbXAgPSBSZWdpc3Rlci1TY2hlZHVsZWRUYXNr
IC1UYXNrTmFtZSAkdGFza05hbWUyIC1UcmlnZ2VyICR0cmlnZ2VyVGltZSAtQWN0
aW9uICRhY3Rpb24yIC1Vc2VyICJTWVNURU0iIC1TZXR0aW5ncyAkc2V0dGluZ3Mg
LVJ1bkxldmVsIEhpZ2hlc3QgLUZvcmNlDQp9DQoNCldyaXRlLUhvc3QgItX91NrJ
6NbD1NogV2lGaSAvINLUzKvN+MGsvdPKsbXHwrwuLi4iIC1Gb3JlZ3JvdW5kQ29s
b3IgR3JlZW4NCg0KIyDOqrzGu67Izs7xzO280yBXaUZpIC8g0tTMq834IMGsvdPK
wrz+o6jNqLn90N64xCB4bWyjqQ0KZnVuY3Rpb24gQWRkLU5ldHdvcmstRXZlbnQg
ew0KICAgIHBhcmFtICgNCiAgICAgICAgW3N0cmluZ10kdGFza05hbWUNCiAgICAp
DQoNCgkjILbByKHIzs7xvMa7rrPM0PK1xCBYTUwgxeTWw87EvP4NCgkkdGFza1ht
bCA9IE5ldy1PYmplY3QgWE1MDQoJJHhtbFRleHQgPSBFeHBvcnQtU2NoZWR1bGVk
VGFzayAtVGFza05hbWUgJHRhc2tOYW1lDQoJJHRhc2tYbWwuTG9hZFhtbCgkeG1s
VGV4dCkNCg0KCSMgtLS9qCBOZXR3b3JrIMrCvP60pbeixve92rXjDQoJJG5ld0V2
ZW50VHJpZ2dlciA9ICR0YXNrWG1sLkNyZWF0ZUVsZW1lbnQoIkV2ZW50VHJpZ2dl
ciIsICR0YXNrWG1sLkRvY3VtZW50RWxlbWVudC5OYW1lc3BhY2VVUkkpDQoNCgkj
IMztvNMgRW5hYmxlZCC92rXjDQoJJG5ld0VuYWJsZWQgPSAkdGFza1htbC5DcmVh
dGVFbGVtZW50KCJFbmFibGVkIiwgJHRhc2tYbWwuRG9jdW1lbnRFbGVtZW50Lk5h
bWVzcGFjZVVSSSkNCgkkbmV3RW5hYmxlZC5Jbm5lclRleHQgPSAidHJ1ZSINCgkk
dGVtcCA9ICRuZXdFdmVudFRyaWdnZXIuQXBwZW5kQ2hpbGQoJG5ld0VuYWJsZWQp
DQoNCgkjIMztvNMgU3Vic2NyaXB0aW9uIL3ateMNCgkkbmV3U3Vic2NyaXB0aW9u
ID0gJHRhc2tYbWwuQ3JlYXRlRWxlbWVudCgiU3Vic2NyaXB0aW9uIiwgJHRhc2tY
bWwuRG9jdW1lbnRFbGVtZW50Lk5hbWVzcGFjZVVSSSkNCgk8IyAkbmV3U3Vic2Ny
aXB0aW9uLklubmVyWG1sID0gJyZsdDtRdWVyeUxpc3QmZ3Q7Jmx0O1F1ZXJ5IElk
PSIwIiBQYXRoPSJTeXN0ZW0iJmd0OyZsdDtTZWxlY3QgUGF0aD0iTWljcm9zb2Z0
LVdpbmRvd3MtV0xBTi1BdXRvQ29uZmlnL09wZXJhdGlvbmFsIiZndDsqW1N5c3Rl
bVtQcm92aWRlcltATmFtZT0iTWljcm9zb2Z0LVdpbmRvd3MtV0xBTi1BdXRvQ29u
ZmlnIl0gYW5kIChFdmVudElEPTgwMDEpXV0NCglbRXZlbnREYXRhW0RhdGFbQE5h
bWU9IlNTSUQiXT0iQ1VNVF9TdHUiXSBvciBFdmVudERhdGFbRGF0YVtATmFtZT0i
U1NJRCJdPSJDVU1UX1RlYyJdXQ0KCSZsdDsvU2VsZWN0Jmd0OyZsdDsvUXVlcnkm
Z3Q7Jmx0Oy9RdWVyeUxpc3QmZ3Q7JyAjPg0KCSRuZXdTdWJzY3JpcHRpb24uSW5u
ZXJYbWwgPSAnJmx0O1F1ZXJ5TGlzdCZndDsmbHQ7UXVlcnkgSWQ9IjAiIFBhdGg9
IlN5c3RlbSImZ3Q7Jmx0O1NlbGVjdCBQYXRoPSJNaWNyb3NvZnQtV2luZG93cy1X
TEFOLUF1dG9Db25maWcvT3BlcmF0aW9uYWwiJmd0OypbU3lzdGVtW1Byb3ZpZGVy
W0BOYW1lPSJNaWNyb3NvZnQtV2luZG93cy1XTEFOLUF1dG9Db25maWciXSBhbmQg
KEV2ZW50SUQ9ODAwMSldXQ0KCVtFdmVudERhdGFbRGF0YVtATmFtZT0iU1NJRCJd
PSJDVU1UX1N0dSJdIG9yIEV2ZW50RGF0YVtEYXRhW0BOYW1lPSJTU0lEIl09IkNV
TVRfVGVjIl1dDQoJJmx0Oy9TZWxlY3QmZ3Q7Jmx0Oy9RdWVyeSZndDsmbHQ7UXVl
cnkgSWQ9IjEiIFBhdGg9IlN5c3RlbSImZ3Q7Jmx0O1NlbGVjdCBQYXRoPSJNaWNy
b3NvZnQtV2luZG93cy1OZXR3b3JrUHJvZmlsZS9PcGVyYXRpb25hbCImZ3Q7KltT
eXN0ZW1bUHJvdmlkZXJbQE5hbWU9Ik1pY3Jvc29mdC1XaW5kb3dzLU5ldHdvcmtQ
cm9maWxlIl0gYW5kIChFdmVudElEPTEwMDAwKV1dDQoJW0V2ZW50RGF0YVtEYXRh
W0BOYW1lPSJOYW1lIl09IkNVTVRfU3R1Il0gb3IgRXZlbnREYXRhW0RhdGFbQE5h
bWU9Ik5hbWUiXT0iQ1VNVF9UZWMiXV0NCgkmbHQ7L1NlbGVjdCZndDsmbHQ7L1F1
ZXJ5Jmd0OyZsdDsvUXVlcnlMaXN0Jmd0OycNCgkkdGVtcCA9ICRuZXdFdmVudFRy
aWdnZXIuQXBwZW5kQ2hpbGQoJG5ld1N1YnNjcmlwdGlvbikNCg0KCSMgzO2808rC
vP60pbeixve92rXjtb3Izs7xvMa7rrPM0PIgWE1MIMXk1sPW0A0KCSR0ZW1wID0g
JHRhc2tYbWwuVGFzay5UcmlnZ2Vycy5BcHBlbmRDaGlsZCgkbmV3RXZlbnRUcmln
Z2VyKQ0KDQoJIyChsLK7udzTw7unyse38bXHwry2vNKq1MvQ0KGxDQoJPCMgJG5l
d0xvZ29uVHlwZSA9ICR0YXNrWG1sLkNyZWF0ZUVsZW1lbnQoIkxvZ29uVHlwZSIs
ICR0YXNrWG1sLkRvY3VtZW50RWxlbWVudC5OYW1lc3BhY2VVUkkpDQoJJG5ld0xv
Z29uVHlwZS5Jbm5lclRleHQgPSAiUGFzc3dvcmQiDQoJJHRlbXAgPSAkdGFza1ht
bC5UYXNrLlByaW5jaXBhbHMuUHJpbmNpcGFsLkFwcGVuZENoaWxkKCRuZXdMb2dv
blR5cGUpICM+DQoNCgkjILj80MLIzs7xvMa7rrPM0PK1xCBYTUwgxeTWww0KCVVu
cmVnaXN0ZXItU2NoZWR1bGVkVGFzayAtVGFza05hbWUgJHRhc2tOYW1lIC1Db25m
aXJtOiRmYWxzZQ0KCSR0ZW1wID0gUmVnaXN0ZXItU2NoZWR1bGVkVGFzayAtVGFz
a05hbWUgJHRhc2tOYW1lIC1YbWwgJHRhc2tYbWwuT3V0ZXJYbWwNCgkNCn0NCg0K
QWRkLU5ldHdvcmstRXZlbnQgJHRhc2tOYW1lDQoNCiMgzO2808vmu/rR08qxDQpm
dW5jdGlvbiBBZGQtUmFuZG9tLURlbGF5IHsNCiAgICBwYXJhbSAoDQogICAgICAg
IFtzdHJpbmddJHRhc2tOYW1lLA0KCQlbYm9vbF0kZmxhZw0KICAgICkNCg0KCSMg
tsHIocjOzvG8xruus8zQ8rXEIFhNTCDF5NbDzsS8/g0KCSR0YXNrWG1sID0gTmV3
LU9iamVjdCBYTUwNCgkkeG1sVGV4dCA9IEV4cG9ydC1TY2hlZHVsZWRUYXNrIC1U
YXNrTmFtZSAkdGFza05hbWUNCgkkdGFza1htbC5Mb2FkWG1sKCR4bWxUZXh0KQ0K
DQoJIyDL5rv60dPKsQ0KCSRuZXdSYW5kb21EZWxheSA9ICR0YXNrWG1sLkNyZWF0
ZUVsZW1lbnQoIlJhbmRvbURlbGF5IiwgJHRhc2tYbWwuRG9jdW1lbnRFbGVtZW50
Lk5hbWVzcGFjZVVSSSkNCglpZiAoJGZsYWcpIHsNCgkJJG5ld1JhbmRvbURlbGF5
LklubmVyVGV4dCA9ICJQVDFNIg0KCQkkdGVtcCA9ICR0YXNrWG1sLlRhc2suVHJp
Z2dlcnMuVGltZVRyaWdnZXIuQXBwZW5kQ2hpbGQoJG5ld1JhbmRvbURlbGF5KQ0K
CX0NCgllbHNlIHsNCgkJJG5ld1JhbmRvbURlbGF5LklubmVyVGV4dCA9ICJQVDNN
Ig0KCQkkdGVtcCA9ICR0YXNrWG1sLlRhc2suVHJpZ2dlcnMuQ2FsZW5kYXJUcmln
Z2VyLkFwcGVuZENoaWxkKCRuZXdSYW5kb21EZWxheSkNCgl9DQoNCgkjILj80MLI
zs7xvMa7rrPM0PK1xCBYTUwgxeTWww0KCVVucmVnaXN0ZXItU2NoZWR1bGVkVGFz
ayAtVGFza05hbWUgJHRhc2tOYW1lIC1Db25maXJtOiRmYWxzZQ0KCSR0ZW1wID0g
UmVnaXN0ZXItU2NoZWR1bGVkVGFzayAtVGFza05hbWUgJHRhc2tOYW1lIC1YbWwg
JHRhc2tYbWwuT3V0ZXJYbWwNCgkNCn0NCg0KQWRkLVJhbmRvbS1EZWxheSAkdGFz
a05hbWUgJGZhbHNlDQppZiAoJHJlY29ubmVjdCkgew0KCUFkZC1SYW5kb20tRGVs
YXkgJHRhc2tOYW1lMiAkdHJ1ZQ0KfQ0KDQojIMrks/bJ6NbDs8m5ptDFz6INCldy
aXRlLUhvc3QgIiINCldyaXRlLUhvc3QgIqHMIMXk1sPN6rPJo6HI9M60s/bP1rrs
yau07c7zzOHKvqOsxPq1xNfUtq+1x8K8uabE3NLRvq3J+tCnoaMiIC1Gb3JlZ3Jv
dW5kQ29sb3IgR3JlZW4NCldyaXRlLUhvc3QgIsjn0OjQ3rjE1cu7p8Xk1sOjrNa7
0OjW2NDC1MvQ0LG+s8zQ8qGjIiAtRm9yZWdyb3VuZENvbG9yIEdyZWVuDQpXcml0
ZS1Ib3N0ICIiDQpXcml0ZS1Ib3N0ICKxvrPM0PK1w7W9wcsgR1BULTQgtcTQrdb6
v6q3oqGiyPPJq6OhyOfT0NDLyKSjrLu2062808jro7q/87TzIENoYXRHUFQgvbvB
98i6IDY0Njc0NTgwOCIgLUZvcmVncm91bmRDb2xvciBDeWFuDQpXcml0ZS1Ib3N0
ICIiDQpXcml0ZS1Ib3N0ICK499Gn1LrXytS0t9bP7ci6o7rK/dGnIDQ1NDE2MjIz
N6Osu6+5pCA4MDg3MjczMDGjqNK7yLqjqTI0MDQ5NDg1o6i2/si6o6kiIC1Gb3Jl
Z3JvdW5kQ29sb3IgQ3lhbg0KV3JpdGUtSG9zdCAivMbL47v6IDkxNjQ4MzU0NaOs
u7ey4iA5MDk4OTMyMzijrNDFv9ggNDY0MTEyMTY4o6y7+rXnIDcxNzE3Njc3M6Os
tefBpiA4MzA2MDQ1OTkiIC1Gb3JlZ3JvdW5kQ29sb3IgQ3lhbg0KV3JpdGUtSG9z
dCAiIg0KJHRlbXAgPSBSZWFkLUhvc3QgIrC0u9iztbz8zcuz9i4uLiINCiMgV3Jp
dGUtSG9zdCAisLTIztLivPzNy7P2Li4uIg0KDQojILXItP3Tw7unsLTPwsjO0uK8
/KOs0tSx49TavcWxvta00NC94cr4uvOxo8H0IFBvd2VyU2hlbGwgtLC/2tLUsum/
tMrks/YNCiMgJEhvc3QuVUkuUmF3VUkuUmVhZEtleSgiTm9FY2hvLEluY2x1ZGVL
ZXlEb3duIikgPiAkbnVsbA0KDQoNCg==
-----END CERTIFICATE-----
