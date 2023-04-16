# �����¼����
function Login-CampusNetwork {
    param (
        [string]$StudentID,
        [string]$Password,
        [string]$Carrier,
		[bool]$Test = $false
    )

    # ��� IP 10.2.4.2 �Ƿ���� Ping ͨ
    if (-not $Test) {
		$pingResult = Test-Connection -ComputerName "10.2.4.2" -Quiet -BufferSize 1 -Count 1
		if ($pingResult) {
			$pingResultText = "���紦����ͨ״̬"
		}
		else {
			$pingResultText = "����δ��ͨ�����ܵ��߻���������磻ִ�е�¼: "
		}
	}
	
	# ������һ�����͵�¼����
    if ($Test -or -not $pingResult) {
        if ([bool]$Carrier) {
			$Carrier = "@$($Carrier)"
        }
		$url = "http://10.2.5.251:801/eportal/?c=Portal&a=login&login_method=1&user_account=$($StudentID)$($Carrier)&user_password=$($Password)"
		$response = Invoke-WebRequest -Uri $url
		$respText = $response.Content.TrimStart('(').TrimEnd(')')
		$respJson = ConvertFrom-Json $respText
		
        switch ($respJson.result) {
            1 {
                $notification = "��¼�ɹ�"
            }
            0 {
				switch ($respJson.ret_code) {
					1 {
						$bytes = [System.Convert]::FromBase64String($respJson.msg)
						$msg = [System.Text.Encoding]::UTF8.GetString($bytes)
						switch ($msg) {
							"userid error1" {
								$notification = "�˺Ų�����"
							}
							"auth error80" {
								$notification = "��ʱ�ν�ֹ����"
							}
							"Rad:UserName_Err" {
								$notification = "�󶨵���Ӫ���˺Ŵ�������ϵ��Ӫ�̺�ʵ��ȥ��Ӫ��У԰Ӫҵ�����а󶨡�"
							}
							"Authentication Fail ErrCode=16" {
								$notification = "��ʱ�β���������"
							}
							"Mac, IP, NASip, PORT err(2)!" {
								$notification = "�����˺Ų������ڴ�����ʹ�ã����������� CUMT_Stu ���� CUMT_Tec ����"
							}
							"Rad:Status_Err" {
								$notification = "���󶨵���Ӫ���˺�״̬�쳣������ϵ��Ӧ��Ӫ�̴���"
							}
							"Rad:Limit Users Err" {
								$notification = "���ĵ�½���ޣ������Է��� http://202.119.196.6:8080/Self �����նˡ�"
							}
							"ldap auth error" {
								$notification = "ͳһ�����֤�û����������"
							}
							default {
								$notification = "δ֪����$($msg)"
								
							}
						}
					}
					2 {
						$notification = "���Ѿ����ڵ�¼״̬"
					}
					3 {
						$notification = "δ֪���󣬴�����룺3"
					}
				}
            }
            default {
                $notification = "δ֪�����$($respJson)"
				
            }
        }

        # ����ϵͳ֪ͨ��Ϣ
		# New-BurntToastNotification -Text "�ѳ��Ե�¼У԰��", $notification
    }
		
	return $pingResultText + $notification
}

# ����ע������
function Logout-CampusNetwork {
	$url = "http://10.2.5.251:801/eportal/?c=Portal&a=logout"
	$response = Invoke-WebRequest -Uri $url
}

# ����ü���־��¼����
function Cut-FileLog {
    param (
        [string[]]$fileContent,
		[string[]]$s,
        [int]$num = 100
    )

	# �ֱ���ÿ���ַ�������������Ϊ 0���ֱ���洢ÿ���ַ�������������
	$counts = @{}
	$lines = @{}
	foreach ($str in $s) {
		$counts[$str] = 0
		$lines[$str] = @()
	}

	# ѭ������ÿһ�У���¼����ÿ���ַ���������������洢����Ӧ��������
	foreach ($line in $fileContent) {
		foreach ($str in $s) {
			if ($line -match $str) {
				$counts[$str]++
				$lines[$str] += $line
				if ($counts[$str] -gt $num) {
					$lines[$str] = $lines[$str] | Select-Object -Last $num
					$counts[$str] = $num
				}
				break
			}
		}
	}

	# ����ԭ�ȵ�˳����������ļ����ݣ�������
	$newFileContent = @()
	foreach ($line in $fileContent) {
		foreach ($str in $s) {
			if ($line -in $lines[$str]) {
				$newFileContent += $line
				break
			}
		}
	}
	return $newFileContent

}

# ����ȡ��־�ļ�·������
function Get-FileLog-Path {
	$logFile = Join-Path $PSScriptRoot "LoginNetwork.log"
	if (-not (Test-Path $logFile)) {
		New-Item -Path $logFile -ItemType File -Force
	}
	return $logFile
}

# �����¼��־����
function Write-FileLog {
    param (
        [string]$Log,
		[string]$caller
    )
	
	# ������־�ļ�·��
	$logFile = Get-FileLog-Path
	
	# ����Ҫ��ӵ���־�ļ��е��ı��ַ���
	$logFormat = "[{0:yyyy-MM-dd HH:mm:ss}] {1} - {2}"
	$timestamp = Get-Date
	$logEntry = $logFormat -f $timestamp, $caller, $Log
	
	# �������־���ݵ���־�ļ�ĩβ
	Add-Content $logFile -Value $logEntry

	# �����־�������� 100 ������ֻ�������µ� 100 ��
	$logContent = Get-Content $logFile
	Set-Content $logFile (Cut-FileLog $logContent @("Monitor", "Trigger"))

}

# �����пɽ��� 5 ��������ѧ�� ���� ��Ӫ�� �Ƿ���Ե�¼ �Ƿ�Ϊ���
# �ƻ�����ִ�е�¼
if ($args) {
	
	# ����Ǽ�⣬��7:05 �� 23:50 ֮���ʱ���� 1 / 20 �ĸ���ִ�е�¼
	$currentDate = Get-Date
	if ($args[4]) {
		$caller = "Monitor"
		$isAfter7_05 = $currentDate.Hour -gt 7 -or ($currentDate.Hour -ge 7 -and $currentDate.Minute -ge 05)
		$isBefore23_50 = $currentDate.Hour -lt 23 -or ($currentDate.Hour -eq 23 -and $currentDate.Minute -le 50)
		if (-not ($isAfter7_05 -and $isBefore23_50)){
			$result = "���� 7:05-23:50 ֮��, �� 1/20 ���ʴ�����¼У԰��; "
			if (Get-Random -Maximum 20) {
				$result += "δ����ִ��"
			}
			else {
				$result += "����ִ�У����: "
				$result += Login-CampusNetwork -StudentID $args[0] -Password $args[1] -Carrier $args[2]
			}
		}
		else {
			$result = Login-CampusNetwork -StudentID $args[0] -Password $args[1] -Carrier $args[2]
		}
	} else {
		$caller = "Trigger"
		$result = Login-CampusNetwork -StudentID $args[0] -Password $args[1] -Carrier $args[2]
	}
	Write-FileLog $result $caller
	Exit
}

# Ҫ�����ԱȨ��
$role = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $role.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") -or [bool]$role.IsSystem
if (-not $isAdmin) {
	Write-Host "��Ҫ����ԱȨ�ޣ�����Ȩ����..." -ForegroundColor Yellow
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# ���������
Write-Host @"

��������������������������������������������������������������������������������������
��������������������������������������������������������������������������������������
��������������������������������������������������������������������������������������
��������������������������������������������������������������������������������������
��������������������������������������������������������������������������������������
��������������������������������������������������������������������������������������
��������������������������������������������������������������������������������������
��������������������������������������������������������������������������������������
��������������������������������������������������������������������������������������

"@ -ForegroundColor Blue

# �ű�����
Write-Host @"
����һ���������� CUMT У԰���Զ���¼�ĳ������ö��ִ�������֧�����¹��ܣ�
�� ���� CUMT_Stu �� CUMT_Tec WiFi ʱ�Զ���¼
�� ���� CUMT_Stu ���� (��̫��) ʱ�Զ���¼
�� �����������ʱ�Զ���¼
�� ÿ������ 7:22 - 7:25 �Զ���¼
�� (��ѡ) ѭ����⣬�����Զ��ص�
���ַ�ʽ��֤��������������飡
�汾��v20230416

"@ -ForegroundColor Cyan

<# # ��װ BurntToast
Write-Host "������ѯ�ʰ�װģ�������� y ���س�"
Write-Host "���ڼ����������ϵͳ֪ͨģ��..."
Install-Module BurntToast
Write-Host "�Ѱ�װ��������ģ��"
Write-Host "" #>

# �趨�ƻ���������
$taskName = "CUMT�Զ���¼У԰��"
$taskName2 = "CUMT�Զ���¼У԰���������"

# ���ƻ������Ѵ��ڣ���ѡ��ɾ�����Ǹ���
$taskExists = Get-ScheduledTask | Where-Object { $_.TaskName -eq $taskName }
$taskExists2 = Get-ScheduledTask | Where-Object { $_.TaskName -eq $taskName2 }
if ($taskExists -or $taskExists2) {
	Write-Host "ϵͳ��⵽�����ù��Զ���¼��" -ForegroundColor Yellow
	
	$logContent = Get-Content (Get-FileLog-Path)
	Write-Host ""
	Write-Host "�����ִ����־���£�"
	Write-Host ((Cut-FileLog $logContent @('Monitor', 'Trigger') 5) -join "`n")
	Write-Host ""
	
	do {
		$response = Read-Host "��ѡ��ɾ������ / ����ԭ�����������ã�(ɾ�� Y / �������� N��Ĭ�� N��"
	} while ($response -notmatch "^[ynYN]$" -and $response -ne '')

	if ($taskExists) {
		Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
	}
	if ($taskExists2) {
		Unregister-ScheduledTask -TaskName $taskName2 -Confirm:$false
	}
	
	if ($response -imatch "^[yY]$") {
		Write-Host "���Ƴ�У԰���Զ���¼���ܣ���ӭ���´�ʹ�ã�" -ForegroundColor Green
		Write-Host "��������˳�..."
		$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
		Exit
	}
	else {
		Write-Host ""
	}
}

# �����û����룬����֤�˻�
Write-Host "�������������������˻���Ϣ��Ȼ�󰴻س���" -ForegroundColor Green
do {
	Write-Host ""
	do {
		$StudentID = Read-Host "����������ѧ��"
	} while (-not $StudentID)
	do {
		$securePassword = Read-Host -Prompt "��������������" -AsSecureString
	} while (-not $securePassword)
	$Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword))
	do {
		$Carrier = Read-Host "������������Ӫ�̣�������ţ�1.�ƶ� 2.��ͨ 3.���� 0.У԰�� / Tec �˺ţ�"
	} while (-not $Carrier)
	switch ($Carrier) {
		"0" {
			$Carrier = ""
		}
		"1" {
			$Carrier = "cmcc"
		}
		"2" {
			$Carrier = "unicom"
		}
		"3" {
			$Carrier = "telecom"
		}
		"У԰��" {
			$Carrier = ""
		}
		"У԰" {
			$Carrier = ""
		}
		"" {
			$Carrier = ""
		}
		"�ƶ�" {
			$Carrier = "cmcc"
		}
		"��ͨ" {
			$Carrier = "unicom"
		}
		"����" {
			$Carrier = "telecom"
		}
		"telecom" {
			$Carrier = "telecom"
		}
		"cmcc" {
			$Carrier = "cmcc"
		}
		"unicom" {
			$Carrier = "unicom"
		}
		default {
			Write-Host "���棺δ֪����Ӫ�̣����ܵ��µ�¼ʧ��" -ForegroundColor Yellow
		}
	}

	do {
		Write-Host ""
		Write-Host "��ȷ��������������У԰����" -NoNewline -ForegroundColor Green
		Write-Host "���ڳ��Ե�¼...  " -NoNewline -ForegroundColor Green
		$result = Login-CampusNetwork -StudentID $StudentID -Password $Password -Carrier $Carrier -Test $true
		Write-Host "��¼�����$result"
		if ($result -eq "���Ѿ����ڵ�¼״̬") {
			Write-Host "��¼״̬���޷���֤����˻���Ϣ��" -ForegroundColor Yellow
			do {
				$response = Read-Host "�Ƿ���ע����¼�������µ�¼����֤��Ϣ�Ƿ���ȷ��(Y / N, ������֤�����Զ���¼ִ��ʧ�ܣ�Ĭ�� Y��"
			} while ($response -notmatch "^[ynYN]$" -and $response -ne '')

			if ($response -imatch "^[yY]$" -or $response -eq '') {
				$flag2 = $true
				$flag = $true
				Logout-CampusNetwork
				Write-Host "��ע��У԰��" -ForegroundColor Green
			} else {
				$flag2 = $false
				$flag = $false
			}
		}
		elseif ($result -eq "��¼�ɹ�") {
			$flag2 = $false
			$flag = $false
		}
		elseif ($result -eq "ͳһ�����֤�û����������") {
			Write-Host ""
			$flag2 = $false
			$flag = $true
		}
		else {
			do {
				$response = Read-Host "��ѡ���Ƿ�������д��Ϣ���ٴγ��Ե�¼����֤��Ϣ�Ƿ���ȷ��(Y / N, ������֤�����Զ���¼ִ��ʧ�ܣ�Ĭ�� Y��"
			} while ($response -notmatch "^[ynYN]$" -and $response -ne '')

			if ($response -imatch "^[yY]$" -or $response -eq '') {
				$flag2 = $false
				$flag = $true
			} else {
				$flag2 = $false
				$flag = $false
			}
		}
	} while ($flag2)
} while ($flag)

Write-Host ""

# �����Զ��ص�
do {
	try {
		$reconnect = Read-Host "�Ƿ���ѭ����⣬�����Զ��صǣ�(����Ҫ������ѭ���������������һ�㲻��Ҫ��ֱ�ӻس�)"
		if ($reconnect -eq '') {
			$reconnect = 0
		}
		else {
			[int]$reconnect = $reconnect
		}
		$flag = $true
	} catch {
		Write-Host "������Ч��������һ��������" -ForegroundColor Red
	}
} while (-not $flag)

Write-Host "�������ý������Ժ�ÿ������ 7:22 - 7:25 ʱ�Զ���¼..." -ForegroundColor Green

# ���浱ǰ�ű�������·��
$scriptPath = $MyInvocation.MyCommand.Path

# �����ƻ�����
$triggerLogin = New-ScheduledTaskTrigger -AtLogOn
$triggerDaily = New-ScheduledTaskTrigger -At "7:22" -Daily
$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass `"$($scriptPath)`" $($StudentID) $($Password) $($Carrier)"
$action2 = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass `"$($scriptPath)`" $($StudentID) $($Password) $($Carrier) $false $true"
$settings = New-ScheduledTaskSettingsSet -DontStopOnIdleEnd -AllowStartIfOnBatteries

$temp = Register-ScheduledTask -TaskName $taskName -Trigger @($triggerLogin, $triggerDaily) -Action $action -User "SYSTEM" -Settings $settings -RunLevel Highest -Force

if ($reconnect) {
	Write-Host "��������ÿ $reconnect ����ѭ�����..." -ForegroundColor Green
	$triggerTime = New-ScheduledTaskTrigger -At "0:00" -Once -RepetitionInterval (New-TimeSpan -Minutes $reconnect)
	$temp = Register-ScheduledTask -TaskName $taskName2 -Trigger $triggerTime -Action $action2 -User "SYSTEM" -Settings $settings -RunLevel Highest -Force
}

Write-Host "���������� WiFi / ��̫������ʱ��¼..." -ForegroundColor Green

# Ϊ�ƻ�������� WiFi / ��̫�� �����¼���ͨ���޸� xml��
function Add-Network-Event {
    param (
        [string]$taskName
    )

	# ��ȡ����ƻ������ XML �����ļ�
	$taskXml = New-Object XML
	$xmlText = Export-ScheduledTask -TaskName $taskName
	$taskXml.LoadXml($xmlText)

	# ���� Network �¼��������ڵ�
	$newEventTrigger = $taskXml.CreateElement("EventTrigger", $taskXml.DocumentElement.NamespaceURI)

	# ��� Enabled �ڵ�
	$newEnabled = $taskXml.CreateElement("Enabled", $taskXml.DocumentElement.NamespaceURI)
	$newEnabled.InnerText = "true"
	$temp = $newEventTrigger.AppendChild($newEnabled)

	# ��� Subscription �ڵ�
	$newSubscription = $taskXml.CreateElement("Subscription", $taskXml.DocumentElement.NamespaceURI)
	<# $newSubscription.InnerXml = '&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="Microsoft-Windows-WLAN-AutoConfig/Operational"&gt;*[System[Provider[@Name="Microsoft-Windows-WLAN-AutoConfig"] and (EventID=8001)]]
	[EventData[Data[@Name="SSID"]="CUMT_Stu"] or EventData[Data[@Name="SSID"]="CUMT_Tec"]]
	&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;' #>
	$newSubscription.InnerXml = '&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="Microsoft-Windows-WLAN-AutoConfig/Operational"&gt;*[System[Provider[@Name="Microsoft-Windows-WLAN-AutoConfig"] and (EventID=8001)]]
	[EventData[Data[@Name="SSID"]="CUMT_Stu"] or EventData[Data[@Name="SSID"]="CUMT_Tec"]]
	&lt;/Select&gt;&lt;/Query&gt;&lt;Query Id="1" Path="System"&gt;&lt;Select Path="Microsoft-Windows-NetworkProfile/Operational"&gt;*[System[Provider[@Name="Microsoft-Windows-NetworkProfile"] and (EventID=10000)]]
	[EventData[Data[@Name="Name"]="CUMT_Stu"] or EventData[Data[@Name="Name"]="CUMT_Tec"]]
	&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;'
	$temp = $newEventTrigger.AppendChild($newSubscription)

	# ����¼��������ڵ㵽����ƻ����� XML ������
	$temp = $taskXml.Task.Triggers.AppendChild($newEventTrigger)

	# �������û��Ƿ��¼��Ҫ���С�
	<# $newLogonType = $taskXml.CreateElement("LogonType", $taskXml.DocumentElement.NamespaceURI)
	$newLogonType.InnerText = "Password"
	$temp = $taskXml.Task.Principals.Principal.AppendChild($newLogonType) #>

	# ��������ƻ������ XML ����
	Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
	$temp = Register-ScheduledTask -TaskName $taskName -Xml $taskXml.OuterXml
	
}

Add-Network-Event $taskName

# ��������ʱ
function Add-Random-Delay {
    param (
        [string]$taskName,
		[string]$delay,
		[bool]$flag
    )

	# ��ȡ����ƻ������ XML �����ļ�
	$taskXml = New-Object XML
	$xmlText = Export-ScheduledTask -TaskName $taskName
	$taskXml.LoadXml($xmlText)

	# �����ʱ
	$newRandomDelay = $taskXml.CreateElement("RandomDelay", $taskXml.DocumentElement.NamespaceURI)
	if ($flag) {
		$newRandomDelay.InnerText = $delay
		$temp = $taskXml.Task.Triggers.TimeTrigger.AppendChild($newRandomDelay)
	}
	else {
		$newRandomDelay.InnerText = $delay
		$temp = $taskXml.Task.Triggers.CalendarTrigger.AppendChild($newRandomDelay)
	}

	# ��������ƻ������ XML ����
	Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
	$temp = Register-ScheduledTask -TaskName $taskName -Xml $taskXml.OuterXml
	
}

Add-Random-Delay $taskName "PT3M" $false
if ($reconnect) {
	Add-Random-Delay $taskName2 "PT$([Math]::Ceiling($reconnect/3))M" $true
}

# ������óɹ���Ϣ
Write-Host @"

�� ������ɣ���δ���ֺ��ִ�����ʾ���������Զ���¼�����Ѿ���Ч��
�� ���ĵ����Ժ�����У԰��ʱ���Զ���¼���������ٴ򿪱����������ڿ��Թرձ�����
���ڱ������ȫ�Զ���¼������������¼�豸���޵������Ҫע��ʱ��
���ֶ��� 10.2.5.251����¼ҳ�棩�����¼�Է���ϵͳ 202.119.196.6:8080/Self ���в�����
�����޸�������Ϣ��ֻ���������б�����
�����ֺ��ֱ����볢���������б�����

"@ -ForegroundColor Green

# �����Ŀ��Ϣ
Write-Host @"
����Ŀ���ӣ�https://github.com/zjsxply/CUMT-Network-Login
����Ŀ��ʱԼ 12 Сʱ���ߣ��ڼ�õ��� GPT-4 �Ĵ���������
��� GPT ����Ȥ����ӭ���룺��� ChatGPT ����Ⱥ 646745808

����ѧԺ�����Դ����Ⱥ����ѧ 454162237������ 808727301��һȺ�� 24049485����Ⱥ��
����� 916483545������ 909893238���ſ� 464112168������ 717176773������ 830604599

"@ -ForegroundColor Cyan

$temp = Read-Host "���س����˳�..."
<# Write-Host "��������˳�..."

# �ȴ��û�������������Ա��ڽű�ִ�н������� PowerShell �����Բ鿴���
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null #>
