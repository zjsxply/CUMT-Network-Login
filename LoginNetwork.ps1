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
	}

    if ($Test -or -not $pingResult) {
        if ([bool]$Carrier) {
			$url = "http://10.2.5.251:801/eportal/?c=Portal&a=login&login_method=1&user_account=$($StudentID)@$($Carrier)&user_password=$($Password)"
        }
		else {
			$url = "http://10.2.5.251:801/eportal/?c=Portal&a=login&login_method=1&user_account=$($StudentID)&user_password=$($Password)"
		}
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
						switch ($respJson.msg) {
							"bGRhcCBhdXRoIGVycm9y" {
								$notification = "�˺š��������Ӫ�̴���"
							}
							"UmFkOlVzZXJOYW1lX0Vycg==" {
								$notification = "�˺Ų�����"
							}
							"TWFjLCBJUCwgTkFTaXAsIFBPUlQgZXJyKDIpIQ==" {
								$notification = "�����˺Ų������ڴ�����ʹ��"
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
                $notification = "δ֪���"
				
            }
        }

        # ����ϵͳ֪ͨ��Ϣ
		# New-BurntToastNotification -Text "�ѳ��Ե�¼У԰��", $notification
		
		return $notification
    }
}

# ����ע������
function Logout-CampusNetwork {
	$url = "http://10.2.5.251:801/eportal/?c=Portal&a=logout"
	$response = Invoke-WebRequest -Uri $url
}

# �����пɽ��� 5 ��������ѧ�� ���� ��Ӫ�� �Ƿ���Ե�¼ �Ƿ�Ϊ���
# �ƻ�����ִ�е�¼
if ($args) {
	
	# ����Ǽ�⣬��7:05 �� 23:50 ֮���ʱ���� 1 / 20 �ĸ���ִ�е�¼
	$currentDate = Get-Date
	if ($args[4] -and -not ($currentDate.Hour -gt 7 -or ($currentDate.Hour -ge 7 -and $currentDate.Minute -ge 05)) -and ($currentDate.Hour -lt 23 -or ($currentDate.Hour -eq 23 -and $currentDate.Minute -le 50))) {
		if (Get-Random -Maximum 20 -Minimum 1 -IncludeMinimum) {
			Login-CampusNetwork -StudentID $args[0] -Password $args[1] -Carrier $args[2]
		}
	} else {
		Login-CampusNetwork -StudentID $args[0] -Password $args[1] -Carrier $args[2]
	}
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
������������������������������������������������������������������������������������������������������������������������
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
Write-Host "����һ�������Զ���¼ CUMT У԰���ĳ���֧�����¹��ܣ�" -ForegroundColor Cyan
Write-Host "�� ���Խ���ʱ�Զ���¼" -ForegroundColor Cyan
Write-Host "�� ���� CUMT_Stu �� CUMT_Tec WiFi ʱ�Զ���¼" -ForegroundColor Cyan
Write-Host "�� �������ߣ���̫����ʱ�Զ���¼" -ForegroundColor Cyan
Write-Host "�� ÿ�� 7:22 AM �Զ���¼" -ForegroundColor Cyan
Write-Host "�� (��ѡ) ���ߺ��Զ�������Լÿ 5 ���Ӽ��һ�Σ�" -ForegroundColor Cyan
Write-Host "�汾��v20230401" -ForegroundColor Cyan
Write-Host ""

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
	do {
		$response = Read-Host "��ѡ��ɾ������ / ����ԭ�����������ã�(ɾ�� Y / �������� N��Ĭ�� �������ã�"
	} while ($response -notmatch "^[ynYN]$" -and $response -ne '')

	if ($taskExists) {
		Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
	}
	if ($taskExists2) {
		Unregister-ScheduledTask -TaskName $taskName2 -Confirm:$false
	}
	
	if ($response -imatch "^[yY]$") {
		Write-Host "���Ƴ�У԰���Զ���¼���ܣ��ڴ����ٴ�ʹ�ã�" -ForegroundColor Green
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
	$StudentID = Read-Host "����������ѧ��"
	$securePassword = Read-Host -Prompt "��������������" -AsSecureString
	$Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword))
	$Carrier = Read-Host "������������Ӫ�̣��ƶ� cmcc����ͨ unicom������ telecom��У԰�� ���գ�"

	do {
		Write-Host ""
		Write-Host "���ڳ��Ե�¼...  " -NoNewline -ForegroundColor Green
		$result = Login-CampusNetwork -StudentID $StudentID -Password $Password -Carrier $Carrier -Test $true
		Write-Host "��¼�����$result"
		if ($result -eq "���Ѿ����ڵ�¼״̬") {
			Write-Host "��¼״̬���޷���֤����˻���Ϣ��" -ForegroundColor Yellow
			do {
				$response = Read-Host "�Ƿ���ע����¼�������µ�¼����֤��Ϣ�Ƿ���ȷ��(Y / N, Ĭ�� Y��"
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
		else {
			Write-Host ""
			$flag2 = $false
			$flag = $true
		}
	} while ($flag2)
} while ($flag)

Write-Host ""

# �Ƿ�����Զ��ص�
do {
	$response = Read-Host "�Ƿ��������Զ��������ܣ�Լÿ 5 ���Ӽ��һ�Σ�(Y / N��һ�㲻��Ҫ��Ĭ�� N)"
} while ($response -notmatch "^[ynYN]$" -and $response -ne '')
$reconnect = $response -imatch "^[yY]$"

Write-Host "���������Զ���¼..." -ForegroundColor Green

# ���浱ǰ�ű�������·��
$scriptPath = $MyInvocation.MyCommand.Path

# �����ƻ�����
$triggerLogin = New-ScheduledTaskTrigger -AtLogOn
$triggerDaily = New-ScheduledTaskTrigger -At "7:22" -Daily
$triggerTime = New-ScheduledTaskTrigger -At "0:00" -Once -RepetitionInterval (New-TimeSpan -Minutes 5)
$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass `"$($scriptPath)`" $($StudentID) $($Password) $($Carrier)"
$action2 = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass `"$($scriptPath)`" $($StudentID) $($Password) $($Carrier) $false $true"
$settings = New-ScheduledTaskSettingsSet -DontStopOnIdleEnd -AllowStartIfOnBatteries

$temp = Register-ScheduledTask -TaskName $taskName -Trigger @($triggerLogin, $triggerDaily) -Action $action -User "SYSTEM" -Settings $settings -RunLevel Highest -Force

if ($reconnect) {
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
		[bool]$flag
    )

	# ��ȡ����ƻ������ XML �����ļ�
	$taskXml = New-Object XML
	$xmlText = Export-ScheduledTask -TaskName $taskName
	$taskXml.LoadXml($xmlText)

	# �����ʱ
	$newRandomDelay = $taskXml.CreateElement("RandomDelay", $taskXml.DocumentElement.NamespaceURI)
	if ($flag) {
		$newRandomDelay.InnerText = "PT1M"
		$temp = $taskXml.Task.Triggers.TimeTrigger.AppendChild($newRandomDelay)
	}
	else {
		$newRandomDelay.InnerText = "PT3M"
		$temp = $taskXml.Task.Triggers.CalendarTrigger.AppendChild($newRandomDelay)
	}

	# ��������ƻ������ XML ����
	Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
	$temp = Register-ScheduledTask -TaskName $taskName -Xml $taskXml.OuterXml
	
}

Add-Random-Delay $taskName $false
if ($reconnect) {
	Add-Random-Delay $taskName2 $true
}

# ������óɹ���Ϣ
Write-Host ""
Write-Host "�� ������ɣ���δ���ֺ�ɫ������ʾ�������Զ���¼�����Ѿ���Ч��" -ForegroundColor Green
Write-Host "�����޸��˻����ã�ֻ���������б�����" -ForegroundColor Green
Write-Host ""
Write-Host "����Ŀ���ӣ�https://github.com/zjsxply/CUMT-Network-Login" -ForegroundColor Cyan
Write-Host "����Ŀ�Ŀ�������ɫ�õ��� GPT-4 ��Э����������Ȥ����ӭ���룺��� ChatGPT ����Ⱥ 646745808" -ForegroundColor Cyan
Write-Host ""
Write-Host "��ѧԺ��Դ����Ⱥ����ѧ 454162237������ 808727301��һȺ��24049485����Ⱥ��" -ForegroundColor Cyan
Write-Host "����� 916483545������ 909893238���ſ� 464112168������ 717176773������ 830604599" -ForegroundColor Cyan
Write-Host ""
$temp = Read-Host "���س����˳�..."
# Write-Host "��������˳�..."

# �ȴ��û�������������Ա��ڽű�ִ�н������� PowerShell �����Բ鿴���
# $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null


