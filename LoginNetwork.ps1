# 定义登录函数
function Login-CampusNetwork {
    param (
        [string]$StudentID,
        [string]$Password,
        [string]$Carrier,
		[bool]$Test = $false
    )

    # 检测 IP 10.2.4.2 是否可以 Ping 通
    if (-not $Test) {
		$pingResult = Test-Connection -ComputerName "10.2.4.2" -Quiet -BufferSize 1 -Count 1
		if ($pingResult) {
			$pingResultText = "网络处于连通状态"
		}
		else {
			$pingResultText = "网络未连通，掉线；执行登录: "
		}
	}
	
	# 测试则一定发送登录请求
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
                $notification = "登录成功"
            }
            0 {
				switch ($respJson.ret_code) {
					1 {
						switch ($respJson.msg) {
							"bGRhcCBhdXRoIGVycm9y" {
								$notification = "账号、密码或运营商错误"
							}
							"UmFkOlVzZXJOYW1lX0Vycg==" {
								$notification = "账号不存在"
							}
							"TWFjLCBJUCwgTkFTaXAsIFBPUlQgZXJyKDIpIQ==" {
								$notification = "您的账号不允许在此网络使用"
							}
						}
					}
					2 {
						$notification = "您已经处于登录状态"
					}
					3 {
						$notification = "未知错误，错误代码：3"
					}
				}
            }
            default {
                $notification = "未知结果"
				
            }
        }

        # 弹出系统通知消息
		# New-BurntToastNotification -Text "已尝试登录校园网", $notification
    }
		
	return $pingResultText + $notification
}

# 定义注销函数
function Logout-CampusNetwork {
	$url = "http://10.2.5.251:801/eportal/?c=Portal&a=logout"
	$response = Invoke-WebRequest -Uri $url
}

# 定义裁剪日志记录函数
function Cut-FileLog {
    param (
        [string[]]$fileContent,
		[string[]]$s,
        [int]$num = 100
    )

	# 分别定义每个字符串包含的行数为 0，分别定义存储每个字符串行数的数组
	$counts = @{}
	$lines = @{}
	foreach ($str in $s) {
		$counts[$str] = 0
		$lines[$str] = @()
	}

	# 循环遍历每一行，记录包含每个字符串的行数并将其存储到相应的数组中
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

	# 按照原先的顺序重新组合文件内容，并返回
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

# 定义取日志文件路径函数
function Get-FileLog-Path {
	$logFile = Join-Path $PSScriptRoot "LoginNetwork.log"
	if (-not (Test-Path $logFile)) {
		New-Item -Path $logFile -ItemType File -Force
	}
	return $logFile
}

# 定义记录日志函数
function Write-FileLog {
    param (
        [string]$Log,
		[string]$caller
    )
	
	# 设置日志文件路径
	$logFile = Get-FileLog-Path
	
	# 设置要添加到日志文件中的文本字符串
	$logFormat = "[{0:yyyy-MM-dd HH:mm:ss}] {1} - {2}"
	$timestamp = Get-Date
	$logEntry = $logFormat -f $timestamp, $caller, $Log
	
	# 添加新日志内容到日志文件末尾
	Add-Content $logFile -Value $logEntry

	# 如果日志条数超过 100 条，则只保留最新的 100 条
	$logContent = Get-Content $logFile
	Set-Content $logFile (Cut-FileLog $logContent @("Monitor", "Trigger"))

}

# 命令行可接收 5 个参数：学号 密码 运营商 是否测试登录 是否为监测
# 计划任务执行登录
if ($args) {
	
	# 如果是监测，则7:05 到 23:50 之外的时间以 1 / 20 的概率执行登录
	$currentDate = Get-Date
	if ($args[4]) {
		$caller = "Monitor"
		$isAfter7_05 = $currentDate.Hour -gt 7 -or ($currentDate.Hour -ge 7 -and $currentDate.Minute -ge 05)
		$isBefore23_50 = $currentDate.Hour -lt 23 -or ($currentDate.Hour -eq 23 -and $currentDate.Minute -le 50)
		if (-not ($isAfter7_05 -and $isBefore23_50)){
			$result = "不在 7:05-23:50 之间, 以 1/20 概率触发登录校园网; "
			if (Get-Random -Maximum 20 -Minimum 1 -IncludeMinimum) {
				$result += "触发执行，结果: "
				$result += Login-CampusNetwork -StudentID $args[0] -Password $args[1] -Carrier $args[2]
			}
			else {
				$result += "未触发执行"
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

# 要求管理员权限
$role = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $role.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") -or [bool]$role.IsSystem
if (-not $isAdmin) {
	Write-Host "需要管理员权限，请求权限中..." -ForegroundColor Yellow
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# 输出点阵字
Write-Host @"

　　　◆◆◆◆◆◆　　◆◆◆◆　◆◆◆◆　◆◆◆◆　　　　◆◆◆　◆◆◆◆◆◆◆◆◆　
　　◆◆◆　　◆◆　　　◆◆　　　◆◆　　　◆◆◆　　　　◆◆　　◆◆　　◆　　◆◆　
　　◆◆　　　　◆◆　　◆　　　　　◆　　　　◆◆◆　　◆◆◆　　◆◆　　◆　　◆◆　
　　◆◆　　　　　　　　◆　　　　　◆　　　　◆◆◆　　◆◆◆　　　　　　◆　　　　　
　◆◆◆　　　　　　　　◆　　　　　◆　　　　◆◆◆◆　◆　◆　　　　　　◆　　　　　
　◆◆◆　　　　　　　　◆　　　　　◆　　　　◆　◆◆◆◆　◆　　　　　　◆　　　　　
　　◆◆　　　　◆◆　　◆◆　　　◆◆　　　　◆　◆◆◆　　◆　　　　　　◆　　　　　
　　◆◆◆　　◆◆◆　　◆◆　　　◆◆　　　　◆　　◆◆　　◆　　　　　　◆　　　　　
　　　◆◆◆◆◆◆　　　◆◆◆◆◆◆◆　　◆◆◆◆　◆◆◆◆◆◆　　　◆◆◆◆◆　　　

"@ -ForegroundColor Blue

# 脚本介绍
Write-Host @"
这是一个可以设置 CUMT 校园网自动登录的程序，支持以下功能：
√ 电脑解锁时自动登录
√ 连接 CUMT_Stu 或 CUMT_Tec WiFi 时自动登录
√ 连接 CUMT_Stu 网线 (以太网) 时自动登录
√ 每天 7:22 AM 自动登录
√ (可选) 掉线时自动重新登录 (自定义循环检测周期)
多种方式保证您的轻快上网体验！
版本：v20230402

"@ -ForegroundColor Cyan

<# # 安装 BurntToast
Write-Host "以下若询问安装模块请输入 y 并回车"
Write-Host "正在检查所依赖的系统通知模块..."
Install-Module BurntToast
Write-Host "已安装所依赖的模块"
Write-Host "" #>

# 设定计划任务名称
$taskName = "CUMT自动登录校园网"
$taskName2 = "CUMT自动登录校园网——监测"

# 若计划任务已存在，则选择删除还是覆盖
$taskExists = Get-ScheduledTask | Where-Object { $_.TaskName -eq $taskName }
$taskExists2 = Get-ScheduledTask | Where-Object { $_.TaskName -eq $taskName2 }
if ($taskExists -or $taskExists2) {
	Write-Host "系统检测到已设置过自动登录。" -ForegroundColor Yellow
	
	$logContent = Get-Content (Get-FileLog-Path)
	Write-Host "最近的执行日志如下："
	Write-Host ((Cut-FileLog $logContent @('Monitor', 'Trigger') 5) -join "`n")
	Write-Host ""
	
	do {
		$response = Read-Host "请选择：删除设置 / 覆盖原设置重新设置？(删除 Y / 重新设置 N，默认 N）"
	} while ($response -notmatch "^[ynYN]$" -and $response -ne '')

	if ($taskExists) {
		Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
	}
	if ($taskExists2) {
		Unregister-ScheduledTask -TaskName $taskName2 -Confirm:$false
	}
	
	if ($response -imatch "^[yY]$") {
		Write-Host "已移除校园网自动登录功能，期待您再次使用！" -ForegroundColor Green
		Write-Host "按任意键退出..."
		$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
		Exit
	}
	else {
		Write-Host ""
	}
}

# 请求用户输入，并验证账户
Write-Host "接下来，请输入您的账户信息，然后按回车键" -ForegroundColor Green
do {
	Write-Host ""
	do {
		$StudentID = Read-Host "请输入您的学号"
	} while (-not $StudentID)
	do {
		$securePassword = Read-Host -Prompt "请输入您的密码" -AsSecureString
	} while (-not $securePassword)
	$Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword))
	do {
		$Carrier = Read-Host "请输入您的运营商（0.校园网 留空；1.移动 cmcc；2.联通 unicom；3.电信 telecom；可输序号）"
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
		"校园网" {
			$Carrier = ""
		}
		"校园" {
			$Carrier = ""
		}
		"移动" {
			$Carrier = "cmcc"
		}
		"联通" {
			$Carrier = "unicom"
		}
		"电信" {
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
			Write-Host "未知的运营商" -ForegroundColor Red
		}
	}

	do {
		Write-Host ""
		Write-Host "正在尝试登录...  " -NoNewline -ForegroundColor Green
		$result = Login-CampusNetwork -StudentID $StudentID -Password $Password -Carrier $Carrier -Test $true
		Write-Host "登录结果：$result"
		if ($result -eq "您已经处于登录状态") {
			Write-Host "登录状态下无法验证你的账户信息。" -ForegroundColor Yellow
			do {
				$response = Read-Host "是否先注销登录，再重新登录以验证信息是否正确？(Y / N, 建议验证，默认 Y）"
			} while ($response -notmatch "^[ynYN]$" -and $response -ne '')

			if ($response -imatch "^[yY]$" -or $response -eq '') {
				$flag2 = $true
				$flag = $true
				Logout-CampusNetwork
				Write-Host "已注销校园网" -ForegroundColor Green
			} else {
				$flag2 = $false
				$flag = $false
			}
		}
		elseif ($result -eq "登录成功") {
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

# 是否掉线自动重登
do {
	try {
		$reconnect = Read-Host "是否开启掉线自动重连功能？(若需要请输入检测间隔的分钟数，一般不需要，请直接回车)"
		if ($reconnect -eq '') {
			$reconnect = 0
		}
		else {
			[int]$reconnect = $reconnect
		}
		$flag = $true
	} catch {
		Write-Host "输入无效，请输入一个整数。" -ForegroundColor Red
	}
} while (-not $flag)

Write-Host "正在设置自动登录..." -ForegroundColor Green

# 保存当前脚本的完整路径
$scriptPath = $MyInvocation.MyCommand.Path

# 创建计划任务
$triggerLogin = New-ScheduledTaskTrigger -AtLogOn
$triggerDaily = New-ScheduledTaskTrigger -At "7:22" -Daily
$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass `"$($scriptPath)`" $($StudentID) $($Password) $($Carrier)"
$action2 = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass `"$($scriptPath)`" $($StudentID) $($Password) $($Carrier) $false $true"
$settings = New-ScheduledTaskSettingsSet -DontStopOnIdleEnd -AllowStartIfOnBatteries

$temp = Register-ScheduledTask -TaskName $taskName -Trigger @($triggerLogin, $triggerDaily) -Action $action -User "SYSTEM" -Settings $settings -RunLevel Highest -Force

if ($reconnect) {
	Write-Host "正在设置每 $reconnect 分钟循环检测..." -ForegroundColor Green
	$triggerTime = New-ScheduledTaskTrigger -At "0:00" -Once -RepetitionInterval (New-TimeSpan -Minutes $reconnect)
	$temp = Register-ScheduledTask -TaskName $taskName2 -Trigger $triggerTime -Action $action2 -User "SYSTEM" -Settings $settings -RunLevel Highest -Force
}

Write-Host "正在设置在 WiFi / 以太网连接时登录..." -ForegroundColor Green

# 为计划任务添加 WiFi / 以太网 连接事件（通过修改 xml）
function Add-Network-Event {
    param (
        [string]$taskName
    )

	# 读取任务计划程序的 XML 配置文件
	$taskXml = New-Object XML
	$xmlText = Export-ScheduledTask -TaskName $taskName
	$taskXml.LoadXml($xmlText)

	# 创建 Network 事件触发器节点
	$newEventTrigger = $taskXml.CreateElement("EventTrigger", $taskXml.DocumentElement.NamespaceURI)

	# 添加 Enabled 节点
	$newEnabled = $taskXml.CreateElement("Enabled", $taskXml.DocumentElement.NamespaceURI)
	$newEnabled.InnerText = "true"
	$temp = $newEventTrigger.AppendChild($newEnabled)

	# 添加 Subscription 节点
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

	# 添加事件触发器节点到任务计划程序 XML 配置中
	$temp = $taskXml.Task.Triggers.AppendChild($newEventTrigger)

	# “不管用户是否登录都要运行”
	<# $newLogonType = $taskXml.CreateElement("LogonType", $taskXml.DocumentElement.NamespaceURI)
	$newLogonType.InnerText = "Password"
	$temp = $taskXml.Task.Principals.Principal.AppendChild($newLogonType) #>

	# 更新任务计划程序的 XML 配置
	Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
	$temp = Register-ScheduledTask -TaskName $taskName -Xml $taskXml.OuterXml
	
}

Add-Network-Event $taskName

# 添加随机延时
function Add-Random-Delay {
    param (
        [string]$taskName,
		[string]$delay,
		[bool]$flag
    )

	# 读取任务计划程序的 XML 配置文件
	$taskXml = New-Object XML
	$xmlText = Export-ScheduledTask -TaskName $taskName
	$taskXml.LoadXml($xmlText)

	# 随机延时
	$newRandomDelay = $taskXml.CreateElement("RandomDelay", $taskXml.DocumentElement.NamespaceURI)
	if ($flag) {
		$newRandomDelay.InnerText = $delay
		$temp = $taskXml.Task.Triggers.TimeTrigger.AppendChild($newRandomDelay)
	}
	else {
		$newRandomDelay.InnerText = $delay
		$temp = $taskXml.Task.Triggers.CalendarTrigger.AppendChild($newRandomDelay)
	}

	# 更新任务计划程序的 XML 配置
	Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
	$temp = Register-ScheduledTask -TaskName $taskName -Xml $taskXml.OuterXml
	
}

Add-Random-Delay $taskName "PT3M" $false
if ($reconnect) {
	Add-Random-Delay $taskName2 "PT$([Math]::Ceiling($reconnect/3))M" $true
}

# 输出设置成功信息
Write-Host @"

√ 设置完成！若未出现红色错误提示，则您的自动登录功能已经生效。
√ 您目前已登录到校园网，并且以后连接校园网时会自动登录，您现在可以关闭本程序。
如需修改设置信息，只需重新运行本程序。

"@ -ForegroundColor Green

# 输出项目信息
Write-Host @"
本项目链接：https://github.com/zjsxply/CUMT-Network-Login
本项目历时约 12 小时上线，期间得到了 GPT-4 的大量帮助！
如有兴趣，欢迎加入：矿大 ChatGPT 交流群 646745808

各学院资源分享群：数学 454162237，化工 808727301（一群）24049485（二群）
计算机 916483545，环测 909893238，信控 464112168，机电 717176773，电力 830604599

"@ -ForegroundColor Cyan

$temp = Read-Host "按回车键退出..."
# Write-Host "按任意键退出..."

# 等待用户按下任意键，以便在脚本执行结束后保留 PowerShell 窗口以查看输出
# $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null


