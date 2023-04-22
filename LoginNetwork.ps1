# 定义登录函数
function Send-Login-Request {
    param (
        [string]$StudentID,
        [string]$Password,
        [string]$Carrier
    )
		
	if ([bool]$Carrier) {
		$Carrier = "@$($Carrier)"
	}
	$url = "http://10.2.5.251:801/eportal/?c=Portal&a=login&login_method=1&user_account=$($StudentID)$($Carrier)&user_password=$($Password)"
	$response = Invoke-WebRequest -Uri $url -UseBasicParsing
	$respText = $response.Content.TrimStart('(').TrimEnd(')')
	$respJson = ConvertFrom-Json $respText
	
	switch ($respJson.result) {
		1 {
			$notification = "登录成功"
		}
		0 {
			switch ($respJson.ret_code) {
				1 {
					$bytes = [System.Convert]::FromBase64String($respJson.msg)
					$msg = [System.Text.Encoding]::UTF8.GetString($bytes)
					switch ($msg) {
						"userid error1" {
							$notification = "账号不存在"
						}
						"auth error80" {
							$notification = "本时段禁止上网"
						}
						"Rad:UserName_Err" {
							$notification = "绑定的运营商账号错误，请联系运营商核实或去运营商校园营业厅进行绑定。"
						}
						"Authentication Fail ErrCode=16" {
							$notification = "本时段不允许上网"
						}
						"Mac, IP, NASip, PORT err(2)!" {
							$notification = "您的账号不允许在此网络使用，请检查接入的是 CUMT_Stu 还是 CUMT_Tec 网络"
						}
						"Rad:Status_Err" {
							$notification = "您绑定的运营商账号状态异常，请联系对应运营商处理。"
						}
						"Rad:Limit Users Err" {
							$notification = "您的登陆超限，请在自服务 http://202.119.196.6:8080/Self 下线终端。"
						}
						"ldap auth error" {
							$notification = "统一身份认证用户名密码错误！"
						}
						default {
							$notification = "未知错误：$($msg)"
							
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
			$notification = "未知结果：$($respJson)"
			
		}
	}
	
	return $notification
}

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
			$pingResultText = "网络未连通，可能掉线或刚连接网络；执行登录: "
		}
	}
	
	# 测试则一定发送登录请求
    if ($Test -or -not $pingResult) {
		$pingResult = Test-Connection -ComputerName "10.2.5.251" -Quiet -BufferSize 1 -Count 1
		if (-not $pingResult) {
			$notification = "非校园网环境"
		}
		else {
			$notification = Send-Login-Request $StudentID $Password $Carrier
			
			# 弹出系统通知消息
			# New-BurntToastNotification -Text "已尝试登录校园网", $notification
		}
		
    }
		
	return $pingResultText + $notification
}

# 定义注销函数
function Logout-CampusNetwork {
	$url = "http://10.2.5.251:801/eportal/?c=Portal&a=logout"
	$response = Invoke-WebRequest -Uri $url -UseBasicParsing
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
			if (Get-Random -Maximum 20) {
				$result += "未触发执行"
			}
			else {
				$result += "触发执行，结果: "
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
这是一个可以设置 CUMT 校园网自动登录的程序。运用多种触发器，支持以下功能：
√ 连接 CUMT_Stu 或 CUMT_Tec WiFi 时自动登录
√ 连接 CUMT_Stu 网线 (以太网) 时自动登录
√ 解锁进入电脑时自动登录
√ 每天上午 7:22 - 7:25 自动登录
√ (可选) 循环检测，掉线自动重登
多种方式保证您的轻快上网体验！
版本：v20230422

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
	Write-Host ""
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
		Write-Host "已移除校园网自动登录功能，欢迎您下次使用！" -ForegroundColor Green
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
		$Carrier = Read-Host "请输入您的运营商（请输序号：1.移动 2.联通 3.电信 0.校园网 / Tec 账号）"
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
		"" {
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
			Write-Host "警告：未知的运营商，可能导致登录失败" -ForegroundColor Yellow
		}
	}

	do {
		Write-Host ""
		Write-Host "请确保您现在已连接校园网。" -NoNewline -ForegroundColor Green
		Write-Host "正在尝试登录...  " -NoNewline -ForegroundColor Green
		$result = Login-CampusNetwork -StudentID $StudentID -Password $Password -Carrier $Carrier -Test $true
		Write-Host "登录结果：$result"
		if ($result -eq "您已经处于登录状态") {
			Write-Host "登录状态下无法验证你的账户信息。" -ForegroundColor Yellow
			do {
				$response = Read-Host "是否先注销登录，再重新登录以验证信息是否正确？(Y / N, 建议验证以免自动登录执行失败，默认 Y）"
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
		elseif ($result -eq "统一身份认证用户名密码错误！") {
			Write-Host ""
			$flag2 = $false
			$flag = $true
		}
		else {
			do {
				$response = Read-Host "请选择是否重新填写信息，再次尝试登录以验证信息是否正确？(Y / N, 建议验证以免自动登录执行失败，默认 Y）"
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

# 掉线自动重登
do {
	try {
		$reconnect = Read-Host "是否开启循环检测，掉线自动重登？(若需要请输入循环检测间隔分钟数；一般不需要，直接回车)"
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

Write-Host "正在设置解锁电脑和每天上午 7:22 - 7:25 时自动登录..." -ForegroundColor Green

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

√ 设置完成！若未出现红字错误提示，则您的自动登录功能已经生效。
√ 您的电脑以后连接校园网时将自动登录，无需您再打开本程序。您现在可以关闭本程序。
由于本程序会全自动登录，如您遇到登录设备超限等情况需要注销时，
请手动打开 10.2.5.251（登录页面），或登录自服务系统 202.119.196.6:8080/Self 进行操作。
如需修改设置信息，只需重新运行本程序。
若出现红字报错，请尝试重新运行本程序。

"@ -ForegroundColor Green

# 输出项目信息
Write-Host @"
本项目链接：https://github.com/zjsxply/CUMT-Network-Login
本项目历时约 12 小时上线，期间得到了 GPT-4 的大量帮助！
如对 GPT 有兴趣，欢迎加入：矿大 ChatGPT 交流群 646745808

另附各学院民间资源分享群：数学 454162237，化工 808727301（一群） 24049485（二群）
计算机 916483545，环测 909893238，信控 464112168，机电 717176773，电力 830604599

"@ -ForegroundColor Cyan

$temp = Read-Host "按回车键退出..."
<# Write-Host "按任意键退出..."

# 等待用户按下任意键，以便在脚本执行结束后保留 PowerShell 窗口以查看输出
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null #>
