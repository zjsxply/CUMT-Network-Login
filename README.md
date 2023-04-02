# CUMT-Network-Login
这是一个可以设置 CUMT 校园网自动登录的程序，支持以下功能：

- 电脑解锁时自动登录
- 连接 `CUMT_Stu` 或 `CUMT_Tec` WiFi 时自动登录
- 连接 `CUMT_Stu` 网线 (以太网) 时自动登录
- 每天 7:22 AM 自动登录
- (可选) 掉线时自动重新登录 (自定义循环检测周期)

多种方式保证您的轻快上网体验！

## 使用方式

双击运行`CUMT自动登录校园网 for Windows.bat`，需授予管理员权限

## 内容说明

本程序使用 Powershell 编写，主程序在 `LoginNetwork.ps1` 中。

我们将该 Powershell 脚本内嵌在 `CUMT自动登录校园网 for Windows.bat` 中，方便用户使用。

只需下载 `CUMT自动登录校园网 for Windows.bat` 即可。

![screenshot](https://github.com/zjsxply/CUMT-Network-Login/blob/main/screenshot.png?raw=true)

## 想做但没实现的功能

弹出 Windows 气泡提示：计划任务只能用 SYSTEM 用户，否则每次执行登录会闪一下蓝色窗口；但 SYSTEM 下执行 `New-BurntToastNotification -Text "已尝试登录校园网", $notification` 不会在当前用户下弹出
