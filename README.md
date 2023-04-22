# CUMT-Network-Login
这是一个可以设置 CUMT 校园网自动登录的程序。运用多种触发器，支持以下功能：

- 连接 `CUMT_Stu` 或 `CUMT_Tec` WiFi 时自动登录
- 连接 `CUMT_Stu` 网线 (以太网) 时自动登录
- 解锁进入电脑时自动登录
- 每天上午 7:22 - 7:25 自动登录
- (可选) 循环检测，掉线自动重登

多种方式保证您的轻快上网体验！

首个版本：v20230401

当前版本：v20230422

## 使用方式

双击运行`CUMT校园网全自动登录 for Windows.bat`，需授予管理员权限

## 环境要求

需要系统中装有 PowerShell，经测试 PowerShell 5.1 可正常运行本脚本

## 内容说明

本程序使用 Powershell 编写，主程序在 `LoginNetwork.ps1` 中。

我们将该 Powershell 脚本内嵌在 `CUMT校园网全自动登录 for Windows.bat` 中，方便用户使用。

只需下载 `CUMT校园网全自动登录 for Windows.bat` 即可。

![screenshot](https://github.com/zjsxply/CUMT-Network-Login/blob/main/screenshot.png?raw=true)

## 想做但没实现的功能

弹出 Windows 气泡提示：计划任务只能用 SYSTEM 用户，否则每次执行登录会闪一下蓝色窗口；但 SYSTEM 下执行 `New-BurntToastNotification -Text "已尝试登录校园网", $notification` 不会在当前用户下弹出
