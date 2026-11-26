# DroidBridge（安卓桥）

Windows 进程级网络应用启动台，经 ADB 把手机上的出口桥接给电脑应用。**只给从这里启动的子进程注入代理环境**，不开启 TUN、不修改系统代理、不写环境变量注册表，也不影响通过桌面快捷方式打开的其它程序。

Python 纯标准库实现，零第三方依赖。

---

## 核心特性

- **本地分流入口**
  - 固定监听 `127.0.0.1:10086`，读取并按文件变更自动缓存 `rules.yaml`，支持 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`、`MATCH` 与 `DIRECT` / `PROXY`；支持明文 HTTP `Transfer-Encoding: chunked` 请求体转发，并在失败时记录具体错误原因。
  - `DIRECT` 目标由电脑直连，`PROXY` 目标通过手机 Clash 的 `127.0.0.1:5038`。支持 HTTP 转发和 HTTPS `CONNECT`，只绑定回环地址。
  - 支持在界面内直接编辑、校验与保存 `rules.yaml`，提供域名命中测试，并在「分流实况」中支持一键将域名加入 `DIRECT` 或 `PROXY`。
  - 内置**手动** ADB 管理面板与预置 `adb`（`vendor/platform-tools/`）：优先使用手动配置路径与系统 `PATH`，找不到时自动兜底使用内置 `adb`，无需额外下载；支持查看已连接设备、多设备切换与手动建立 / 删除 `adb forward` 转发。
- **三层代理注入**
  - **普通 / Node 应用**：注入 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY`，并清空 `NO_PROXY`，确保请求进入本地分流入口。
  - **Electron / Chromium 应用**：自动根据同目录特征文件识别，并额外注入 `--proxy-server`（解决 Windows 下 Chromium 忽略 `*_PROXY` 环境变量的问题），在启动前对已运行实例做单实例锁提示。
  - **Firefox / Gecko 应用**：自动根据同目录 `xul.dll`、`omni.ja` 等特征识别；使用 `-no-remote -profile` 在 `profiles/` 下隔离运行独立配置目录，每次启动自动写入 `user.js`，通过 `parent.lock` 避免误与日常 Firefox 冲突；编辑面板支持一键从本机默认 Firefox 配置同步账号、书签与扩展。
- **独立轻量桌面壳与系统托盘常驻**
  - 自动使用本机 Chrome / Edge `--app=` 模式搭配独立用户目录与 `--no-proxy-server` 打开界面，自身不受外部代理干扰。
  - 启动台自己的独立浏览器进程不会被误判为目标 Chrome / Edge 已运行；真正已打开的目标浏览器仍会触发单实例提示。
  - 支持系统托盘常驻（Windows 下关闭主窗口默认驻留托盘保持分流不断网，可从托盘菜单重新打开界面、开关代理或彻底退出）与单实例窗口唤起复用。
- **原生 Windows 体验**
  - 通过 Win32 API 原生文件选择器（`GetOpenFileNameW`）选取 `.exe`，无需手动复制路径。
  - 自动提取目标 `.exe` 的真实图标展示在应用卡片上（失败时自动回退为首字母头像）。
  - 使用 `Toolhelp32` + `QueryFullProcessImageNameW` 进程全路径枚举运行状态，不闪黑框。
- **本地接口防护**
  - 每次启动生成随机 `API_TOKEN`，校验 `Host`、`Origin` 与 `X-DroidBridge-Token`。

---

## 运行环境

- Windows 10 / 11
- Python 3（仅使用标准库，无需 `pip install`）
- Google Chrome 或 Microsoft Edge（用于独立窗口展示）
- 手机上的 Clash 通过 ADB 映射到电脑的 `127.0.0.1:5038`

---

## 快速使用

1. **配置（可选）**
   - 首次启动会自动生成本地 `config.json` 和 `rules.yaml`，也可以将 `config.example.json` 复制为 `config.json` 后按需修改手机 Clash 上游、分流入口、规则文件与应用列表。
   - `config.json` 与独立浏览器配置目录 `profiles/` 已加入 `.gitignore`，不会提交个人配置与内网规则。
2. **启动 DroidBridge**
   - `launch_droidbridge.vbs`：推荐方式，静默启动无控制台黑窗。
   - `launch_droidbridge.bat`：备选无黑窗启动脚本（适合 `.vbs` 被拦截的环境）。
   - `debug_droidbridge.bat`：保留控制台窗口启动，方便查看运行或报错输出。
3. **配置分流**
   - 手机通过 ADB 映射 Clash 的 HTTP 端口到电脑 `127.0.0.1:5038`，DroidBridge 默认把本地分流入口开在 `127.0.0.1:10086`。
   - 在 `rules.yaml` 里填写公司网关的 `DIRECT` 规则。Mirasim 的代理设置填写 `127.0.0.1:10086`，并清空它自己的直连例外列表，让请求统一交给 DroidBridge 判断。
   - 所有请求固定进入 `10086`，没有其他旁路模式；需要直连的目标统一写成 `DIRECT` 规则。
   - 当前 YAML 支持 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`（IPv4/IPv6）和最后一条 `MATCH`，动作支持 `DIRECT` 和 `PROXY`。`IP-CIDR` 只匹配请求中的 IP 字面量，不额外解析域名；`PROXY` 会转发到手机 Clash 的上游端口。
4. **管理 ADB 转发（可选）**
   - 主界面的「手机 Clash (ADB)」面板显示 adb 路径、已连接设备和当前端口转发。
   - 转发缺失时点「建立转发」，会按当前「手机 Clash 上游端口」建立 `adb forward tcp:<端口> tcp:<端口>`；不再需要时点「删除转发」。
   - 面板全程手动，不会自动连接设备或自动建立转发。若系统 `PATH` 中没有 `adb`，会自动使用项目内置的 `vendor/platform-tools/adb.exe`，也可在「连接与设置」中手动指定路径。
5. **创建桌面快捷方式（可选）**
   - 双击 `create_desktop_shortcut.vbs` 即可在桌面生成带图标的 `DroidBridge.lnk` 快捷方式（支持直接固定到任务栏）。

---

## 目录说明

| 文件 | 说明 |
| --- | --- |
| `droidbridge.py` | 后端 HTTP 服务、进程级代理注入、Win32 进程检测与图标提取 |
| `index.html` | 单文件前端界面 |
| `config.example.json` | 默认配置模板（首次运行会自动生成本地 `config.json`） |
| `rules.example.yaml` | Clash 风格规则模板（首次运行会生成本地 `rules.yaml`） |
| `test_routing.py` / `test_adb.py` | 分流规则与 ADB 辅助模块的单元测试 |
| `droidbridge.ico` / `.png` / `.svg` | 应用图标资源 |
| `vendor/` | 内置预置依赖：`platform-tools/`（最小 Windows `adb` 运行文件）与 `scrcpy-server` |
| `launch_droidbridge.vbs` / `.bat` | 静默启动脚本 |
| `debug_droidbridge.bat` | 调试启动脚本 |
| `create_desktop_shortcut.vbs` | 一键创建桌面快捷方式脚本 |
