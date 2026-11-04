# IEC 61850 Wireshark Lua Dissector Plugin

这是一个用于解析 IEC 61850 协议数据报文的 Wireshark Lua 插件，支持以下三种主要协议：

## 支持的协议

1. **GOOSE (Generic Object Oriented Substation Event)** - 通用面向对象变电站事件
   - 以太网类型：0x88B8
   - 用于快速传输变电站事件信息

2. **SV (Sampled Values)** - 采样值
   - 以太网类型：0x88BA
   - 用于传输电流/电压采样数据

3. **MMS (Manufacturing Message Specification)** - 制造报文规范
   - TCP 端口：102, 1002, 10002
   - 用于客户端 - 服务器通信

## 安装方法

### Linux
```bash
# 创建插件目录（如果不存在）
mkdir -p ~/.local/lib/wireshark/plugins/

# 复制插件文件
cp iec61850_dissector.lua ~/.local/lib/wireshark/plugins/

# 或者系统级安装
sudo cp iec61850_dissector.lua /usr/share/wireshark/plugins/
```

### Windows
```
将 iec61850_dissector.lua 复制到:
C:\Program Files\Wireshark\plugins\
```

### macOS
```bash
# 创建插件目录
mkdir -p ~/.local/lib/wireshark/plugins/

# 复制插件文件
cp iec61850_dissector.lua ~/.local/lib/wireshark/plugins/
```

## 验证安装

1. 启动 Wireshark
2. 点击菜单：`帮助 (Help)` → `关于 Wireshark (About Wireshark)`
3. 查看 `插件 (Plugins)` 标签页
4. 确认列表中显示 "IEC 61850 Protocol Dissector"

或者在 Wireshark 启动时查看控制台输出，应该能看到：
```
IEC 61850 plugin loaded successfully
```

## 功能特性

### ASN.1 BER 解码
- 自动识别和解析 BER 编码的 TLV (Tag-Length-Value) 结构
- 支持以下数据类型：
  - BOOLEAN (布尔值)
  - INTEGER (整数)
  - BIT STRING (位串)
  - OCTET STRING (字节串)
  - NULL
  - OBJECT IDENTIFIER (对象标识符)
  - UTF8String / VisibleString (字符串)
  - SEQUENCE (序列)
  - APPLICATION 类标签

### GOOSE 报文解析
- APPID (应用标识符)
- 长度字段
- 保留字段
- GOOSE APDU (ASN.1 BER 编码)
  - GoCB Reference (控制块引用)
  - TimeAllowedToLive (存活时间)
  - DataSet Reference (数据集引用)
  - stNum (状态号)
  - sqNum (序列号)
  - Test 标志
  - ConfRev (配置版本)
  - NumDatSetEntries (数据条目数)
  - All Data (所有数据)

### SV 报文解析
- APPID (应用标识符)
- 长度字段
- 保留字段
- SV APDU (ASN.1 BER 编码)
  - SvID (采样值 ID)
  - SmpCnt (采样计数)
  - ConfRev (配置版本)
  - SmpSynch (采样同步)
  - DataSet Reference (数据集引用)
  - All Data (所有数据)

### MMS 报文解析
- 完整的 ASN.1 BER 解码
- 支持 MMS 服务类型识别：
  - Initiate / Conclude
  - Read / Write
  - GetVariableAccessAttributes
  - DefineNamedVariable
  - EventNotification
  - Journal 操作
  - ProgramInvocation 操作
  - Domain 操作

## 使用方法

1. **捕获流量**
   - 选择适当的网络接口
   - 开始捕获

2. **过滤表达式**
   ```
   iec61850          # 所有 IEC 61850 协议
   goose             # 仅 GOOSE 报文
   sv                # 仅采样值报文
   mms               # 仅 MMS 报文
   ethertype == 0x88b8  # GOOSE 以太网类型
   ethertype == 0x88ba  # SV 以太网类型
   tcp.port == 102      # MMS TCP 端口
   ```

3. **查看详细信息**
   - 在数据包列表中选择 IEC 61850 数据包
   - 在数据包详情面板中展开 "IEC 61850 Protocol Suite"
   - 查看各个字段的详细解析

## 故障排除

### 插件未加载
- 检查 Wireshark 的插件目录路径是否正确
- 确认 Lua 解释器已启用：`帮助` → `关于 Wireshark` → `文件夹` 查看插件路径
- 检查 Wireshark 控制台是否有错误信息

### 语法错误
- 使用 `luac -p iec61850_dissector.lua` 检查语法
- 确保 Wireshark 版本与 Lua 版本兼容

### 协议未被识别
- 检查以太网的类型是否正确 (GOOSE: 0x88B8, SV: 0x88BA)
- 对于 MMS，确认 TCP 端口是否为 102 或其他配置的端口
- 可以尝试手动设置协议：右键数据包 → `Decode As` → 选择相应协议

## 技术细节

### 协议识别逻辑
1. **GOOSE**: APPID 范围 0x0000-0x3FFF，且长度字段匹配
2. **SV**: APPID 范围 0x4000-0x7FFF，且长度字段匹配
3. **MMS**: 基于 TCP 端口 (102, 1002, 10002) 或 ASN.1 标签特征

### ASN.1 BER 解码器
- 支持定长和不定长编码
- 递归解析嵌套结构
- 自动识别标签类别 (Universal, Application, Context-specific)

## 开发信息

- **版本**: 1.0.0
- **许可证**: 参见 LICENSE 文件
- **兼容性**: Wireshark 3.x 及以上版本

## 贡献

欢迎提交问题报告和功能请求。如需扩展特定 MMS 服务的详细解析，可以参考 IEC 61850-8-1 标准文档。

## 参考资源

- IEC 61850 标准文档
- Wireshark Lua API 文档：https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html
- IEC 61850 协议入门指南
