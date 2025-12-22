from tools.wazuh_siem_tool import WazuhSIEMTool

tool = WazuhSIEMTool()
result = tool.run("192.168.119.15", days=30)

print(result)