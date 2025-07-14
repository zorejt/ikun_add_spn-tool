Hi ikun们，这是一个ldap spn修改工具，用于通过 ldap 协议连接到dc，修改目标用户的 servicePrincipalName（SPN）属性
LDAP连接：使用LDAP协议连接到指定的dc。
用户身份验证：支持使用域凭据（用户名和密码）进行身份验证。
SPN修改：将自定义SPN添加到目标用户的servicePrincipalName属性中。
交互式输入：提示输入DC IP、域、凭据、目标用户和SPN，默认值便于使用。
错误处理：对LDAP连接、身份验证和属性修改进行稳健的错误处理。
日志记录：详细的带时间戳的日志，用于跟踪执行进度和错误

注意：此工具仅用于教育和授权测试目的。未经授权修改Active Directory属性可能违反安全策略或法律。负责任地使用。
例子：这是内网环境，域账号是henry/H3nry_987TGV!，根据bloodhound关系修改alfred，然后搭配impacket-GetUserSPNs进行kerberroasting攻击
<img width="1046" height="396" alt="image" src="https://github.com/user-attachments/assets/d19842ba-4068-44e9-a5fc-6ff671ab95ce" />
<img width="824" height="782" alt="image (1)" src="https://github.com/user-attachments/assets/d65d74f3-6b32-4831-b478-f08465b70d4b" />
<img width="1706" height="346" alt="image (2)" src="https://github.com/user-attachments/assets/d9a4f6ab-2294-4f0f-963b-c6caf3435af0" />

