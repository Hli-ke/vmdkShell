# import socket
# import base64
# import time

# # ================= 配置区域 =================

# # 1. 目标 ESP8266 的地址 (默认AP网关通常是 192.168.4.1)
# TARGET_IP = '192.168.4.1'
# TARGET_PORT = 8567

# # 2. 你想要 ESP8266 连接的 WiFi 信息
# NEW_WIFI_SSID = "ziroom1902(01.05)"  # 修改这里：你的WiFi名
# NEW_WIFI_PASS = "@4001001111@"   # 修改这里：你的WiFi密码

# # 3. Base64 码表设置
# # 如果你在 C++ 里修改了 base64_table，请必须在这里同步修改 MY_TABLE
# STD_TABLE = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
# MY_TABLE  = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" 
# # 示例：如果你在C++里把表倒序了，就把上面 MY_TABLE 改成你的倒序字符串

# # ================= 协议常量 (不要动) =================
# MAGIC_HEADER = b'\x85\x67\x94\x02'
# SEPARATOR    = b'\x85\x92'

# def send_config():
#     print("-" * 40)
#     print(f"目标: {TARGET_IP}:{TARGET_PORT}")
#     print(f"配置: SSID='{NEW_WIFI_SSID}', PASS='{NEW_WIFI_PASS}'")
    
#     # 1. 构造原始 Payload (SSID + 分隔符 + 密码)
#     # encode() 将字符串转为 bytes
#     raw_payload = NEW_WIFI_SSID.encode('utf-8') + SEPARATOR + NEW_WIFI_PASS.encode('utf-8')
    
#     # 2. Base64 编码
#     # 得到标准 Base64
#     b64_bytes = base64.b64encode(raw_payload)
    
#     # 3. 处理换表 (如果 MY_TABLE 和标准表不同)
#     if MY_TABLE != STD_TABLE:
#         print("检测到自定义 Base64 表，正在转换...")
#         trans_table = bytes.maketrans(STD_TABLE, MY_TABLE)
#         b64_bytes = b64_bytes.translate(trans_table)
    
#     # 4. 拼接最终数据包
#     # 格式: [Magic Header] + [Base64 Data] + [\n]
#     # 注意：末尾加 \n 是因为 C++ 代码用了 readBytesUntil('\n')
#     packet_data = MAGIC_HEADER + b64_bytes + b'\n'
    
#     print(f"发送数据长度: {len(packet_data)} bytes")
#     # print(f"发送内容(Hex): {packet_data.hex()}") # 调试用

#     # 5. 建立 TCP 连接发送
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.settimeout(5) # 5秒超时
    
#     try:
#         print("正在连接 ESP8266 ...")
#         s.connect((TARGET_IP, TARGET_PORT))
#         print("已连接! 正在发送数据...")
        
#         s.sendall(packet_data)
        
#         # 6. 等待回复

#         print(">>> 发送成功！设备正在重启连接 WiFi...")
            
#     except Exception as e:
#         print(f"连接发生错误: {e}")
#     finally:
#         s.close()
#         print("-" * 40)

# if __name__ == "__main__":
#     send_config()



# import socket
# import struct

# TARGET_IP = '192.168.18.117' # 可以是 AP IP，也可以是 STA IP
# CURRENT_PORT = 8567       # 当前的端口

# # 协议常量
# HEADER_PORT = b'\x10\xC5\x07\xB2'
# SEPARATOR   = b'\x85\x92'

# def change_device_port(new_port):
#     print(f"准备将端口修改为: {new_port}")
    
#     # 构造包: Header + Port(2 bytes, Big Endian) + Separator
#     # '>H' 表示 Big-Endian Unsigned Short (2字节)
#     packet = HEADER_PORT + struct.pack('>H', new_port) + SEPARATOR
    
#     try:
#         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         s.settimeout(2)
#         s.connect((TARGET_IP, CURRENT_PORT))
#         s.sendall(packet)
#         resp = s.recv(1024)
#         print("设备回复:", resp.decode().strip())
#         s.close()
#         print("请等待设备重启，然后使用新端口连接。")
#     except Exception as e:
#         print("错误:", e)

# if __name__ == "__main__":
#     p = int(input("请输入新端口号 (1024-65535): "))
#     change_device_port(p)



import socket
import struct

# 配置
TARGET_IP = '192.168.18.117' # 必须是连接成功后的 IP
TARGET_PORT = 8567          # 或者是你修改后的新端口

# 协议常量 (必须与 C++ 一致)
HEADER_SERVO = b'\x4C\x01\x72\x54'
SEPARATOR    = b'\x85\x92'

def move_servo(angle):
    if not (0 <= angle <= 180):
        print("错误: 角度必须在 0-180 之间")
        return

    # 构造包: Header + Angle(1 byte) + Separator
    # 'B' 表示 unsigned char (1字节)
    packet = HEADER_SERVO + struct.pack('B', angle) + SEPARATOR
    
    print(f"发送指令: {packet.hex()}")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((TARGET_IP, TARGET_PORT))
        
        s.sendall(packet)
        
        resp = s.recv(1024)
        print("设备回复:", resp.decode().strip())
        s.close()
    except Exception as e:
        print("通信错误:", e)

if __name__ == "__main__":
    while True:
        val = input("请输入角度 (q退出): ")
        if val == 'q': break
        try:
            move_servo(int(val))
        except:
            print("输入无效")