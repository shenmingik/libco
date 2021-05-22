import shutil
import os

current_path = os.getcwd()
print(current_path)

# 将头文件都拷贝到/usr/include/libco 头文件下
if os.path.exists("/usr/include/libco") == False:
    os.mkdir("/usr/include/libco")
    shutil.copytree(current_path+"/include","/usr/include/libco")

# 将lib库文件拷贝到/usr/lib下
if os.path.exists("/usr/lib/libco") == False:
    os.mkdir("/usr/lib/libco")
    shutil.copytree(current_path+"/lib","/usr/lib/libco/lib")
    shutil.copytree(current_path+"/solib","/usr/lib/libco/solib")