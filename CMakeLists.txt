cmake_minimum_required(VERSION 3.0)
project(test)

# 设置编译选项
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -g)

# 设置头文件搜索路径
include_directories(${PROJECT_SOURCE_DIR}/include)

# 设置可执行文件输出路径
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

# 加载子目录
add_subdirectory(example)
#add_subdirectory(auxiliary_process)
add_subdirectory(src)