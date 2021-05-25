# 添加当前路径下所有文件到SRC_LIST
aux_source_directory(. SRC_LIST)

# 生成可执行文件
add_executable(test1 ${SRC_LIST})

target_link_libraries(test1 colib pthread dl)