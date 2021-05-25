# 添加当前路径下所有文件到SRC_LIST
aux_source_directory(. SRC_LIST)

# 生成可执行文件
add_library(libco ${SRC_LIST})

target_link_libraries(libco pthread dl)