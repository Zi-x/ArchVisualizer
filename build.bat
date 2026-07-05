@echo off
chcp 65001 >nul
echo 正在打包 AUTOSAR 架构分析工具...
pyinstaller -F -w --name="AUTOSAR架构分析工具" draw_rte_arch_gui.py
echo 打包完成! exe文件在 dist 目录下
pause