# masnmapscan
(弃用，推荐另一个版本：https://github.com/7dog7/masscan_to_nmap )
整合了masscan和nmap两款扫描器，masscan扫描端口，nmap扫描端口对应服务，二者结合起来实现了又快又好地扫描。并且加入了针对目标资产有防火墙的应对措施

首先pip install -r requirements.txt安装所需插件，然后将ip地址每行一个保存到txt文本里，与本程序放在同一目录下，masscan安装完成后也与本程序放在同一目录下，运行程序即可。最终会在当前目录下生成一个scan_url_port.txt的扫描结果
