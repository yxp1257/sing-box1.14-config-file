sing-box1.14的配置文件自动生成，下载两个文件，用python3直接运行：python3 merge_subscription.py --url "你的订阅链接" --template sing_box_template.json 即可生成适合sing-box1.14可用的配置文件config.json

支持内容是 base64 编码的 vless:// / vmess:// / trojan:// / hysteria2:// 链接列表

目前这个脚本支持订阅链接（HTTP/HTTPS URL，指向一段 base64 编码的节点列表），支持：单条节点链接，ss://（Shadowsocks）节点，多个订阅合并。

下载两个文件后，需要在当前文件夹下打开cmd，然后再运行python3 merge_subscription.py --url "你的订阅链接" --template sing_box_template.json

单条节点链接：
python3 merge_subscription.py --link "vless://xxxx@server:443?...#我的节点"

也可以一次传多个（多次写 --url 或 --link）
python3 merge_subscription.py ^
  --url "https://smipro.up.app/sub" ^
  --link "trojan://password@server2:443?...#备用节点" ^
  --link "vless://uuid@server3:443?...#另一个节点"
