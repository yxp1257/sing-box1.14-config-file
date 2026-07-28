sing-box1.14的配置文件使用，下载两个文件，用python3直接运行：python3 merge_subscription.py --url "你的订阅链接" --template sing_box_template.json 即可生成适合sing-box1.14可用的配置文件config.json

只支持内容是 base64 编码的 vless:// / vmess:// / trojan:// / hysteria2:// 链接列表

目前这个脚本只支持订阅链接（HTTP/HTTPS URL，指向一段 base64 编码的节点列表），其他形式确实都不支持：本地节点文件，Clash YAML 格式的订阅，单条节点链接，ss://（Shadowsocks）节点，多个订阅合并（比如你同时有两个机场，想把两边节点都塞进同一份配置）。

下载两个文件后，需要在当前文件夹下打开cmd，然后再运行python3 merge_subscription.py --url "你的订阅链接" --template sing_box_template.json

只加单条节点链接：
python3 merge_subscription.py --link "vless://xxxx@server:443?...#我的节点"

也可以一次传多个（多次写 --url 或 --link）
python3 merge_subscription.py \
  --url "https://sminoy-production.up.railway.app/sub" \
  --link "trojan://password@server2:443?...#备用节点" \
  --link "vless://uuid@server3:443?...#另一个节点"
