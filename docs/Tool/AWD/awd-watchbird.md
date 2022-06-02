# awd-watchbird

A powerful PHP WAF for AWD

![img](https://github.sre.pub/leohearts/awd-watchbird/raw/master/resources/logo.svg)

## How to use

- 下载最新 [release](https://github.com/leohearts/awd-watchbird/releases)
- 将waf.so,watchbird.php文件存放在/var/www/html或其他目录中
- 将watchbird.php放在www-data可读的目录, 确保当前用户对目标目录可写, 然后执行`php watchbird.php --install [Web目录]`, 安装器将输出安装了watchbird的文件路径
- 访问任意启用了waf的文件, 参数`?watchbird=ui`打开watchbird控制台, 创建一个初始密码
- 如需卸载, 请在相同的位置输入`php watchbird.php --uninstall [Web目录]`, 如果您多次运行了安装, 请多次运行卸载直到卸载器无输出

## Deployment

- `git clone https://github.com/leohearts/awd-watchbird.git`
- 使用 `pyhton3 pack.py` 将源码打包为单文件
- 编译waf.c生成.so文件,参考命令:gcc waf.c -shared -o waf.so

## Screenshot

![1](https://camo.githubusercontent.com/b2ef32ae55be900d66d47bfcae0f61e4998d63287888063d86ef771b8112b8ae/68747470733a2f2f692e6c6f6c692e6e65742f323032312f30332f30382f44454c4264494d78794367746c75662e706e67)

![2](https://camo.githubusercontent.com/1047219c1d9a7ea2a2f0609fbbc0de41217fce0459c1950c0f067d8056ba3d93/68747470733a2f2f692e6c6f6c692e6e65742f323032312f30332f30382f366a79725759557849584d7371706c2e706e67)

![3](https://camo.githubusercontent.com/76435c2c39cf72486a43e0d867fc1663001b4de73ec179bc410272f675f8bfef/68747470733a2f2f692e6c6f6c692e6e65742f323032312f30332f30382f526e593756415a744a6d49654b6f582e706e67)

## Link

Github repo: https://github.sre.pub/leohearts/awd-watchbird