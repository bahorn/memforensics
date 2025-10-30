#!/bin/sh
KERNEL=`vol -f $1 banners.Banners 2>/dev/null| grep "Linux version" | cut  -f 2 | head -n 1 | tr -d '\n'`
echo $KERNEL
SYMBOL_PATH=`curl https://raw.githubusercontent.com/Abyss-W4tcher/volatility3-symbols/master/banners/banners_plain.json | jq -r ".[\"$KERNEL\"][0]"`
wget https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/$SYMBOL_PATH -O symbols/`basename $SYMBOL_PATH`
