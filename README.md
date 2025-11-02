# memforensics

test setup for dumping memory and using volatility

## setup

```
virtualenv -p python3 .venv
source .venv/bin/activate
pip install -r requirements.txt
```

then activate the venv in every shell you want to run this in.

## volitilty plugins

### `find_hooked.py`

idea here was to iterate though kallsyms and look at which functions don't have
nops at the start (and are supported by ftrace).
this lets you find direct patches.

written by claude so steal it if you want
