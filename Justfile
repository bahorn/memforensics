null:

dump path="/tmp/dump.lime":
    sudo insmod ./tools/LiME/src/lime-`uname -r`.ko format=lime path={{path}}
    sudo rmmod lime

get-symbols dump:
    ./tools/get_banner.sh {{dump}}

analyze dump:
    vol -s symbols -f {{dump}} linux.malware.hidden_modules
    vol -s symbols -f {{dump}} linux.tracing.ftrace
