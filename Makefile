
sources = \
	jmap_mail.c \
	charset.c \
	util.c \
	chartable.c \
	hash.c \
	strhash.c \
	xmalloc.c \
	mpool.c \
	strarray.c \
	message.c \
	times.c \
	parseaddr.c \
	htmlchar.c \
	arrayu64.c \
	mkgmtime.c \
	gmtoff_tm.c \
	main.c

all: $(sources)
	#clang -I. -I/usr/local/Cellar/icu4c/64.2/include/ -c $(sources)
	clang -I. -I/usr/local/opt/icu4c/include -L/usr/local/opt/icu4c/lib $(sources) -o mimer -licuuc
