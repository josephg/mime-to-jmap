.PHONY: Debug Release debug release clean build-web all

all: release build-web

debug: Debug
release: Release

Debug Release:
	mkdir -p $@
	cd $@; emcmake cmake -DCMAKE_BUILD_TYPE=$@ ..
	$(MAKE) -C $@ -j4 all
	cp $@/cyrus.js $@/cyrus.wasm dist/

clean:
	rm -rf Debug Release web

# This is only built in release mode but that should be fine.
build-web:
	mkdir -p $@
	cd $@; emcmake cmake -DCMAKE_BUILD_TYPE=Release -DWASM_ENVIRONMENT:STRING='-s ENVIRONMENT=web' ..
	$(MAKE) -C $@ -j4 all
	cp $@/cyrus.js dist/cyrus.web.js
