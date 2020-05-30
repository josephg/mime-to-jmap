.PHONY: Debug Release clean

Debug Release:
	mkdir -p $@
	cd $@; emcmake cmake -DCMAKE_BUILD_TYPE=$@ ..
	$(MAKE) -C $@ -j4 all
	cp $@/cyrus.js $@/cyrus.wasm dist/

clean:
	rm -rf Debug Release