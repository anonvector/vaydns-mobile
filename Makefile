.PHONY: build clean

build:
	gomobile bind -trimpath -target android/arm,android/arm64,android/amd64 -androidapi 21 \
		-ldflags '-s -w' \
		-o ../app/libs/vaydns.aar ./vaydns

clean:
	rm -f ../app/libs/vaydns.aar ../app/libs/vaydns-sources.jar
