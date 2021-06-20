all: build

build:
	documatio build

dev:
	documatio dev

clean:
	documatio clean

depend:
	curl https://raw.githubusercontent.com/pojntfx/documatio/main/documatio | bash -s -- upgrade
