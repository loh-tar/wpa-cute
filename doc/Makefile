all: man html

man:
	ronn --roff < wpa-cute.ronn > wpa-cute.8

html:
	ronn --html < wpa-cute.ronn > wpa-cute.html

clean:
	rm -f wpa-cute.8 wpa-cute.html
