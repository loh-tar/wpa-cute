all: man html pdf

FILES += wpa-cute

man:
	for i in $(FILES); do docbook2man $$i.sgml; done

html:
	for i in $(FILES); do docbook2html $$i.sgml && \
		mv index.html $$i.html; done

pdf:
	for i in $(FILES); do docbook2pdf $$i.sgml; done


clean:
	rm -f wpa-cute.8
	rm -f manpage.links manpage.refs
	rm -f $(FILES:%=%.pdf)
	rm -f $(FILES:%=%.html)
