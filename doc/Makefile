MyPrettyName := wpaCute
MyExecName := wpa-cute

# Fetch some data out of README, works nice but may have room for improvements
MyVersion != grep "Last version is" ../README |grep -e"[[:digit:]]*\.[[:digit:]]*\.[[:digit:]]*" -o
MyDate != grep "Last version is" ../README | cut -d' ' -f5,6
MyDate != date +%F -d "01 ${MyDate}"

RonnOptions := --manual ${MyPrettyName} --organization "${MyPrettyName} v${MyVersion}" --date "${MyDate}"

info:
	@echo "The usual call is 'man' to build the man-page"
	@echo "  $$ make man"
	@echo ""
	@echo "But also available is 'html' to build the man-page as .html file,"
	@echo "'all' to build both, and 'clean' to remove the hard work again"

all: man html

man:
	ronn ${RonnOptions} --roff ${MyExecName}.ronn

html:
	ronn ${RonnOptions} --html ${MyExecName}.ronn

clean:
	rm -f ${MyExecName}.8 ${MyExecName}.8.html

test:
	@echo $(RonnOptions)
	@echo ${MyVersion} ${MyDate}
