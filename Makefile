CFLAGS=-Wall
CXXFLAGS=-Wall

build: ipmi

clean:
	rm -f *.o ipmi

ipmi: mongoose.o ipmi.o main.o ipmi_mongoose.o
	$(CXX) $(LDFLAGS) -o $@ $^

ipmi.o: ipmi.cpp ipmi.h
ipmi.cpp: mongoose.h insist.h ipmi.h

mongoose.c: mongoose.h
	curl -s https://raw.githubusercontent.com/cesanta/mongoose/master/mongoose.c > $@

mongoose.h:
	curl -s https://raw.githubusercontent.com/cesanta/mongoose/master/mongoose.h > $@

insist.h:
	curl -s https://raw.githubusercontent.com/jordansissel/experiments/master/c/better-assert/insist.h > $@
