CFLAGS=-Wall -g -I $(vendor)
CXXFLAGS=-Wall -std=c++11 -g -I $(vendor)
LDFLAGS+=-lssl -lcrypto

QUIET := @

out := .build
vendor := .vendor

.PHONY: build
build: $(out)/ipmi

.PHONY: clean
clean:
	$(QUIET)rm -rf $(out)

$(out) $(vendor):
	$(QUIET)mkdir -p $@


$(out)/ipmi: $(out)/client.o $(out)/mongoose.o $(out)/ipmi.o | $(out)
$(out)/ipmi: main.cpp
	@printf "%-20s %s\n" "$@" "(link) $^"
	$(QUIET)$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: run-test
run-test: $(out)/ipmi
	$(QUIET)$(out)/ipmi

$(out)/test: $(out) $(out)/mongoose.o $(out)/test.o | $(out)
	$(CXX) -o $@ $^ $(LDFLAGS)

client.cpp: $(vendor)/mongoose.h

$(out)/mongoose.o: $(vendor)/mongoose.c  | $(out)
	@printf "%-20s %s\n" "$@" "(c) $<"
	$(QUIET)$(CC) -o $@ -c $<  $(CFLAGS)

$(out)/%.o: %.c | $(out)
	@printf "%-20s %s\n" "$@" "(c) $<"
	$(QUIET)$(CC) -o $@ -c $<  $(CFLAGS)

$(out)/%.o: %.cpp | $(out)
	@printf "%-20s %s\n" "$@" "(c++) $<"
	$(QUIET)$(CXX) -o $@ -c $<  $(CXXFLAGS)

$(out)/ipmi.o: ipmi.cpp ipmi.h

ipmi.cpp: $(vendor)/mongoose.h $(vendor)/insist.h ipmi.h

$(vendor)/mongoose.c: $(vendor)/mongoose.h | $(vendor)
	@printf "%-20s %s\n" "$@" "Downloading"
	$(QUIET)curl -s https://raw.githubusercontent.com/cesanta/mongoose/master/mongoose.c > $@

$(vendor)/mongoose.h: | $(vendor)
	@printf "%-20s %s\n" "$@" "Downloading"
	$(QUIET)curl -s https://raw.githubusercontent.com/cesanta/mongoose/master/mongoose.h > $@

$(vendor)/insist.h: | $(vendor)
	@printf "%-20s %s\n" "$@" "Downloading"
	$(QUIET)curl -s https://raw.githubusercontent.com/jordansissel/experiments/master/c/better-assert/insist.h > $@