FILES = $(shell ls ebin/*.beam | grep -v smtp_rfc822_parse)

compile:
	@./rebar3 compile

clean:
	@./rebar3 clean -a

test:
	ERL_AFLAGS="-s ssl" 
	./rebar3 eunit

dialyze:
	dialyzer $(FILES)

.PHONY: compile clean test dialyze
