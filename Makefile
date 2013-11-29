compile:
	@./rebar compile

clean:
	@./rebar clean

test:
	./rebar -C rebar.test.config get-deps
	./rebar -C rebar.test.config compile
	ERL_AFLAGS="-s ssl" 
	./rebar -C rebar.test.config skip_deps=true eunit

.PHONY: compile clean test
