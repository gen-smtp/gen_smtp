compile:
	@./rebar3 compile

clean:
	@./rebar3 clean -a

test:
	ERL_AFLAGS="-s ssl" 
	./rebar3 eunit

dialyze:
	./rebar3 dialyzer

xref:
	./rebar3 xref

.PHONY: compile clean test dialyze
