compile:
	@./rebar3 compile

clean:
	@./rebar3 clean -a

test:
	ERL_AFLAGS="-s ssl" 
	./rebar3 eunit

dialyze:
	./rebar3 as dialyzer dialyzer

xref:
	./rebar3 as test xref

bench:
	./rebar3 as test bench

.PHONY: compile clean test dialyze bench
