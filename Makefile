BENCH_BASELINE?=baseline

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

bench-init:
	./rebar3 as test bench --save-baseline $(BENCH_BASELINE)

bench-compare:
	./rebar3 as test bench --baseline $(BENCH_BASELINE)

.PHONY: compile clean test dialyze bench bench-init bench-compare
