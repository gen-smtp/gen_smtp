MINIMAL_COVERAGE = 75

compile:
	@./rebar3 compile

clean:
	@./rebar3 clean -a

test:
	ERL_AFLAGS="-s ssl" 
	./rebar3 eunit -c

proper:
	./rebar3 proper -c

cover:
	./rebar3 cover --verbose --min_coverage $(MINIMAL_COVERAGE)

dialyze:
	./rebar3 as dialyzer dialyzer

xref:
	./rebar3 as test xref

docs:
	./rebar3 edoc

.PHONY: compile clean test dialyze
