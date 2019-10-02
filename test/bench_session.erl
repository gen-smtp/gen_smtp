%% @doc Benchmark for full SMTP session
-module(bench_session).

-export([session/1,
		 bench_session/2]).

%% @doc benchmark to test SMTP session performance
%% Doesn't include TCP setup time. Only single SMTP mail delivery session.
session(init) ->
	Port = 9876,
	gen_smtp_application:ensure_all_started(gen_smtp),
	{ok, _ServerPid} = gen_smtp_server:start(
				  dummy_smtp_handler,
				  [{domain, "localhost"},
				   {port, Port}]),
	{ok, Cli} = gen_smtp_client:open([{relay, "localhost"}, {port, Port}]),
	Cli;
session({stop, Cli}) ->
	ok = gen_smtp_client:close(Cli),
	gen_smtp_server:stop(gen_smtp_server),
	ok;
session({input, _St}) ->
	{<<"from@example.com">>,
	 ["<to@example.com>"],
	 binary:copy(<<0>>, 512 * 1024)}.

bench_session(Mail, Cli) ->
	{ok, _} = gen_smtp_client:deliver(Cli, Mail).
