-module(gen_smtp_server_test).

-compile([export_all, nowarn_export_all]).

-include_lib("eunit/include/eunit.hrl").

invalid_lmtp_port_test_() ->
	{"gen_smtp_server should prevent starting LMTP on port 25 (RFC2023, secion 5)",
	 fun() ->
		Options = [{port, 25}, {sessionoptions, [{protocol, lmtp}]}],
		[?_assertMatch({error, invalid_lmtp_port},
						 gen_smtp_server:start(gen_smtp_server, Options)),
		?_assertError(invalid_lmtp_port,
						gen_smtp_server:child_spec("LMTP Server", gen_smtp_server, Options))]
	 end}.
