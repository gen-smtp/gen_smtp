-module(gen_smtp_server_test).

-compile([export_all, nowarn_export_all]).

-include_lib("eunit/include/eunit.hrl").

invalid_lmtp_port_test_() ->
    {"gen_smtp_server should prevent starting LMTP on port 25 (RFC2023, section 5)", fun() ->
        Options = [{port, 25}, {sessionoptions, [{protocol, lmtp}]}],
        [
            ?_assertMatch(
                {error, invalid_lmtp_port},
                gen_smtp_server:start(gen_smtp_server, Options)
            ),
            ?_assertError(
                invalid_lmtp_port,
                gen_smtp_server:child_spec("LMTP Server", gen_smtp_server, Options)
            )
        ]
    end}.

%% Client rejects server's certificate during STARTTLS: `ssl' closes the socket, but the callback
%% should still be notified with `ssl_handshake_error' (and not `send_error' of the "454" reply)
starttls_handshake_error_test() ->
    {ok, _} = application:ensure_all_started(gen_smtp),
    {ok, _} = gen_smtp_server:start(
        ?MODULE,
        ?MODULE,
        [
            {port, 0},
            {domain, "localhost"},
            {sessionoptions, [
                {tls_options, [
                    {keyfile, "test/fixtures/mx1.example.com-server.key"},
                    {certfile, "test/fixtures/mx1.example.com-server.crt"}
                ]},
                {callbackoptions, [self()]}
            ]}
        ]
    ),
    try
        Port = ranch:get_port(?MODULE),
        {ok, Sock} = gen_tcp:connect("localhost", Port, [list, {packet, line}, {active, false}]),
        ?assertMatch({ok, "220 " ++ _}, gen_tcp:recv(Sock, 0, 5000)),
        ok = gen_tcp:send(Sock, "EHLO somehost.com\r\n"),
        ok = recv_ehlo_reply(Sock),
        ok = gen_tcp:send(Sock, "STARTTLS\r\n"),
        ?assertMatch({ok, "220 " ++ _}, gen_tcp:recv(Sock, 0, 5000)),
        %% Client doesn't trust any CA, so it aborts the handshake with a "bad certificate" alert
        ?assertMatch(
            {error, _},
            ssl:connect(
                Sock,
                [{verify, verify_peer}, {cacerts, []}, {server_name_indication, disable}],
                5000
            )
        ),
        receive
            {handle_error, Kind, Details} ->
                ?assertMatch({ssl_handshake_error, {tls_alert, _}}, {Kind, Details})
        after 5000 ->
            error(no_handle_error_call)
        end
    after
        gen_smtp_server:stop(?MODULE)
    end.

recv_ehlo_reply(Sock) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, "250-" ++ _} -> recv_ehlo_reply(Sock);
        {ok, "250 " ++ _} -> ok
    end.

%% gen_smtp_server_session callbacks for `starttls_handshake_error_test'

init(_Hostname, _SessionCount, _Peer, [TestPid]) ->
    {ok, "localhost ESMTP test", TestPid}.

handle_EHLO(_Hostname, Extensions, TestPid) ->
    {ok, [{"STARTTLS", true} | Extensions], TestPid}.

handle_STARTTLS(TestPid) ->
    TestPid.

handle_error(Kind, Details, TestPid) ->
    TestPid ! {handle_error, Kind, Details},
    {ok, TestPid}.

code_change(_OldVsn, TestPid, _Extra) ->
    {ok, TestPid}.

terminate(Reason, TestPid) ->
    {ok, Reason, TestPid}.
