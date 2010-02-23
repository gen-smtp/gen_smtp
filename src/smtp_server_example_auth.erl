-module(smtp_server_example_auth).
-behaviour(gen_smtp_server_session).


-export([init/3, handle_HELO/2, handle_EHLO/3, handle_MAIL/2, handle_MAIL_extension/2,
	handle_RCPT/2, handle_RCPT_extension/2, handle_DATA/4, handle_RSET/1, handle_VRFY/2, handle_AUTH/4, handle_other/3]).

init(Hostname, SessionCount, Address) ->
	io:format("peer: ~p~n", [Address]),
	case SessionCount > 20 of
		false ->
			Banner = io_lib:format("~s ESMTP smtp_server_example", [Hostname]),
			State = {},
			{ok, Banner, State};
		true ->
			io:format("Connection limit exceeded~n"),
			{stop, normal, io_lib:format("421 ~s is too busy to accept mail right now", [Hostname])}
	end.

handle_HELO(Hostname, State) ->
	io:format("HELO from ~s~n", [Hostname]),
	{ok, State}.

handle_EHLO(Hostname, Extensions, State) ->
	io:format("EHLO from ~s~n", [Hostname]),
	MyExtensions = Extensions ++ [{"AUTH", "PLAIN LOGIN CRAM-MD5"}, {"STARTTLS", true}],
	{ok, MyExtensions, State}.

handle_MAIL(From, State) ->
	io:format("Mail from ~s~n", [From]),
	{ok, State}.

handle_MAIL_extension(Extension, State) ->
	io:format("Mail to extension ~s~n", [Extension]),
	{ok, State}.

handle_RCPT(To, State) ->
	io:format("Mail to ~s~n", [To]),
	{ok, State}.

handle_RCPT_extension(Extension, State) ->
	io:format("Mail from extension ~s~n", [Extension]),
	{ok, State}.

handle_DATA(_From, _To, _Data, State) ->
	% some kind of unique id
	Reference = io_lib:format("~p", [make_ref()]),
	{ok, Reference, State}.

handle_RSET(State) ->
	% reset any relevant internal state
	State.

handle_VRFY(_Address, State) ->
	{error, "252 VRFY disabled by policy, just send some mail", State}.

handle_AUTH(Type, "username", "PaSSw0rd", State) when Type =:= login; Type =:= plain ->
	{ok, State};
handle_AUTH('cram-md5', "username", {Digest, Seed}, State) ->
	case smtp_util:compute_cram_digest(<<"PaSSw0rd">>, Seed) of
		Digest ->
			{ok, State};
		_ ->
			error
	end;
handle_AUTH(_Type, _Username, _Password, _State) ->
	error.

handle_other(Verb, _Args, State) ->
	{lists:flatten(io_lib:format("500 Error: command not recognized : '~s'", [Verb])), State}.
