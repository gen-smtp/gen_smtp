-module(smtp_server_example).
-behaviour(gen_smtp_server_session).

-export([init/3, handle_HELO/2, handle_EHLO/3, handle_MAIL/2, handle_MAIL_extension/2,
	handle_RCPT/2, handle_RCPT_extension/2, handle_DATA/4, handle_RSET/1, handle_VRFY/2, handle_other/3]).

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

handle_HELO("invalid", State) ->
	% contrived example
	{error, "554 invalid hostname", State};
handle_HELO(Hostname, State) ->
	io:format("HELO from ~s~n", [Hostname]),
	{ok, State}.

handle_EHLO("invalid", _Extensions, State) ->
	% contrived example
	{error, "554 invalid hostname", State};
handle_EHLO(Hostname, Extensions, State) ->
	io:format("EHLO from ~s~n", [Hostname]),
	MyExtensions = Extensions ++ [{"WTF", true}],
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

handle_DATA(From, To, Data, State) ->
	% some kind of unique id
	Reference = io_lib:format("~p", [make_ref()]),
	io:format("message from ~s to ~p queued as ~s, body follows:~n~s~nEOF~n", [From, To, Reference, Data]),
	{ok, Reference, State}.

handle_RSET(State) ->
	% reset any relevant internal state
	State.

handle_VRFY(_Address, State) ->
	{error, "252 VRFY disabled by policy, just send some mail", State}.

handle_other(_Verb, _Args, State) ->
	{"500 Error: command not recognized", State}.
