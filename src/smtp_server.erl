-module(smtp_server).
-behaviour(gen_smtp_server_session).

-export([init/3, handle_HELO/2, handle_EHLO/3, handle_MAIL/2, handle_MAIL_extension/2,
	handle_RCPT/2, handle_RCPT_extension/2, handle_DATA/4, handle_RSET/1, handle_VRFY/2, handle_other/3]).

init(Hostname, _SessionCount, _Address) ->
	Banner = io_lib:format("~s ESMTP smtp_server", [Hostname]),
	State = {},
	{ok, Banner, State}.

handle_HELO(_Hostname, State) ->
	%io:format("HELO from ~s~n", [Hostname]),
	{ok, State}.

handle_EHLO(_Hostname, Extensions, State) ->
	%io:format("EHLO from ~s~n", [Hostname]),
	MyExtensions = lists:append(Extensions, [{"WTF", true}]),
	{ok, MyExtensions, State}.

handle_MAIL(_From, State) ->
	%io:format("Mail from ~s~n", [From]),
	{ok, State}.

handle_MAIL_extension(_Extension, State) ->
	%io:format("Mail to extension ~s~n", [Extension]),
	{ok, State}.

handle_RCPT(_To, State) ->
	%io:format("Mail to ~s~n", [To]),
	{ok, State}.

handle_RCPT_extension(_Extension, State) ->
	%io:format("Mail from extension ~s~n", [Extension]),
	{ok, State}.

handle_DATA(From, To, Data, State) ->
	% some kind of unique id
	Reference = io_lib:format("~p", [make_ref()]),
	io:format("parsing message:~n"),
	try mimemail:decode(Data) of
		_ ->
			ok
	catch
		error:non_mime ->
			ok;
		What:Why ->
			Hash = lists:flatten([io_lib:format("~2.16.0b", [X]) || <<X>> <= erlang:md5(Data)]),
			io:format("Mime parser failed with reason: ~p:~p dumping to ~s~n", [What, Why, Hash]),
			{ok, File} = file:open(Hash, [write]),
			file:write(File, io_lib:format("~p", [Data])),
			file:close(File)
	end,
	io:format("message from ~s to ~p queued as ~s by session ~p~n", [From, To, Reference, self()]),
	{ok, Reference, State}.

handle_RSET(State) ->
	% reset any relevant internal state
	State.

handle_VRFY(_Address, State) ->
	{error, "252 VRFY disabled by policy, just send some mail", State}.

handle_other(_Verb, _Args, State) ->
	{"500 Error: command not recognized", State}.
