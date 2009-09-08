%%% Copyright 2009 Andrew Thompson <andrew@hijacked.us>. All rights reserved.
%%%
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions are met:
%%%
%%%   1. Redistributions of source code must retain the above copyright notice,
%%%      this list of conditions and the following disclaimer.
%%%   2. Redistributions in binary form must reproduce the above copyright
%%%      notice, this list of conditions and the following disclaimer in the
%%%      documentation and/or other materials provided with the distribution.
%%%
%%% THIS SOFTWARE IS PROVIDED BY THE FREEBSD PROJECT ``AS IS'' AND ANY EXPRESS OR
%%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
%%% MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
%%% EVENT SHALL THE FREEBSD PROJECT OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
%%% INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
%%% (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
%%% ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
%%% SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

%% @doc A simple SMTP client used for sending mail - assumes relaying via a
%% smarthost.

-module(gen_smtp_client).
-compile(export_all).

-include_lib("kernel/src/inet_dns.hrl").

-define(DEFAULT_OPTIONS, [
		{ssl, false}, % whether to connect on 465 in ssl mode
		{tls, if_available}, % always, never, if_available
		{auth, if_available},
		{hostname, guess_FQDN()},
		{retries, 2} % how many retries per smtp host on temporary failure
	]).

-define(AUTH_PREFERENCE, [
		"CRAM-MD5",
		"LOGIN",
		"PLAIN"
	]).

send(Email, Options) ->
	NewOptions = lists:ukeymerge(1, lists:sort(Options),
		lists:sort(?DEFAULT_OPTIONS)),
	case check_options(NewOptions) of
		ok ->
			Pid = spawn_link(?MODULE, send_it, [Email, NewOptions, self()]),
			{ok, Pid};
		{error, Reason} ->
			{error, Reason}
	end.

send_it(Email, Options, Parent) ->
	RelayDomain = proplists:get_value(relay, Options),
	MXRecords = mxlookup(RelayDomain),
	%io:format("MX records for ~s are ~p~n", [RelayDomain, MXRecords]),
	Hosts = case MXRecords of
		[] ->
			[{0, RelayDomain}]; % maybe we're supposed to relay to a host directly
		_ ->
			MXRecords
	end,
	Parent ! try_smtp_sessions(Hosts, Email, Options, []).

try_smtp_sessions([{Distance, Host} | Tail] = Hosts, Email, Options, RetryList) ->
	Retries = proplists:get_value(retries, Options),
	try do_smtp_session(Host, Email, Options) of
		Result ->
			Result
	catch
		throw:{permanant_failure, Message} ->
			% permanant failure means no retries, and don't even continue with other hosts
			{error, no_more_hosts, {permanant_failure, Host, Message}};
		throw:{FailureType, Message} ->
			case proplists:get_value(Host, RetryList) of
				{Host, RetryCount} when RetryCount >= Retries ->
					% out of chances
					NewHosts = lists:keydelete(Host, 2, Hosts),
					NewRetryList = lists:keydelete(Host, 1, RetryList);
				_ ->
					% otherwise...
					io:format("scheduling ~s for retry~n", [Host]),
					NewHosts = lists:append(lists:keydelete(Host, 2, Hosts), [{Distance, Host}]),
					NewRetryList = lists:append(lists:keydelete(Host, 1, RetryList), [{Host, 1}])
			end,
			case NewHosts of
				[] ->
					{error, retries_exceeded, {FailureType, Host, Message}};
				_ ->
					try_smtp_sessions(NewHosts, Email, Options, NewRetryList)
			end
	end.

do_smtp_session(Host, Email, Options) ->
	{ok, Socket, Host, Banner} = connect(Host, Options),
	io:format("connected to ~s; banner was ~s~n", [Host, Banner]),
	{ok, Extensions} = try_EHLO(Socket, Options),
	io:format("Extensions are ~p~n", [Extensions]),
	{Socket2, Extensions2} = try_STARTTLS(Socket, Options,
		Extensions),
	io:format("Extensions are ~p~n", [Extensions2]),
	Authed = try_AUTH(Socket2, Options, proplists:get_value("AUTH", Extensions2)),
	io:format("Authentication status is ~p~n", [Authed]),
	try_sending_it(Email, Socket2, Extensions2),
	io:format("Mail sending successful~n"),
	quit(Socket).

try_sending_it({From, To, Body}, Socket, Extensions) ->
	try_MAIL_FROM(From, Socket, Extensions),
	try_RCPT_TO(To, Socket, Extensions),
	try_DATA(Body, Socket, Extensions).

try_MAIL_FROM([$< | _] = From, Socket, Extensions) ->
	% TODO do we need to bother with SIZE?
	socket:send(Socket, "MAIL FROM: "++From++"\r\n"),
	case read_possible_multiline_reply(Socket) of
		{ok, "250"++_} ->
			true;
		{ok, "4"++_ = Msg} ->
			quit(Socket),
			throw({temporary_failure, Msg});
		{ok, Msg} ->
			io:format("Mail FROM rejected: ~p~n", [Msg]),
			quit(Socket),
			throw({permanant_failure, Msg})
	end;
try_MAIL_FROM(From, Socket, Extensions) ->
	% someone was bad and didn't put in the angle brackets
	try_MAIL_FROM("<"++From++">", Socket, Extensions).

try_RCPT_TO([], _Socket, _Extensions) ->
	true;
try_RCPT_TO([[$< | _] = To | Tail], Socket, Extensions) ->
	socket:send(Socket, "RCPT TO: "++To++"\r\n"),
	case read_possible_multiline_reply(Socket) of
		{ok, "250"++_} ->
			try_RCPT_TO(Tail, Socket, Extensions);
		{ok, "251"++_} ->
			try_RCPT_TO(Tail, Socket, Extensions);
		{ok, "4"++_ = Msg} ->
			throw({temporary_failure, Msg});
		{ok, Msg} ->
			throw({permanant_failure, Msg})
	end;
try_RCPT_TO([To | Tail], Socket, Extensions) ->
	% someone was bad and didn't put in the angle brackets
	try_RCPT_TO(["<"++To++">" | Tail], Socket, Extensions).

try_DATA(Body, Socket, Extensions) ->
	socket:send(Socket, "DATA\r\n"),
	case read_possible_multiline_reply(Socket) of
		{ok, "354"++_} ->
			socket:send(Socket, Body++"\r\n.\r\n"),
			case read_possible_multiline_reply(Socket) of
				{ok, "250"++_} ->
					true;
				{ok, "4"++_ = Msg} ->
					throw({temporary_failure, Msg});
				{ok, Msg} ->
					throw({permanant_failure, Msg})
			end;
		{ok, "4"++_ = Msg} ->
			throw({temporary_failure, Msg});
		{ok, Msg} ->
			throw({permanant_failure, Msg})
	end.

try_AUTH(Socket, Options, []) ->
	case proplists:get_value(auth, Options) of
		always ->
			erlang:error(no_auth);
		_ ->
			false
	end;
try_AUTH(Socket, Options, undefined) ->
	case proplists:get_value(auth, Options) of
		always ->
			erlang:error(no_auth);
		_ ->
			false
	end;
try_AUTH(Socket, Options, AuthTypes) ->
	case proplists:is_defined(username, Options) and
		proplists:is_defined(password, Options) and
		(proplists:get_value(auth, Options) =/= never) of
		false ->
			case proplists:get_value(auth, Options) of
				always ->
					erlang:error(no_auth);
				_ ->
					false
			end;
		true ->
			Username = proplists:get_value(username, Options),
			Password = proplists:get_value(password, Options),
			io:format("Auth types: ~p~n", [AuthTypes]),
			Types = re:split(AuthTypes, " ", [{return, list}, trim]),
			case do_AUTH(Socket, Username, Password, Types) of
				false ->
					case proplists:get_value(auth, Options) of
						always ->
							erlang:error(auth_failed);
						_ ->
							false
					end;
				true ->
					true
			end
	end.

do_AUTH(Socket, Username, Password, Types) ->
	FixedTypes = lists:map(fun(X) -> string:to_upper(X) end, Types),
	io:format("Fixed types: ~p~n", [FixedTypes]),
	AllowedTypes = lists:filter(fun(X) -> lists:member(X, FixedTypes) end,
		?AUTH_PREFERENCE),
	io:format("available authentication types, in order of preference: ~p~n",
		[AllowedTypes]),
	do_AUTH_each(Socket, Username, Password, AllowedTypes).

do_AUTH_each(Socket, Username, Password, []) ->
	false;
do_AUTH_each(Socket, Username, Password, ["CRAM-MD5" | Tail]) ->
	socket:send(Socket, "AUTH CRAM-MD5\r\n"),
	case read_possible_multiline_reply(Socket) of
		{ok, "334 "++Rest} ->
			Seed64 = string:strip(string:strip(Rest, right, $\n), right, $\r),
			Seed = base64:decode_to_string(Seed64),
			Digest = gen_smtp_server_session:compute_cram_digest(Password, Seed),
			String = binary_to_list(base64:encode(Username++" "++Digest)),
			socket:send(Socket, String++"\r\n"),
			case read_possible_multiline_reply(Socket) of
				{ok, "235"++_} ->
					io:format("authentication accepted~n"),
					true;
				{ok, Msg} ->
					io:format("authentication rejected: ~s~n", [Msg]),
					do_AUTH_each(Socket, Username, Password, Tail)
			end;
		{ok, Something} ->
			io:format("got ~s~n", [Something]),
			do_AUTH_each(Socket, Username, Password, Tail)
	end;
do_AUTH_each(Socket, Username, Password, ["LOGIN" | Tail]) ->
	socket:send(Socket, "AUTH LOGIN\r\n"),
	case read_possible_multiline_reply(Socket) of
		{ok, "334 VXNlcm5hbWU6\r\n"} ->
			io:format("username prompt~n"),
			U = binary_to_list(base64:encode(Username)),
			socket:send(Socket, U++"\r\n"),
			case read_possible_multiline_reply(Socket) of
				{ok, "334 UGFzc3dvcmQ6\r\n"} ->
					io:format("password prompt~n"),
					P = binary_to_list(base64:encode(Password)),
					socket:send(Socket, P++"\r\n"),
					case read_possible_multiline_reply(Socket) of
						{ok, "235 "++_} ->
							io:format("authentication accepted~n"),
							true;
						{ok, Msg} ->
							io:format("password rejected: ~s", [Msg]),
							do_AUTH_each(Socket, Username, Password, Tail)
					end;
				{ok, Msg2} ->
					io:format("username rejected: ~s", [Msg2]),
					do_AUTH_each(Socket, Username, Password, Tail)
			end;
		{ok, Something} ->
			io:format("got ~s~n", [Something]),
			do_AUTH_each(Socket, Username, Password, Tail)
	end;
do_AUTH_each(Socket, Username, Password, ["PLAIN" | Tail]) ->
	AuthString = binary_to_list(base64:encode("\0"++Username++"\0"++Password)),
	socket:send(Socket, "AUTH PLAIN "++AuthString++"\r\n"),
	case read_possible_multiline_reply(Socket) of
		{ok, "235"++_} ->
			io:format("authentication accepted~n"),
			true;
		Else ->
			% TODO do we need to bother trying the multi-step PLAIN?
			io:format("authentication rejected~n"),
			io:format("~p~n", [Else]),
			do_AUTH_each(Socket, Username, Password, Tail)
	end;
do_AUTH_each(Socket, Username, Password, [Type | Tail]) ->
	io:format("unsupported AUTH type ~s~n", [Type]),
	do_AUTH_each(Socket, Username, Password, Tail).

try_EHLO(Socket, Options) ->
	case socket:send(Socket, "EHLO "++proplists:get_value(hostname, Options)++"\r\n") of
		ok ->
			{ok, Reply} = read_possible_multiline_reply(Socket),
			[_ | Reply2] = re:split(Reply, "\r\n", [{return, list}, trim]),
			Extensions = lists:map(fun(Entry) ->
						Body = string:substr(Entry, 5),
						case re:split(Body, " ", [{return, list}, trim,
									{parts, 2}]) of
							[Verb, Parameters] ->
								{string:to_upper(Verb), Parameters};
							[Body] ->
								case string:str(Body, "=") of
									0 ->
										{string:to_upper(Body), true};
									_ ->
										io:format("discarding option ~p~n", [Body]),
										[]
								end
						end
				end, Reply2),
			{ok, Extensions}
		end.

% check if we should try to do TLS
try_STARTTLS(Socket, Options, Extensions) ->
		case {proplists:get_value(tls, Options),
				proplists:get_value("STARTTLS", Extensions)} of
			{Atom, true} when Atom =:= always; Atom =:= if_available ->
			io:format("Starting TLS~n"),
			case {do_STARTTLS(Socket, Options), Atom} of
				{false, always} ->
					io:format("TLS failed~n"),
					erlang:exit(no_tls);
				{false, if_available} ->
					io:format("TLS failed~n"),
					{Socket, Extensions};
				{{S, E}, _} ->
					io:format("TLS started~n"),
					{S, E}
			end;
		{always, _} ->
			erlang:exit(no_tls);
		_ ->
			{Socket, Extensions}
	end.

%% attempt to upgrade socket to TLS
do_STARTTLS(Socket, Options) ->
	socket:send(Socket, "STARTTLS\r\n"),
	case read_possible_multiline_reply(Socket) of
		{ok, "220"++_} ->
			crypto:start(),
			application:start(ssl),
			case socket:to_ssl_client(Socket, [], 5000) of
				{ok, NewSocket} ->
					%NewSocket;
					{ok, Extensions} = try_EHLO(NewSocket, Options),
					{NewSocket, Extensions};
				Else ->
					io:format("~p~n", [Else]),
					false
			end;
		{ok, "4"++_ = Msg} ->
			quit(Socket),
			throw({temporary_failure, Msg});
		{ok, Msg} ->
			quit(Socket),
			throw({permanant_failure, Msg})
	end.

%% try connecting to a host
connect(Host, Options) ->
	SockOpts = [list, {packet, line}, {keepalive, true}, {active, false}],
	Proto = case proplists:get_value(ssl, Options) of
		true ->
			crypto:start(),
			application:start(ssl),
			ssl;
		false ->
			tcp
	end,
	Port = case proplists:get_value(port, Options) of
		undefined when Proto =:= ssl ->
			465;
		undefined when Proto =:= tcp ->
			25;
		OPort when is_integer(OPort) ->
			OPort
	end,
	%io:format("doing socket connect ~p, ~p, ~p, 5000~n", [Proto, Host, Port, SockOpts]),
	case socket:connect(Proto, Host, Port, SockOpts, 5000) of
		{ok, Socket} ->
			case read_possible_multiline_reply(Socket) of
				{ok, "220"++_ = Banner} ->
					{ok, Socket, Host, Banner};
				{ok, "4"++_ = Msg} ->
					quit(Socket),
					throw({temporary_failure, Msg});
				{ok, Msg} ->
					quit(Socket),
					throw({permanant_failure, Msg})
			end;
		{error, Reason} ->
			throw({network_failure, {error, Reason}})
	end.

%% read a multiline reply (eg. EHLO reply)
read_possible_multiline_reply(Socket) ->
	case socket:recv(Socket, 0) of
		{ok, Packet} ->
			case string:substr(Packet, 4, 1) of
				"-" ->
					Code = string:substr(Packet, 1, 3),
					read_multiline_reply(Socket, Code, [Packet]);
				" " ->
					{ok, Packet}
			end;
		Error ->
			throw({network_failure, Error})
	end.

read_multiline_reply(Socket, Code, Acc) ->
	End = Code++" ",
	Cont = Code++"-",
	case socket:recv(Socket, 0) of
		{ok, Packet} ->
			case {string:substr(Packet, 1, 3), string:substr(Packet, 4, 1)} of
				{Code, " "} ->
					{ok, string:join(lists:reverse([Packet | Acc]), "")};
				{Code, "-"} ->
					read_multiline_reply(Socket, Code, [Packet | Acc]);
				Packet ->
					% TODO - catch this
					throw({unexpected_response, Packet, Acc})
			end;
		Error ->
			throw({network_failure, Error})
	end.

quit(Socket) ->
	socket:send(Socket, "QUIT\r\n"),
	socket:close(Socket),
	ok.

% TODO - more checking
check_options(Options) ->
	case proplists:get_value(relay, Options) of
		undefined ->
			{error, no_relay};
		_ ->
			case proplists:get_value(auth, Options) of
				Atom when Atom =:= always ->
					case proplists:is_defined(username, Options) and
						proplists:is_defined(password, Options) of
						false ->
							{error, no_credentials};
						true ->
							ok
					end;
				_ ->
					ok
			end
	end.

% returns a sorted list of mx servers, lowest distance first
mxlookup(Domain) ->
	case whereis(inet_db) of
		P when is_pid(P) ->
			ok;
		_ -> 
			inet_db:start(),
			inet_db:init()
	end,
	case lists:keyfind(nameserver, 1, inet_db:get_rc()) of
		false ->
			% we got no nameservers configured, suck in resolv.conf
			inet_config:do_load_resolv(os:type(), longnames);
		_ ->
			ok
	end,
	case inet_res:lookup(Domain, in, ?S_MX) of
		{error, Reply} ->
			Reply;
		Result ->
			lists:sort(fun({Pref, _Name}, {Pref2, _Name2}) -> Pref =< Pref2 end, Result)
	end.

guess_FQDN() ->
	{ok, Hostname} = inet:gethostname(),
	{ok, Hostent} = inet:gethostbyname(Hostname),
	{hostent, FQDN, _Aliases, inet, _, _Addresses} = Hostent,
	FQDN.

