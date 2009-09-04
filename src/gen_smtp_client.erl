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
		{auth, never},
		{hostname, guess_FQDN()}
	]).

send(Email, Options) ->
	NewOptions = lists:ukeymerge(1, lists:sort(Options),
		lists:sort(?DEFAULT_OPTIONS)),
	case check_options(NewOptions) of
		ok ->
			Ref = make_ref(),
			Pid = spawn_link(?MODULE, send_it, [Email, NewOptions, self(), Ref]),
			{ok, Pid, Ref};
		{error, Reason} ->
			{error, Reason}
	end.

send_it(Email, Options, Parent, Ref) ->
	RelayDomain = proplists:get_value(relay, Options),
	MXRecords = mxlookup(RelayDomain),
	%io:format("MX records for ~s are ~p~n", [RelayDomain, MXRecords]),
	Hosts = case MXRecords of
		[] ->
			[{0, RelayDomain}]; % maybe we're supposed to relay to a host directly
		_ ->
			MXRecords
	end,
	case connect(Hosts, Options) of
		failed ->
			Parent ! {failed, no_connection, Ref};
		{ok, Socket, Host, Banner} ->
			io:format("connected to ~s; banner was ~s~n", [Host, Banner]),
			{ok, Extensions} = try_EHLO(Socket, Options),
			io:format("Extensions are ~p~n", [Extensions]),
			{Socket2, Extensions2} = try_STARTTLS(Socket, Options,
				Extensions, Parent, Ref),
			io:format("Extensions are ~p~n", [Extensions2]),
			ok
	end,
	ok.

try_AUTH(Socket, Options, AuthTypes) ->
	ok.

try_EHLO(Socket, Options) ->
	case socket:send(Socket, "EHLO "++proplists:get_value(hostname, Options)++"\r\n") of
		ok ->
			Reply = read_multiline_reply(Socket, "250", []),
			[_ | Reply2] = re:split(Reply, "\r\n", [{return, list}, trim]),
			%io:format("~p~n", [Reply2]),
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
										[]
								end
						end
				end, Reply2),
			{ok, Extensions}
		end.

% check if we should try to do TLS
try_STARTTLS(Socket, Options, Extensions, Parent, Ref) ->
		case {proplists:get_value(tls, Options),
				proplists:get_value("STARTTLS", Extensions)} of
			{Atom, true} when Atom =:= always; Atom =:= if_available ->
			io:format("Starting TLS~n"),
			case {do_STARTTLS(Socket, Options), Atom} of
				{false, always} ->
					io:format("TLS failed~n"),
					Parent ! {failed, no_tls, Ref},
					erlang:exit(no_tls);
				{false, if_available} ->
					io:format("TLS failed~n"),
					{Socket, Extensions};
				{{S, E}, _} ->
					io:format("TLS started~n"),
					{S, E}
			end;
		{always, _} ->
			Parent ! {failed, no_tls, Ref},
			erlang:exit(no_tls);
		_ ->
			{Socket, Extensions}
	end.

%% attempt to upgrade socket to TLS
do_STARTTLS(Socket, Options) ->
	socket:send(Socket, "STARTTLS\r\n"),
	case socket:recv(Socket, 0) of
		{ok, "220 "++_} ->
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
		Resp ->
			io:format("STARTTLS response: ~p~n", [Resp]),
			false
	end.

%% try connecting to all returned MX records until
%% success
connect([], Options) ->
	failed;
connect([{_, Host} | Tail], Options) ->
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
	case socket:connect(Proto, Host, Port, SockOpts, 5000) of
		{ok, Socket} ->
			case socket:recv(Socket, 0) of
				{ok, "220-"++_ = Banner} ->
					Banner2 = read_multiline_reply(Socket, "220", [Banner]),
					{ok, Socket, Host, Banner2};
				{ok, "220 "++_ = Banner} ->
					{ok, Socket, Host, Banner};
				Other ->
					io:format("got ~p~n", [Other]),
					socket:close(Socket),
					connect(Tail, Options)
			end;
		{error, Reason} ->
			connect(Tail, Options)
	end.

%% read a multiline reply (eg. EHLO reply)
read_multiline_reply(Socket, Code, Acc) ->
	End = Code++" ",
	Cont = Code++"-",
	case socket:recv(Socket, 0) of
		{ok, Packet} ->
			case {string:substr(Packet, 1, 3), string:substr(Packet, 4, 1)} of
				{Code, " "} ->
					string:join(lists:reverse([Packet | Acc]), "");
				{Code, "-"} ->
					read_multiline_reply(Socket, Code, [Packet | Acc]);
				_ ->
					error
			end;
		Error ->
			Error
	end.

% TODO - more checking
check_options(Options) ->
	case proplists:get_value(relay, Options) of
		undefined ->
			{error, no_relay};
		_ ->
			case proplists:get_value(auth, Options) of
				Atom when Atom =:= always; Atom =:= if_available ->
					case proplists:is_defined(username, Options) and
						proplists:is_defined(password, Options) of
						false ->
							{error, no_credentials};
						true ->
							ok
					end;
				never ->
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

