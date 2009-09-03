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

send(Email, Options) ->
	case check_options(Options) of
		ok ->
			Ref = make_ref(),
			Pid = spawn_link(?MODULE, send_it, [Email, Options, self(), Ref]),
			{ok, Pid, Ref};
		{error, Reason} ->
			{error, Reason}
	end.

send_it(Email, Options, Parent, Ref) ->
	RelayDomain = proplists:get_value(relay, Options),
	MXRecords = mxlookup(RelayDomain),
	case connect(MXRecords, Options) of
		failed ->
			Parent ! {failed, Ref};
		{ok, Socket, Host, Banner} ->
			io:format("connected to ~s; banner was ~s~n", [Host, Banner]),
			ok
	end,
	ok.

%% try connecting to all returned MX records until
%% success
connect([], Options) ->
	failed;
connect([{_, Host} | Tail], Options) ->
	SockOpts = [list, {packet, line}, {keepalive, true}, {active, false}],
	case gen_tcp:connect(Host, 25, SockOpts, 5000) of
		{ok, Socket} ->
			case gen_tcp:recv(Socket, 0) of
				{ok, "220-"++_ = Banner} ->
					Banner2 = read_multiline_reply(Socket, "220", [Banner]),
					{ok, Socket, Host, Banner2};
				{ok, "220 "++_ = Banner} ->
					{ok, Socket, Host, Banner};
				Other ->
					io:format("got ~p~n", [Other]),
					gen_tcp:close(Socket),
					connect(Tail, Options)
			end;
		{error, Reason} ->
			connect(Tail, Options)
	end.

%% read a multiline reply (eg. EHLO reply)
read_multiline_reply(Socket, Code, Acc) ->
	End = Code++" ",
	Cont = Code++"-",
	case gen_tcp:recv(Socket, 0) of
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
			ok
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
