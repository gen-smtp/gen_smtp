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

%% @doc A simple SMTP client used for sending mail

-module(gen_smtp_client).
-compile(export_all).

-include_lib("kernel/src/inet_dns.hrl").

send(Email, Options) ->
	% TODO - check options
	Ref = make_ref(),
	Pid = spawn(?MODULE, send_it, [Email, Options]),
	{ok, Pid, Ref}.

send_it(Email, Options) ->
	ok.

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
