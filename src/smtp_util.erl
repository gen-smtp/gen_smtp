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

%% @doc Module with some general utility functions for SMTP.

-module(smtp_util).
-compile(export_all).

-include_lib("kernel/src/inet_dns.hrl").

%% @doc returns a sorted list of mx servers for `Domain', lowest distance first
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

%% @doc guess the current host's fully qualified domain name
guess_FQDN() ->
	{ok, Hostname} = inet:gethostname(),
	{ok, Hostent} = inet:gethostbyname(Hostname),
	{hostent, FQDN, _Aliases, inet, _, _Addresses} = Hostent,
	FQDN.

%% @doc Compute the CRAM digest of `Key' and `Data'
-spec(compute_cram_digest/2 :: (Key :: binary(), Data :: string()) -> string()).
compute_cram_digest(Key, Data) ->
	Bin = crypto:md5_mac(Key, Data),
	lists:flatten([io_lib:format("~2.16.0b", [X]) || <<X>> <= Bin]).

%% @doc Trim \r\n from `String'
-spec(trim_crlf/1 :: (String :: string()) -> string()).
trim_crlf(String) ->
	string:strip(string:strip(String, right, $\n), right, $\r).
