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
-export([
		mxlookup/1, guess_FQDN/0, compute_cram_digest/2, get_cram_string/1,
		trim_crlf/1, rfc5322_timestamp/0, zone/0, generate_message_id/0,
         parse_rfc822_addresses/1,
         combine_rfc822_addresses/1,
         generate_message_boundary/0]).

-include_lib("kernel/include/inet.hrl").

%% @doc returns a sorted list of mx servers for `Domain', lowest distance first
mxlookup(Domain) ->
	case whereis(inet_db) of
		P when is_pid(P) ->
			ok;
		_ ->
			inet_db:start()
	end,
	case lists:keyfind(nameserver, 1, inet_db:get_rc()) of
		false ->
			% we got no nameservers configured, suck in resolv.conf
			inet_config:do_load_resolv(os:type(), longnames);
		_ ->
			ok
	end,
	case inet_res:lookup(Domain, in, mx) of
		[] ->
			lists:map(fun(X) -> {10, inet_parse:ntoa(X)} end, inet_res:lookup(Domain, in, a));
		Result ->
			lists:sort(fun({Pref, _Name}, {Pref2, _Name2}) -> Pref =< Pref2 end, Result)
	end.

%% @doc guess the current host's fully qualified domain name, on error return "localhost"
-spec guess_FQDN() -> string().
guess_FQDN() ->
	{ok, Hostname} = inet:gethostname(),
    guess_FQDN_1(Hostname, inet:gethostbyname(Hostname)).

guess_FQDN_1(_Hostname, {ok, #hostent{ h_name = FQDN }}) ->
	FQDN;
guess_FQDN_1(Hostname, {error, nxdomain = Error}) ->
    error_logger:info_msg("~p could not get FQDN for ~p (error ~p), using \"localhost\" instead.",
                          [?MODULE, Error, Hostname]),
    "localhost".

%% @doc Compute the CRAM digest of `Key' and `Data'
-spec compute_cram_digest(Key :: binary(), Data :: binary()) -> binary().
compute_cram_digest(Key, Data) ->
	Bin = crypto:hmac(md5, Key, Data),
	list_to_binary([io_lib:format("~2.16.0b", [X]) || <<X>> <= Bin]).

%% @doc Generate a seed string for CRAM.
-spec get_cram_string(Hostname :: string()) -> string().
get_cram_string(Hostname) ->
	binary_to_list(base64:encode(lists:flatten(io_lib:format("<~B.~B@~s>", [rand:uniform(4294967295), rand:uniform(4294967295), Hostname])))).

%% @doc Trim \r\n from `String'
-spec trim_crlf(String :: string()) -> string().
trim_crlf(String) ->
	string:strip(string:strip(String, right, $\n), right, $\r).

-define(DAYS, ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]).
-define(MONTHS, ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]).
%% @doc Generate a RFC 5322 timestamp based on the current time
rfc5322_timestamp() ->
	{{Year, Month, Day}, {Hour, Minute, Second}} = calendar:local_time(),
	NDay = calendar:day_of_the_week(Year, Month, Day),
	DoW = lists:nth(NDay, ?DAYS),
	MoY = lists:nth(Month, ?MONTHS),
	io_lib:format("~s, ~b ~s ~b ~2..0b:~2..0b:~2..0b ~s", [DoW, Day, MoY, Year, Hour, Minute, Second, zone()]).

%% @doc Calculate the current timezone and format it like -0400. Borrowed from YAWS.
zone() ->
	Time = erlang:universaltime(),
	LocalTime = calendar:universal_time_to_local_time(Time),
	DiffSecs = calendar:datetime_to_gregorian_seconds(LocalTime) -
	calendar:datetime_to_gregorian_seconds(Time),
	zone((DiffSecs/3600)*100).

%% Ugly reformatting code to get times like +0000 and -1300

zone(Val) when Val < 0 ->
	io_lib:format("-~4..0w", [trunc(abs(Val))]);
zone(Val) when Val >= 0 ->
	io_lib:format("+~4..0w", [trunc(abs(Val))]).

%% @doc Generate a unique message ID
generate_message_id() ->
	FQDN = guess_FQDN(),
    Md5 = [io_lib:format("~2.16.0b", [X]) || <<X>> <= erlang:md5(term_to_binary([unique_id(), FQDN]))],
	io_lib:format("<~s@~s>", [Md5, FQDN]).

%% @doc Generate a unique MIME message boundary
generate_message_boundary() ->
	FQDN = guess_FQDN(),
    ["_=", [io_lib:format("~2.36.0b", [X]) || <<X>> <= erlang:md5(term_to_binary([unique_id(), FQDN]))], "=_"].

unique_id() ->
    {erlang:system_time(), erlang:unique_integer()}.

-define(is_whitespace(Ch), (Ch =< 32)).

combine_rfc822_addresses([]) ->
	<<>>;
combine_rfc822_addresses(Addresses) ->
	iolist_to_binary(combine_rfc822_addresses(Addresses, [])).

combine_rfc822_addresses([], [32, $, | Acc]) ->
	lists:reverse(Acc);
combine_rfc822_addresses([{undefined, Email}|Rest], Acc) ->
	combine_rfc822_addresses(Rest, [32, $,, Email|Acc]);
combine_rfc822_addresses([{"", Email}|Rest], Acc) ->
	combine_rfc822_addresses(Rest, [32, $,, Email|Acc]);
combine_rfc822_addresses([{<<>>, Email}|Rest], Acc) ->
	combine_rfc822_addresses(Rest, [32, $,, Email|Acc]);
combine_rfc822_addresses([{Name, Email}|Rest], Acc) ->
	Quoted = [ opt_quoted(Name)," <", Email, ">" ],
	combine_rfc822_addresses(Rest, [32, $,, Quoted|Acc]).

opt_quoted(B) when is_binary(B) ->
	opt_quoted(binary_to_list(B));
opt_quoted(S) when is_list(S) ->
    NoControls = lists:map(
        fun
            (C) when C < 32 -> 32;
            (C) -> C
        end,
        S),
    case lists:any(fun is_special/1, NoControls) of
        false -> NoControls;
        true ->
            lists:flatten([
                $",
                lists:map(
                    fun
                        ($\") -> [$\\, $"];
                        ($\\) -> [$\\, $\\];
                        (C) -> C
                    end,
                    NoControls),
                $"])
    end.

% See https://www.w3.org/Protocols/rfc822/3_Lexical.html#z2
is_special($() -> true;
is_special($)) -> true;
is_special($<) -> true;
is_special($>) -> true;
is_special($@) -> true;
is_special($,) -> true;
is_special($;) -> true;
is_special($:) -> true;
is_special($\\) -> true;
is_special($\") -> true;
is_special($.) -> true;
is_special($[) -> true;
is_special($]) -> true;
is_special($') -> true; % special for some smtp servers
is_special(_) -> false.


parse_rfc822_addresses(B) when is_binary(B) ->
	parse_rfc822_addresses(binary_to_list(B));

parse_rfc822_addresses(S) when is_list(S) ->
	Scanned = lists:reverse([{'$end', 0}|scan_rfc822(S, [])]),
	smtp_rfc822_parse:parse(Scanned).

scan_rfc822([], Acc) ->
	Acc;
scan_rfc822([Ch|R], Acc) when ?is_whitespace(Ch) ->
	scan_rfc822(R, Acc);
scan_rfc822([$"|R], Acc) ->
	{Token, Rest} = scan_rfc822_scan_endquote(R, [], false),
	scan_rfc822(Rest, [{string, 0, Token}|Acc]);
scan_rfc822([$,|Rest], Acc) ->
	scan_rfc822(Rest, [{',', 0}|Acc]);
scan_rfc822([$<|Rest], Acc) ->
	{Token, R} = scan_rfc822_scan_endpointybracket(Rest),
	scan_rfc822(R, [{'>', 0}, {string, 0, Token}, {'<', 0}|Acc]);
scan_rfc822(String, Acc) ->
	case re:run(String, "(.+?)([\s<>,].*)", [{capture, all_but_first, list}]) of
		{match, [Token, Rest]} ->
			scan_rfc822(Rest, [{string, 0, Token}|Acc]);
		nomatch ->
			[{string, 0, String}|Acc]
	end.

scan_rfc822_scan_endpointybracket(String) ->
	case re:run(String, "(.*?)>(.*)", [{capture, all_but_first, list}]) of
		{match, [Token, Rest]} ->
			{Token, Rest};
		nomatch ->
			{String, []}
	end.

scan_rfc822_scan_endquote([$\\|R], Acc, InEscape) ->
	%% in escape
	scan_rfc822_scan_endquote(R, Acc, not(InEscape));
scan_rfc822_scan_endquote([$"|R], Acc, true) ->
	scan_rfc822_scan_endquote(R, [$"|Acc], false);
scan_rfc822_scan_endquote([$"|Rest], Acc, false) ->
	%% Done!
	{lists:reverse(Acc), Rest};
scan_rfc822_scan_endquote([Ch|Rest], Acc, _) ->
	scan_rfc822_scan_endquote(Rest, [Ch|Acc], false).
