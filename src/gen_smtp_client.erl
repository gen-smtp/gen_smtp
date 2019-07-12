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

-define(DEFAULT_OPTIONS, [
		{ssl, false}, % whether to connect on 465 in ssl mode
		{tls, if_available}, % always, never, if_available
		{tls_options, [{versions, ['tlsv1', 'tlsv1.1', 'tlsv1.2']}]}, % used in ssl:connect, http://erlang.org/doc/man/ssl.html
		{auth, if_available},
		{hostname, smtp_util:guess_FQDN()},
		{retries, 1} % how many retries per smtp host on temporary failure
	]).

-define(AUTH_PREFERENCE, [
		"CRAM-MD5",
		"LOGIN",
		"PLAIN",
		"XOAUTH2"
	]).

-define(TIMEOUT, 1200000).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-compile(export_all).
-else.
-export([send/2, send/3, send_blocking/2, open/1, deliver/2, close/1]).
-endif.


-export_type([smtp_client_socket/0,
              email/0,
              email_address/0,
              options/0,
              callback/0,
              smtp_session_error/0,
              host_failure/0,
              failure/0,
              validate_options_error/0]).

-type email_address() :: string() | binary().
-type email() :: {From :: email_address(),
                  To :: [email_address(), ...],
                  Body :: string() | binary() | fun( () -> string() | binary() )}.

-type options() :: [{ssl, boolean()} |
                    {tls, always | never | if_available} |
                    {tls_options, list()} | % ssl:option() / ssl:tls_client_option()
                    {sockopts, [gen_tcp:connect_option()]} |
                    {port, inet:port_number()} |
                    {timeout, timeout()} |
                    {relay, inet:ip_address() | inet:hostname()} |
                    {no_mx_lookups, boolean()} |
                    {auth, always | never | if_available} |
                    {hostname, string()} |
                    {retries, non_neg_integer()} |
                    {username, string()} |
                    {password, string()} |
                    {trace_fun, fun( (Fmt :: string(), Args :: [any()]) -> any() )}].

-type extensions() :: [{binary(), binary()}].

-opaque smtp_client_socket() :: {smtp_socket:socket(), extensions(), options()}.

-type callback() :: fun( ({exit, any()} |
                          smtp_session_error() |
                          {ok, binary()}) -> any() ).

%% Smth that is thrown from inner SMTP functions
-type permanent_failure_reason() :: binary() |  % server's 5xx response
                                    auth_failed |
                                    ssl_not_started.
-type temporary_failure_reason() :: binary() |  %server's 4xx response
                                    tls_failed.
-type validate_options_error() :: no_relay |
                                  invalid_port |
                                  no_credentials.
-type failure() :: {temporary_failure, temporary_failure_reason()} |
                   {permanent_failure, permanent_failure_reason()} |
                   {missing_requirement, auth | tls} |
                   {unexpected_response, [binary()]} |
                   {network_failure, {error, timeout | inet:posix()}}.
-type smtp_host() :: inet:hostname().
-type host_failure() ::
        {temporary_failure, smtp_host(), temporary_failure_reason()} |
        {permanent_failure, smtp_host(), permanent_failure_reason()} |
        {missing_requirement, smtp_host(), auth | tls} |
        {unexpected_response, smtp_host(), [binary()]} |
        {network_failure, smtp_host(), {error, timeout | inet:posix()}}.
-type smtp_session_error() ::
        {error, no_more_hosts, {permanent_failure, smtp_host(), permanent_failure_reason()}} |
        {error, retries_exceeded, host_failure()}.


-spec send(Email :: email(), Options :: options()) -> {'ok', pid()} | {'error', validate_options_error()}.
%% @doc Send an email in a non-blocking fashion via a spawned_linked process.
%% The process will exit abnormally on a send failure.
send(Email, Options) ->
	send(Email, Options, undefined).

%% @doc Send an email nonblocking and invoke a callback with the result of the send.
%% The callback will receive either `{ok, Receipt}' where Receipt is the SMTP server's receipt
%% identifier,  `{error, Type, Message}' or `{exit, ExitReason}', as the single argument.
-spec send(Email :: email(), Options :: options(), Callback :: callback() | 'undefined') -> {'ok', pid()} | {'error', validate_options_error()}.
send(Email, Options, Callback) ->
	NewOptions = lists:ukeymerge(1, lists:sort(Options),
		lists:sort(?DEFAULT_OPTIONS)),
	case check_options(NewOptions) of
		ok when is_function(Callback) ->
			spawn(fun() ->
						process_flag(trap_exit, true),
						Pid = spawn_link(fun() ->
									send_it_nonblock(Email, NewOptions, Callback)
							end
						),
						receive
							{'EXIT', Pid, Reason} ->
								case Reason of
									X when X == normal; X == shutdown ->
										ok;
									Error ->
										Callback({exit, Error})
								end
						end
				end);
		ok ->
			Pid = spawn_link(fun () ->
						send_it_nonblock(Email, NewOptions, Callback)
				end
			),
			{ok, Pid};
		{error, Reason} ->
			{error, Reason}
	end.

-spec send_blocking(Email :: email(), Options :: options()) ->
                           binary() |
                           smtp_session_error() |
                           {error, validate_options_error()}.
%% @doc Send an email and block waiting for the reply. Returns either a binary that contains
%% the SMTP server's receipt or `{error, Type, Message}' or `{error, Reason}'.
send_blocking(Email, Options) ->
	NewOptions = lists:ukeymerge(1, lists:sort(Options),
		lists:sort(?DEFAULT_OPTIONS)),
	case check_options(NewOptions) of
		ok ->
			send_it(Email, NewOptions);
		{error, Reason} ->
			{error, Reason}
	end.

-spec send_it_nonblock(Email :: email(), Options :: options(), Callback :: callback() | 'undefined') ->
                              {'ok', binary()} |
                              smtp_session_error().
send_it_nonblock(Email, Options, Callback) ->
	case send_it(Email, Options) of
		{error, Type, Message} when is_function(Callback) ->
			Callback({error, Type, Message}),
			{error, Type, Message};
		{error, Type, Message} ->
			erlang:exit({error, Type, Message});
		Receipt when is_function(Callback) ->
			Callback({ok, Receipt}),
			{ok, Receipt};
		Receipt ->
			{ok, Receipt}
	end.

-spec open(Options :: options()) ->
                  {ok, SocketDescriptor :: smtp_client_socket()} |
                  smtp_session_error() |
                  {error, bad_option, validate_options_error()}.
%% @doc Open a SMTP client socket with the provided options
%% Once the socket has been opened, you can use it with deliver/2.
open(Options) ->
	NewOptions = lists:ukeymerge(1, lists:sort(Options),
															 lists:sort(?DEFAULT_OPTIONS)),
	case check_options(NewOptions) of
		ok ->
			RelayDomain = proplists:get_value(relay, NewOptions),
			MXRecords = case proplists:get_value(no_mx_lookups, NewOptions) of
										true ->
											[];
										_ ->
											smtp_util:mxlookup(RelayDomain)
									end,
			%io:format("MX records for ~s are ~p~n", [RelayDomain, MXRecords]),
			Hosts = case MXRecords of
								[] ->
									[{0, RelayDomain}]; % maybe we're supposed to relay to a host directly
								_ ->
									MXRecords
							end,
			case try_smtp_sessions(Hosts, NewOptions, []) of
				{error, _, _} = Error -> Error;
				SocketDescriptor -> {ok, SocketDescriptor}
			end;
		{error, Reason} ->
			{error, bad_option, Reason}
	end.

-spec deliver(Socket :: smtp_client_socket(), Email :: email()) -> {'ok', Receipt :: binary()} | {error, failure()}.
%% @doc Deliver an email on an open smtp client socket.
%% For use with a socket opened with open/1. The socket can be reused as long as the previous call to deliver/2 returned `{ok, Receipt}'.
deliver({Socket, Extensions, Options}, Email) ->
	try try_sending_it(Email, Socket, Extensions, Options) of
		Receipt -> {ok, Receipt}
	catch
		throw:FailMsg ->
			{error, FailMsg}
	end.

-spec close(Socker:: smtp_client_socket()) -> ok.
%% @doc Close an open smtp client socket opened with open/1.
close({Socket, _Extensions, _Options}) ->
	quit(Socket).

-spec send_it(Email :: email(), Options :: options()) -> binary() |
                                                         smtp_session_error().
send_it(Email, Options) ->
	RelayDomain = to_string(proplists:get_value(relay, Options)),
	MXRecords = case proplists:get_value(no_mx_lookups, Options) of
		true ->
			[];
		_ ->
			smtp_util:mxlookup(RelayDomain)
	end,
	trace(Options, "MX records for ~s are ~p~n", [RelayDomain, MXRecords]),
	Hosts = case MXRecords of
		[] ->
			[{0, RelayDomain}]; % maybe we're supposed to relay to a host directly
		_ ->
			MXRecords
	end,
	case try_smtp_sessions(Hosts, Options, []) of
		{error, _, _} = Error ->
			Error;
		{Socket, Extensions, Options1} ->
			Receipt = try_sending_it(Email, Socket, Extensions, Options1),
			quit(Socket),
			Receipt
	end.

-spec try_smtp_sessions(Hosts :: [{non_neg_integer(), string()}, ...], Options :: options(), RetryList :: list()) ->
                               smtp_client_socket() |
                               smtp_session_error().
try_smtp_sessions([{_Distance, Host} | _Tail] = Hosts, Options, RetryList) ->
	try open_smtp_session(Host, Options) of
		Res -> Res
	catch
		throw:FailMsg ->
			handle_smtp_throw(FailMsg, Hosts, Options, RetryList)
	end.

-spec handle_smtp_throw(failure(), [{non_neg_integer(), smtp_host()}], options(), list()) ->
                               smtp_client_socket() |
                               smtp_session_error().
handle_smtp_throw({permanent_failure, Message}, [{_Distance, Host} | _Tail], _Options, _RetryList) ->
	% permanent failure means no retries, and don't even continue with other hosts
	{error, no_more_hosts, {permanent_failure, Host, Message}};
handle_smtp_throw({temporary_failure, tls_failed}, [{_Distance, Host} | _Tail] = Hosts, Options, RetryList) ->
	% Could not start the TLS handshake; if tls is optional then try without TLS
	case proplists:get_value(tls, Options) of
		if_available ->
			NoTLSOptions = [{tls,never} | proplists:delete(tls, Options)],
			try open_smtp_session(Host, NoTLSOptions) of
				Res -> Res
			catch
				throw:FailMsg ->
					handle_smtp_throw(FailMsg, Hosts, Options, RetryList)
			end;
		_ ->
			try_next_host({temporary_failure, tls_failed}, Hosts, Options, RetryList)
	end;
handle_smtp_throw(FailMsg, Hosts, Options, RetryList) ->
	try_next_host(FailMsg, Hosts, Options, RetryList).

try_next_host({FailureType, Message}, [{_Distance, Host} | _Tail] = Hosts, Options, RetryList) ->
	Retries = proplists:get_value(retries, Options),
	RetryCount = proplists:get_value(Host, RetryList),
	case fetch_next_host(Retries, RetryCount, Hosts, RetryList, Options) of
		{[], _NewRetryList} ->
			{error, retries_exceeded, {FailureType, Host, Message}};
		{NewHosts, NewRetryList} ->
			try_smtp_sessions(NewHosts, Options, NewRetryList)
	end.

fetch_next_host(Retries, RetryCount, [{_Distance, Host} | Tail], RetryList, Options) when is_integer(RetryCount), RetryCount >= Retries ->
	% out of chances
	trace(Options, "retries for ~s exceeded (~p of ~p)~n", [Host, RetryCount, Retries]),
	{Tail, lists:keydelete(Host, 1, RetryList)};
fetch_next_host(Retries, RetryCount, [{Distance, Host} | Tail], RetryList, Options) when is_integer(RetryCount) ->
	trace(Options, "scheduling ~s for retry (~p of ~p)~n", [Host, RetryCount, Retries]),
	{Tail ++ [{Distance, Host}], lists:keydelete(Host, 1, RetryList) ++ [{Host, RetryCount + 1}]};
fetch_next_host(0, _RetryCount, [{_Distance, Host} | Tail], RetryList, _Options) ->
	% done retrying completely
	{Tail, lists:keydelete(Host, 1, RetryList)};
fetch_next_host(Retries, _RetryCount, [{Distance, Host} | Tail], RetryList, Options) ->
	% otherwise...
	trace(Options, "scheduling ~s for retry (~p of ~p)~n", [Host, 1, Retries]),
	{Tail ++ [{Distance, Host}], lists:keydelete(Host, 1, RetryList) ++ [{Host, 1}]}.


-spec open_smtp_session(Host :: string(), Options :: options()) -> smtp_client_socket().
open_smtp_session(Host, Options) ->
	{ok, Socket, _Host2, Banner} = connect(Host, Options),
	trace(Options, "connected to ~s; banner was ~s~n", [Host, Banner]),
	{ok, Extensions} = try_EHLO(Socket, Options),
	trace(Options, "Extensions are ~p~n", [Extensions]),
	{Socket2, Extensions2} = try_STARTTLS(Socket, Options, Extensions),
	trace(Options, "Extensions are ~p~n", [Extensions2]),
	Authed = try_AUTH(Socket2, Options, proplists:get_value(<<"AUTH">>, Extensions2)),
	trace(Options, "Authentication status is ~p~n", [Authed]),
	{Socket2, Extensions, Options}.

-spec try_sending_it(Email :: email(), Socket :: smtp_socket:socket(), Extensions :: extensions(), Options :: options()) -> binary().
try_sending_it({From, To, Body}, Socket, Extensions, Options) ->
	try_MAIL_FROM(From, Socket, Extensions, Options),
	try_RCPT_TO(To, Socket, Extensions, Options),
	try_DATA(Body, Socket, Extensions, Options).

-spec try_MAIL_FROM(From :: email_address(), Socket :: smtp_socket:socket(), Extensions :: extensions(), Options :: options()) -> true.
try_MAIL_FROM(From, Socket, Extensions, Options) when is_binary(From) ->
	try_MAIL_FROM(binary_to_list(From), Socket, Extensions, Options);
try_MAIL_FROM("<" ++ _ = From, Socket, _Extensions, Options) ->
	% TODO do we need to bother with SIZE?
	smtp_socket:send(Socket, ["MAIL FROM: ", From, "\r\n"]),
	case read_possible_multiline_reply(Socket) of
		{ok, <<"250", _Rest/binary>>} ->
			true;
		{ok, <<"4", _Rest/binary>> = Msg} ->
			quit(Socket),
			throw({temporary_failure, Msg});
		{ok, Msg} ->
			trace(Options, "Mail FROM rejected: ~p~n", [Msg]),
			quit(Socket),
			throw({permanent_failure, Msg})
	end;
try_MAIL_FROM(From, Socket, Extension, Options) ->
	% someone was bad and didn't put in the angle brackets
	try_MAIL_FROM("<"++From++">", Socket, Extension, Options).

-spec try_RCPT_TO(Tos :: [email_address()], Socket :: smtp_socket:socket(), Extensions :: extensions(), Options :: options()) -> true.
try_RCPT_TO([], _Socket, _Extensions, _Options) ->
	true;
try_RCPT_TO([To | Tail], Socket, Extensions, Options) when is_binary(To) ->
	try_RCPT_TO([binary_to_list(To) | Tail], Socket, Extensions, Options);
try_RCPT_TO(["<" ++ _ = To | Tail], Socket, Extensions, Options) ->
	smtp_socket:send(Socket, ["RCPT TO: ",To,"\r\n"]),
	case read_possible_multiline_reply(Socket) of
		{ok, <<"250", _Rest/binary>>} ->
			try_RCPT_TO(Tail, Socket, Extensions, Options);
		{ok, <<"251", _Rest/binary>>} ->
			try_RCPT_TO(Tail, Socket, Extensions, Options);
		{ok, <<"4", _Rest/binary>> = Msg} ->
			quit(Socket),
			throw({temporary_failure, Msg});
		{ok, Msg} ->
			quit(Socket),
			throw({permanent_failure, Msg})
	end;
try_RCPT_TO([To | Tail], Socket, Extensions, Options) ->
	% someone was bad and didn't put in the angle brackets
	try_RCPT_TO(["<"++To++">" | Tail], Socket, Extensions, Options).

-spec try_DATA(Body :: binary() | function(), Socket :: smtp_socket:socket(), Extensions :: extensions(), Options :: options()) -> binary().
try_DATA(Body, Socket, Extensions, Options) when is_function(Body) ->
	try_DATA(Body(), Socket, Extensions, Options);
try_DATA(Body, Socket, _Extensions, _Options) ->
	smtp_socket:send(Socket, "DATA\r\n"),
	case read_possible_multiline_reply(Socket) of
		{ok, <<"354", _Rest/binary>>} ->
			%% Escape period at start of line (rfc5321 4.5.2)
			EscapedBody = re:replace(Body, <<"^\\\.">>, <<"..">>, [global, multiline, {return, binary}]),
			smtp_socket:send(Socket, [EscapedBody, "\r\n.\r\n"]),
			case read_possible_multiline_reply(Socket) of
				{ok, <<"250 ", Receipt/binary>>} ->
					Receipt;
				{ok, <<"4", _Rest2/binary>> = Msg} ->
					quit(Socket),
					throw({temporary_failure, Msg});
				{ok, Msg} ->
					quit(Socket),
					throw({permanent_failure, Msg})
			end;
		{ok, <<"4", _Rest/binary>> = Msg} ->
			quit(Socket),
			throw({temporary_failure, Msg});
		{ok, Msg} ->
			quit(Socket),
			throw({permanent_failure, Msg})
	end.

-spec try_AUTH(Socket :: smtp_socket:socket(), Options :: options(), AuthTypes :: [string()]) -> boolean().
try_AUTH(Socket, Options, []) ->
	case proplists:get_value(auth, Options) of
		always ->
			quit(Socket),
			erlang:throw({missing_requirement, auth});
		_ ->
			false
	end;
try_AUTH(Socket, Options, undefined) ->
	case proplists:get_value(auth, Options) of
		always ->
			quit(Socket),
			erlang:throw({missing_requirement, auth});
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
					quit(Socket),
					erlang:throw({missing_requirement, auth});
				_ ->
					false
			end;
		true ->

			Username = to_binary(proplists:get_value(username, Options)),
			Password = to_binary(proplists:get_value(password, Options)),
			trace(Options, "Auth types: ~p~n", [AuthTypes]),
			Types = re:split(AuthTypes, " ", [{return, list}, trim]),
			case do_AUTH(Socket, Username, Password, Types, Options) of
				false ->
					case proplists:get_value(auth, Options) of
						always ->
							quit(Socket),
							erlang:throw({permanent_failure, auth_failed});
						_ ->
							false
					end;
				true ->
					true
			end
	end.

to_string(String) when is_list(String)   -> String;
to_string(Binary) when is_binary(Binary) -> binary_to_list(Binary).

to_binary(String) when is_binary(String)   -> String;
to_binary(String) when is_list(String) -> list_to_binary(String).

-spec do_AUTH(Socket :: smtp_socket:socket(), Username :: binary(), Password :: binary(), Types :: [string()], Options :: options()) -> boolean().
do_AUTH(Socket, Username, Password, Types, Options) ->
	FixedTypes = [string:to_upper(X) || X <- Types],
	trace(Options, "Fixed types: ~p~n", [FixedTypes]),
	AllowedTypes = [X  || X <- ?AUTH_PREFERENCE, lists:member(X, FixedTypes)],
	trace(Options, "available authentication types, in order of preference: ~p~n", [AllowedTypes]),
	do_AUTH_each(Socket, Username, Password, AllowedTypes, Options).

-spec do_AUTH_each(Socket :: smtp_socket:socket(), Username :: binary(), Password :: binary(), AuthTypes :: [string()], Options :: options()) -> boolean().
do_AUTH_each(_Socket, _Username, _Password, [], _Options) ->
	false;
do_AUTH_each(Socket, Username, Password, ["CRAM-MD5" | Tail], Options) ->
	smtp_socket:send(Socket, "AUTH CRAM-MD5\r\n"),
	case read_possible_multiline_reply(Socket) of
		{ok, <<"334 ", Rest/binary>>} ->
			Seed64 = binstr:strip(binstr:strip(Rest, right, $\n), right, $\r),
			Seed = base64:decode(Seed64),
			Digest = smtp_util:compute_cram_digest(Password, Seed),
			String = base64:encode(list_to_binary([Username, " ", Digest])),
			smtp_socket:send(Socket, [String, "\r\n"]),
			case read_possible_multiline_reply(Socket) of
				{ok, <<"235", _Rest/binary>>} ->
					trace(Options, "authentication accepted~n", []),
					true;
				{ok, Msg} ->
					trace(Options, "authentication rejected: ~s~n", [Msg]),
					do_AUTH_each(Socket, Username, Password, Tail, Options)
			end;
		{ok, Something} ->
			trace(Options, "got ~s~n", [Something]),
			do_AUTH_each(Socket, Username, Password, Tail, Options)
	end;
do_AUTH_each(Socket, Username, Password, ["XOAUTH2" | Tail], Options) ->
	Str = base64:encode(list_to_binary(["user=", Username, 1, "auth=Bearer ", Password, 1, 1])),
	smtp_socket:send(Socket, ["AUTH XOAUTH2 ", Str, "\r\n"]),
	case read_possible_multiline_reply(Socket) of
		{ok, <<"235", _Rest/binary>>} ->
			true;
		{ok, _Msg} ->
			do_AUTH_each(Socket, Username, Password, Tail, Options)
	end;
do_AUTH_each(Socket, Username, Password, ["LOGIN" | Tail], Options) ->
	smtp_socket:send(Socket, "AUTH LOGIN\r\n"),
	case read_possible_multiline_reply(Socket) of
		%% base64 Username: or username:
		{ok, Prompt} when Prompt == <<"334 VXNlcm5hbWU6\r\n">>; Prompt == <<"334 dXNlcm5hbWU6\r\n">> ->
			trace(Options, "username prompt~n", []),
			U = base64:encode(Username),
			smtp_socket:send(Socket, [U,"\r\n"]),
			case read_possible_multiline_reply(Socket) of
				%% base64 Password: or password:
				{ok, Prompt2} when Prompt2 == <<"334 UGFzc3dvcmQ6\r\n">>; Prompt2 == <<"334 cGFzc3dvcmQ6\r\n">> ->
					trace(Options, "password prompt~n", []),
					P = base64:encode(Password),
					smtp_socket:send(Socket, [P,"\r\n"]),
					case read_possible_multiline_reply(Socket) of
						{ok, <<"235 ", _Rest/binary>>} ->
							trace(Options, "authentication accepted~n", []),
							true;
						{ok, Msg} ->
							trace(Options, "password rejected: ~s", [Msg]),
							do_AUTH_each(Socket, Username, Password, Tail, Options)
					end;
				{ok, Msg2} ->
					trace(Options, "username rejected: ~s", [Msg2]),
					do_AUTH_each(Socket, Username, Password, Tail, Options)
			end;
		{ok, Something} ->
			trace(Options, "got ~s~n", [Something]),
			do_AUTH_each(Socket, Username, Password, Tail, Options)
	end;
do_AUTH_each(Socket, Username, Password, ["PLAIN" | Tail], Options) ->
	AuthString = base64:encode(<<0, Username/binary, 0, Password/binary>>),
	smtp_socket:send(Socket, ["AUTH PLAIN ", AuthString, "\r\n"]),
	case read_possible_multiline_reply(Socket) of
		{ok, <<"235", _Rest/binary>>} ->
			trace(Options, "authentication accepted~n", []),
			true;
		Else ->
			% TODO do we need to bother trying the multi-step PLAIN?
			trace(Options, "authentication rejected ~p~n", [Else]),
			do_AUTH_each(Socket, Username, Password, Tail, Options)
	end;
do_AUTH_each(Socket, Username, Password, [Type | Tail], Options) ->
	trace(Options, "unsupported AUTH type ~s~n", [Type]),
	do_AUTH_each(Socket, Username, Password, Tail, Options).

-spec try_EHLO(Socket :: smtp_socket:socket(), Options :: options()) -> {ok, extensions()}.
try_EHLO(Socket, Options) ->
	ok = smtp_socket:send(Socket, ["EHLO ", proplists:get_value(hostname, Options, smtp_util:guess_FQDN()), "\r\n"]),
	case read_possible_multiline_reply(Socket) of
		{ok, <<"500", _Rest/binary>>} ->
			% Unrecognized command, fall back to HELO
			try_HELO(Socket, Options);
		{ok, <<"4", _Rest/binary>> = Msg} ->
			quit(Socket),
			throw({temporary_failure, Msg});
		{ok, Reply} ->
			{ok, parse_extensions(Reply, Options)}
	end.

-spec try_HELO(Socket :: smtp_socket:socket(), Options :: options()) -> {ok, list()}.
try_HELO(Socket, Options) ->
	ok = smtp_socket:send(Socket, ["HELO ", proplists:get_value(hostname, Options, smtp_util:guess_FQDN()), "\r\n"]),
	case read_possible_multiline_reply(Socket) of
		{ok, <<"250", _Rest/binary>>} ->
			{ok, []};
		{ok, <<"4", _Rest/binary>> = Msg} ->
			quit(Socket),
			throw({temporary_failure, Msg});
		{ok, Msg} ->
			quit(Socket),
			throw({permanent_failure, Msg})
	end.

% check if we should try to do TLS
-spec try_STARTTLS(Socket :: smtp_socket:socket(), Options :: options(), Extensions :: extensions()) -> {smtp_socket:socket(), extensions()}.
try_STARTTLS(Socket, Options, Extensions) ->
	case {proplists:get_value(tls, Options),
			proplists:get_value(<<"STARTTLS">>, Extensions)} of
		{Atom, true} when Atom =:= always; Atom =:= if_available ->
			trace(Options, "Starting TLS~n", []),
			case {do_STARTTLS(Socket, Options), Atom} of
				{false, always} ->
					trace(Options, "TLS failed~n", []),
					quit(Socket),
					erlang:throw({temporary_failure, tls_failed});
				{false, if_available} ->
					trace(Options, "TLS failed~n", []),
					{Socket, Extensions};
				{{S, E}, _} ->
					trace(Options, "TLS started~n", []),
					{S, E}
			end;
		{always, _} ->
			quit(Socket),
			erlang:throw({missing_requirement, tls});
		_ ->
			trace(Options, "TLS not requested ~p~n", [Options]),
			{Socket, Extensions}
	end.

%% attempt to upgrade socket to TLS
-spec do_STARTTLS(Socket :: smtp_socket:socket(), Options :: options()) -> {smtp_socket:socket(), extensions()} | false.
do_STARTTLS(Socket, Options) ->
	smtp_socket:send(Socket, "STARTTLS\r\n"),
	case read_possible_multiline_reply(Socket) of
		{ok, <<"220", _Rest/binary>>} ->
			case catch smtp_socket:to_ssl_client(Socket, proplists:get_value(tls_options, Options, []), 5000) of
				{ok, NewSocket} ->
					%NewSocket;
					{ok, Extensions} = try_EHLO(NewSocket, Options),
					{NewSocket, Extensions};
				{'EXIT', Reason} ->
					quit(Socket),
					error_logger:error_msg("Error in ssl upgrade: ~p.~n", [Reason]),
					erlang:throw({temporary_failure, tls_failed});
				{error, closed} ->
					quit(Socket),
					error_logger:error_msg("Error in ssl upgrade: socket closed.~n"),
					erlang:throw({temporary_failure, tls_failed});
				{error, ssl_not_started} ->
					quit(Socket),
					error_logger:error_msg("SSL not started.~n"),
					erlang:throw({permanent_failure, ssl_not_started});
				Else ->
					trace(Options, "~p~n", [Else]),
					false
			end;
		{ok, <<"4", _Rest/binary>> = Msg} ->
			quit(Socket),
			erlang:throw({temporary_failure, Msg});
		{ok, Msg} ->
			quit(Socket),
			erlang:throw({permanent_failure, Msg})
	end.

%% try connecting to a host
connect(Host, Options) when is_binary(Host) ->
	connect(binary_to_list(Host), Options);
connect(Host, Options) ->
	AddSockOpts = case proplists:get_value(sockopts, Options) of
		undefined -> [];
		Other -> Other
	end,
	SockOpts = [binary, {packet, line}, {keepalive, true}, {active, false} | AddSockOpts],
	Proto = case proplists:get_value(ssl, Options) of
		true ->
			ssl;
		_ ->
			tcp
	end,
	Port = case proplists:get_value(port, Options) of
		undefined when Proto =:= ssl ->
			465;
		OPort when is_integer(OPort) ->
			OPort;
		_ ->
			25
	end,
	Timeout = case proplists:get_value(timeout, Options) of
		undefined -> 5000;
		OTimeout -> OTimeout
	end,
	case smtp_socket:connect(Proto, Host, Port, SockOpts, Timeout) of
		{ok, Socket} ->
			case read_possible_multiline_reply(Socket) of
				{ok, <<"220", Banner/binary>>} ->
					{ok, Socket, Host, Banner};
				{ok, <<"4", _Rest/binary>> = Msg} ->
					quit(Socket),
					throw({temporary_failure, Msg});
				{ok, Msg} ->
					quit(Socket),
					throw({permanent_failure, Msg})
			end;
		{error, Reason} ->
			throw({network_failure, {error, Reason}})
	end.

%% read a multiline reply (eg. EHLO reply)
-spec read_possible_multiline_reply(Socket :: smtp_socket:socket()) -> {ok, binary()}.
read_possible_multiline_reply(Socket) ->
	case smtp_socket:recv(Socket, 0, ?TIMEOUT) of
		{ok, Packet} ->
			case binstr:substr(Packet, 4, 1) of
				<<"-">> ->
					Code = binstr:substr(Packet, 1, 3),
					read_multiline_reply(Socket, Code, [Packet]);
				<<" ">> ->
					{ok, Packet}
			end;
		Error ->
			throw({network_failure, Error})
	end.

-spec read_multiline_reply(Socket :: smtp_socket:socket(), Code :: binary(), Acc :: [binary()]) -> {ok, binary()}.
read_multiline_reply(Socket, Code, Acc) ->
	case smtp_socket:recv(Socket, 0, ?TIMEOUT) of
		{ok, Packet} ->
			case {binstr:substr(Packet, 1, 3), binstr:substr(Packet, 4, 1)} of
				{Code, <<" ">>} ->
					{ok, list_to_binary(lists:reverse([Packet | Acc]))};
				{Code, <<"-">>} ->
					read_multiline_reply(Socket, Code, [Packet | Acc]);
				_ ->
					quit(Socket),
					throw({unexpected_response, lists:reverse([Packet | Acc])})
			end;
		Error ->
			throw({network_failure, Error})
	end.

quit(Socket) ->
	smtp_socket:send(Socket, "QUIT\r\n"),
	smtp_socket:close(Socket),
	ok.

% TODO - more checking
check_options(Options) ->
	CheckedOptions = [relay, port, auth],
	lists:foldl(fun(Option, State) ->
		case State of
			ok ->
				Value = proplists:get_value(Option, Options),
				check_option({Option, Value}, Options);
			Other -> Other
		end
	end, ok, CheckedOptions).

check_option({relay, undefined}, _Options) -> {error, no_relay};
check_option({relay, _}, _Options) -> ok;
check_option({port, undefined}, _Options) -> ok;
check_option({port, Port}, _Options) when is_integer(Port) -> ok;
check_option({port, _}, _Options) -> {error, invalid_port};
check_option({auth, always}, Options) ->
	case proplists:is_defined(username, Options) and
		proplists:is_defined(password, Options) of
		false ->
			{error, no_credentials};
		true ->
			ok
	end;
check_option({auth, _}, _Options) -> ok.

-spec parse_extensions(Reply :: binary(), Options :: options()) -> extensions().
parse_extensions(Reply, Options) ->
	[_ | Reply2] = re:split(Reply, "\r\n", [{return, binary}, trim]),
	[
		begin
				Body = binstr:substr(Entry, 5),
				case re:split(Body, " ",  [{return, binary}, trim, {parts, 2}]) of
					[Verb, Parameters] ->
						{binstr:to_upper(Verb), Parameters};
					[Body] ->
						case binstr:strchr(Body, $=) of
							0 ->
								{binstr:to_upper(Body), true};
							_ ->
								trace(Options, "discarding option ~p~n", [Body]),
								[]
						end
				end
		end  || Entry <- Reply2].

trace(Options, Format, Args) ->
	case proplists:get_value(trace_fun, Options) of
		undefined -> ok;
		F -> F(Format, Args)
	end.

-ifdef(TEST).

session_start_test_() ->
	{foreach,
		local,
		fun() ->
				{ok, ListenSock} = smtp_socket:listen(tcp, 9876),
				{ListenSock}
		end,
		fun({ListenSock}) ->
				smtp_socket:close(ListenSock)
		end,
		[fun({ListenSock}) ->
					{"simple session initiation",
						fun() ->
								Options = [{relay, "localhost"}, {port, 9876}, {hostname, "testing"}],
								{ok, _Pid} = send({"test@foo.com", ["foo@bar.com"], "hello world"}, Options),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								ok
						end
					}
			end,
			fun({ListenSock}) ->
					{"retry on crashed EHLO twice if requested",
						fun() ->
								Options = [{relay, "localhost"}, {port, 9876}, {hostname, "testing"}, {retries, 2}],
								{ok, _Pid} = send({"test@foo.com", ["foo@bar.com"], "hello world"}, Options),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:close(X),
								{ok, Y} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(Y, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								smtp_socket:close(Y),
								{ok, Z} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(Z, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(Z, 0, 1000)),
								ok
						end
					}
			end,
			fun({ListenSock}) ->
					{"retry on crashed EHLO",
						fun() ->
								Options = [{relay, "localhost"}, {port, 9876}, {hostname, "testing"}],
								{ok, Pid} = send({"test@foo.com", ["foo@bar.com"], "hello world"}, Options),
								unlink(Pid),
								Monitor = erlang:monitor(process, Pid),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:close(X),
								{ok, Y} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(Y, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								smtp_socket:close(Y),
								?assertEqual({error, timeout}, smtp_socket:accept(ListenSock, 1000)),
								receive {'DOWN', Monitor, _, _, Error} -> ?assertMatch({error, retries_exceeded, _}, Error) end,
								ok
						end
					}
			end,
			fun({ListenSock}) ->
					{"abort on 554 greeting",
						fun() ->
								Options = [{relay, "localhost"}, {port, 9876}, {hostname, "testing"}],
								{ok, Pid} = send({"test@foo.com", ["foo@bar.com"], "hello world"}, Options),
								unlink(Pid),
								Monitor = erlang:monitor(process, Pid),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "554 get lost, kid\r\n"),
								?assertMatch({ok, "QUIT\r\n"}, smtp_socket:recv(X, 0, 1000)),
								receive {'DOWN', Monitor, _, _, Error} -> ?assertMatch({error, no_more_hosts, _}, Error) end,
								ok
						end
					}
			end,
			fun({ListenSock}) ->
					{"retry on 421 greeting",
						fun() ->
								Options = [{relay, "localhost"}, {port, 9876}, {hostname, "testing"}],
								{ok, _Pid} = send({"test@foo.com", ["foo@bar.com"], "hello world"}, Options),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "421 can't you see I'm busy?\r\n"),
								?assertMatch({ok, "QUIT\r\n"}, smtp_socket:recv(X, 0, 1000)),
								{ok, Y} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(Y, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								ok
						end
					}
			end,
			fun({ListenSock}) ->
					{"retry on messed up EHLO response",
						fun() ->
								Options = [{relay, "localhost"}, {port, 9876}, {hostname, "testing"}],
								{ok, Pid} = send({"test@foo.com", ["foo@bar.com"], "hello world"}, Options),
								unlink(Pid),
								Monitor = erlang:monitor(process, Pid),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250-server.example.com EHLO\r\n250-AUTH LOGIN PLAIN\r\n421 too busy\r\n"),
								?assertMatch({ok, "QUIT\r\n"}, smtp_socket:recv(X, 0, 1000)),

								{ok, Y} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(Y, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								smtp_socket:send(Y, "250-server.example.com EHLO\r\n250-AUTH LOGIN PLAIN\r\n421 too busy\r\n"),
								?assertMatch({ok, "QUIT\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								receive {'DOWN', Monitor, _, _, Error} -> ?assertMatch({error, retries_exceeded, _}, Error) end,
								ok
						end
					}
			end,
			fun({ListenSock}) ->
					{"retry with HELO when EHLO not accepted",
						fun() ->
								Options = [{relay, "localhost"}, {port, 9876}, {hostname, "testing"}],
								{ok, _Pid} = send({"test@foo.com", ["foo@bar.com"], "hello world"}, Options),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "220 \r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "500 5.3.3 Unrecognized command\r\n"),
								?assertMatch({ok, "HELO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 Some banner\r\n"),
								?assertMatch({ok, "MAIL FROM: <test@foo.com>\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 ok\r\n"),
								?assertMatch({ok, "RCPT TO: <foo@bar.com>\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 ok\r\n"),
								?assertMatch({ok, "DATA\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "354 ok\r\n"),
								?assertMatch({ok, "hello world\r\n"}, smtp_socket:recv(X, 0, 1000)),
								?assertMatch({ok, ".\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 ok\r\n"),
								?assertMatch({ok, "QUIT\r\n"}, smtp_socket:recv(X, 0, 1000)),
								ok
						end
					}
			end,
			fun({ListenSock}) ->
					{"a valid complete transaction without TLS advertised should succeed",
						fun() ->
								Options = [{relay, "localhost"}, {port, 9876}, {hostname, "testing"}],
								{ok, _Pid} = send({"test@foo.com", ["foo@bar.com"], "hello world"}, Options),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 hostname\r\n"),
								?assertMatch({ok, "MAIL FROM: <test@foo.com>\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 ok\r\n"),
								?assertMatch({ok, "RCPT TO: <foo@bar.com>\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 ok\r\n"),
								?assertMatch({ok, "DATA\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "354 ok\r\n"),
								?assertMatch({ok, "hello world\r\n"}, smtp_socket:recv(X, 0, 1000)),
								?assertMatch({ok, ".\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 ok\r\n"),
								?assertMatch({ok, "QUIT\r\n"}, smtp_socket:recv(X, 0, 1000)),
								ok
						end
					}
			end,
			fun({ListenSock}) ->
					{"a valid complete transaction exercising period escaping",
						fun() ->
								Options = [{relay, "localhost"}, {port, 9876}, {hostname, "testing"}],
								{ok, _Pid} = send({"test@foo.com", ["foo@bar.com"], ".hello world"}, Options),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 hostname\r\n"),
								?assertMatch({ok, "MAIL FROM: <test@foo.com>\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 ok\r\n"),
								?assertMatch({ok, "RCPT TO: <foo@bar.com>\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 ok\r\n"),
								?assertMatch({ok, "DATA\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "354 ok\r\n"),
								?assertMatch({ok, "..hello world\r\n"}, smtp_socket:recv(X, 0, 1000)),
								?assertMatch({ok, ".\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 ok\r\n"),
								?assertMatch({ok, "QUIT\r\n"}, smtp_socket:recv(X, 0, 1000)),
								ok
						end
					}
			end,
			fun({ListenSock}) ->
					{"a valid complete transaction with binary arguments should succeed",
						fun() ->
								Options = [{relay, "localhost"}, {port, 9876}, {hostname, "testing"}],
								{ok, _Pid} = send({<<"test@foo.com">>, [<<"foo@bar.com">>], <<"hello world">>}, Options),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 hostname\r\n"),
								?assertMatch({ok, "MAIL FROM: <test@foo.com>\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 ok\r\n"),
								?assertMatch({ok, "RCPT TO: <foo@bar.com>\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 ok\r\n"),
								?assertMatch({ok, "DATA\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "354 ok\r\n"),
								?assertMatch({ok, "hello world\r\n"}, smtp_socket:recv(X, 0, 1000)),
								?assertMatch({ok, ".\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 ok\r\n"),
								?assertMatch({ok, "QUIT\r\n"}, smtp_socket:recv(X, 0, 1000)),
								ok
						end
					}
			end,
			fun({ListenSock}) ->
					{"a valid complete transaction with TLS advertised should succeed",
						fun() ->
								Options = [{relay, "localhost"}, {port, 9876}, {hostname, <<"testing">>}],
								{ok, _Pid} = send({"test@foo.com", ["foo@bar.com"], "hello world"}, Options),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250-hostname\r\n250 STARTTLS\r\n"),
								?assertMatch({ok, "STARTTLS\r\n"}, smtp_socket:recv(X, 0, 1000)),
								gen_smtp_application:ensure_all_started(gen_smtp),
								smtp_socket:send(X, "220 ok\r\n"),
								{ok, Y} = smtp_socket:to_ssl_server(X, [{certfile, "test/fixtures/server.crt"}, {keyfile, "test/fixtures/server.key"}], 5000),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								smtp_socket:send(Y, "250-hostname\r\n250 STARTTLS\r\n"),
								?assertMatch({ok, "MAIL FROM: <test@foo.com>\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								smtp_socket:send(Y, "250 ok\r\n"),
								?assertMatch({ok, "RCPT TO: <foo@bar.com>\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								smtp_socket:send(Y, "250 ok\r\n"),
								?assertMatch({ok, "DATA\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								smtp_socket:send(Y, "354 ok\r\n"),
								?assertMatch({ok, "hello world\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								?assertMatch({ok, ".\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								smtp_socket:send(Y, "250 ok\r\n"),
								?assertMatch({ok, "QUIT\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								ok
						end
					}
			end,
			fun({ListenSock}) ->
					{"a valid complete transaction with TLS advertised and binary arguments should succeed",
						fun() ->
								Options = [{relay, "localhost"}, {port, 9876}, {hostname, <<"testing">>}],
								{ok, _Pid} = send({<<"test@foo.com">>, [<<"foo@bar.com">>], <<"hello world">>}, Options),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250-hostname\r\n250 STARTTLS\r\n"),
								?assertMatch({ok, "STARTTLS\r\n"}, smtp_socket:recv(X, 0, 1000)),
								gen_smtp_application:ensure_all_started(gen_smtp),
								smtp_socket:send(X, "220 ok\r\n"),
								{ok, Y} = smtp_socket:to_ssl_server(X, [{certfile, "test/fixtures/server.crt"}, {keyfile, "test/fixtures/server.key"}], 5000),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								smtp_socket:send(Y, "250-hostname\r\n250 STARTTLS\r\n"),
								?assertMatch({ok, "MAIL FROM: <test@foo.com>\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								smtp_socket:send(Y, "250 ok\r\n"),
								?assertMatch({ok, "RCPT TO: <foo@bar.com>\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								smtp_socket:send(Y, "250 ok\r\n"),
								?assertMatch({ok, "DATA\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								smtp_socket:send(Y, "354 ok\r\n"),
								?assertMatch({ok, "hello world\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								?assertMatch({ok, ".\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								smtp_socket:send(Y, "250 ok\r\n"),
								?assertMatch({ok, "QUIT\r\n"}, smtp_socket:recv(Y, 0, 1000)),
								ok
						end
					}
			end,

			fun({ListenSock}) ->
					{"AUTH PLAIN should work",
						fun() ->
								Options = [{relay, "localhost"}, {port, 9876}, {hostname, "testing"}, {username, "user"}, {password, "pass"}],
								{ok, _Pid} = send({"test@foo.com", ["foo@bar.com"], "hello world"}, Options),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250-hostname\r\n250 AUTH PLAIN\r\n"),
								AuthString = binary_to_list(base64:encode("\0user\0pass")),
								AuthPacket = "AUTH PLAIN "++AuthString++"\r\n",
								?assertEqual({ok, AuthPacket}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "235 ok\r\n"),
								?assertMatch({ok, "MAIL FROM: <test@foo.com>\r\n"}, smtp_socket:recv(X, 0, 1000)),
								ok
						end
					}
			end,
			fun({ListenSock}) ->
					{"AUTH LOGIN should work",
						fun() ->
								Options = [{relay, "localhost"}, {port, 9876}, {hostname, "testing"}, {username, "user"}, {password, "pass"}],
								{ok, _Pid} = send({"test@foo.com", ["foo@bar.com"], "hello world"}, Options),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250-hostname\r\n250 AUTH LOGIN\r\n"),
								?assertEqual({ok, "AUTH LOGIN\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "334 VXNlcm5hbWU6\r\n"),
								UserString = binary_to_list(base64:encode("user")),
								?assertEqual({ok, UserString++"\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "334 UGFzc3dvcmQ6\r\n"),
								PassString = binary_to_list(base64:encode("pass")),
								?assertEqual({ok, PassString++"\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "235 ok\r\n"),
								?assertMatch({ok, "MAIL FROM: <test@foo.com>\r\n"}, smtp_socket:recv(X, 0, 1000)),
								ok
						end
					}
			end,
			fun({ListenSock}) ->
					{"AUTH LOGIN should work with lowercase prompts",
						fun() ->
								Options = [{relay, "localhost"}, {port, 9876}, {hostname, "testing"}, {username, "user"}, {password, "pass"}],
								{ok, _Pid} = send({"test@foo.com", ["foo@bar.com"], "hello world"}, Options),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250-hostname\r\n250 AUTH LOGIN\r\n"),
								?assertEqual({ok, "AUTH LOGIN\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "334 dXNlcm5hbWU6\r\n"),
								UserString = binary_to_list(base64:encode("user")),
								?assertEqual({ok, UserString++"\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "334 cGFzc3dvcmQ6\r\n"),
								PassString = binary_to_list(base64:encode("pass")),
								?assertEqual({ok, PassString++"\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "235 ok\r\n"),
								?assertMatch({ok, "MAIL FROM: <test@foo.com>\r\n"}, smtp_socket:recv(X, 0, 1000)),
								ok
						end
					}
			end,
			fun({ListenSock}) ->
					{"AUTH CRAM-MD5 should work",
						fun() ->
								Options = [{relay, "localhost"}, {port, 9876}, {hostname, "testing"}, {username, "user"}, {password, "pass"}],
								{ok, _Pid} = send({"test@foo.com", ["foo@bar.com"], "hello world"}, Options),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250-hostname\r\n250 AUTH CRAM-MD5\r\n"),
								?assertEqual({ok, "AUTH CRAM-MD5\r\n"}, smtp_socket:recv(X, 0, 1000)),
								Seed = smtp_util:get_cram_string(smtp_util:guess_FQDN()),
								DecodedSeed = base64:decode_to_string(Seed),
								Digest = smtp_util:compute_cram_digest("pass", DecodedSeed),
								String = binary_to_list(base64:encode(list_to_binary(["user ", Digest]))),
								smtp_socket:send(X, "334 "++Seed++"\r\n"),
								{ok, Packet} = smtp_socket:recv(X, 0, 1000),
								CramDigest = smtp_util:trim_crlf(Packet),
								?assertEqual(String, CramDigest),
								smtp_socket:send(X, "235 ok\r\n"),
								?assertMatch({ok, "MAIL FROM: <test@foo.com>\r\n"}, smtp_socket:recv(X, 0, 1000)),
								ok
						end
					}
			end,
			fun({ListenSock}) ->
					{"AUTH CRAM-MD5 should work",
						fun() ->
								Options = [{relay, <<"localhost">>}, {port, 9876}, {hostname, <<"testing">>}, {username, <<"user">>}, {password, <<"pass">>}],
								{ok, _Pid} = send({<<"test@foo.com">>, [<<"foo@bar.com">>, <<"baz@bar.com">>], <<"hello world">>}, Options),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250-hostname\r\n250 AUTH CRAM-MD5\r\n"),
								?assertEqual({ok, "AUTH CRAM-MD5\r\n"}, smtp_socket:recv(X, 0, 1000)),
								Seed = smtp_util:get_cram_string(smtp_util:guess_FQDN()),
								DecodedSeed = base64:decode_to_string(Seed),
								Digest = smtp_util:compute_cram_digest("pass", DecodedSeed),
								String = binary_to_list(base64:encode(list_to_binary(["user ", Digest]))),
								smtp_socket:send(X, "334 "++Seed++"\r\n"),
								{ok, Packet} = smtp_socket:recv(X, 0, 1000),
								CramDigest = smtp_util:trim_crlf(Packet),
								?assertEqual(String, CramDigest),
								smtp_socket:send(X, "235 ok\r\n"),
								?assertMatch({ok, "MAIL FROM: <test@foo.com>\r\n"}, smtp_socket:recv(X, 0, 1000)),
								ok
						end
					}
			end,
			fun({ListenSock}) ->
					{"should bail when AUTH is required but not provided",
						fun() ->
								Options = [{relay, <<"localhost">>}, {port, 9876}, {hostname, <<"testing">>}, {auth, always}, {username, <<"user">>}, {retries, 0}, {password, <<"pass">>}],
								{ok, Pid} = send({<<"test@foo.com">>, [<<"foo@bar.com">>, <<"baz@bar.com">>], <<"hello world">>}, Options),
								unlink(Pid),
								Monitor = erlang:monitor(process, Pid),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250-hostname\r\n250 8BITMIME\r\n"),
								?assertEqual({ok, "QUIT\r\n"}, smtp_socket:recv(X, 0, 1000)),
								receive {'DOWN', Monitor, _, _, Error} -> ?assertMatch({error, retries_exceeded, {missing_requirement, _, auth}}, Error) end,
								ok
						end
					}
			end,
			fun({ListenSock}) ->
					{"should bail when AUTH is required but of an unsupported type",
						fun() ->
								Options = [{relay, <<"localhost">>}, {port, 9876}, {hostname, <<"testing">>}, {auth, always}, {username, <<"user">>}, {retries, 0}, {password, <<"pass">>}],
								{ok, Pid} = send({<<"test@foo.com">>, [<<"foo@bar.com">>, <<"baz@bar.com">>], <<"hello world">>}, Options),
								unlink(Pid),
								Monitor = erlang:monitor(process, Pid),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250-hostname\r\n250-AUTH GSSAPI\r\n250 8BITMIME\r\n"),
								?assertEqual({ok, "QUIT\r\n"}, smtp_socket:recv(X, 0, 1000)),
								receive {'DOWN', Monitor, _, _, Error} -> ?assertMatch({error, no_more_hosts, {permanent_failure, _, auth_failed}}, Error) end,
								ok
						end
					}
			end,
			fun({_ListenSock}) ->
					{"Connecting to a SSL socket directly should work",
						fun() ->
								gen_smtp_application:ensure_all_started(gen_smtp),
								{ok, ListenSock} = smtp_socket:listen(ssl, 9877, [{certfile, "test/fixtures/server.crt"}, {keyfile, "test/fixtures/server.key"}]),
								Options = [{relay, <<"localhost">>}, {port, 9877}, {hostname, <<"testing">>}, {ssl, true}],
								{ok, _Pid} = send({<<"test@foo.com">>, [<<"<foo@bar.com>">>, <<"baz@bar.com">>], <<"hello world">>}, Options),
								{ok, X} = smtp_socket:accept(ListenSock, 1000),
								smtp_socket:send(X, "220 Some banner\r\n"),
								?assertMatch({ok, "EHLO testing\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250-hostname\r\n250 AUTH CRAM-MD5\r\n"),
								?assertEqual({ok, "MAIL FROM: <test@foo.com>\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 ok\r\n"),
								?assertMatch({ok, "RCPT TO: <foo@bar.com>\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 ok\r\n"),
								?assertMatch({ok, "RCPT TO: <baz@bar.com>\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 ok\r\n"),
								?assertMatch({ok, "DATA\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "354 ok\r\n"),
								?assertMatch({ok, "hello world\r\n"}, smtp_socket:recv(X, 0, 1000)),
								?assertMatch({ok, ".\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:send(X, "250 ok\r\n"),
								?assertMatch({ok, "QUIT\r\n"}, smtp_socket:recv(X, 0, 1000)),
								smtp_socket:close(ListenSock),
								ok
						end
					}
			end

		]
	}.

extension_parse_test_() ->
	[
		{"parse extensions",
			fun() ->
					Res = parse_extensions(<<"250-smtp.example.com\r\n250-PIPELINING\r\n250-SIZE 20971520\r\n250-VRFY\r\n250-ETRN\r\n250-STARTTLS\r\n250-AUTH CRAM-MD5 PLAIN DIGEST-MD5 LOGIN\r\n250-AUTH=CRAM-MD5 PLAIN DIGEST-MD5 LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250 DSN">>, []),
					?assertEqual(true, proplists:get_value(<<"PIPELINING">>, Res)),
					?assertEqual(<<"20971520">>, proplists:get_value(<<"SIZE">>, Res)),
					?assertEqual(true, proplists:get_value(<<"VRFY">>, Res)),
					?assertEqual(true, proplists:get_value(<<"ETRN">>, Res)),
					?assertEqual(true, proplists:get_value(<<"STARTTLS">>, Res)),
					?assertEqual(<<"CRAM-MD5 PLAIN DIGEST-MD5 LOGIN">>, proplists:get_value(<<"AUTH">>, Res)),
					?assertEqual(true, proplists:get_value(<<"ENHANCEDSTATUSCODES">>, Res)),
					?assertEqual(true, proplists:get_value(<<"8BITMIME">>, Res)),
					?assertEqual(true, proplists:get_value(<<"DSN">>, Res)),
					?assertEqual(10, length(Res)),
					ok
			end
		}
	].

-endif.
