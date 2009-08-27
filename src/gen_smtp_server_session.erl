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

%% @doc A Per-connection SMTP server, extensible via a callback module.

-module(gen_smtp_server_session).
-behaviour(gen_server).

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(BUILTIN_EXTENSIONS, [{"SIZE", "10240000"}, {"8BITMIME", true}, {"PIPELINING", true}]).
-define(TIMEOUT, 180000). % 3 minutes

%% External API
-export([start_link/4, start/4, compute_cram_digest/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
		code_change/3]).

-export([behaviour_info/1]).

-record(envelope,
	{
		from :: string(),
		to = [] :: [string()],
		data = "" :: string(),
		headers = [] :: [{string(), string()}], %proplist
		expectedsize :: pos_integer(),
		auth = {[], []} :: {string(), string()} % {"username", "password"}
	}
).

-record(state,
	{
		socket = erlang:error({undefined, socket}) :: port() | {'ssl', any()},
		module = erlang:error({undefined, module}) :: atom(),
		hostname = erlang:error({undefined, hostname}) :: string(),
		envelope = undefined :: 'undefined' | #envelope{},
		extensions = [] :: [string()],
		waitingauth = false :: bool() | string(),
		authdata :: 'undefined' | string(),
		readmessage = false :: bool(),
		readheaders = false :: bool(),
		tls = false :: bool(),
		callbackstate :: any()
	}
).

behaviour_info(callbacks) ->
	[{init,3},
		{handle_HELO,2},
		{handle_EHLO,3},
		{handle_MAIL,2},
		{handle_MAIL_extension,2},
		{handle_RCPT,2},
		{handle_RCPT_extension,2},
		{handle_DATA,5},
		{handle_RSET,1},
		{handle_VRFY,2},
		{handle_other,3},
		{terminate,2},
		{code_change,3}];
behaviour_info(_Other) ->
	undefined.

% TODO - there should be an Options parameter instead of SessionCount (and possibly Hostname)
-spec(start_link/4 :: (Socket :: port(), Module :: atom(), Hostname :: string(), SessionCount :: pos_integer()) -> {'ok', pid()}).
start_link(Socket, Module, Hostname, SessionCount) ->
	gen_server:start_link(?MODULE, [Socket, Module, Hostname, SessionCount], []).

-spec(start/4 :: (Socket :: port(), Module :: atom(), Hostname :: string(), SessionCount :: pos_integer()) -> {'ok', pid()}).
start(Socket, Module, Hostname, SessionCount) ->
	gen_server:start(?MODULE, [Socket, Module, Hostname, SessionCount], []).

-spec(init/1 :: (Args :: list()) -> {'ok', #state{}} | {'stop', any()} | 'ignore').
init([Socket, Module, Hostname, SessionCount]) ->
	{A1, A2, A3} = now(),
	random:seed(A1, A2, A3),
	{ok, {PeerName, _Port}} = inet:peername(Socket),
	case Module:init(Hostname, SessionCount, PeerName) of
		{ok, Banner, CallbackState} ->
			gen_tcp:send(Socket, io_lib:format("220 ~s\r\n", [Banner])),
			inet:setopts(Socket, [{active, once}, {packet, line}, list]),
			{ok, #state{socket = Socket, module = Module, hostname = Hostname, callbackstate = CallbackState}, ?TIMEOUT};
		{stop, Reason, Message} ->
			gen_tcp:send(Socket, Message ++ "\r\n"),
			gen_tcp:close(Socket),
			{stop, Reason};
		ignore ->
			gen_tcp:close(Socket),
			ignore
	end.

%% @hidden
handle_call(stop, _From, State) ->
	{stop, normal, ok, State};

handle_call(Request, _From, State) ->
	{reply, {unknown_call, Request}, State}.

%% @hidden
handle_cast(_Msg, State) ->
	{noreply, State}.

handle_info({tcp, Socket, ".\r\n"}, #state{readmessage = true, envelope = Envelope, module = Module} = State) ->
	%io:format("done reading message~n"),
	%io:format("entire message~n~s~n", [Envelope#envelope.data]),
	Valid = case has_extension(State#state.extensions, "SIZE") of
		{true, Value} ->
			case length(Envelope#envelope.data) > list_to_integer(Value) of
				true ->
					gen_tcp:send(Socket, "552 Message too large\r\n"),
					false;
				false ->
					true
			end;
		false ->
			true
	end,
	case Valid of
		true ->
			case Module:handle_DATA(Envelope#envelope.from, Envelope#envelope.to, Envelope#envelope.headers, Envelope#envelope.data, State#state.callbackstate) of
				{ok, Reference, CallbackState} ->
					gen_tcp:send(Socket, io_lib:format("250 queued as ~s\r\n", [Reference])),
					inet:setopts(Socket, [{active, once}]),
					{noreply, State#state{readmessage = false, envelope = #envelope{}, callbackstate = CallbackState}, ?TIMEOUT};
				{error, Message, CallbackState} ->
					gen_tcp:send(Socket, Message++"\r\n"),
					inet:setopts(Socket, [{active, once}]),
					{noreply, State#state{readmessage = false, envelope = #envelope{}, callbackstate = CallbackState}, ?TIMEOUT}
			end
	end;
handle_info({tcp, Socket, "\r\n"}, #state{readheaders = true, envelope = Envelope} = State) ->
	%io:format("Header terminator~n"),
	inet:setopts(Socket, [{active, once}]),
	{noreply, State#state{readheaders = false, readmessage = true, envelope = Envelope#envelope{headers = lists:reverse(Envelope#envelope.headers)}}, ?TIMEOUT};
handle_info({tcp, Socket, Packet}, #state{readheaders = true, envelope = Envelope} = State) ->
	case Packet of
		"." ++ String ->
			String;
		String ->
			String
	end,
	%io:format("Header candidate: ~p~n", [String]),
	NewState = case String of % first, check for a leading space or tab
		[H | _T] when H =:= $\s; H =:= $\t ->
			% TODO - check for "invisible line"
			case Envelope#envelope.headers of
				[] ->
					% if the header list is empty, this means that this line can't be a continuation of a previous header
					State#state{readmessage = true, readheaders = false,
						envelope = Envelope#envelope{data = string:concat(Envelope#envelope.data, String)}};
				_ ->
					[{FieldName, FieldValue} | T] = Envelope#envelope.headers,
					State#state{envelope = Envelope#envelope{headers = [{FieldName, string:concat(FieldValue, trim_crlf(String))} | T]}}
			end;
		_ -> % okay, now see if it's a header
			case string:str(String, ":") of
				0 -> % not a line starting a field
					State#state{readmessage = true, readheaders = false,
						envelope = Envelope#envelope{data = string:concat(Envelope#envelope.data, String), headers = lists:reverse(Envelope#envelope.headers)}};
				1 -> % WTF, colon as first character on line
					State#state{readmessage = true, readheaders = false,
						envelope = Envelope#envelope{data = string:concat(Envelope#envelope.data, String), headers = lists:reverse(Envelope#envelope.headers)}};
				Index ->
					FieldName = string:substr(String, 1, Index - 1),
					F = fun(X) -> X > 32 andalso X < 127 end,
					case lists:all(F, FieldName) of
						true ->
							FieldValue = string:strip(trim_crlf(string:substr(String, Index+1))),
							State#state{envelope = Envelope#envelope{headers = [{FieldName, FieldValue} | Envelope#envelope.headers]}};
						false ->
							State#state{readmessage = true, readheaders = false,
								envelope = Envelope#envelope{data = string:concat(Envelope#envelope.data, String), headers = lists:reverse(Envelope#envelope.headers)}}
					end
			end
	end,
	inet:setopts(Socket, [{active, once}]),
	{noreply, NewState, ?TIMEOUT};
handle_info({tcp, Socket, Packet}, #state{readmessage = true, envelope = Envelope} = State) ->
	%io:format("got message chunk \"~p\"~n", [Packet]),
	% if there's a leading dot, trim it off
	case Packet of
		"." ++ String ->
			String;
		String ->
			String
	end,
	inet:setopts(Socket, [{active, once}]),
	{noreply, State#state{envelope = Envelope#envelope{data = string:concat(Envelope#envelope.data, String)}}, ?TIMEOUT};
handle_info({tcp, Socket, Packet}, State) ->
	case handle_request(parse_request(Packet), State) of
		{ok, NewState} ->
			case NewState#state.socket of
				{ssl, SSLSocket} ->
					ssl:setopts(SSLSocket, [{active, once}]);
				Socket ->
					inet:setopts(Socket, [{active, once}])
			end,
			{noreply, NewState, ?TIMEOUT};
		{stop, Reason, NewState} ->
			{stop, Reason, NewState}
	end;
handle_info({ssl, Socket, Packet}, State) ->
	case handle_request(parse_request(Packet), State) of
		{ok, NewState} ->
			ssl:setopts(Socket, [{active, once}]),
			{noreply, NewState, ?TIMEOUT};
		{stop, Reason, NewState} ->
			{stop, Reason, NewState}
	end;
handle_info({tcp_closed, _Socket}, State) ->
	%io:format("Connection closed~n"),
	{stop, normal, State};
handle_info(timeout, #state{socket = {ssl, Socket}} = State) ->
	ssl:send(Socket, "421 Error: timeout exceeded\r\n"),
	ssl:close(Socket),
	{stop, normal, State};
handle_info(timeout, #state{socket = Socket} = State) ->
	gen_tcp:send(Socket, "421 Error: timeout exceeded\r\n"),
	gen_tcp:close(Socket),
	{stop, normal, State};
handle_info(Info, State) ->
	io:format("unhandled info message ~p~n", [Info]),
	{noreply, State}.

%% @hidden
-spec(terminate/2 :: (Reason :: any(), State :: #state{}) -> 'ok').
terminate(Reason, State) ->
	% io:format("Session terminating due to ~p~n", [Reason]),
	case State#state.socket of
		{ssl, Socket} ->
			ssl:close(Socket);
		Socket ->
			gen_tcp:close(Socket)
	end,
	ok.

%% @hidden
code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

-spec(parse_request/1 :: (Packet :: string()) -> {string(), list()}).
parse_request(Packet) ->
	Request = string:strip(string:strip(string:strip(string:strip(Packet, right, $\n), right, $\r), right, $\s), left, $\s),
	case string:str(Request, " ") of
		0 ->
			% io:format("got a ~s request~n", [Request]),
			case string:to_upper(Request) of
				"QUIT" -> {"QUIT", []};
				"DATA" -> {"DATA", []};
				% likely a base64-encoded client reply
				_      -> {Request, []}
			end;
		Index ->
			Verb = string:substr(Request, 1, Index - 1),
			Parameters = string:strip(string:substr(Request, Index + 1), left, $\s),
			%io:format("got a ~s request with parameters ~s~n", [Verb, Parameters]),
			{string:to_upper(Verb), Parameters}
	end.

-spec(handle_request/2 :: ({Verb :: string(), Args :: string()}, State :: #state{}) -> {'ok', #state{}} | {'stop', any(), #state{}}).
handle_request({[], _Any}, #state{socket = Socket} = State) ->
	socket_send(Socket, "500 Error: bad syntax\r\n"),
	{ok, State};
handle_request({"HELO", []}, #state{socket = Socket} = State) ->
	socket_send(Socket, "501 Syntax: HELO hostname\r\n"),
	{ok, State};
handle_request({"HELO", Hostname}, #state{socket = Socket, hostname = MyHostname, module = Module} = State) ->
	case Module:handle_HELO(Hostname, State#state.callbackstate) of
		{ok, CallbackState} ->
			socket_send(Socket, io_lib:format("250 ~s\r\n", [MyHostname])),
			{ok, State#state{envelope = #envelope{}, callbackstate = CallbackState}};
		{error, Message, CallbackState} ->
			socket_send(Socket, Message ++ "\r\n"),
			{ok, State#state{callbackstate = CallbackState}}
	end;
handle_request({"EHLO", []}, #state{socket = Socket} = State) ->
	socket_send(Socket, "501 Syntax: EHLO hostname\r\n"),
	{ok, State};
handle_request({"EHLO", Hostname}, #state{socket = Socket, hostname = MyHostname, module = Module} = State) ->
	case Module:handle_EHLO(Hostname, ?BUILTIN_EXTENSIONS, State#state.callbackstate) of
		{ok, Extensions, CallbackState} ->
			case Extensions of
				[] ->
					socket_send(Socket, io_lib:format("250 ~s\r\n", [MyHostname])),
					State#state{extensions = Extensions, callbackstate = CallbackState};
				_Else ->
					F =
					fun({E, true}, {Pos, Len, Acc}) when Pos =:= Len ->
							{Pos, Len, string:concat(string:concat(string:concat(Acc, "250 "), E), "\r\n")};
						({E, Value}, {Pos, Len, Acc}) when Pos =:= Len ->
							{Pos, Len, string:concat(Acc, io_lib:format("250 ~s ~s\r\n", [E, Value]))};
						({E, true}, {Pos, Len, Acc}) ->
							{Pos+1, Len, string:concat(string:concat(string:concat(Acc, "250-"), E), "\r\n")};
						({E, Value}, {Pos, Len, Acc}) ->
							{Pos+1, Len, string:concat(Acc, io_lib:format("250-~s ~s\r\n", [E, Value]))}
					end,
					Extensions2 = case State#state.tls of
						true ->
							Extensions -- [{"STARTTLS", true}];
						false ->
							Extensions
					end,
					{_, _, Response} = lists:foldl(F, {1, length(Extensions2), string:concat(string:concat("250-", MyHostname), "\r\n")}, Extensions2),
					socket_send(Socket, Response),
					{ok, State#state{extensions = Extensions2, envelope = #envelope{}, callbackstate = CallbackState}}
			end;
		{error, Message, CallbackState} ->
			socket_send(Socket, Message++"\r\n"),
			{ok, State#state{callbackstate = CallbackState}}
	end;

handle_request({"AUTH", _Args}, #state{envelope = undefined, socket = Socket} = State) ->
	socket_send(Socket, "503 Error: send EHLO first\r\n"),
	{ok, State};
handle_request({"AUTH", Args}, #state{socket = Socket, extensions = Extensions, envelope = Envelope} = State) ->
	case string:str(Args, " ") of
		0 ->
			AuthType = Args,
			Parameters = false;
		Index ->
			AuthType = string:substr(Args, 1, Index - 1),
			Parameters = string:strip(string:substr(Args, Index + 1), left, $\s)
	end,

	case has_extension(Extensions, "AUTH") of
		false ->
			socket_send(Socket, "502 Error: AUTH not implemented\r\n");
		{true, AvailableTypes} ->
			case lists:member(string:to_upper(AuthType), string:tokens(AvailableTypes, " ")) of
				false ->
					socket_send(Socket, "504 Unrecognized authentication type\r\n"),
					{ok, State};
				true ->
					case string:to_upper(AuthType) of
						"LOGIN" ->
							% gen_tcp:send(Socket, "334 " ++ base64:encode_to_string("Username:")),
							socket_send(Socket, "334 VXNlcm5hbWU6\r\n"),
							{ok, State#state{waitingauth = "LOGIN", envelope = Envelope#envelope{auth = {[], []}}}};
						"PLAIN" when Parameters =/= false ->
							% TODO - duplicated below in handle_request waitingauth PLAIN
							case string:tokens(base64:decode_to_string(Parameters), [0]) of
								[_Identity, Username, Password] ->
									try_auth('plain', Username, Password, State);
								[Username, Password] ->
									try_auth('plain', Username, Password, State);
								_ ->
									% TODO error
									{ok, State}
							end;
						"PLAIN" ->
							socket_send(Socket, "334\r\n"),
							{ok, State#state{waitingauth = "PLAIN", envelope = Envelope#envelope{auth = {[], []}}}};
						"CRAM-MD5" ->
							crypto:start(), % ensure crypto is started, we're gonna need it
							String = get_cram_string(State#state.hostname),
							socket_send(Socket, "334 "++String++"\r\n"),
							{ok, State#state{waitingauth = "CRAM-MD5", authdata=base64:decode_to_string(String), envelope = Envelope#envelope{auth = {[], []}}}}
						%"DIGEST-MD5" -> % TODO finish this? (see rfc 2831)
							%crypto:start(), % ensure crypto is started, we're gonna need it
							%Nonce = get_digest_nonce(),
							%Response = io_lib:format("nonce=\"~s\",realm=\"~s\",qop=\"auth\",algorithm=md5-sess,charset=utf-8", Nonce, State#state.hostname),
							%gen_tcp:send(Socket, "334 "++Response++"\r\n"),
							%{ok, State#state{waitingauth = "DIGEST-MD5", authdata=base64:decode_to_string(Nonce), envelope = Envelope#envelope{auth = {[], []}}}}
					end
			end
	end;

% the client sends a response to auth-cram-md5
handle_request({Username64, []}, #state{socket = Socket, waitingauth = "CRAM-MD5", envelope = #envelope{auth = {[],[]}}} = State) ->
	case string:tokens(base64:decode_to_string(Username64), " ") of
		[Username, Digest] ->
			try_auth('cram-md5', Username, {Digest, State#state.authdata}, State#state{authdata=undefined});
		_ ->
			% TODO error
			{ok, State#state{waitingauth=false, authdata=undefined}}
	end;

% the client sends a \0username\0password response to auth-plain
handle_request({Username64, []}, #state{socket = Socket, waitingauth = "PLAIN", envelope = #envelope{auth = {[],[]}}} = State) ->
	case string:tokens(base64:decode_to_string(Username64), [0]) of
		[_Identity, Username, Password] ->
			try_auth('plain', Username, Password, State);
		[Username, Password] ->
			try_auth('plain', Username, Password, State);
		_ ->
			% TODO error
			{ok, State#state{waitingauth=false}}
	end;

% the client sends a username response to auth-login
handle_request({Username64, []}, #state{socket = Socket, waitingauth = "LOGIN", envelope = #envelope{auth = {[],[]}}} = State) ->
	Envelope = State#state.envelope,
	Username = base64:decode_to_string(Username64),
	% gen_tcp:send(Socket, "334 " ++ base64:encode_to_string("Password:")),
	socket_send(Socket, "334 UGFzc3dvcmQ6\r\n"),
	% store the provided username in envelope.auth
	NewState = State#state{envelope = Envelope#envelope{auth = {Username, []}}},
	{ok, NewState};

% the client sends a password response to auth-login
handle_request({Password64, []}, #state{socket = Socket, waitingauth = "LOGIN", module = Module, envelope = #envelope{auth = {Username,[]}}} = State) ->
	Password = base64:decode_to_string(Password64),
	try_auth('login', Username, Password, State);

handle_request({"MAIL", _Args}, #state{envelope = undefined, socket = Socket} = State) ->
	socket_send(Socket, "503 Error: send HELO/EHLO first\r\n"),
	{ok, State};
handle_request({"MAIL", Args}, #state{socket = Socket, module = Module, envelope = Envelope} = State) ->
	case Envelope#envelope.from of
		undefined ->
			case string:str(string:to_upper(Args), "FROM:") of
				1 ->
					Address = string:strip(string:substr(Args, 6), left, $\s),
					case parse_encoded_address(Address) of
						error ->
							socket_send(Socket, "501 Bad sender address syntax\r\n"),
							{ok, State};
						{ParsedAddress, []} ->
							%io:format("From address ~s (parsed as ~s)~n", [Address, ParsedAddress]),
							case Module:handle_MAIL(ParsedAddress, State#state.callbackstate) of
								{ok, CallbackState} ->
									socket_send(Socket, "250 sender Ok\r\n"),
									{ok, State#state{envelope = Envelope#envelope{from = ParsedAddress}, callbackstate = CallbackState}};
								{error, Message, CallbackState} ->
									socket_send(Socket, Message ++ "\r\n"),
									{ok, State#state{callbackstate = CallbackState}}
							end;
						{ParsedAddress, ExtraInfo} ->
							%io:format("From address ~s (parsed as ~s) with extra info ~s~n", [Address, ParsedAddress, ExtraInfo]),
							Options = lists:map(fun(X) -> string:to_upper(X) end, string:tokens(ExtraInfo, " ")),
							%io:format("options are ~p~n", [Options]),
							 F = fun(_, {error, Message}) ->
									 {error, Message};
								 ("SIZE="++Size, InnerState) ->
									case has_extension(State#state.extensions, "SIZE") of
										{true, Value} ->
											case list_to_integer(Size) > list_to_integer(Value) of
												true ->
													{error, io_lib:format("552 Estimated message length ~s exceeds limit of ~s\r\n", [Size, Value])};
												false ->
													InnerState#state{envelope = Envelope#envelope{expectedsize = list_to_integer(Size)}}
											end;
										false ->
											{error, "555 Unsupported option SIZE\r\n"}
									end;
								("BODY="++_BodyType, InnerState) ->
									case has_extension(State#state.extensions, "8BITMIME") of
										{true, _} ->
											InnerState;
										false ->
											{error, "555 Unsupported option BODY\r\n"}
									end;
								(X, InnerState) ->
									case Module:handle_MAIL_extension(X, InnerState#state.callbackstate) of
										{ok, CallbackState} ->
											InnerState#state{callbackstate = CallbackState};
										error ->
											{error, io_lib:format("555 Unsupported option: ~s\r\n", [ExtraInfo])}
									end
							end,
							case lists:foldl(F, State, Options) of
								{error, Message} ->
									%io:format("error: ~s~n", [Message]),
									socket_send(Socket, Message),
									{ok, State};
								NewState ->
									%io:format("OK~n"),
									case Module:handle_MAIL(ParsedAddress, State#state.callbackstate) of
										{ok, CallbackState} ->
											socket_send(Socket, "250 sender Ok\r\n"),
											{ok, State#state{envelope = Envelope#envelope{from = ParsedAddress}, callbackstate = CallbackState}};
										{error, Message, CallbackState} ->
											socket_send(Socket, Message ++ "\r\n"),
											{ok, NewState#state{callbackstate = CallbackState}}
									end
							end
					end;
				_Else ->
					socket_send(Socket, "501 Syntax: MAIL FROM:<address>\r\n"),
					{ok, State}
			end;
		_Other ->
			socket_send(Socket, "503 Error: Nested MAIL command\r\n"),
			{ok, State}
	end;
handle_request({"RCPT", _Args}, #state{envelope = undefined, socket = Socket} = State) ->
	socket_send(Socket, "503 Error: need MAIL command\r\n"),
	{ok, State};
handle_request({"RCPT", Args}, #state{socket = Socket, envelope = Envelope, module = Module} = State) ->
	case string:str(string:to_upper(Args), "TO:") of
		1 ->
			Address = string:strip(string:substr(Args, 4), left, $\s),
			case parse_encoded_address(Address) of
				error ->
					socket_send(Socket, "501 Bad recipient address syntax\r\n"),
					{ok, State};
				{[], _} ->
					% empty rcpt to addresses aren't cool
					socket_send(Socket, "501 Bad recipient address syntax\r\n"),
					{ok, State};
				{ParsedAddress, []} ->
					%io:format("To address ~s (parsed as ~s)~n", [Address, ParsedAddress]),
					case Module:handle_RCPT(ParsedAddress, State#state.callbackstate) of
						{ok, CallbackState} ->
							socket_send(Socket, "250 recipient Ok\r\n"),
							{ok, State#state{envelope = Envelope#envelope{to = lists:append(Envelope#envelope.to, [ParsedAddress])}, callbackstate = CallbackState}};
						{error, Message, CallbackState} ->
							socket_send(Socket, Message++"\r\n"),
							{ok, State#state{callbackstate = CallbackState}}
					end;
				{ParsedAddress, ExtraInfo} ->
					% TODO - are there even any RCPT extensions?
					io:format("To address ~s (parsed as ~s) with extra info ~s~n", [Address, ParsedAddress, ExtraInfo]),
					socket_send(Socket, io_lib:format("555 Unsupported option: ~s\r\n", [ExtraInfo])),
					{ok, State}
			end;
		_Else ->
			socket_send(Socket, "501 Syntax: RCPT TO:<address>\r\n"),
			{ok, State}
	end;
handle_request({"DATA", []}, #state{socket = Socket, envelope = undefined} = State) ->
	socket_send(Socket, "503 Error: send HELO/EHLO first\r\n"),
	{ok, State};
handle_request({"DATA", []}, #state{socket = Socket, envelope = Envelope} = State) ->
	case {Envelope#envelope.from, Envelope#envelope.to} of
		{undefined, _} ->
			socket_send(Socket, "503 Error: need MAIL command\r\n"),
			{ok, State};
		{_, []} ->
			socket_send(Socket, "503 Error: need RCPT command\r\n"),
			{ok, State};
		_Else ->
			socket_send(Socket, "354 enter mail, end with line containing only '.'\r\n"),
			%io:format("switching to data read mode~n"),
			{ok, State#state{readheaders = true}}
	end;
handle_request({"RSET", _Any}, #state{socket = Socket, envelope = Envelope, module = Module} = State) ->
	socket_send(Socket, "250 Ok\r\n"),
	% if the client sends a RSET before a HELO/EHLO don't give them a valid envelope
	NewEnvelope = case Envelope of
		undefined -> undefined;
		_Something -> #envelope{}
	end,
	{ok, State#state{envelope = NewEnvelope, callbackstate = Module:handle_RSET(State#state.callbackstate)}};
handle_request({"NOOP", _Any}, #state{socket = Socket} = State) ->
	socket_send(Socket, "250 Ok\r\n"),
	{ok, State};
handle_request({"QUIT", _Any}, #state{socket = Socket} = State) ->
	socket_send(Socket, "221 Bye\r\n"),
	{stop, normal, State};
handle_request({"VRFY", Address}, #state{module= Module, socket = Socket} = State) ->
	case parse_encoded_address(Address) of
		{ParsedAddress, []} ->
			case Module:handle_VRFY(Address, State#state.callbackstate) of
				{ok, Reply, CallbackState} ->
					socket_send(Socket, io_lib:format("250 ~s\r\n", [Reply])),
					{ok, State#state{callbackstate = CallbackState}};
				{error, Message, CallbackState} ->
					socket_send(Socket, Message++"\r\n"),
					{ok, State#state{callbackstate = CallbackState}}
			end;
		_Other ->
			socket_send(Socket, "501 Syntax: VRFY username/address\r\n"),
			{ok, State}
	end;
handle_request({"STARTTLS", []}, #state{module = Module, socket = Socket, tls=false} = State) ->
	case has_extension(State#state.extensions, "STARTTLS") of
		{true, _} ->
			gen_tcp:send(Socket, "220 OK\r\n"),
			crypto:start(),
			application:start(ssl),
			% TODO: certfile and keyfile should be at configurable locations
			case ssl:ssl_accept(Socket, [{ssl_imp, new}, {depth, 0}, {certfile, "server.crt"}, {keyfile, "server.key"}], 5000) of
				{ok, NewSocket} ->
					io:format("SSL negotiation sucessful~n"),
					{ok, State#state{socket = {ssl, NewSocket}, envelope=undefined,
							authdata=undefined, waitingauth=false, readmessage=false,
							readheaders=false, tls=true}};
				{error, Reason} ->
					io:format("SSL handshake failed : ~p~n", [Reason]),
					socket_send(Socket, "454 TLS negotiation failed\r\n"),
					{ok, State}
			end;
		false ->
			socket_send(Socket, "500 Command unrecognized\r\n"),
			{ok, State}
	end;
handle_request({"STARTTLS", []}, #state{module = Module, socket = Socket} = State) ->
	socket_send(Socket, "500 TLS already negotiated\r\n"),
	{ok, State};
handle_request({"STARTTLS", Args}, #state{module = Module, socket = Socket} = State) ->
	socket_send(Socket, "501 Syntax error (no parameters allowed)\r\n"),
	{ok, State};
handle_request({Verb, Args}, #state{socket = Socket, module = Module} = State) ->
	{Message, CallbackState} = Module:handle_other(Verb, Args, State#state.callbackstate),
	socket_send(Socket, Message++"\r\n"),
	{ok, State#state{callbackstate = CallbackState}}.

-spec(parse_encoded_address/1 :: (Address :: string()) -> {string(), string()} | 'error').
parse_encoded_address([]) ->
	error; % empty
parse_encoded_address("<@" ++ Address) ->
	case string:str(Address, ":") of
		0 ->
			error; % invalid address
		Index ->
			parse_encoded_address(string:substr(Address, Index + 1), "", {false, true})
	end;
parse_encoded_address("<" ++ Address) ->
	parse_encoded_address(Address, "", {false, true});
parse_encoded_address(" " ++ Address) ->
	parse_encoded_address(Address);
parse_encoded_address(Address) ->
	parse_encoded_address(Address, "", {false, false}).

-spec(parse_encoded_address/3 :: (Address :: string(), Acc :: string(), Flags :: {bool(), bool()}) -> {string(), string()}).
parse_encoded_address([], Acc, {_Quotes, false}) ->
	{lists:reverse(Acc), []};
parse_encoded_address([], _Acc, {_Quotes, true}) ->
	error; % began with angle brackets but didn't end with them
parse_encoded_address(_, Acc, _) when length(Acc) > 129 ->
	error; % too long
parse_encoded_address([$\\ | Tail], Acc, Flags) ->
	[H | NewTail] = Tail,
	parse_encoded_address(NewTail, [H | Acc], Flags);
parse_encoded_address([$" | Tail], Acc, {false, AB}) ->
	parse_encoded_address(Tail, Acc, {true, AB});
parse_encoded_address([$" | Tail], Acc, {true, AB}) ->
	parse_encoded_address(Tail, Acc, {false, AB});
parse_encoded_address([$> | Tail], Acc, {false, true}) ->
	{lists:reverse(Acc), string:strip(Tail, left, $\s)};
parse_encoded_address([$> | _Tail], _Acc, {false, false}) ->
	error; % ended with angle brackets but didn't begin with them
parse_encoded_address([$\s | Tail], Acc, {false, false}) ->
	{lists:reverse(Acc), string:strip(Tail, left, $\s)};
parse_encoded_address([$\s | _Tail], _Acc, {false, true}) ->
	error; % began with angle brackets but didn't end with them
parse_encoded_address([H | Tail], Acc, {false, AB}) when H >= $0, H =< $9 ->
	parse_encoded_address(Tail, [H | Acc], {false, AB}); % digits
parse_encoded_address([H | Tail], Acc, {false, AB}) when H >= $@, H =< $Z ->
	parse_encoded_address(Tail, [H | Acc], {false, AB}); % @ symbol and uppercase letters
parse_encoded_address([H | Tail], Acc, {false, AB}) when H >= $a, H =< $z ->
	parse_encoded_address(Tail, [H | Acc], {false, AB}); % lowercase letters
parse_encoded_address([H | Tail], Acc, {false, AB}) when H =:= $-; H =:= $.; H =:= $_ ->
	parse_encoded_address(Tail, [H | Acc], {false, AB}); % dash, dot, underscore
parse_encoded_address([_H | _Tail], _Acc, {false, _AB}) ->
	error;
parse_encoded_address([H | Tail], Acc, Quotes) ->
	parse_encoded_address(Tail, [H | Acc], Quotes).

-spec(has_extension/2 :: (Extensions :: [{string(), string()}], Extension :: string()) -> {'true', string()} | 'false').
has_extension(Exts, Ext) ->
	Extension = string:to_upper(Ext),
	Extensions = lists:map(fun({X, Y}) -> {string:to_upper(X), Y} end, Exts),
	%io:format("extensions ~p~n", [Extensions]),
	case proplists:get_value(Extension, Extensions) of
		undefined ->
			false;
		Value ->
			{true, Value}
	end.

-spec(trim_crlf/1 :: (String :: string()) -> string()).
trim_crlf(String) ->
	string:strip(string:strip(String, right, $\n), right, $\r).

-spec(try_auth/4 :: (AuthType :: 'login' | 'plain' | 'cram-md5', Username :: string(), Credential :: string() | {string(), string()}, State :: #state{}) -> {'ok', #state{}}).
try_auth(AuthType, Username, Credential, #state{module = Module, socket = Socket, envelope = Envelope} = State) ->
	% clear out waiting auth
	NewState = State#state{waitingauth = false, envelope = Envelope#envelope{auth = {[], []}}},
	case erlang:function_exported(Module, handle_AUTH, 4) of
		true ->
			case Module:handle_AUTH(AuthType, Username, Credential, State#state.callbackstate) of
				{ok, CallbackState} ->
					socket_send(Socket, "235 Authentication successful.\r\n"),
					{ok, NewState#state{callbackstate = CallbackState,
					                    envelope = Envelope#envelope{auth = {Username, Credential}}}};
				Other ->
					socket_send(Socket, "535 Authentication failed.\r\n"),
					{ok, NewState}
				end;
		false ->
			io:format("Please define handle_AUTH/4 in your server module or remove AUTH from your module extensions~n"),
			socket_send(Socket, "535 authentication failed (#5.7.1)\r\n"),
			{ok, NewState}
	end.

-spec(get_cram_string/1 :: (Hostname :: string()) -> string()).
get_cram_string(Hostname) ->
	binary_to_list(base64:encode(lists:flatten(io_lib:format("<~B.~B@~s>", [crypto:rand_uniform(0, 4294967295), crypto:rand_uniform(0, 4294967295), Hostname])))).
%get_digest_nonce() ->
	%A = [io_lib:format("~2.16.0b", [X]) || <<X>> <= erlang:md5(integer_to_list(crypto:rand_uniform(0, 4294967295)))],
	%B = [io_lib:format("~2.16.0b", [X]) || <<X>> <= erlang:md5(integer_to_list(crypto:rand_uniform(0, 4294967295)))],
	%binary_to_list(base64:encode(lists:flatten(A ++ B))).

-spec(compute_cram_digest/2 :: (Key :: binary(), Data :: string()) -> string()).
compute_cram_digest(Key, Data) ->
	Bin = crypto:md5_mac(Key, Data),
	lists:flatten([io_lib:format("~2.16.0b", [X]) || <<X>> <= Bin]).

socket_send({ssl, Socket}, Message) ->
	ssl:send(Socket, Message);
socket_send(Socket, Message) ->
	gen_tcp:send(Socket, Message).

-ifdef(EUNIT).
parse_encoded_address_test_() ->
	[
		{"Valid addresses should parse",
			fun() ->
					?assertEqual({"God@heaven.af.mil", []}, parse_encoded_address("<God@heaven.af.mil>")),
					?assertEqual({"God@heaven.af.mil", []}, parse_encoded_address("<\\God@heaven.af.mil>")),
					?assertEqual({"God@heaven.af.mil", []}, parse_encoded_address("<\"God\"@heaven.af.mil>")),
					?assertEqual({"God@heaven.af.mil", []}, parse_encoded_address("<@gateway.af.mil,@uucp.local:\"\\G\\o\\d\"@heaven.af.mil>")),
					?assertEqual({"God2@heaven.af.mil", []}, parse_encoded_address("<God2@heaven.af.mil>"))
			end
		},
		{"Addresses that are sorta valid should parse",
			fun() ->
					?assertEqual({"God@heaven.af.mil", []}, parse_encoded_address("God@heaven.af.mil")),
					?assertEqual({"God@heaven.af.mil", []}, parse_encoded_address("God@heaven.af.mil ")),
					?assertEqual({"God@heaven.af.mil", []}, parse_encoded_address(" God@heaven.af.mil ")),
					?assertEqual({"God@heaven.af.mil", []}, parse_encoded_address(" <God@heaven.af.mil> "))
			end
		},
		{"Addresses containing unescaped <> that aren't at start/end should fail",
			fun() ->
					?assertEqual(error, parse_encoded_address("<<")),
					?assertEqual(error, parse_encoded_address("<God<@heaven.af.mil>"))
			end
		},
		{"Address that begins with < but doesn't end with a > should fail",
			fun() ->
					?assertEqual(error, parse_encoded_address("<God@heaven.af.mil")),
					?assertEqual(error, parse_encoded_address("<God@heaven.af.mil "))
			end
		},
		{"Address that begins without < but ends with a > should fail",
			fun() ->
					?assertEqual(error, parse_encoded_address("God@heaven.af.mil>"))
			end
		},
		{"Address longer than 129 character should fail",
			fun() ->
					MegaAddress = lists:seq(97, 122) ++ lists:seq(97, 122) ++ lists:seq(97, 122) ++ "@" ++ lists:seq(97, 122) ++ lists:seq(97, 122),
					?assertEqual(error, parse_encoded_address(MegaAddress))
			end
		},
		{"Address with an invalid route should fail",
			fun() ->
					?assertEqual(error, parse_encoded_address("<@gateway.af.mil God@heaven.af.mil>"))
			end
		},
		{"Empty addresses should parse OK",
			fun() ->
					?assertEqual({[], []}, parse_encoded_address("<>")),
					?assertEqual({[], []}, parse_encoded_address(" <> "))
			end
		},
		{"Completely empty addresses are an error",
			fun() ->
					?assertEqual(error, parse_encoded_address("")),
					?assertEqual(error, parse_encoded_address(" "))
			end
		},
		{"addresses with trailing parameters should return the trailing parameters",
			fun() ->
					?assertEqual({"God@heaven.af.mil", "SIZE=100 BODY=8BITMIME"}, parse_encoded_address("<God@heaven.af.mil> SIZE=100 BODY=8BITMIME"))
			end
		}
	].

parse_request_test_() ->
	[
		{"Parsing normal SMTP requests",
			fun() ->
					?assertEqual({"HELO", []}, parse_request("HELO")),
					?assertEqual({"EHLO", "hell.af.mil"}, parse_request("EHLO hell.af.mil")),
					?assertEqual({"MAIL", "FROM:God@heaven.af.mil"}, parse_request("MAIL FROM:God@heaven.af.mil"))
			end
		},
		{"Verbs should be uppercased",
			fun() ->
					?assertEqual({"HELO", "hell.af.mil"}, parse_request("helo hell.af.mil"))
			end
		},
		{"Leading and trailing spaces are removed",
			fun() ->
					?assertEqual({"HELO", "hell.af.mil"}, parse_request(" helo   hell.af.mil           "))
			end
		},
		{"Blank lines are blank",
			fun() ->
					?assertEqual({[], []}, parse_request(""))
			end
		}
	].

smtp_session_test_() ->
	{foreach,
		local,
		fun() ->
				Self = self(),
				spawn(fun() ->
							{ok, ListenSock} = gen_tcp:listen(9876, [list, {packet, line}, {reuseaddr, true}, {keepalive, true}, {backlog, 30}, {active, false}]),
							{ok, X} = gen_tcp:accept(ListenSock),
							inet:setopts(X, [list, {packet, line}, {reuseaddr, true}, {keepalive, true}, {backlog, 30}, {active, false}]),
							gen_tcp:controlling_process(X, Self),
							Self ! X
					end),
				{ok, CSock} = gen_tcp:connect("localhost", 9876,  [list, {packet, line}, {active, false}]),
				receive
					SSock when is_port(SSock) ->
						?debugFmt("Got server side of the socket ~p, client is ~p~n", [SSock, CSock])
				end,
				{ok, Pid} = gen_smtp_server_session:start(SSock, smtp_server_example, "localhost", 1),
				gen_tcp:controlling_process(SSock, Pid),
				{CSock, Pid}
		end,
		fun({CSock, _Pid}) ->
				gen_tcp:close(CSock)
		end,
		[fun({CSock, _Pid}) ->
					{"A new connection should get a banner",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> ok end,
								?assertMatch("220 localhost"++_Stuff,  Packet)
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"A correct response to HELO",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "HELO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250 localhost\r\n",  Packet2)
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"An error in response to an invalid HELO",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "HELO\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("501 Syntax: HELO hostname\r\n",  Packet2)
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"A rejected HELO",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "HELO invalid\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("554 invalid hostname\r\n",  Packet2)
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"A rejected EHLO",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO invalid\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("554 invalid hostname\r\n",  Packet2)
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"EHLO response",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F) ->
										receive
											{tcp, CSock, "250-"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F);
											{tcp, CSock, "250 "++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												ok;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(ok, Foo(Foo))
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"Unsupported AUTH PLAIN",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F) ->
										receive
											{tcp, CSock, "250-"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F);
											{tcp, CSock, "250"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												ok;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(ok, Foo(Foo)),
								gen_tcp:send(CSock, "AUTH PLAIN\r\n"),
								receive {tcp, CSock, Packet4} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("502 Error: AUTH not implemented\r\n",  Packet4)
						end
					}
			end
		]
	}.

smtp_session_auth_test_() ->
	{foreach,
		local,
		fun() ->
				Self = self(),
				spawn(fun() ->
							{ok, ListenSock} = gen_tcp:listen(9876, [list, {packet, line}, {reuseaddr, true}, {keepalive, true}, {backlog, 30}, {active, false}]),
							{ok, X} = gen_tcp:accept(ListenSock),
							inet:setopts(X, [list, {packet, line}, {reuseaddr, true}, {keepalive, true}, {backlog, 30}, {active, false}]),
							gen_tcp:controlling_process(X, Self),
							Self ! X
					end),
				{ok, CSock} = gen_tcp:connect("localhost", 9876,  [list, {packet, line}, {active, false}]),
				receive
					SSock when is_port(SSock) ->
						?debugFmt("Got server side of the socket ~p, client is ~p~n", [SSock, CSock])
				end,
				{ok, Pid} = gen_smtp_server_session:start(SSock, smtp_server_example_auth, "localhost", 1),
				gen_tcp:controlling_process(SSock, Pid),
				{CSock, Pid}
		end,
		fun({CSock, _Pid}) ->
				gen_tcp:close(CSock)
		end,
		[fun({CSock, _Pid}) ->
					{"EHLO response includes AUTH",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F, Acc) ->
										receive
											{tcp, CSock, "250-AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, true);
											{tcp, CSock, "250-"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, Acc);
											{tcp, CSock, "250 AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												true;
											{tcp, CSock, "250 "++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												Acc;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(true, Foo(Foo, false))
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"AUTH before EHLO is error",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "AUTH CRAZY\r\n"),
								receive {tcp, CSock, Packet4} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("503 "++_,  Packet4)
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"Unknown authentication type",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F, Acc) ->
										receive
											{tcp, CSock, "250-AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, true);
											{tcp, CSock, "250-"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, Acc);
											{tcp, CSock, "250 AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												true;
											{tcp, CSock, "250 "++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												Acc;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(true, Foo(Foo, false)),
								gen_tcp:send(CSock, "AUTH CRAZY\r\n"),
								receive {tcp, CSock, Packet4} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("504 Unrecognized authentication type\r\n",  Packet4)
						end
					}
			end,

			fun({CSock, _Pid}) ->
					{"A successful AUTH PLAIN",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F, Acc) ->
										receive
											{tcp, CSock, "250-AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, true);
											{tcp, CSock, "250-"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, Acc);
											{tcp, CSock, "250 AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												true;
											{tcp, CSock, "250 "++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												Acc;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(true, Foo(Foo, false)),
								gen_tcp:send(CSock, "AUTH PLAIN\r\n"),
								receive {tcp, CSock, Packet4} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("334\r\n",  Packet4),
								String = binary_to_list(base64:encode("\0username\0PaSSw0rd")),
								gen_tcp:send(CSock, String++"\r\n"),
								receive {tcp, CSock, Packet5} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("235 Authentication successful.\r\n",  Packet5)
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"A successful AUTH PLAIN with an identity",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F, Acc) ->
										receive
											{tcp, CSock, "250-AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, true);
											{tcp, CSock, "250-"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, Acc);
											{tcp, CSock, "250 AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												true;
											{tcp, CSock, "250 "++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												Acc;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(true, Foo(Foo, false)),
								gen_tcp:send(CSock, "AUTH PLAIN\r\n"),
								receive {tcp, CSock, Packet4} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("334\r\n",  Packet4),
								String = binary_to_list(base64:encode("username\0username\0PaSSw0rd")),
								gen_tcp:send(CSock, String++"\r\n"),
								receive {tcp, CSock, Packet5} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("235 Authentication successful.\r\n",  Packet5)
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"A successful immediate AUTH PLAIN",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F, Acc) ->
										receive
											{tcp, CSock, "250-AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, true);
											{tcp, CSock, "250-"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, Acc);
											{tcp, CSock, "250 AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												true;
											{tcp, CSock, "250 "++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												Acc;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(true, Foo(Foo, false)),
								String = binary_to_list(base64:encode("\0username\0PaSSw0rd")),
								gen_tcp:send(CSock, "AUTH PLAIN "++String++"\r\n"),
								receive {tcp, CSock, Packet5} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("235 Authentication successful.\r\n",  Packet5)
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"A successful immediate AUTH PLAIN with an identity",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F, Acc) ->
										receive
											{tcp, CSock, "250-AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, true);
											{tcp, CSock, "250-"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, Acc);
											{tcp, CSock, "250 AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												true;
											{tcp, CSock, "250 "++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												Acc;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(true, Foo(Foo, false)),
								String = binary_to_list(base64:encode("username\0username\0PaSSw0rd")),
								gen_tcp:send(CSock, "AUTH PLAIN "++String++"\r\n"),
								receive {tcp, CSock, Packet5} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("235 Authentication successful.\r\n",  Packet5)
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"An unsuccessful immediate AUTH PLAIN",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F, Acc) ->
										receive
											{tcp, CSock, "250-AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, true);
											{tcp, CSock, "250-"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, Acc);
											{tcp, CSock, "250 AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												true;
											{tcp, CSock, "250 "++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												Acc;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(true, Foo(Foo, false)),
								String = binary_to_list(base64:encode("username\0username\0PaSSw0rd2")),
								gen_tcp:send(CSock, "AUTH PLAIN "++String++"\r\n"),
								receive {tcp, CSock, Packet5} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("535 Authentication failed.\r\n",  Packet5)
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"An unsuccessful AUTH PLAIN",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F, Acc) ->
										receive
											{tcp, CSock, "250-AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, true);
											{tcp, CSock, "250-"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, Acc);
											{tcp, CSock, "250 AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												true;
											{tcp, CSock, "250 "++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												Acc;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(true, Foo(Foo, false)),
								gen_tcp:send(CSock, "AUTH PLAIN\r\n"),
								receive {tcp, CSock, Packet4} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("334\r\n",  Packet4),
								String = binary_to_list(base64:encode("\0username\0NotThePassword")),
								gen_tcp:send(CSock, String++"\r\n"),
								receive {tcp, CSock, Packet5} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("535 Authentication failed.\r\n",  Packet5)
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"A successful AUTH LOGIN",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F, Acc) ->
										receive
											{tcp, CSock, "250-AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, true);
											{tcp, CSock, "250-"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, Acc);
											{tcp, CSock, "250 AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												true;
											{tcp, CSock, "250 "++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												Acc;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(true, Foo(Foo, false)),
								gen_tcp:send(CSock, "AUTH LOGIN\r\n"),
								receive {tcp, CSock, Packet4} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("334 VXNlcm5hbWU6\r\n",  Packet4),
								String = binary_to_list(base64:encode("username")),
								gen_tcp:send(CSock, String++"\r\n"),
								receive {tcp, CSock, Packet5} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("334 UGFzc3dvcmQ6\r\n",  Packet5),
								PString = binary_to_list(base64:encode("PaSSw0rd")),
								gen_tcp:send(CSock, PString++"\r\n"),
								receive {tcp, CSock, Packet6} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("235 Authentication successful.\r\n",  Packet6)
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"An unsuccessful AUTH LOGIN",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F, Acc) ->
										receive
											{tcp, CSock, "250-AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, true);
											{tcp, CSock, "250-"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, Acc);
											{tcp, CSock, "250 AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												true;
											{tcp, CSock, "250 "++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												Acc;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(true, Foo(Foo, false)),
								gen_tcp:send(CSock, "AUTH LOGIN\r\n"),
								receive {tcp, CSock, Packet4} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("334 VXNlcm5hbWU6\r\n",  Packet4),
								String = binary_to_list(base64:encode("username2")),
								gen_tcp:send(CSock, String++"\r\n"),
								receive {tcp, CSock, Packet5} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("334 UGFzc3dvcmQ6\r\n",  Packet5),
								PString = binary_to_list(base64:encode("PaSSw0rd")),
								gen_tcp:send(CSock, PString++"\r\n"),
								receive {tcp, CSock, Packet6} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("535 Authentication failed.\r\n",  Packet6)
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"A successful AUTH CRAM-MD5",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F, Acc) ->
										receive
											{tcp, CSock, "250-AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, true);
											{tcp, CSock, "250-"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, Acc);
											{tcp, CSock, "250 AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												true;
											{tcp, CSock, "250 "++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												Acc;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(true, Foo(Foo, false)),
								gen_tcp:send(CSock, "AUTH CRAM-MD5\r\n"),
								receive {tcp, CSock, Packet4} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("334 "++_,  Packet4),

								["334", Seed64] = string:tokens(trim_crlf(Packet4), " "),
								Seed = base64:decode_to_string(Seed64),
								Digest = compute_cram_digest("PaSSw0rd", Seed),
								String = binary_to_list(base64:encode("username "++Digest)),
								gen_tcp:send(CSock, String++"\r\n"),
								receive {tcp, CSock, Packet5} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("235 Authentication successful.\r\n",  Packet5)
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"An unsuccessful AUTH CRAM-MD5",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F, Acc) ->
										receive
											{tcp, CSock, "250-AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, true);
											{tcp, CSock, "250-"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, Acc);
											{tcp, CSock, "250 AUTH"++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												true;
											{tcp, CSock, "250 "++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												Acc;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(true, Foo(Foo, false)),
								gen_tcp:send(CSock, "AUTH CRAM-MD5\r\n"),
								receive {tcp, CSock, Packet4} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("334 "++_,  Packet4),

								["334", Seed64] = string:tokens(trim_crlf(Packet4), " "),
								Seed = base64:decode_to_string(Seed64),
								Digest = compute_cram_digest("Passw0rd", Seed),
								String = binary_to_list(base64:encode("username "++Digest)),
								gen_tcp:send(CSock, String++"\r\n"),
								receive {tcp, CSock, Packet5} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("535 Authentication failed.\r\n",  Packet5)
						end
					}
			end
		]
	}.

smtp_session_tls_test_() ->
	{foreach,
		local,
		fun() ->
				Self = self(),
				spawn(fun() ->
							{ok, ListenSock} = gen_tcp:listen(9876, [list, {packet, line}, {reuseaddr, true}, {keepalive, true}, {backlog, 30}, {active, false}]),
							{ok, X} = gen_tcp:accept(ListenSock),
							inet:setopts(X, [list, {packet, line}, {reuseaddr, true}, {keepalive, true}, {backlog, 30}, {active, false}]),
							gen_tcp:controlling_process(X, Self),
							Self ! X
					end),
				{ok, CSock} = gen_tcp:connect("localhost", 9876,  [list, {packet, line}, {active, false}]),
				receive
					SSock when is_port(SSock) ->
						?debugFmt("Got server side of the socket ~p, client is ~p~n", [SSock, CSock])
				end,
				{ok, Pid} = gen_smtp_server_session:start(SSock, smtp_server_example_auth, "localhost", 1),
				gen_tcp:controlling_process(SSock, Pid),
				{CSock, Pid}
		end,
		fun({CSock, _Pid}) ->
				gen_tcp:close(CSock)
		end,
		[fun({CSock, _Pid}) ->
					{"EHLO response includes STARTTLS",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F, Acc) ->
										receive
											{tcp, CSock, "250-STARTTLS"++_} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, true);
											{tcp, CSock, "250-"++Packet3} ->
												?debugFmt("XX~sXX", [Packet3]),
												inet:setopts(CSock, [{active, once}]),
												F(F, Acc);
											{tcp, CSock, "250 STARTTLS"++_} ->
												inet:setopts(CSock, [{active, once}]),
												true;
											{tcp, CSock, "250 "++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												Acc;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(true, Foo(Foo, false))
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"STARTTLS does a SSL handshake",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F, Acc) ->
										receive
											{tcp, CSock, "250-STARTTLS"++_} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, true);
											{tcp, CSock, "250-"++Packet3} ->
												?debugFmt("XX~sXX", [Packet3]),
												inet:setopts(CSock, [{active, once}]),
												F(F, Acc);
											{tcp, CSock, "250 STARTTLS"++_} ->
												inet:setopts(CSock, [{active, once}]),
												true;
											{tcp, CSock, "250 "++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												Acc;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(true, Foo(Foo, false)),
								gen_tcp:send(CSock, "STARTTLS\r\n"),
								receive {tcp, CSock, Packet4} -> ok end,
								?assertMatch("220 "++_,  Packet4),
								application:start(ssl),
								Result = ssl:connect(CSock, [{ssl_impl, new}]),
								?assertMatch({ok, Socket}, Result),
								{ok, Socket} = Result
								%ssl:setopts(Socket, [{active, once}]),
								%ssl:send(Socket, "EHLO somehost.com\r\n"),
								%receive {ssl, Socket, Packet5} -> ssl:setopts(Socket, [{active, once}]) end,
								%?assertEqual("Foo", Packet5),
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"After STARTTLS, EHLO doesn't report STARTTLS",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F, Acc) ->
										receive
											{tcp, CSock, "250-STARTTLS"++_} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, true);
											{tcp, CSock, "250-"++Packet3} ->
												?debugFmt("XX~sXX", [Packet3]),
												inet:setopts(CSock, [{active, once}]),
												F(F, Acc);
											{tcp, CSock, "250 STARTTLS"++_} ->
												inet:setopts(CSock, [{active, once}]),
												true;
											{tcp, CSock, "250 "++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												Acc;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(true, Foo(Foo, false)),
								gen_tcp:send(CSock, "STARTTLS\r\n"),
								receive {tcp, CSock, Packet4} -> ok end,
								?assertMatch("220 "++_,  Packet4),
								application:start(ssl),
								Result = ssl:connect(CSock, [{ssl_impl, new}]),
								?assertMatch({ok, Socket}, Result),
								{ok, Socket} = Result,
								ssl:setopts(Socket, [{active, once}]),
								ssl:send(Socket, "EHLO somehost.com\r\n"),
								receive {ssl, Socket, Packet5} -> ssl:setopts(Socket, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet5),
								Bar = fun(F, Acc) ->
										receive
											{ssl, Socket, "250-STARTTLS"++_} ->
												ssl:setopts(Socket, [{active, once}]),
												F(F, true);
											{ssl, Socket, "250-"++_} ->
												ssl:setopts(Socket, [{active, once}]),
												F(F, Acc);
											{ssl, Socket, "250 STARTTLS"++_} ->
												ssl:setopts(Socket, [{active, once}]),
												true;
											{ssl, Socket, "250 "++_} ->
												ssl:setopts(Socket, [{active, once}]),
												Acc;
											R ->
												ssl:setopts(Socket, [{active, once}]),
												error
										end
								end,
								?assertEqual(false, Bar(Bar, false))
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"After STARTTLS, re-negotiating STARTTLS is an error",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F, Acc) ->
										receive
											{tcp, CSock, "250-STARTTLS"++_} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, true);
											{tcp, CSock, "250-"++Packet3} ->
												?debugFmt("XX~sXX", [Packet3]),
												inet:setopts(CSock, [{active, once}]),
												F(F, Acc);
											{tcp, CSock, "250 STARTTLS"++_} ->
												inet:setopts(CSock, [{active, once}]),
												true;
											{tcp, CSock, "250 "++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												Acc;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(true, Foo(Foo, false)),
								gen_tcp:send(CSock, "STARTTLS\r\n"),
								receive {tcp, CSock, Packet4} -> ok end,
								?assertMatch("220 "++_,  Packet4),
								application:start(ssl),
								Result = ssl:connect(CSock, [{ssl_impl, new}]),
								?assertMatch({ok, Socket}, Result),
								{ok, Socket} = Result,
								ssl:setopts(Socket, [{active, once}]),
								ssl:send(Socket, "EHLO somehost.com\r\n"),
								receive {ssl, Socket, Packet5} -> ssl:setopts(Socket, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet5),
								Bar = fun(F, Acc) ->
										receive
											{ssl, Socket, "250-STARTTLS"++_} ->
												ssl:setopts(Socket, [{active, once}]),
												F(F, true);
											{ssl, Socket, "250-"++_} ->
												ssl:setopts(Socket, [{active, once}]),
												F(F, Acc);
											{ssl, Socket, "250 STARTTLS"++_} ->
												ssl:setopts(Socket, [{active, once}]),
												true;
											{ssl, Socket, "250 "++_} ->
												ssl:setopts(Socket, [{active, once}]),
												Acc;
											R ->
												ssl:setopts(Socket, [{active, once}]),
												error
										end
								end,
								?assertEqual(false, Bar(Bar, false)),
								ssl:send(Socket, "STARTTLS\r\n"),
								receive {ssl, Socket, Packet6} -> ssl:setopts(Socket, [{active, once}]) end,
								?assertMatch("500 "++_,  Packet6)
						end
					}
			end,
			fun({CSock, _Pid}) ->
					{"STARTTLS can't take any parameters",
						fun() ->
								inet:setopts(CSock, [{active, once}]),
								receive {tcp, CSock, Packet} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("220 localhost"++_Stuff,  Packet),
								gen_tcp:send(CSock, "EHLO somehost.com\r\n"),
								receive {tcp, CSock, Packet2} -> inet:setopts(CSock, [{active, once}]) end,
								?assertMatch("250-localhost\r\n",  Packet2),
								Foo = fun(F, Acc) ->
										receive
											{tcp, CSock, "250-STARTTLS"++_} ->
												inet:setopts(CSock, [{active, once}]),
												F(F, true);
											{tcp, CSock, "250-"++Packet3} ->
												?debugFmt("XX~sXX", [Packet3]),
												inet:setopts(CSock, [{active, once}]),
												F(F, Acc);
											{tcp, CSock, "250 STARTTLS"++_} ->
												inet:setopts(CSock, [{active, once}]),
												true;
											{tcp, CSock, "250 "++Packet3} ->
												inet:setopts(CSock, [{active, once}]),
												Acc;
											R ->
												inet:setopts(CSock, [{active, once}]),
												error
										end
								end,
								?assertEqual(true, Foo(Foo, false)),
								gen_tcp:send(CSock, "STARTTLS foo\r\n"),
								receive {tcp, CSock, Packet4} -> ok end,
								?assertMatch("501 "++_,  Packet4)
						end
					}
			end
		]
	}.

-endif.
