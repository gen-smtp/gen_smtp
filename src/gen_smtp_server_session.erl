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
-export([start_link/4, start/4]).

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
		auth = undefined :: {string(), string()} % {"username", "password"}
	}
).

-record(state,
	{
		socket = erlang:error({undefined, socket}) :: port(),
		module = erlang:error({undefined, module}) :: atom(),
		hostname = erlang:error({undefined, hostname}) :: string(),
		envelope = undefined :: 'undefined' | #envelope{},
		extensions = [] :: [string()],
		waitingauth = false :: bool() | string(),
		readmessage = false :: bool(),
		readheaders = false :: bool(),
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

start_link(Socket, Module, Hostname, SessionCount) ->
	gen_server:start_link(?MODULE, [Socket, Module, Hostname, SessionCount], []).

start(Socket, Module, Hostname, SessionCount) ->
	gen_server:start(?MODULE, [Socket, Module, Hostname, SessionCount], []).

init([Socket, Module, Hostname, SessionCount]) ->
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
			inet:setopts(Socket, [{active, once}]),
			{noreply, NewState, ?TIMEOUT};
		{stop, Reason, NewState} ->
			{stop, Reason, NewState}
	end;
handle_info({tcp_closed, _Socket}, State) ->
	%io:format("Connection closed~n"),
	{stop, normal, State};
handle_info(timeout, #state{socket = Socket} = State) ->
	gen_tcp:send(Socket, "421 Error: timeout exceeded\r\n"),
	gen_tcp:close(Socket),
	{stop, normal, State};
handle_info(_Info, State) ->
	{noreply, State}.

%% @hidden
terminate(Reason, State) ->
	% io:format("Session terminating due to ~p~n", [Reason]),
	gen_tcp:close(State#state.socket),
	ok.

%% @hidden
code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

parse_request(Packet) ->
	Request = string:strip(string:strip(string:strip(string:strip(Packet, right, $\n), right, $\r), right, $\s), left, $\s),
	case string:str(Request, " ") of
		0 -> % whole thing is the verb
			%io:format("got a ~s request~n", [Request]),
			{string:to_upper(Request), []};
		Index ->
			Verb = string:substr(Request, 1, Index - 1),
			Parameters = string:strip(string:substr(Request, Index + 1), left, $\s),
			%io:format("got a ~s request with parameters ~s~n", [Verb, Parameters]),
			{string:to_upper(Verb), Parameters}
	end.

-spec(handle_request/2 :: ({Verb :: string(), Args :: string()}, State :: #state{}) -> {'ok', #state{}} | {'stop', any(), #state{}}).
handle_request({[], _Any}, #state{socket = Socket} = State) ->
	gen_tcp:send(Socket, "500 Error: bad syntax\r\n"),
	{ok, State};
handle_request({"HELO", []}, #state{socket = Socket} = State) ->
	gen_tcp:send(Socket, "501 Syntax: HELO hostname\r\n"),
	{ok, State};
handle_request({"HELO", Hostname}, #state{socket = Socket, hostname = MyHostname, module = Module} = State) ->
	case Module:handle_HELO(Hostname, State#state.callbackstate) of
		{ok, CallbackState} ->
			gen_tcp:send(Socket, io_lib:format("250 ~s\r\n", [MyHostname])),
			{ok, State#state{envelope = #envelope{}, callbackstate = CallbackState}};
		{error, Message, CallbackState} ->
			gen_tcp:send(Socket, Message ++ "\r\n"),
			{ok, State#state{callbackstate = CallbackState}}
	end;
handle_request({"EHLO", []}, #state{socket = Socket} = State) ->
	gen_tcp:send(Socket, "501 Syntax: EHLO hostname\r\n"),
	{ok, State};
handle_request({"EHLO", Hostname}, #state{socket = Socket, hostname = MyHostname, module = Module} = State) ->
	case Module:handle_EHLO(Hostname, ?BUILTIN_EXTENSIONS, State#state.callbackstate) of
		{ok, Extensions, CallbackState} ->
			case Extensions of
				[] ->
					gen_tcp:send(Socket, io_lib:format("250 ~s\r\n", [MyHostname])),
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
					{_, _, Response} = lists:foldl(F, {1, length(Extensions), string:concat(string:concat("250-", MyHostname), "\r\n")}, Extensions),
					gen_tcp:send(Socket, Response),
					{ok, State#state{extensions = Extensions, envelope = #envelope{}, callbackstate = CallbackState}}
			end;
		{error, Message, CallbackState} ->
			gen_tcp:send(Socket, Message++"\r\n"),
			{ok, State#state{callbackstate = CallbackState}}
	end;

handle_request({"AUTH", _Args}, #state{envelope = undefined, socket = Socket} = State) ->
	gen_tcp:send(Socket, "503 Error: send EHLO first\r\n"),
	{ok, State};
handle_request({"AUTH", AuthType}, #state{socket = Socket, module = Module, extensions = Extensions} = State) ->
	case has_extension(Extensions, "AUTH") of
		false ->
			gen_tcp:send(Socket, "502 Error: AUTH not implemented\r\n");
		{true, AvailableTypes} ->
			case lists:member(AuthType, string:tokens(AvailableTypes, " ")) of
				false ->
					gen_tcp:send(Socket, "504 Unrecognized authentication type\r\n");
				true ->
					case AuthType of
						"LOGIN" ->
							% gen_tcp:send(Socket, "334 " ++ base64:encode_to_string("Username:")),
							gen_tcp:send(Socket, "334 VXNlcm5hbWU\r\n"),
							{ok, State#state{waitingauth = "LOGIN"}};
						"PLAIN" ->    {ok, State};	% not yet implemented
						"CRAM-MD5" -> {ok, State}	% not yet implemented
					end
			end
	end;

handle_request({"MAIL", _Args}, #state{envelope = undefined, socket = Socket} = State) ->
	gen_tcp:send(Socket, "503 Error: send HELO/EHLO first\r\n"),
	{ok, State};
handle_request({"MAIL", Args}, #state{socket = Socket, module = Module, envelope = Envelope} = State) ->
	case Envelope#envelope.from of
		undefined ->
			case string:str(string:to_upper(Args), "FROM:") of
				1 ->
					Address = string:strip(string:substr(Args, 6), left, $\s),
					case parse_encoded_address(Address) of
						error ->
							gen_tcp:send(Socket, "501 Bad sender address syntax\r\n"),
							{ok, State};
						{ParsedAddress, []} ->
							%io:format("From address ~s (parsed as ~s)~n", [Address, ParsedAddress]),
							case Module:handle_MAIL(ParsedAddress, State#state.callbackstate) of
								{ok, CallbackState} ->
									gen_tcp:send(Socket, "250 sender Ok\r\n"),
									{ok, State#state{envelope = Envelope#envelope{from = ParsedAddress}, callbackstate = CallbackState}};
								{error, Message, CallbackState} ->
									gen_tcp:send(Socket, Message ++ "\r\n"),
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
									gen_tcp:send(Socket, Message),
									{ok, State};
								NewState ->
									%io:format("OK~n"),
									case Module:handle_MAIL(ParsedAddress, State#state.callbackstate) of
										{ok, CallbackState} ->
											gen_tcp:send(Socket, "250 sender Ok\r\n"),
											{ok, State#state{envelope = Envelope#envelope{from = ParsedAddress}, callbackstate = CallbackState}};
										{error, Message, CallbackState} ->
											gen_tcp:send(Socket, Message ++ "\r\n"),
											{ok, NewState#state{callbackstate = CallbackState}}
									end
							end
					end;
				_Else ->
					gen_tcp:send(Socket, "501 Syntax: MAIL FROM:<address>\r\n"),
					{ok, State}
			end;
		_Other ->
			gen_tcp:send(Socket, "503 Error: Nested MAIL command\r\n"),
			{ok, State}
	end;
handle_request({"RCPT", _Args}, #state{envelope = undefined, socket = Socket} = State) ->
	gen_tcp:send(Socket, "503 Error: need MAIL command\r\n"),
	{ok, State};
handle_request({"RCPT", Args}, #state{socket = Socket, envelope = Envelope, module = Module} = State) ->
	case string:str(string:to_upper(Args), "TO:") of
		1 ->
			Address = string:strip(string:substr(Args, 4), left, $\s),
			case parse_encoded_address(Address) of
				error ->
					gen_tcp:send(Socket, "501 Bad recipient address syntax\r\n"),
					{ok, State};
				{[], _} ->
					% empty rcpt to addresses aren't cool
					gen_tcp:send(Socket, "501 Bad recipient address syntax\r\n"),
					{ok, State};
				{ParsedAddress, []} ->
					%io:format("To address ~s (parsed as ~s)~n", [Address, ParsedAddress]),
					case Module:handle_RCPT(ParsedAddress, State#state.callbackstate) of
						{ok, CallbackState} ->
							gen_tcp:send(Socket, "250 recipient Ok\r\n"),
							{ok, State#state{envelope = Envelope#envelope{to = lists:append(Envelope#envelope.to, [ParsedAddress])}, callbackstate = CallbackState}};
						{error, Message, CallbackState} ->
							gen_tcp:send(Socket, Message++"\r\n"),
							{ok, State#state{callbackstate = CallbackState}}
					end;
				{ParsedAddress, ExtraInfo} ->
					% TODO - are there even any RCPT extensions?
					io:format("To address ~s (parsed as ~s) with extra info ~s~n", [Address, ParsedAddress, ExtraInfo]),
					gen_tcp:send(Socket, io_lib:format("555 Unsupported option: ~s\r\n", [ExtraInfo])),
					{ok, State}
			end;
		_Else ->
			gen_tcp:send(Socket, "501 Syntax: RCPT TO:<address>\r\n"),
			{ok, State}
	end;
handle_request({"DATA", []}, #state{socket = Socket, envelope = undefined} = State) ->
	gen_tcp:send(Socket, "503 Error: send HELO/EHLO first\r\n"),
	{ok, State};
handle_request({"DATA", []}, #state{socket = Socket, envelope = Envelope} = State) ->
	case {Envelope#envelope.from, Envelope#envelope.to} of
		{undefined, _} ->
			gen_tcp:send(Socket, "503 Error: need MAIL command\r\n"),
			{ok, State};
		{_, []} ->
			gen_tcp:send(Socket, "503 Error: need RCPT command\r\n"),
			{ok, State};
		_Else ->
			gen_tcp:send(Socket, "354 enter mail, end with line containing only '.'\r\n"),
			%io:format("switching to data read mode~n"),
			{ok, State#state{readheaders = true}}
	end;
handle_request({"RSET", _Any}, #state{socket = Socket, envelope = Envelope, module = Module} = State) ->
	gen_tcp:send(Socket, "250 Ok\r\n"),
	% if the client sends a RSET before a HELO/EHLO don't give them a valid envelope
	NewEnvelope = case Envelope of
		undefined -> undefined;
		_Something -> #envelope{}
	end,
	{ok, State#state{envelope = NewEnvelope, callbackstate = Module:handle_RSET(State#state.callbackstate)}};
handle_request({"NOOP", _Any}, #state{socket = Socket} = State) ->
	gen_tcp:send(Socket, "250 Ok\r\n"),
	{ok, State};
handle_request({"QUIT", _Any}, #state{socket = Socket} = State) ->
	gen_tcp:send(Socket, "221 Bye\r\n"),
	{stop, normal, State};
handle_request({"VRFY", Address}, #state{module= Module, socket = Socket} = State) ->
	case parse_encoded_address(Address) of
		{ParsedAddress, []} ->
			case Module:handle_VRFY(Address, State#state.callbackstate) of
				{ok, Reply, CallbackState} ->
					gen_tcp:send(Socket, io_lib:format("250 ~s\r\n", [Reply])),
					{ok, State#state{callbackstate = CallbackState}};
				{error, Message, CallbackState} ->
					gen_tcp:send(Socket, Message++"\r\n"),
					{ok, State#state{callbackstate = CallbackState}}
			end;
		_Other ->
			gen_tcp:send(Socket, "501 Syntax: VRFY username/address\r\n"),
			{ok, State}
	end;
handle_request({Verb, Args}, #state{socket = Socket, module = Module} = State) ->
	{Message, CallbackState} = Module:handle_other(Verb, Args, State#state.callbackstate),
	gen_tcp:send(Socket, Message++"\r\n"),
	{ok, State#state{callbackstate = CallbackState}}.

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

trim_crlf(String) ->
	string:strip(string:strip(String, right, $\n), right, $\r).

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
			end

		]
	}.

-endif.
