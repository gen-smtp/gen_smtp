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

-define(BUILTIN_EXTENSIONS, [{"SIZE", "10240000"}, {"8BITMIME", true}]).

%% External API
-export([start_link/2, start/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
		code_change/3]).

-record(envelope,
	{
		from :: string(),
		to = [] :: [string()],
		data = "" :: string(),
		expectedsize :: pos_integer(),
		bodytype
	}
).

-record(state,
	{
		socket = erlang:error({undefined, socket}) :: port(),
		module = erlang:error({undefined, module}) :: atom(),
		hostname = "localhost" :: string(),
		envelope = undefined :: 'undefined' | #envelope{},
		extensions = [] :: [string()],
		readmessage = false :: bool()
	}
).

start_link(Socket, Module) ->
	gen_server:start_link(?MODULE, [Socket, Module], []).

start(Socket, Module) ->
	gen_server:start(?MODULE, [Socket, Module], []).

init([Socket, Module]) ->
	inet:setopts(Socket, [{active, once}, {packet, line}, list]),
	gen_tcp:send(Socket, "220 localhost ESMTP\r\n"),
	{ok, #state{socket = Socket, module = Module}}.

%% @hidden
handle_call(stop, _From, State) ->
	{stop, normal, ok, State};

handle_call(Request, _From, State) ->
	{reply, {unknown_call, Request}, State}.

%% @hidden
handle_cast(_Msg, State) ->
	{noreply, State}.

	
handle_info({tcp, Socket, ".\r\n"}, #state{readmessage = true, envelope = Envelope} = State) ->
	io:format("done reading message~n"),
	io:format("entire message~n~s~n", [Envelope#envelope.data]),
	case has_extension(State#state.extensions, "SIZE") of
		{true, Value} ->
			case length(Envelope#envelope.data) > list_to_integer(Value) of
				true ->
					gen_tcp:send(Socket, "552 Message too large\r\n");
				false ->
					gen_tcp:send(Socket, "250 Ok\r\n")
			end;
		false ->
			gen_tcp:send(Socket, "250 Ok\r\n")
	end,
	inet:setopts(Socket, [{active, once}]),
	{noreply, State#state{readmessage = false}};
handle_info({tcp, Socket, Packet}, #state{readmessage = true, envelope = Envelope} = State) ->
	io:format("got message chunk \"~s\"~n", [Packet]),
	inet:setopts(Socket, [{active, once}]),
	{noreply, State#state{envelope = Envelope#envelope{data = string:concat(Envelope#envelope.data, Packet)}}};
handle_info({tcp, Socket, Packet}, State) ->
	io:format("Packet ~p~n", [Packet]),
	State2 = handle_request(parse_request(Packet), State),
	inet:setopts(Socket, [{active, once}]),
	{noreply, State2};
handle_info({tcp_closed, _Socket}, State) ->
	io:format("Connection closed~n~n", []),
	{stop, normal, State};
handle_info(_Info, State) ->
	{noreply, State}.

%% @hidden
terminate(Reason, State) ->
	io:format("Terminating due to ~p~n", [Reason]),
	gen_tcp:close(State#state.socket),
	ok.

%% @hidden
code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

parse_request(Packet) ->
	Request = string:strip(string:strip(string:strip(string:strip(Packet, right, $\n), right, $\r), right, $\s), left, $\s),
	case string:str(Request, " ") of
		0 -> % whole thing is the verb
			io:format("got a ~s request~n", [Request]),
			{string:to_upper(Request), []};
		Index ->
			Verb = string:substr(Request, 1, Index - 1),
			Parameters = string:strip(string:substr(Request, Index + 1), left, $\s),
			io:format("got a ~s request with parameters ~s~n", [Verb, Parameters]),
			{string:to_upper(Verb), Parameters}
	end.

handle_request({[], _Any}, #state{socket = Socket} = State) ->
	gen_tcp:send(Socket, "500 Error: bad syntax\r\n"),
	State;
handle_request({"HELO", []}, #state{socket = Socket} = State) ->
	gen_tcp:send(Socket, "501 Syntax: HELO hostname\r\n"),
	State;
handle_request({"HELO", _Hostname}, #state{socket = Socket, hostname = MyHostname, module = Module} = State) ->
	gen_tcp:send(Socket, io_lib:format("250 ~s\r\n", [MyHostname])),
	State#state{envelope = #envelope{}};
handle_request({"EHLO", []}, #state{socket = Socket} = State) ->
	gen_tcp:send(Socket, "501 Syntax: EHLO hostname\r\n"),
	State;
handle_request({"EHLO", Hostname}, #state{socket = Socket, hostname = MyHostname, module = Module} = State) ->
	%Extensions = Module:handle_EHLO(Hostname, ?BUILTIN_EXTENSIONS),
	Extensions = ?BUILTIN_EXTENSIONS,
	case Extensions of
		[] ->
			gen_tcp:send(Socket, io_lib:format("250 ~s\r\n", [MyHostname])),
			State#state{extensions = Extensions};
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
			State#state{extensions = Extensions}
	end;
handle_request({"MAIL", _Args}, #state{envelope = undefined, socket = Socket} = State) ->
	gen_tcp:send(Socket, "503 Error: send HELO/EHLO first\r\n"),
	State;
handle_request({"MAIL", Args}, #state{socket = Socket, envelope = Envelope} = State) ->
	case Envelope#envelope.from of
		undefined ->
			case string:str(string:to_upper(Args), "FROM:") of
				1 ->
					Address = string:strip(string:substr(Args, 6), left, $\s),
					case parse_encoded_address(Address) of
						error ->
							gen_tcp:send(Socket, "501 Bad sender address syntax\r\n"),
							State;
						{ParsedAddress, []} ->
							io:format("From address ~s (parsed as ~s)~n", [Address, ParsedAddress]),
							gen_tcp:send(Socket, "250 Ok\r\n"),
							State#state{envelope = Envelope#envelope{from = ParsedAddress}};
						{ParsedAddress, ExtraInfo} ->
							io:format("From address ~s (parsed as ~s) with extra info ~s~n", [Address, ParsedAddress, ExtraInfo]),
							Options = lists:map(fun(X) -> string:to_upper(X) end, string:tokens(ExtraInfo, " ")),
							%io:format("options are ~p~n", [Options]),
							 F = fun(_, {error, Message}) ->
									 {error, Message};
								 ("SIZE="++Size, InnerState) ->
									case has_extension(Envelope, "SIZE") of
										{true, Value} ->
											case list_to_integer(Size) > list_to_integer(Value) of
												true ->
													{error, io_lib:format("552 Estimated message length ~s exceeds limit of ~s\r\n", [Size, Value])};
												false ->
													InnerState#state{envelope = Envelope#envelope{expectedsize = list_to_integer(Size)}}
											end;
										false ->
											{error, "552 Unsupported option SIZE\r\n"}
									end;
								("BODY="++BodyType, InnerState) ->
									case has_extension(Envelope, "8BITMIME") of
										{true, _} ->
											case BodyType of
												_ when BodyType =:= "8BITMIME"; BodyType =:= "7BIT" ->
													InnerState#state{envelope = Envelope#envelope{bodytype = BodyType}};
												_ ->
													{error, io_lib:format("555 Unsupported BODY type: ~s\r\n", [BodyType])}
											end;
										false ->
											{error, "552 Unsupported option BODY\r\n"}
									end;
								(X, InnerState) ->
									% TODO send to the callback
									{error, io_lib:format("555 Unsupported option: ~s\r\n", [ExtraInfo])}
							end,
							case lists:foldl(F, State, Options) of
								{error, Message} ->
									io:format("error: ~s~n", [Message]),
									gen_tcp:send(Socket, Message),
									State;
								#state{envelope = NewEnvelope} = NewState ->
									io:format("OK~n"),
									gen_tcp:send(Socket, "250 Ok\r\n"),
									NewState#state{envelope = NewEnvelope#envelope{from = ParsedAddress}}
							end
					end;
				_Else ->
					gen_tcp:send(Socket, "501 Syntax: MAIL FROM:<address>\r\n"),
					State
			end;
		_Other ->
			gen_tcp:send(Socket, "503 Error: Nested MAIL command\r\n"),
			State
	end;
handle_request({"RCPT", _Args}, #state{envelope = undefined, socket = Socket} = State) ->
	gen_tcp:send(Socket, "503 Error: need MAIL command\r\n"),
	State;
handle_request({"RCPT", Args}, #state{socket = Socket, envelope = Envelope} = State) ->
	case string:str(string:to_upper(Args), "TO:") of
		1 ->
			Address = string:strip(string:substr(Args, 4), left, $\s),
			case parse_encoded_address(Address) of
				error ->
					gen_tcp:send(Socket, "501 Bad recipient address syntax\r\n"),
					State;
				{ParsedAddress, []} ->
					io:format("To address ~s (parsed as ~s)~n", [Address, ParsedAddress]),
					gen_tcp:send(Socket, "250 Ok\r\n"),
					State#state{envelope = Envelope#envelope{to = lists:append(Envelope#envelope.to, [ParsedAddress])}};
				{ParsedAddress, ExtraInfo} ->
					io:format("To address ~s (parsed as ~s) with extra info ~s~n", [Address, ParsedAddress, ExtraInfo]),
					gen_tcp:send(Socket, io_lib:format("555 Unsupported option: ~s\r\n", [ExtraInfo])),
					State
			end;
		_Else ->
			gen_tcp:send(Socket, "501 Syntax: RCPT TO:<address>\r\n"),
			State
	end;
handle_request({"DATA", []}, #state{socket = Socket, envelope = undefined} = State) ->
	gen_tcp:send(Socket, "503 Error: send HELO/EHLO first\r\n"),
	State;
handle_request({"DATA", []}, #state{socket = Socket, envelope = Envelope} = State) ->
	case {Envelope#envelope.from, Envelope#envelope.to} of
		{undefined, _} ->
			gen_tcp:send(Socket, "503 Error: need MAIL command\r\n"),
			State;
		{_, []} ->
			gen_tcp:send(Socket, "503 Error: need RCPT command\r\n"),
			State;
		_Else ->
			gen_tcp:send(Socket, "354 Ok\r\n"),
			io:format("switching to data read mode~n"),
			State#state{readmessage = true}
	end;
handle_request({"RSET", _Any}, #state{socket = Socket, envelope = Envelope} = State) ->
	gen_tcp:send(Socket, "250 Ok\r\n"),
	% if the client sends a RSET before a HELO/EHLO don't give them a valid envelope
	NewEnvelope = case Envelope of
		undefined -> undefined;
		_Something -> #envelope{}
	end,
	State#state{envelope = NewEnvelope};
handle_request({"NOOP", _Any}, #state{socket = Socket} = State) ->
	gen_tcp:send(Socket, "250 Ok\r\n"),
	State;
handle_request({"QUIT", _Any}, #state{socket = Socket} = State) ->
	gen_tcp:send(Socket, "221 Bye\r\n"),
	gen_tcp:close(Socket),
	State;
handle_request({Verb, Args}, #state{socket = Socket} = State) ->
	io:format("unhandled request ~s with arguments ~s~n", [Verb, Args]),
	gen_tcp:send(Socket, "502 Error: command not recognized\r\n"),
	State.

parse_encoded_address("<@" ++ Address) ->
	case string:str(Address, ":") of
		0 ->
			error; % invalid address
		Index ->
			parse_encoded_address(string:substr(Address, Index + 1))
	end;
parse_encoded_address("<" ++ Address) ->
	parse_encoded_address(Address);
parse_encoded_address(Address) ->
	parse_encoded_address(Address, "", noquotes).

parse_encoded_address([], Acc, Quotes) ->
	{lists:reverse(Acc), []};
parse_encoded_address(_, Acc, _) when length(Acc) > 129 ->
	error; % too long
parse_encoded_address([$\\ | Tail], Acc, Quotes) ->
	[H | NewTail] = Tail,
	parse_encoded_address(NewTail, [H | Acc], Quotes);
parse_encoded_address([$" | Tail], Acc, noquotes) ->
	parse_encoded_address(Tail, Acc, quotes);
parse_encoded_address([$" | Tail], Acc, quotes) ->
	parse_encoded_address(Tail, Acc, noquotes);
parse_encoded_address([$> | Tail], Acc, noquotes) ->
	{lists:reverse(Acc), string:strip(Tail, left, $\s)};
parse_encoded_address([$\s | Tail], Acc, noquotes) ->
	{lists:reverse(Acc), string:strip(Tail, left, $\s)};
parse_encoded_address([H | Tail], Acc, noquotes) when H >= 48, H =< 57 ->
	parse_encoded_address(Tail, [H | Acc], noquotes); % digits
parse_encoded_address([H | Tail], Acc, noquotes) when H >= 64, H =< 90 ->
	parse_encoded_address(Tail, [H | Acc], noquotes); % @ symbol and uppercase letters
parse_encoded_address([H | Tail], Acc, noquotes) when H >= 97, H =< 122 ->
	parse_encoded_address(Tail, [H | Acc], noquotes); % lowercase letters
parse_encoded_address([H | Tail], Acc, noquotes) when H =:= 45; H =:= 46; H =:= 95 ->
	parse_encoded_address(Tail, [H | Acc], noquotes); % dash, dot, underscore
parse_encoded_address(_, _Acc, quotes) ->
	error;
parse_encoded_address([H | Tail], Acc, Quotes) ->
	parse_encoded_address(Tail, [H | Acc], Quotes).

has_extension(Exts, Ext) ->
	Extension = string:to_upper(Ext),
	Extensions = lists:map(fun({X, Y}) -> {string:to_upper(X), Y} end, Exts),
	%io:format("extensions ~p~n", [Extensions]),
	case lists:keyfind(Extension, 1, Extensions) of
		{_, Value} ->
			{true, Value};
		false ->
			false
	end.
