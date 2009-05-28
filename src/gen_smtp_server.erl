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

%% @doc A non-blocking tcp listener.  based on the tcp_listener module by Serge
%% Aleynikov [http://www.trapexit.org/Building_a_Non-blocking_TCP_server_using_OTP_principles]

-module(gen_smtp_server).
-behaviour(gen_server).

-define(PORT, 2525).

%% External API
-export([start_link/2, start/2, start/1, start_link/1, stop/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
		code_change/3]).


-ifdef(R13B).
-type(ref() :: reference()).
-endif.

-record(state, {
		listener :: port(),       % Listening socket
		acceptor :: ref(),       % Asynchronous acceptor's internal reference
		sessions = [] :: [pid()]
		}).

-type(state() :: #state{}).

%% @doc Start the listener with callback module `Module' on port `Port' linked to the calling process.
-spec(start_link/2 :: (Module :: atom(), Port :: integer()) -> {'ok', pid()} | 'ignore' | {'error', any()}).
start_link(Module, Port) when is_integer(Port) ->
	gen_server:start_link(?MODULE, [Module, Port], []).

%% @doc Start the listener with callback module `Module' on port `Port' linked to no process.
-spec(start/2 :: (Module :: atom(), Port :: integer()) -> {'ok', pid()} | 'ignore' | {'error', any()}).
start(Module, Port) when is_integer(Port) -> 
	gen_server:start(?MODULE, [Port], []).

%% @doc Start the listener with callback module `Module' on the default port linked to no process.
-spec(start/1 :: (Module :: atom()) -> {'ok', pid()} | 'ignore' | {'error', any()}).
start(Module) -> 
	start(Module, ?PORT).

%% @doc Start the listener with callback module `Module' on the default port linked to the calling process.
-spec(start_link/1 :: (Module :: atom()) -> {'ok', pid()} | 'ignore' | {'error', any()}).
start_link(Module) -> 
	start_link(Module, ?PORT).

%% @doc Stop the listener pid() `Pid' with reason `normal'.
-spec(stop/1 :: (Pid :: pid()) -> 'ok').
stop(Pid) -> 
	gen_server:call(Pid, stop).

%% @hidden
init([Port]) ->
	io:format("~p starting at ~p~n", [?MODULE, node()]),
	process_flag(trap_exit, true),
	Opts = [list, {packet, line}, {reuseaddr, true},
		{keepalive, true}, {backlog, 30}, {active, false}],
	case gen_tcp:listen(Port, Opts) of
		{ok, Listen_socket} ->
			%%Create first accepting process
			{ok, Ref} = prim_inet:async_accept(Listen_socket, -1),
			{ok, #state{listener = Listen_socket, acceptor = Ref}};
		{error, Reason} ->
			io:format("Could not start gen_tcp:  ~p~n", [Reason]),
			{stop, Reason}
	end.

%% @hidden
handle_call(stop, _From, State) ->
	{stop, normal, ok, State};

handle_call(Request, _From, State) ->
	{reply, {unknown_call, Request}, State}.

%% @hidden
handle_cast(_Msg, State) ->
	{noreply, State}.

%% @hidden
handle_info({inet_async, ListSock, Ref, {ok, CliSocket}}, #state{listener=ListSock, acceptor=Ref} = State) ->
	try
		case set_sockopt(ListSock, CliSocket) of
			ok  ->
				ok;
			{error, Reason} ->
				exit({set_sockopt, Reason})
		end,

		%% New client connected
		io:format("new client connection.~n", []),
		Sessions = case gen_smtp_server_session:start(CliSocket, smtp_server_example, "localhost", length(State#state.sessions) + 1) of
			{ok, Pid} ->
				link(Pid),
				gen_tcp:controlling_process(CliSocket, Pid),
				lists:append(State#state.sessions, [Pid]);
			_Other ->
				State#state.sessions
		end,
		%% Signal the network driver that we are ready to accept another connection
		case prim_inet:async_accept(ListSock, -1) of
			{ok, NewRef} ->
				ok;
			{error, NewRef} ->
				exit({async_accept, inet:format_error(NewRef)})
		end,

		{noreply, State#state{acceptor=NewRef, sessions = Sessions}}
	catch exit:Why ->
		error_logger:error_msg("Error in async accept: ~p.\n", [Why]),
		{stop, Why, State}
end;

handle_info({'EXIT', From, Reason}, State) ->
	case lists:member(From, State#state.sessions) of
		true ->
			{noreply, State#state{sessions = lists:delete(From, State#state.sessions)}};
		false ->
			io:format("process ~p exited with reason ~p~n", [From, Reason]),
			{noreply, State}
	end;
	
handle_info({inet_async, ListSock, Ref, Error}, #state{listener=ListSock, acceptor=Ref} = State) ->
	error_logger:error_msg("Error in socket acceptor: ~p.\n", [Error]),
	{stop, Error, State};

handle_info(_Info, State) ->
	{noreply, State}.

%% @hidden
terminate(Reason, State) ->
	io:format("Terminating due to ~p", [Reason]),
	gen_tcp:close(State#state.listener),
	ok.

%% @hidden
code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

-spec(set_sockopt/2 :: (ListSock :: port(), CliSocket :: port()) -> 'ok' | any()).
set_sockopt(ListSock, CliSocket) ->
	true = inet_db:register_socket(CliSocket, inet_tcp),
	case prim_inet:getopts(ListSock, [active, nodelay, keepalive, delay_send, priority, tos]) of
		{ok, Opts} ->
			case prim_inet:setopts(CliSocket, Opts) of
				ok -> ok;
				Error -> gen_tcp:close(CliSocket),
					Error % return error
			end;
		Error ->
			gen_tcp:close(CliSocket),
			Error % return error
	end.

