%%% Copyright 2009 Jack Danger Canty <code@jackcanty.com>. All rights reserved.
%%%
%%% Permission is hereby granted, free of charge, to any person obtaining
%%% a copy of this software and associated documentation files (the
%%% "Software"), to deal in the Software without restriction, including
%%% without limitation the rights to use, copy, modify, merge, publish,
%%% distribute, sublicense, and/or sell copies of the Software, and to
%%% permit persons to whom the Software is furnished to do so, subject to
%%% the following conditions:
%%% 
%%% The above copyright notice and this permission notice shall be
%%% included in all copies or substantial portions of the Software.
%%% 
%%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
%%% EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
%%% MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
%%% NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
%%% LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
%%% OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
%%% WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

%% @doc Facilitates transparent gen_tcp/ssl socket handling
-module(socket).


-define(TCP_LISTEN_OPTIONS,[  {packet, line},
                              {reuseaddr, true},
                              {keepalive, true},
                              {backlog, 30},
                              {active, false}]).
-define(TCP_CONNECT_OPTIONS,[ {packet, line},
                            	{active, false}]).
-define(SSL_LISTEN_OPTIONS, [ {packet, line},
                              {reuseaddr, true},
                              {keepalive, true},
                              {reuse_sessions, false},
                              {backlog, 30},
                              {ssl_imp, new},
                              {depth, 0},
                              {certfile, "server.crt"},
                              {keyfile, "server.key"},
                              {active, false}]).
-define(SSL_CONNECT_OPTIONS,[ {packet, line},
                              {ssl_imp, new},
                              {depth, 0},
                              {certfile, "server.crt"},
                              {keyfile, "server.key"},
                              {active, false}]).

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% API
-export([connect/3, connect/4, connect/5]).
-export([listen/2, accept/2]).
% -export([send/2, recv/2, recv/3]).
% -export([controlling_process/2]).
% -export([close/1, shutdown/2]).
% -export([type/1]).

%%%-----------------------------------------------------------------
%%% API
%%%-----------------------------------------------------------------
connect(Protocol, Address, Port) -> 
	connect(Protocol, Address, Port, [], infinity).
connect(Protocol, Address, Port, Opts) -> 
	connect(Protocol, Address, Port, Opts, infinity).
connect(tcp, Address, Port, Opts, Time) ->
	gen_tcp:connect(Address, Port, tcp_connect_options(Opts), Time);
connect(ssl, Address, Port, Opts, Time) ->
	ssl:connect(Address, Port, ssl_connect_options(Opts), Time).
	

listen(Protocol, Port) ->
	listen(Protocol, Port, []).
listen(ssl, Port, Options) ->
	ssl:listen(Port, ssl_listen_options(Options));
listen(tcp, Port, Options) ->
	gen_tcp:listen(Port, tcp_listen_options(Options)).

accept(Socket) ->
	accept(Socket, infinity).
accept(Socket, Timeout) when is_port(Socket) ->
	io:format("Socket: ~p~n", [Socket]),
	case gen_tcp:accept(Socket, Timeout) of
		{ok, NewSocket} ->
			{ok, Opts} = inet:getopts(Socket, [active,keepalive,packet,reuseaddr]),
			inet:setopts(NewSocket, [list|Opts]),
			{ok, NewSocket};
		Error -> Error
	end;
accept(Socket, Timeout) ->
	case ssl:transport_accept(Socket, Timeout) of
		{ok, TransportSocket} ->
			ssl:ssl_accept(TransportSocket);
		Error -> Error
	end.

%%%-----------------------------------------------------------------
%%% Internal functions (OS_Mon configuration)
%%%-----------------------------------------------------------------

tcp_listen_options([list|Options]) ->
	tcp_listen_options(Options);
tcp_listen_options(Options) ->
	[list|proplist_merge(Options, ?TCP_LISTEN_OPTIONS)].
ssl_listen_options([list|Options]) ->
	ssl_listen_options(Options);
ssl_listen_options(Options) ->
	[list|proplist_merge(Options, ?SSL_LISTEN_OPTIONS)].

tcp_connect_options([list|Options]) ->
	tcp_connect_options(Options);
tcp_connect_options(Options) ->
	[list|proplist_merge(Options, ?TCP_CONNECT_OPTIONS)].
ssl_connect_options([list|Options]) ->
	ssl_connect_options(Options);
ssl_connect_options(Options) ->
	[list|proplist_merge(Options, ?SSL_CONNECT_OPTIONS)].

proplist_merge(PrimaryList, DefaultList) ->
	lists:ukeymerge(1,
		lists:keysort(1, PrimaryList),
		lists:keysort(1, DefaultList)
	).


-ifdef(EUNIT).
-define(TEST_PORT, 7586).
connect_test_() ->
	[
		{"listen and connect via tcp",
		fun() ->
			Self = self(),
			spawn(fun() ->
						{ok, ListenSocket} = listen(tcp, ?TEST_PORT, tcp_listen_options([])),
						?assert(is_port(ListenSocket)),
						{ok, ServerSocket} = accept(ListenSocket),
						gen_tcp:controlling_process(ServerSocket, Self),
						Self ! ListenSocket
				end),
			{ok, ClientSocket} = connect(tcp, "localhost", ?TEST_PORT,  tcp_connect_options([])),
			receive
				ListenSocket when is_port(ListenSocket) -> ok
			end,
			?assert(is_port(ClientSocket)),
			gen_tcp:close(ClientSocket),
			gen_tcp:close(ListenSocket)
		end
		},
		{"listen and connect via ssl",
		fun() ->
			Self = self(),
			application:start(crypto),
			application:start(ssl),
			spawn(fun() ->
						{ok, ListenSocket} = listen(ssl, ?TEST_PORT, ssl_listen_options([])),
						?assertMatch([sslsocket|_], tuple_to_list(ListenSocket)),
						accept(ListenSocket),
						Self ! ListenSocket
				end),
			{ok, ClientSocket} = connect(ssl, "localhost", ?TEST_PORT,  []),
			receive
				{sslsocket,_,_} = ListenSocket -> ok
			end,
			io:format("ClientSocket: ~p~n", [ClientSocket]),
			?assertMatch([sslsocket|_], tuple_to_list(ClientSocket)),
			ssl:close(ClientSocket),
			ssl:close(ListenSocket)
		end
		}
	].

accept_test_() ->
	[
		{"Accept via tcp",
		fun() ->
			{ok, ListenSocket} = listen(tcp, ?TEST_PORT, tcp_listen_options([])),
			?assert(is_port(ListenSocket)),
			spawn(fun()-> gen_tcp:connect("localhost", ?TEST_PORT, tcp_connect_options([])) end),
			{ok, ServerSocket} = gen_tcp:accept(ListenSocket),
			?assert(is_port(ListenSocket)),
 			gen_tcp:close(ServerSocket),
			gen_tcp:close(ListenSocket)
		end
		},
		{"Accept via ssl",
		fun() ->
			{ok, ListenSocket} = listen(ssl, ?TEST_PORT, ssl_listen_options([])),
			?assertMatch([sslsocket|_], tuple_to_list(ListenSocket)),
			spawn(fun()->ssl:connect("localhost", ?TEST_PORT, ssl_connect_options([])) end),
			accept(ListenSocket),
			ssl:close(ListenSocket)
		end
		}
	].
-endif.