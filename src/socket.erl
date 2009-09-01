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

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% API
-export([connect/3, connect/4, connect/5]).
% -export([listen/2, accept/3]).
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
connect(Protocol, Address, Port, Opts, Time) ->
	apply(mod(Protocol), connect, [Address, Port, Opts, Time]).
	
%%%-----------------------------------------------------------------
%%% Internal functions (OS_Mon configuration)
%%%-----------------------------------------------------------------

mod({sslsocket,_,_}) -> % an ssl application socket
	ssl;
mod(ssl) ->
	ssl;
mod(_) ->
	gen_tcp.

-ifdef(EUNIT).
-define(TEST_PORT, 7586).
-define(TCP_LISTEN_OPTIONS, [list,
                            {packet, line},
                            {reuseaddr, true},
                            {keepalive, true},
                            {backlog, 30},
                            {active, false}]).
-define(TCP_CONNECT_OPTIONS,[list,
                            {packet, line},
                            {active, false}]).
-define(SSL_LISTEN_OPTIONS, [list,
                            {packet, line},
                            {reuseaddr, true},
                            {keepalive, true},
                            {backlog, 30},
                            {ssl_imp, new},
                            {depth, 0},
                            {certfile, "server.crt"},
                            {keyfile, "server.key"},
                            {active, false}]).
-define(SSL_CONNECT_OPTIONS,[list,
                            {packet, line},
                            {depth, 0},
                            {certfile, "server.crt"},
                            {keyfile, "server.key"},
                            {active, false}]).
connect_test() ->
	[
		{"connecting via tcp",
		fun() ->
			Self = self(),
			spawn(fun() ->
						{ok, ListenSock} = gen_tcp:listen(?TEST_PORT, ?TCP_LISTEN_OPTIONS),
						{ok, ServerSocket} = gen_tcp:accept(ListenSock),
						inet:setopts(ServerSocket, ?TCP_LISTEN_OPTIONS),
						gen_tcp:controlling_process(ServerSocket, Self)
				end),
			{ok, ClientSocket} = connect(tcp, "localhost", ?TEST_PORT,  ?TCP_CONNECT_OPTIONS),
			?assert(is_port(ClientSocket)),
			gen_tcp:close(ClientSocket)
		end
		},
		{"connecting via ssl",
		fun() ->
			Self = self(),
			spawn(fun() ->
						{ok, ListenSock} = ssl:listen(?TEST_PORT, ?SSL_LISTEN_OPTIONS),
						{ok, ServerSocket} = ssl:transport_accept(ListenSock),
						ssl:ssl_accept(ServerSocket),
						inet:setopts(ServerSocket, ?TCP_LISTEN_OPTIONS),
						gen_tcp:controlling_process(ServerSocket, Self)
				end),
			{ok, ClientSocket} = connect(ssl, "localhost", ?TEST_PORT,  ?SSL_CONNECT_OPTIONS),
			?assertMatch([sslsocket|_], tuple_to_list(ClientSocket)),
			ssl:close(ClientSocket)
		end
		}
	].

-endif.