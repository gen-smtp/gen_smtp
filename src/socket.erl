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


-define(TCP_LISTEN_OPTIONS,[  {active, false},
                              {backlog, 30},
                              {keepalive, true},
                              {packet, line},
                              {reuseaddr, true}]).
-define(TCP_CONNECT_OPTIONS,[ {active, false},
                              {packet, line}]).
-define(SSL_LISTEN_OPTIONS, [ {active, false},
                              {backlog, 30},
                              {certfile, "server.crt"},
                              {depth, 0},
                              {keepalive, true},
                              {keyfile, "server.key"},
                              {packet, line},
                              {reuse_sessions, false},
                              {reuseaddr, true},
                              {ssl_imp, new}]).
-define(SSL_CONNECT_OPTIONS,[ {active, false},
                              {certfile, "server.crt"},
                              {depth, 0},
                              {keyfile, "server.key"},
                              {packet, line},
                              {ssl_imp, new}]).

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% API
-export([connect/3, connect/4, connect/5]).
-export([listen/2, accept/1, accept/2]).
-export([send/2, recv/2, recv/3]).
-export([controlling_process/2]).
-export([close/1, shutdown/2]).
-export([active_once/1]).
-export([type/1]).

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
	case gen_tcp:accept(Socket, Timeout) of
		{ok, NewSocket} ->
			{ok, Opts} = inet:getopts(Socket, [active,keepalive,packet,reuseaddr]),
			inet:setopts(NewSocket, [list|Opts]),
			{ok, NewSocket};
		Error -> Error
	end;
accept(Socket, Timeout) ->
	case ssl:transport_accept(Socket, Timeout) of
		{ok, NewSocket} ->
			ssl:ssl_accept(NewSocket),
			{ok, NewSocket};
		Error -> Error
	end.

send(Socket, Data) when is_port(Socket) ->
	gen_tcp:send(Socket, Data);
send(Socket, Data) ->
	ssl:send(Socket, Data).

recv(Socket, Length) ->
	recv(Socket, Length, infinity).
recv(Socket, Length, Timeout) when is_port(Socket) ->
	gen_tcp:recv(Socket, Length, Timeout);
recv(Socket, Data, Timeout) ->
	ssl:recv(Socket, Data, Timeout).

controlling_process(Socket, NewOwner) when is_port(Socket) ->
	gen_tcp:controlling_process(Socket, NewOwner);
controlling_process(Socket, NewOwner) ->
	ssl:controlling_process(Socket, NewOwner).

close(Socket) when is_port(Socket) ->
	gen_tcp:close(Socket);
close(Socket) ->
	ssl:close(Socket).

shutdown(Socket, How) when is_port(Socket) ->
	gen_tcp:shutdown(Socket, How);
shutdown(Socket, How) ->
	ssl:shutdown(Socket, How).

active_once(Socket) when is_port(Socket) ->
	inet:setopts(Socket, [{active, once}]);
active_once(Socket) ->
	ssl:setopts(Socket, [{active, once}]).

type(Socket) when is_port(Socket) ->
	tcp;
type(_Socket) ->
	ssl.

%%%-----------------------------------------------------------------
%%% Internal functions (OS_Mon configuration)
%%%-----------------------------------------------------------------

tcp_listen_options([Format|Options]) when Format =:= list; Format =:= binary ->
	tcp_listen_options(Options, Format);
tcp_listen_options(Options) ->
	tcp_listen_options(Options, list).
tcp_listen_options(Options, Format) ->
	[Format|proplist_merge(Options, ?TCP_LISTEN_OPTIONS)].

ssl_listen_options([Format|Options]) when Format =:= list; Format =:= binary ->
	ssl_listen_options(Options, Format);
ssl_listen_options(Options) ->
	ssl_listen_options(Options, list).
ssl_listen_options(Options, Format) ->
	[Format|proplist_merge(Options, ?SSL_LISTEN_OPTIONS)].

tcp_connect_options([Format|Options]) when Format =:= list; Format =:= binary ->
	tcp_connect_options(Options, Format);
tcp_connect_options(Options) ->
	tcp_connect_options(Options, list).
tcp_connect_options(Options, Format) ->
	[Format|proplist_merge(Options, ?TCP_CONNECT_OPTIONS)].

ssl_connect_options([Format|Options]) when Format =:= list; Format =:= binary ->
	ssl_connect_options(Options, Format);
ssl_connect_options(Options) ->
	ssl_connect_options(Options, list).
ssl_connect_options(Options, Format) ->
	[Format|proplist_merge(Options, ?SSL_CONNECT_OPTIONS)].

proplist_merge(PrimaryList, DefaultList) ->
	Merged = lists:ukeymerge(1,
		lists:keysort(1, PrimaryList),
		lists:keysort(1, DefaultList)
	),
	%% remove all the values that don't belong here
	lists:filter(
		fun(Option) ->
			case Option of
				{Key,_} ->
					proplists:is_defined(Key, DefaultList);
				_ -> false
			end
		end,
		Merged
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
						controlling_process(ServerSocket, Self),
						Self ! ListenSocket
				end),
			{ok, ClientSocket} = connect(tcp, "localhost", ?TEST_PORT,  tcp_connect_options([])),
			receive
				ListenSocket when is_port(ListenSocket) -> ok
			end,
			?assert(is_port(ClientSocket)),
			close(ListenSocket)
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
						{ok, ServerSocket} = accept(ListenSocket),
						controlling_process(ServerSocket, Self),
						Self ! ListenSocket
				end),
			{ok, ClientSocket} = connect(ssl, "localhost", ?TEST_PORT,  []),
			receive
				{sslsocket,_,_} = ListenSocket -> ok
			end,
			?assertMatch([sslsocket|_], tuple_to_list(ClientSocket)),
			close(ListenSocket)
		end
		}
	].

accept_test_() ->
	[
		{"Accept via tcp",
		fun() ->
			{ok, ListenSocket} = listen(tcp, ?TEST_PORT, tcp_listen_options([])),
			?assert(is_port(ListenSocket)),
			spawn(fun()-> connect(ssl, "localhost", ?TEST_PORT, tcp_connect_options([])) end),
			{ok, ServerSocket} = accept(ListenSocket),
			?assert(is_port(ListenSocket)),
 			close(ServerSocket),
			close(ListenSocket)
		end
		},
		{"Accept via ssl",
		fun() ->
			application:start(crypto),
			application:start(ssl),
			{ok, ListenSocket} = listen(ssl, ?TEST_PORT, ssl_listen_options([])),
			?assertMatch([sslsocket|_], tuple_to_list(ListenSocket)),
			spawn(fun()->connect(ssl, "localhost", ?TEST_PORT, ssl_connect_options([])) end),
			accept(ListenSocket),
			close(ListenSocket)
		end
		}
	].

type_test_() ->
	[
		{"a tcp socket returns 'tcp'",
		fun() ->
			{ok, ListenSocket} = listen(tcp, ?TEST_PORT, tcp_listen_options([])),
			?assertMatch(tcp, type(ListenSocket)),
			close(ListenSocket)
		end
		},
		{"an ssl socket returns 'ssl'",
		fun() ->
			application:start(crypto),
			application:start(ssl),
			{ok, ListenSocket} = listen(ssl, ?TEST_PORT, ssl_listen_options([])),
			?assertMatch(ssl, type(ListenSocket)),
			close(ListenSocket)
		end
		}
	].

active_once_test_() ->
	[
		{"socket is set to active:once on tcp",
		fun() ->
			{ok, ListenSocket} = listen(tcp, ?TEST_PORT, tcp_listen_options([])),
			?assertEqual({ok, [{active,false}]}, inet:getopts(ListenSocket, [active])),
			active_once(ListenSocket),
			?assertEqual({ok, [{active,once}]}, inet:getopts(ListenSocket, [active])),
			close(ListenSocket)
		end
		},
		{"socket is set to active:once on ssl",
		fun() ->
			{ok, ListenSocket} = listen(ssl, ?TEST_PORT, ssl_listen_options([])),
			?assertEqual({ok, [{active,false}]}, ssl:getopts(ListenSocket, [active])),
			active_once(ListenSocket),
			?assertEqual({ok, [{active,once}]}, ssl:getopts(ListenSocket, [active])),
			close(ListenSocket)
		end
		}
	].

option_test_() ->
	[
		{"options removes bogus values",
		fun() ->
			?assertEqual([list|?TCP_LISTEN_OPTIONS], tcp_listen_options([{notvalid,whatever}]))
		end
		},
		{"tcp_listen_options has defaults",
		fun() ->
			?assertEqual([list|?TCP_LISTEN_OPTIONS], tcp_listen_options([]))
		end
		},
		{"tcp_connect_options has defaults",
		fun() ->
			?assertEqual([list|?TCP_CONNECT_OPTIONS], tcp_connect_options([]))
		end
		},
		{"ssl_listen_options has defaults",
		fun() ->
			?assertEqual([list|?SSL_LISTEN_OPTIONS], ssl_listen_options([]))
		end
		},
		{"ssl_connect_options has defaults",
		fun() ->
			?assertEqual([list|?SSL_CONNECT_OPTIONS], ssl_connect_options([]))
		end
		},
		{"tcp_listen_options defaults to list type",
		fun() ->
			?assertEqual([list|?TCP_LISTEN_OPTIONS], tcp_listen_options([{active,false}])),
			?assertEqual([binary|?TCP_LISTEN_OPTIONS], tcp_listen_options([binary,{active,false}]))
		end
		},
		{"tcp_connect_options defaults to list type",
		fun() ->
			?assertEqual([list|?TCP_CONNECT_OPTIONS], tcp_connect_options([{active,false}])),
			?assertEqual([binary|?TCP_CONNECT_OPTIONS], tcp_connect_options([binary,{active,false}]))
		end
		},
		{"ssl_listen_options defaults to list type",
		fun() ->
			?assertEqual([list|?SSL_LISTEN_OPTIONS], ssl_listen_options([{active,false}])),
			?assertEqual([binary|?SSL_LISTEN_OPTIONS], ssl_listen_options([binary,{active,false}]))
		end
		},
		{"ssl_connect_options defaults to list type",
		fun() ->
			?assertEqual([list|?SSL_CONNECT_OPTIONS], ssl_connect_options([{active,false}])),
			?assertEqual([binary|?SSL_CONNECT_OPTIONS], ssl_connect_options([binary,{active,false}]))
		end
		},
		{"tcp_listen_options merges provided proplist",
		fun() ->
			?assertMatch([list,{active, true},
			                   {backlog, 30},
			                   {keepalive, true},
			                   {packet, 2},
			                   {reuseaddr, true}],
			             tcp_listen_options([{active, true},{packet,2}]))
		end
		},
		{"tcp_connect_options merges provided proplist",
		fun() ->
			?assertMatch([list,{active, true},
			                   {packet, 2}],
			             tcp_connect_options([{active, true},{packet,2}]))
		end
		},
		{"ssl_listen_options merges provided proplist",
		fun() ->
			?assertMatch([list,{active, true},
			                   {backlog, 30},
			                   {certfile, "server.crt"},
			                   {depth, 0},
			                   {keepalive, true},
			                   {keyfile, "server.key"},
			                   {packet, 2},
			                   {reuse_sessions, false},
			                   {reuseaddr, true},
			                   {ssl_imp, new}],
			             ssl_listen_options([{active, true},{packet,2}]))
		end
		},
		{"ssl_connect_options merges provided proplist",
		fun() ->
			?assertMatch([list,{active, true},
			                   {certfile, "server.crt"},
			                   {depth, 0},
			                   {keyfile, "server.key"},
			                   {packet, 2},
			                   {ssl_imp, new}],
			             ssl_connect_options([{active, true},{packet,2}]))
		end
		}
	].

-endif.