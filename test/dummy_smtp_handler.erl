%% Dummy SMTP session handler. It does absolutely nothing.
-module(dummy_smtp_handler).
-behaviour(gen_smtp_server_session).


-export([init/4, handle_HELO/2, handle_EHLO/3, handle_MAIL/2, handle_MAIL_extension/2,
         handle_RCPT/2, handle_RCPT_extension/2, handle_DATA/4, handle_RSET/1, handle_VRFY/2,
         handle_other/3, handle_AUTH/4, handle_STARTTLS/1, handle_info/2,
         code_change/3, terminate/2]).

init(_Hostname, _SessionCount, _Address, _Options) ->
    State = [],
    {ok, <<"hi">>, State}.

handle_HELO(_Hostname, State) ->
    {ok, 10 * 1024 * 1024, State}. % 10mb

handle_EHLO(_Hostname, Extensions, State) ->
    {ok, Extensions, State}.

handle_MAIL(_From, State) ->
    {ok, State}.

handle_MAIL_extension(_Extension, _State) ->
    error.

handle_RCPT(_To, State) ->
    {ok, State}.

handle_RCPT_extension(_Extension, _State) ->
    error.

handle_DATA(_From, _To, _Data, State) ->
    %% some kind of unique id
    Reference = erlang:integer_to_binary(erlang:unique_integer()),
    {ok, Reference, State}.

handle_RSET(State) ->
    State.

handle_VRFY(_Address, State) ->
    {error, "252 VRFY disabled by policy, just send some mail", State}.

handle_other(Verb, _Args, State) ->
    {["500 Error: command not recognized : '", Verb, "'"], State}.

handle_AUTH(_Type, _Username, _Password, _State) ->
    error.

handle_STARTTLS(State) ->
    State.

handle_info(_Info, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(Reason, State) ->
    {ok, Reason, State}.
