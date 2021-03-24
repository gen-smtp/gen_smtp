%% @doc A simple example callback module for `gen_smtp_server_session' that also serves as
%% documentation for the required callback API.

-module(smtp_server_example).
-behaviour(gen_smtp_server_session).


-export([init/4, handle_HELO/2, handle_EHLO/3, handle_MAIL/2, handle_MAIL_extension/2,
	handle_RCPT/2, handle_RCPT_extension/2, handle_DATA/4, handle_RSET/1, handle_VRFY/2,
	handle_other/3, handle_AUTH/4, handle_STARTTLS/1, handle_info/2, handle_error/3,
	code_change/3, terminate/2]).
-include_lib("hut/include/hut.hrl").
-define(RELAY, true).

-record(state,
	{
		options = [] :: list()
	}).

-type(error_message() :: {'error', string(), #state{}}).

%% @doc Initialize the callback module's state for a new session.
%% The arguments to the function are the SMTP server's hostname (for use in the SMTP banner),
%% The number of current sessions (eg. so you can do session limiting), the IP address of the
%% connecting client, and a freeform list of options for the module. The Options are extracted
%% from the `callbackoptions' parameter passed into the `gen_smtp_server_session' when it was
%% started.
%%
%% If you want to continue the session, return `{ok, Banner, State}' where Banner is the SMTP
%% banner to send to the client and State is the callback module's state. The State will be passed
%% to ALL subsequent calls to the callback module, so it can be used to keep track of the SMTP
%% session. You can also return `{stop, Reason, Message}' where the session will exit with Reason
%% and send Message to the client.
-spec init(Hostname :: inet:hostname(), SessionCount :: non_neg_integer(),
           Address :: inet:ip_address(), Options :: list()) -> {'ok', iodata(), #state{}} | {'stop', any(), iodata()}.
init(Hostname, SessionCount, Address, Options) ->
	?log(info, "peer: ~p~n", [Address]),
	case SessionCount > 20 of
		false ->
			Banner = [Hostname, " ESMTP smtp_server_example"],
			State = #state{options = Options},
			{ok, Banner, State};
		true ->
			?log(warning, "Connection limit exceeded~n"),
			{stop, normal, ["421 ", Hostname, " is too busy to accept mail right now"]}
	end.

%% @doc Handle the HELO verb from the client. Arguments are the Hostname sent by the client as
%% part of the HELO and the callback State.
%%
%% Return values are `{ok, State}' to simply continue with a new state, `{ok, MessageSize, State}'
%% to continue with the SMTP session but to impose a maximum message size (which you can determine
%% , for example, by looking at the IP address passed in to the init function) and the new callback
%% state. You can reject the HELO by returning `{error, Message, State}' and the Message will be
%% sent back to the client. The reject message MUST contain the SMTP status code, eg. 554.
-spec handle_HELO(Hostname :: binary(), State :: #state{}) -> {'ok', pos_integer(), #state{}} | {'ok', #state{}} | error_message().
handle_HELO(<<"invalid">>, State) ->
	% contrived example
	{error, "554 invalid hostname", State};
handle_HELO(<<"trusted_host">>, State) ->
	{ok, State}; %% no size limit because we trust them.
handle_HELO(Hostname, State) ->
	?log(info, "HELO from ~s~n", [Hostname]),
	% 640kb of HELO should be enough for anyone.
	MaxSize = proplists:get_value(size, State#state.options, 655360),
	{ok, MaxSize, State}.
	%If {ok, State} was returned here, we'd use the default 10mb limit

%% @doc Handle the EHLO verb from the client. As with EHLO the hostname is provided as an argument,
%% but in addition to that the list of ESMTP Extensions enabled in the session is passed. This list
%% of extensions can be modified by the callback module to add/remove extensions.
%%
%% The return values are `{ok, Extensions, State}' where Extensions is the new list of extensions
%% to use for this session or `{error, Message, State}' where Message is the reject message as
%% with handle_HELO.
-spec handle_EHLO(Hostname :: binary(), Extensions :: list(), State :: #state{}) -> {'ok', list(), #state{}} | error_message().
handle_EHLO(<<"invalid">>, _Extensions, State) ->
	% contrived example
	{error, "554 invalid hostname", State};
handle_EHLO(Hostname, Extensions, State) ->
	?log(info, "EHLO from ~s~n", [Hostname]),
	% You can advertise additional extensions, or remove some defaults
	MyExtensions1 = case proplists:get_value(auth, State#state.options, false) of
		true ->
			% auth is enabled, so advertise it
			Extensions ++ [{"AUTH", "PLAIN LOGIN CRAM-MD5"}, {"STARTTLS", true}];
		false ->
			Extensions
	end,
	MyExtensions2 = case proplists:get_value(size, State#state.options) of
		undefined ->
			MyExtensions1;
		infinity ->
			[ {"SIZE", "0"} | lists:keydelete("SIZE", 1, MyExtensions1) ];
		Size when is_integer(Size), Size > 0 ->
			[ {"SIZE", integer_to_list(Size)} | lists:keydelete("SIZE", 1, MyExtensions1) ]
	end,
	{ok, MyExtensions2, State}.

%% @doc Handle the MAIL FROM verb. The From argument is the email address specified by the
%% MAIL FROM command. Extensions to the MAIL verb are handled by the `handle_MAIL_extension'
%% function.
%%
%% Return values are either `{ok, State}' or `{error, Message, State}' as before.
-spec handle_MAIL(From :: binary(), State :: #state{}) -> {'ok', #state{}} | error_message().
handle_MAIL(<<"badguy@blacklist.com">>, State) ->
	{error, "552 go away", State};
handle_MAIL(From, State) ->
	?log(info, "Mail from ~s~n", [From]),
	% you can accept or reject the FROM address here
	{ok, State}.

%% @doc Handle an extension to the MAIL verb. Return either `{ok, State}' or `error' to reject
%% the option.
-spec handle_MAIL_extension(Extension :: binary(), State :: #state{}) -> {'ok', #state{}} | 'error'.
handle_MAIL_extension(<<"X-SomeExtension">> = Extension, State) ->
	?log(info, "Mail from extension ~s~n", [Extension]),
	% any MAIL extensions can be handled here
	{ok, State};
handle_MAIL_extension(Extension, _State) ->
	?log(warning, "Unknown MAIL FROM extension ~s~n", [Extension]),
	error.

-spec handle_RCPT(To :: binary(), State :: #state{}) -> {'ok', #state{}} | {'error', string(), #state{}}.
handle_RCPT(<<"nobody@example.com">>, State) ->
	{error, "550 No such recipient", State};
handle_RCPT(To, State) ->
	?log(info, "Mail to ~s~n", [To]),
	% you can accept or reject RCPT TO addresses here, one per call
	{ok, State}.

-spec handle_RCPT_extension(Extension :: binary(), State :: #state{}) -> {'ok', #state{}} | 'error'.
handle_RCPT_extension(<<"X-SomeExtension">> = Extension, State) ->
	% any RCPT TO extensions can be handled here
	?log(info, "Mail to extension ~s~n", [Extension]),
	{ok, State};
handle_RCPT_extension(Extension, _State) ->
	?log(warning, "Unknown RCPT TO extension ~s~n", [Extension]),
	error.

%% @doc Handle the DATA verb from the client, which corresponds to the body of
%% the message. After receiving the body, a SMTP server can put the email in
%% a queue for later delivering while a LMTP server can handle the delivery
%% directly (LMTP servers are supposed to be simpler and handle emails to
%% local users directly without the need for a queue). Relaying the email to
%% another server is also an option.
%%
%% When using the SMTP protocol, `handle_DATA' should return a single "aggregate" delivery status
%% in the form of a `{ok, SuccessMsg, State}' tuple or `{error, ErrorMsg, State}'.
%% At this point, if `ok' is returned, we have accepted the full responsibility
%% of delivering the email.
%%
%% When using the LMTP protocol, `handle_DATA' should return a status for
%% each accepted address in `handle_RCPT' in the form of a `{multiple, StatusList, State}' tuple
%% where `StatusList' is a list of `{ok, SuccessMsg}' or `{error, ErrorMsg}' tuples
%% (the statuses should be presented in the same order as the recipient addresses were accepted).
%% For each `ok' in the `StatusList', we have accepted full responsibility for
%% delivering the email to that specific recipient. When a single recipient is
%% specified the returned value can also follow the SMTP format.
%%
%% `ErrorMsg' should always start with the SMTP error code, while `SuccessMsg'
%% should not (the `250' code is automatically prepended).
%%
%% According to the SMTP specification the, responsibility of delivering an
%% email must be taken seriously and the servers MUST NOT loose the message.
-spec handle_DATA(From :: binary(),
				  To :: [binary(),...],
				  Data :: binary(),
				  State :: #state{}
				 ) -> {ok | error, string(), #state{}} |
					  {multiple, [{ok | error, string()}], #state{}}.
handle_DATA(_From, _To, <<>>, State) ->
	{error, "552 Message too small", State};
handle_DATA(From, To, Data, State) ->
	% if RELAY is true, then relay email to email address, else send email data to console
	case proplists:get_value(relay, State#state.options, false) of
		true -> relay(From, To, Data);
		false ->
			% some kind of unique id
			Reference = lists:flatten([io_lib:format("~2.16.0b", [X]) || <<X>> <= erlang:md5(term_to_binary(unique_id()))]),
			case proplists:get_value(parse, State#state.options, false) of
				false -> ok;
				true ->
					% In this example we try to decode the email
					try mimemail:decode(Data) of
						_Result ->
							?log(info, "Message decoded successfully!~n")
					catch
						What:Why ->
							?log(warning, "Message decode FAILED with ~p:~p~n", [What, Why]),
							case proplists:get_value(dump, State#state.options, false) of
							false -> ok;
							true ->
								%% optionally dump the failed email somewhere for analysis
								File = "dump/"++Reference,
								case filelib:ensure_dir(File) of
									ok ->
										file:write_file(File, Data);
									_ ->
										ok
								end
							end
					end
			end,
			queue_or_deliver(From, To, Data, Reference, State)
	end.

-spec handle_RSET(State :: #state{}) -> #state{}.
handle_RSET(State) ->
	% reset any relevant internal state
	State.

-spec handle_VRFY(Address :: binary(), State :: #state{}) -> {'ok', string(), #state{}} | {'error', string(), #state{}}.
handle_VRFY(<<"someuser">>, State) ->
	{ok, "someuser@"++smtp_util:guess_FQDN(), State};
handle_VRFY(_Address, State) ->
	{error, "252 VRFY disabled by policy, just send some mail", State}.

-spec handle_other(Verb :: binary(), Args :: binary(), #state{}) -> {string(), #state{}}.
handle_other(Verb, _Args, State) ->
	% You can implement other SMTP verbs here, if you need to
	{["500 Error: command not recognized : '", Verb, "'"], State}.

%% this callback is OPTIONAL
%% it only gets called if you add AUTH to your ESMTP extensions
-spec handle_AUTH(Type :: 'login' | 'plain' | 'cram-md5', Username :: binary(), Password :: binary() | {binary(), binary()}, #state{}) -> {'ok', #state{}} | 'error'.
handle_AUTH(Type, <<"username">>, <<"PaSSw0rd">>, State) when Type =:= login; Type =:= plain ->
	{ok, State};
handle_AUTH('cram-md5', <<"username">>, {Digest, Seed}, State) ->
	case smtp_util:compute_cram_digest(<<"PaSSw0rd">>, Seed) of
		Digest ->
			{ok, State};
		_ ->
			error
	end;
handle_AUTH(_Type, _Username, _Password, _State) ->
	error.

%% this callback is OPTIONAL
%% it only gets called if you add STARTTLS to your ESMTP extensions
-spec handle_STARTTLS(#state{}) -> #state{}.
handle_STARTTLS(State) ->
    ?log(info, "TLS Started~n"),
    State.

-spec handle_info(Info :: term(), State :: term()) ->
    {noreply, NewState :: term()} |
    {noreply, NewState :: term(), timeout() | hibernate} |
    {stop, Reason :: term(), NewState :: term()}.
handle_info(_Info, State) ->
    ?log(info, "handle_info(~p, ~p)", [_Info, State]),
	{noreply, State}.

%% This optional callback is called when different kinds of protocol errors happen.
%% Return {ok, State} to let gen_smtp decide how to act or {stop, Reason, #state{}}
%% to stop the process with reason Reason immediately.
-spec handle_error(gen_smtp_server_session:error_class(), any(), #state{}) ->
		  {ok, State} | {stop, any(), State}.
handle_error(Class, Details, State) ->
    ?log(info, "handle_error(~p, ~p, ~p)", [Class, Details, State]),
	{ok, State}.

-spec code_change(OldVsn :: any(), State :: #state{}, Extra :: any()) -> {ok, #state{}}.
code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

-spec terminate(Reason :: any(), State :: #state{}) -> {'ok', any(), #state{}}.
terminate(Reason, State) ->
	{ok, Reason, State}.

%%% Internal Functions %%%

unique_id() ->
    erlang:unique_integer().

-spec relay(binary(), [binary()], binary()) -> ok.
relay(_, [], _) ->
	ok;
relay(From, [To|Rest], Data) ->
	% relay message to email address
	[_User, Host] = string:tokens(binary_to_list(To), "@"),
	gen_smtp_client:send({From, [To], erlang:binary_to_list(Data)}, [{relay, Host}]),
	relay(From, Rest, Data).

%% @doc Helps `handle_DATA' to deal with the received email.
%% This function is not directly required by the behaviour.
-spec queue_or_deliver(From :: binary(),
					   To :: [binary(),...],
					   Data :: binary(),
					   Reference :: string(),
					   State :: #state{}
					  ) -> {ok | error, string(), #state{}} |
						   {multiple, [{ok | error, string()}], #state{}}.
queue_or_deliver(From, To, Data, Reference, State) ->
	% At this point, if we return ok, we've accepted responsibility for the emaill
	Length = byte_size(Data),
	case proplists:get_value(protocol, State#state.options, smtp) of
		smtp ->
			?log(info, "message from ~s to ~p queued as ~s, body length ~p~n", [From, To, Reference, Length]),
			% ... should actually handle the email,
			%     if `ok` is returned we are taking the responsibility of the delivery.
			{ok, ["queued as ~s", Reference], State};
		lmtp ->
			?log(info, "message from ~s delivered to ~p, body length ~p~n", [From, To, Length]),
			Multiple = [{ok, ["delivered to ", Recipient]} || Recipient <- To],
			% ... should actually handle the email for each recipient for each `ok`
			{multiple, Multiple, State}
	end.
