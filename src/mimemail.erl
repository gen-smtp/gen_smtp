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

%%% @doc A module for decoding/encoding MIME 1.0 email
-module(mimemail).

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([encode/1, decode/2, decode/1]).

-compile(export_all).

-define(DEFAULT_OPTIONS, [
		{encoding, get_default_encoding()}, % default encoding is utf-8 if we can find the iconv module
		{decode_attachments, true} % should we decode any base64/quoted printable attachments?
	]).

-spec(decode/1 :: (Email :: string()) -> {string(), string(), [{string(), string()}], [{string(), string()}], list()}).
decode(All) ->
	{Headers, Body} = parse_headers(All),
	decode(Headers, Body, ?DEFAULT_OPTIONS).

-spec(decode/2 :: (Headers :: [{string(), string()}], Body :: string()) -> {string(), string(), [{string(), string()}], [{string(), string()}], list()}).
decode(All, Options) when is_binary(All), is_list(Options) ->
	{Headers, Body} = parse_headers(All),
	decode(Headers, Body, Options);
decode(Headers, Body) when is_list(Headers), is_binary(Body) ->
	decode(Headers, Body, ?DEFAULT_OPTIONS).

decode(Headers, Body, Options) ->
	case proplists:get_value(encoding, Options, none) of
		none ->
			ok;
		SomeEncoding ->
			case whereis(iconv) of
				undefined ->
					{ok, _Pid} = iconv:start();
				_ ->
					ok
			end
	end,
	%FixedHeaders = fix_headers(Headers),
	case parse_with_comments(get_header_value(<<"MIME-Version">>, Headers)) of
		undefined ->
			erlang:error(non_mime);
		Other ->
			decode_component(Headers, Body, Other)
	end.

-spec(encode/1 :: (MimeMail :: {string(), string(), [{string(), string()}], [{string(), string()}], list()}) -> string()).
encode({_Type, _Subtype, Headers, ContentTypeParams, Parts}) ->
	string:join(encode_headers(Headers), "\r\n") ++ "\r\n\r\n" ++ 
	string:join(
		encode_component(ContentTypeParams, Parts),
		"\r\n"
	);
encode(_) ->
	io:format("Not a mime-decoded DATA~n"),
	erlang:error(non_mime).


decode_headers([], Acc, Charset) ->
	lists:reverse(Acc);
decode_headers([{Key, Value} | Headers], Acc, Charset) ->
	decode_headers(Headers, [{Key, decode_header(Value, Charset)} | Acc], Charset).

decode_header(Value, Charset) ->
	case re:run(Value, "=\\?([-A-Za-z0-9_]+)\\?([^/s])\\?([^\s]+)\\?=", [ungreedy]) of
		nomatch ->
			Value;
		{match,[{AllStart, AllEnd},{EncodingStart, EncodingEnd},{TypeStart, _},{DataStart, DataEnd}]} ->
			Encoding = binstr:substr(Value, EncodingStart+1, EncodingEnd),
			Type = binstr:to_lower(binstr:substr(Value, TypeStart+1, 1)),
			Data = binstr:substr(Value, DataStart+1, DataEnd),

			io:format("data: ~p~n", [Data]),

			DecodedData = case Type of
				<<"q">> ->
					decode_quoted_printable(re:replace(Data, "_", " ", [{return, binary}, global]));
				<<"b">> ->
					decode_base64(re:replace(Data, "_", " ", [{return, binary}, global]))
			end,

			io:format("~p~n", [binstr:substr(Value, AllStart + 1 + AllEnd)]),

			Tail = case binstr:strpos(binstr:substr(Value, AllStart + 1 + AllEnd), "=?") of
				0 ->
					binstr:substr(Value, AllStart + 1 + AllEnd);
				Index ->
					binstr:substr(Value, AllStart + AllEnd + Index)
			end,

			io:format("Encoding is ~p, Data is ~p~n", [Encoding, DecodedData]),
			NewValue = list_to_binary([binstr:substr(Value, 1, AllStart), DecodedData, Tail]),
			decode_header(NewValue, Charset)
	end.


decode_component(Headers, Body, MimeVsn) when MimeVsn =:= <<"1.0">> ->
	case parse_content_disposition(get_header_value(<<"Content-Disposition">>, Headers)) of
		{Disposition, DispositionParams} ->
			ok;
		_ -> % defaults
			Disposition = <<"inline">>,
			DispositionParams = []
	end,

	case parse_content_type(get_header_value(<<"Content-Type">>, Headers)) of
		{<<"multipart">>, SubType, Parameters} ->
			case proplists:get_value(<<"boundary">>, Parameters) of
				undefined ->
					erlang:error(no_boundary);
				Boundary ->
					% io:format("this is a multipart email of type:  ~s and boundary ~s~n", [SubType, Boundary]),
					Parameters2 = [{<<"content-type-params">>, Parameters}, {<<"disposition">>, Disposition}, {<<"disposition-params">>, DispositionParams}],
					{<<"multipart">>, SubType, Headers, Parameters2, split_body_by_boundary(Body, list_to_binary(["--", Boundary]), MimeVsn)}
			end;
		{<<"message">>, <<"rfc822">>, Parameters} ->
			{NewHeaders, NewBody} = parse_headers(Body),
			Parameters2 = [{<<"content-type-params">>, Parameters}, {<<"disposition">>, Disposition}, {<<"disposition-params">>, DispositionParams}],
			{<<"message">>, <<"rfc822">>, Headers, Parameters2, decode(NewHeaders, NewBody)};
		{Type, SubType, Parameters} ->
			%io:format("body is ~s/~s~n", [Type, SubType]),
			Parameters2 = [{<<"content-type-params">>, Parameters}, {<<"disposition">>, Disposition}, {<<"disposition-params">>, DispositionParams}],
			{Type, SubType, Headers, Parameters2, decode_body(get_header_value(<<"Content-Transfer-Encoding">>, Headers), Body)};
		undefined -> % defaults
			Type = <<"text">>,
			SubType = <<"plain">>,
			Parameters = [{<<"content-type-params">>, {<<"charset">>, <<"us-ascii">>}}, {<<"disposition">>, Disposition}, {<<"disposition-params">>, DispositionParams}],
			{Type, SubType, Headers, Parameters, Body}
	end;
decode_component(Headers, Body, Other) ->
	% io:format("Unknown mime version ~s~n", [Other]),
	{error, mime_version}.

-spec(get_header_value/2 :: (Needle :: string(), Headers :: [{string(), string()}]) -> string() | 'undefined').
get_header_value(Needle, Headers) ->
	%io:format("Headers: ~p~n", [Headers]),
	F =
	fun({Header, _Value}) ->
			string:to_lower(binary_to_list(Header)) =:= string:to_lower(binary_to_list(Needle))
	end,
	case lists:filter(F, Headers) of
		% TODO if there's duplicate headers, should we use the first or the last?
		[{_Header, Value}|_T] ->
			Value;
		_ ->
			undefined
	end.

-spec(parse_with_comments/1 :: (Value :: string()) -> string() | 'error';
	(Value :: atom()) -> atom()).
parse_with_comments(Value) when is_binary(Value) ->
	parse_with_comments(Value, [], 0, false);
parse_with_comments(Value) ->
	Value.

-spec(parse_with_comments/4 :: (Value :: string(), Acc :: string(), Depth :: non_neg_integer(), Quotes :: bool()) -> string() | 'error').
parse_with_comments(<<>>, Acc, Depth, Quotes) when Quotes ->
	{error, quotes};
parse_with_comments(<<>>, Acc, Depth, Quotes) when Depth > 0 ->
	{error, comments};
parse_with_comments(<<>>, Acc, Depth, _Quotes) ->
	binstr:strip(list_to_binary(lists:reverse(Acc)));
parse_with_comments(<<$\\, H, Tail/binary>>, Acc, Depth, Quotes) when Depth > 0, H > 32, H < 127 ->
	parse_with_comments(Tail, Acc, Depth, Quotes);
parse_with_comments(<<$\\, Tail/binary>>, Acc, Depth, Quotes) when Depth > 0 ->
	parse_with_comments(Tail, Acc, Depth, Quotes);
parse_with_comments(<<$\\, H, Tail/binary>>, Acc, Depth, Quotes) when H > 32, H < 127 ->
	parse_with_comments(Tail, [H | Acc], Depth, Quotes);
parse_with_comments(<<$\\, Tail/binary>>, Acc, Depth, Quotes) ->
	parse_with_comments(Tail, [$\\ | Acc], Depth, Quotes);
parse_with_comments(<<$(, Tail/binary>>, Acc, Depth, Quotes) when not Quotes ->
	parse_with_comments(Tail, Acc, Depth + 1, Quotes);
parse_with_comments(<<$), Tail/binary>>, Acc, Depth, Quotes) when Depth > 0, not Quotes ->
	parse_with_comments(Tail, Acc, Depth - 1, Quotes);
parse_with_comments(<<_, Tail/binary>>, Acc, Depth, Quotes) when Depth > 0 ->
	parse_with_comments(Tail, Acc, Depth, Quotes);
parse_with_comments(<<$", T/binary>>, Acc, Depth, true) -> %"
	parse_with_comments(T, Acc, Depth, false);
parse_with_comments(<<$", T/binary>>, Acc, Depth, false) -> %"
	parse_with_comments(T, Acc, Depth, true);
parse_with_comments(<<H, Tail/binary>>, Acc, Depth, Quotes) ->
	parse_with_comments(Tail, [H | Acc], Depth, Quotes).

-spec(parse_content_type/1 :: (Value :: 'undefined') -> 'undefined';
	(Value :: string()) -> {string(), string(), string()}).
parse_content_type(undefined) ->
	undefined;
parse_content_type(String) ->
	try parse_content_disposition(String) of
		{RawType, Parameters} ->
			case binstr:strchr(RawType, $/) of
				Index when Index < 2 ->
					throw(bad_content_type);
				Index ->
					Type = binstr:substr(RawType, 1, Index - 1),
					SubType = binstr:substr(RawType, Index + 1),
					{binstr:to_lower(Type), binstr:to_lower(SubType), Parameters}
			end
		catch
			bad_disposition ->
				throw(bad_content_type)
	end.

-spec(parse_content_disposition/1 :: (Value :: 'undefined') -> 'undefined';
	(String :: string()) -> {string(), string()}).
parse_content_disposition(undefined) ->
	undefined;
parse_content_disposition(String) ->
	[Disposition | Parameters] = binstr:split(parse_with_comments(String), <<";">>),
	F =
	fun(X) ->
		Y = binstr:strip(binstr:strip(X), both, $\t),
		case binstr:strchr(Y, $=) of
			Index when Index < 2 ->
				throw(bad_disposition);
			Index ->
				Key = binstr:substr(Y, 1, Index - 1),
				Value = binstr:substr(Y, Index + 1),
				{binstr:to_lower(Key), Value}
		end
	end,
	Params = lists:map(F, Parameters),
	{binstr:to_lower(Disposition), Params}.

split_body_by_boundary(Body, Boundary, MimeVsn) ->
	% find the indices of the first and last boundary
	case [binstr:strpos(Body, Boundary), binstr:strpos(Body, list_to_binary([Boundary, "--"]))] of
		[Start, End] when Start =:= 0; End =:= 0 ->
			erlang:error(bad_boundary);
		[Start, End] ->
			NewBody = binstr:substr(Body, Start + byte_size(Boundary), End - Start),
			% from now on, we can be sure that each boundary is preceeded by a CRLF
			Parts = split_body_by_boundary_(NewBody, list_to_binary(["\r\n", Boundary]), []),
			Res = lists:filter(fun({Headers, Body2}) -> byte_size(Body2) =/= 0 end, Parts),
			lists:map(fun({Headers, Body2}) -> decode_component(Headers, Body2, MimeVsn) end, Res)
	end.

split_body_by_boundary_([], _Boundary, Acc) ->
	list_to_binary(lists:reverse(Acc));
split_body_by_boundary_(Body, Boundary, Acc) ->
	% trim the incomplete first line
	TrimmedBody = binstr:substr(Body, binstr:strpos(Body, "\r\n") + 2),
	case binstr:strpos(TrimmedBody, Boundary) of
		0 ->
			lists:reverse([{[], TrimmedBody} | Acc]);
		Index ->
			split_body_by_boundary_(binstr:substr(TrimmedBody, Index + byte_size(Boundary)), Boundary,
				[parse_headers(binstr:substr(TrimmedBody, 1, Index - 1)) | Acc])
	end.

-spec(parse_headers/1 :: (Body :: string()) -> {[{string(), string()}], string()}).
parse_headers(Body) ->
	case binstr:strpos(Body, "\r\n") of
		0 ->
			{[], Body};
		1 ->
			{[], binstr:substr(Body, 3)};
		Index ->
			parse_headers(binstr:substr(Body, Index+2), binstr:substr(Body, 1, Index - 1), [])
	end.


parse_headers(Body, <<H, Tail/binary>>, []) when H =:= $\s; H =:= $\t ->
	% folded headers
	{[], list_to_binary([H, Tail, "\r\n", Body])};
parse_headers(Body, <<H, T/binary>>, Headers) when H =:= $\s; H =:= $\t ->
	% folded headers
	[{FieldName, OldFieldValue} | OtherHeaders] = Headers,
	FieldValue = list_to_binary([OldFieldValue, T]),
	%io:format("~p = ~p~n", [FieldName, FieldValue]),
	case binstr:strpos(Body, "\r\n") of
		0 ->
			{lists:reverse([{FieldName, FieldValue} | OtherHeaders]), Body};
		1 ->
			{lists:reverse([{FieldName, FieldValue} | OtherHeaders]), binstr:substr(Body, 3)};
		Index2 ->
			parse_headers(binstr:substr(Body, Index2 + 2), binstr:substr(Body, 1, Index2 - 1), [{FieldName, FieldValue} | OtherHeaders])
	end;
parse_headers(Body, Line, Headers) ->
	%io:format("line: ~p, nextpart ~p~n", [Line, binstr:substr(Body, 1, 10)]),
	case binstr:strchr(Line, $:) of
		0 ->
			{lists:reverse(Headers), list_to_binary([Line, "\r\n", Body])};
		Index ->
			FieldName = binstr:substr(Line, 1, Index - 1),
			F = fun(X) -> X > 32 andalso X < 127 end,
			case binstr:all(F, FieldName) of
				true ->
					FieldValue = binstr:strip(binstr:substr(Line, Index+1)),
					case binstr:strpos(Body, "\r\n") of
						0 ->
							{lists:reverse([{FieldName, FieldValue} | Headers]), Body};
						1 ->
							{lists:reverse([{FieldName, FieldValue} | Headers]), binstr:substr(Body, 3)};
						Index2 ->
							parse_headers(binstr:substr(Body, Index2 + 2), binstr:substr(Body, 1, Index2 - 1), [{FieldName, FieldValue} | Headers])
					end;
				false ->
					{lists:reverse(Headers), list_to_binary([Line, "\r\n", Body])}
			end
	end.

-spec(decode_body/2 :: (Type :: string() | 'undefined', Body :: string()) -> string()).
decode_body(undefined, Body) ->
	Body;
decode_body(Type, Body) ->
	case binstr:to_lower(Type) of
		<<"quoted-printable">> ->
			decode_quoted_printable(Body);
		<<"base64">> ->
			decode_base64(Body);
		Other ->
			Body
	end.

decode_base64(Body) ->
	base64:mime_decode(Body).

decode_quoted_printable(Body) ->
	case binstr:strpos(Body, "\r\n") of
		0 ->
			decode_quoted_printable(Body, <<>>, []);
		Index ->
			decode_quoted_printable(binstr:substr(Body, 1, Index +1), binstr:substr(Body, Index + 2), [])
	end.

decode_quoted_printable(<<>>, <<>>, Acc) ->
	list_to_binary(lists:reverse(Acc));
decode_quoted_printable(Line, Rest, Acc) ->
	%?debugFmt("line ~p~n", [Line]),
	%?debugFmt("rest ~p~n", [Rest]),
	case binstr:strpos(Rest, "\r\n") of
		0 ->
			decode_quoted_printable(Rest, <<>>, [decode_quoted_printable_line(Line, []) | Acc]);
		Index ->
			%io:format("next line ~p~nnext rest ~p~n", [binstr:substr(Rest, 1, Index +1), binstr:substr(Rest, Index + 2)]),
			decode_quoted_printable(binstr:substr(Rest, 1, Index +1), binstr:substr(Rest, Index + 2),
				[decode_quoted_printable_line(Line, []) | Acc])
	end.

decode_quoted_printable_line(<<>>, Acc) ->
	lists:reverse(Acc);
decode_quoted_printable_line(<<$\r, $\n>>, Acc) ->
	lists:reverse(["\r\n" | Acc]);
decode_quoted_printable_line(<<$=, C, T/binary>>, Acc) when C =:= $\s; C =:= $\t ->
	case binstr:all(fun(X) -> X =:= $\s orelse X =:= $\t end, T) of
		true ->
			lists:reverse(Acc);
		false ->
			throw(badchar)
	end;
decode_quoted_printable_line(<<$=, $\r, $\n>>, Acc) ->
	lists:reverse(Acc);
decode_quoted_printable_line(<<$=, A:2/binary, T/binary>>, Acc) ->
	%<<X:1/binary, Y:1/binary>> = A,
	case binstr:all(fun(C) -> (C >= $0 andalso C =< $9) orelse (C >= $A andalso C =< $F) end, A) of
		true ->
			{ok, [C | []], []} = io_lib:fread("~16u", binary_to_list(A)),
			decode_quoted_printable_line(T, [C | Acc]);
		false ->
			throw(badchar)
	end;
decode_quoted_printable_line(<<$=>>, Acc) ->
	% soft newline
	lists:reverse(Acc);
decode_quoted_printable_line(<<H, T/binary>>, Acc) when H >= $!, H =< $< ->
	decode_quoted_printable_line(T, [H | Acc]);
decode_quoted_printable_line(<<H, T/binary>>, Acc) when H >= $>, H =< $~ ->
	decode_quoted_printable_line(T, [H | Acc]);
decode_quoted_printable_line(<<H, T/binary>>, Acc) when H =:= $\s; H =:= $\t ->
	% if the rest of the line is whitespace, truncate it
	case binstr:all(fun(X) -> X =:= $\s orelse X =:= $\t end, T) of
		true ->
			lists:reverse(Acc);
		false ->
			decode_quoted_printable_line(T, [H | Acc])
	end.

encode_headers(Headers) ->
	encode_headers(Headers, []).
encode_headers([], EncodedHeaders) ->
	EncodedHeaders;
encode_headers([{Key, Value}|T] = _Headers, EncodedHeaders) ->
	encode_headers(T, encode_folded_header(Key++": "++Value, EncodedHeaders)).

encode_folded_header(Header, HeaderLines) ->
  case string:str(Header, ";") of
		0 ->
			HeaderLines ++ [Header];
		Index ->
			Remainder = string:substr(Header, Index+1),
			TabbedRemainder = case Remainder of
				[$\t|_] -> Remainder;
				_       -> "\t"++Remainder
			end,
			HeaderLines ++
			[ string:substr(Header, 1, Index) ] ++
			encode_folded_header(TabbedRemainder, [])
	end.

encode_component(Params, Parts) ->
	case Params of

		% is this a multipart component?
		[	{"content-type-params", [{"boundary", Boundary}]},
			{"disposition", "inline"},
			{"disposition-params", []}
		] ->
			[""] ++  % blank line before start of component
			lists:flatmap(
				fun(Part) ->
					["--"++Boundary] ++ % start with the boundary
					encode_component_part(Part)
				end,
				Parts
			) ++ ["--"++Boundary++"--"] % final boundary (with /--$/)
			  ++ [""]; % blank line at the end of the multipart component

		% or an inline component?
	  _ -> [Parts]
	end.

encode_component_part(Part) ->
	case Part of
		{<<"multipart">>, _, Headers, PartParams, Body} ->
			encode_headers(Headers)
			++ [""] ++
			encode_component(PartParams, Body);

		{_Type, _SubType, Headers, _PartParams, Body} ->
			PartData = case Body of
				{_,_,_,_,_} -> encode_component_part(Body);
				String      -> [String]
			end,
			encode_headers(Headers)
			++ [""] ++
			encode_body(
					get_header_value("Content-Transfer-Encoding", Headers),
					PartData
			 );

		_ ->
			io:format("encode_component_part couldn't match Part to: ~p~n", [Part]),
			[]
	end.

encode_body(undefined, Body) ->
	Body;
encode_body(Type, Body) ->
	case string:to_lower(Type) of
		"quoted-printable" ->
			[InnerBody] = Body,
			encode_quoted_printable(InnerBody);
		"base64" ->
			[InnerBody] = Body,
			wrap_to_76(base64:encode_to_string(InnerBody)) ++ [""];
		_ -> Body
	end.

wrap_to_76(String) ->
	wrap_to_76(String, []).
wrap_to_76([], Lines) ->
	Lines;
wrap_to_76(String, Lines) when length(String) >= 76 ->
	wrap_to_76(
		string:substr(String, 76+1),
		Lines ++ [string:substr(String, 1, 76)]
	);
wrap_to_76(String, Lines) ->
	wrap_to_76(
		[],
		Lines ++ [String]
	).

encode_quoted_printable(Body) ->
	[encode_quoted_printable(Body, [], 0)].

encode_quoted_printable(Body, Acc, L) when L >= 75 ->
	LastLine = case string:str(Acc, "\n") of
		0 ->
			Acc;
		Index ->
			string:substr(Acc, 1, Index-1)
	end,
	Len = length(LastLine),
	case string:str(LastLine, " ") of
		0 when L =:= 75 ->
			% uh-oh, no convienient whitespace, just cram a soft newline in
			encode_quoted_printable(Body, [$\n, $\r, $= | Acc], 0);
		1 when L =:= 75 ->
			% whitespace is the last character we wrote
			encode_quoted_printable(Body, [$\n, $\r, $= | Acc], 0);
		SIndex when (L - 75) < SIndex ->
			% okay, we can safely stick some whitespace in
			Prefix = string:substr(Acc, 1, SIndex-1),
			Suffix = string:substr(Acc, SIndex),
			NewAcc = lists:concat([Prefix, "\n\r=", Suffix]),
			encode_quoted_printable(Body, NewAcc, 0);
		_ ->
			% worst case, we're over 75 characters on the line
			% and there's no obvious break points, just stick one
			% in at position 75 and call it good. However, we have
			% to be very careful not to stick the soft newline in
			% the middle of an existing quoted-printable escape.

			% TODO - fix this to be less stupid
			I = 3, % assume we're at most 3 over our cutoff
			Prefix = string:substr(Acc, 1, I),
			Suffix = string:substr(Acc, I+1),
			NewAcc = lists:concat([Prefix, "\n\r=", Suffix]),
			encode_quoted_printable(Body, NewAcc, 0)
	end;
encode_quoted_printable([], Acc, _L) ->
	lists:reverse(Acc);
encode_quoted_printable([$= | T] , Acc, L) ->
	encode_quoted_printable(T, [$D, $3, $= | Acc], L+3);
encode_quoted_printable([$\r, $\n | T] , Acc, L) ->
	encode_quoted_printable(T, [$\n, $\r | Acc], 0);
encode_quoted_printable([H | T], Acc, L) when H >= $!, H =< $< ->
	encode_quoted_printable(T, [H | Acc], L+1);
encode_quoted_printable([H | T], Acc, L) when H >= $>, H =< $~ ->
	encode_quoted_printable(T, [H | Acc], L+1);
encode_quoted_printable([H, $\r, $\n | T], Acc, L) when H =:= $\s; H =< $\t ->
	[[A, B]] = io_lib:format("~2.16.0B", [H]),
	encode_quoted_printable(T, [$\n, $\r, B, A, $= | Acc], 0);
encode_quoted_printable([H | T], Acc, L) when H =:= $\s; H =< $\t ->
	encode_quoted_printable(T, [H | Acc], L+1);
encode_quoted_printable([H | T], Acc, L) ->
	[[A, B]]= io_lib:format("=~2.16.0B", [H]),
	encode_quoted_printable(T, [B, A, $= | Acc], L+3).

get_default_encoding() ->
	case code:ensure_loaded(iconv) of
		{error, _} ->
			none;
		{module, iconv} ->
			<<"utf-8">>
	end.

-ifdef(EUNIT).

parse_with_comments_test_() ->
	[
		{"bleh",
			fun() ->
					?assertEqual(<<"1.0">>, parse_with_comments(<<"1.0">>)),
					?assertEqual(<<"1.0">>, parse_with_comments(<<"1.0  (produced by MetaSend Vx.x)">>)),
					?assertEqual(<<"1.0">>, parse_with_comments(<<"(produced by MetaSend Vx.x) 1.0">>)),
					?assertEqual(<<"1.0">>, parse_with_comments(<<"1.(produced by MetaSend Vx.x)0">>))
			end
		},
		{"comments that parse as empty",
			fun() ->
					?assertEqual(<<>>, parse_with_comments(<<"(comment (nested (deeply)) (and (oh no!) again))">>)),
					?assertEqual(<<>>, parse_with_comments(<<"(\\)\\\\)">>)),
					?assertEqual(<<>>, parse_with_comments(<<"(by way of Whatever <redir@my.org>)    (generated by Eudora)">>))
			end
		},
		{"some more",
			fun() ->
					?assertEqual(<<":sysmail@  group. org, Muhammed. Ali @Vegas.WBA">>, parse_with_comments(<<"\":sysmail\"@  group. org, Muhammed.(the greatest) Ali @(the)Vegas.WBA">>)),
					?assertEqual(<<"Pete <pete@silly.test>">>, parse_with_comments(<<"Pete(A wonderful \\) chap) <pete(his account)@silly.test(his host)>">>))
			end
		},
		{"non list values",
			fun() ->
					?assertEqual(undefined, parse_with_comments(undefined)),
					?assertEqual(17, parse_with_comments(17))
			end
		},
		{"Parens within quotes ignored",
			fun() ->
				?assertEqual(<<"Height (from xkcd).eml">>, parse_with_comments(<<"\"Height (from xkcd).eml\"">>)),
				?assertEqual(<<"Height (from xkcd).eml">>, parse_with_comments(<<"\"Height \(from xkcd\).eml\"">>))
			end
		},
		{"Escaped quotes are handled correctly",
			fun() ->
					?assertEqual(<<"Hello \"world\"">>, parse_with_comments(<<"Hello \\\"world\\\"">>)),
					?assertEqual(<<"<boss@nil.test>, Giant; \"Big\" Box <sysservices@example.net>">>, parse_with_comments(<<"<boss@nil.test>, \"Giant; \\\"Big\\\" Box\" <sysservices@example.net>">>))
			end
		},
		{"backslash not part of a quoted pair",
			fun() ->
					?assertEqual(<<"AC \\ DC">>, parse_with_comments(<<"AC \\ DC">>)),
					?assertEqual(<<"AC  DC">>, parse_with_comments(<<"AC ( \\ ) DC">>))
			end
		},
		{"Unterminated quotes or comments",
			fun() ->
					?assertEqual({error, quotes}, parse_with_comments(<<"\"Hello there ">>)),
					?assertEqual({error, quotes}, parse_with_comments(<<"\"Hello there \\\"">>)),
					?assertEqual({error, comments}, parse_with_comments(<<"(Hello there ">>)),
					?assertEqual({error, comments}, parse_with_comments(<<"(Hello there \\\)">>))
			end
		}
	].
	
parse_content_type_test_() ->
	[
		{"parsing content types",
			fun() ->
					?assertEqual({<<"text">>, <<"plain">>, [{<<"charset">>, <<"us-ascii">>}]}, parse_content_type(<<"text/plain; charset=us-ascii (Plain text)">>)),
					?assertEqual({<<"text">>, <<"plain">>, [{<<"charset">>, <<"us-ascii">>}]}, parse_content_type(<<"text/plain; charset=\"us-ascii\"">>)),
					?assertEqual({<<"text">>, <<"plain">>, [{<<"charset">>, <<"us-ascii">>}]}, parse_content_type(<<"Text/Plain; Charset=\"us-ascii\"">>)),
					?assertEqual({<<"multipart">>, <<"mixed">>, [{<<"boundary">>, <<"----_=_NextPart_001_01C9DCAE.1F2CB390">>}]},
						parse_content_type(<<"multipart/mixed; boundary=\"----_=_NextPart_001_01C9DCAE.1F2CB390\"">>))
			end
		},
		{"parsing content type with a tab in it",
			fun() ->
					?assertEqual({<<"text">>, <<"plain">>, [{<<"charset">>, <<"us-ascii">>}]}, parse_content_type(<<"text/plain;\tcharset=us-ascii">>)),
					?assertEqual({<<"text">>, <<"plain">>, [{<<"charset">>, <<"us-ascii">>}, {<<"foo">>, <<"bar">>}]}, parse_content_type(<<"text/plain;\tcharset=us-ascii;\tfoo=bar">>))
			end
		},
		{"invalid content types",
			fun() ->
					?assertThrow(bad_content_type, parse_content_type(<<"text\\plain; charset=us-ascii">>)),
					?assertThrow(bad_content_type, parse_content_type(<<"text/plain; charset us-ascii">>))
				end
			}
	].

parse_content_disposition_test_() ->
	[
		{"parsing valid dispositions",
			fun() ->
					?assertEqual({<<"inline">>, []}, parse_content_disposition(<<"inline">>)),
					?assertEqual({<<"inline">>, []}, parse_content_disposition(<<"inline;">>)),
					?assertEqual({<<"attachment">>, [{<<"filename">>, <<"genome.jpeg">>}, {<<"modification-date">>, <<"Wed, 12 Feb 1997 16:29:51 -0500">>}]}, parse_content_disposition(<<"attachment; filename=genome.jpeg;modification-date=\"Wed, 12 Feb 1997 16:29:51 -0500\";">>)),
					?assertEqual({<<"text/plain">>, [{<<"charset">>, <<"us-ascii">>}]}, parse_content_disposition(<<"text/plain; charset=us-ascii (Plain text)">>))
			end
		},
		{"invalid dispositions",
			fun() ->
					?assertThrow(bad_disposition, parse_content_disposition(<<"inline; =bar">>)),
					?assertThrow(bad_disposition, parse_content_disposition(<<"inline; bar">>))
			end
		}
	].

various_parsing_test_() ->
	[
		{"split_body_by_boundary test",
			fun() ->
					?assertEqual([{[], <<"foo bar baz">>}], split_body_by_boundary_(<<"stuff\r\nfoo bar baz">>, <<"--bleh">>, [])),
					?assertEqual([{[], <<"foo\r\n">>}, {[], <<>>}, {[], <<>>}, {[], <<"bar baz">>}], split_body_by_boundary_(<<"stuff\r\nfoo\r\n--bleh\r\n--bleh\r\n--bleh-- stuff\r\nbar baz">>, <<"--bleh">>, [])),
					%?assertEqual([{[], []}, {[], []}, {[], "bar baz"}], split_body_by_boundary_("\r\n--bleh\r\n--bleh\r\n", "--bleh", [])),
					%?debugFmt("~p~n", [split_body_by_boundary("stuff\r\nfoo\r\n--bleh\r\n--bleh\r\n--bleh-- stuff\r\nbar baz", "--bleh", "1.0")]),
					%?assertMatch([{"text", "plain", [], _,"foo\r\n"}], split_body_by_boundary("stuff\r\nfoo\r\n--bleh\r\n--bleh\r\n--bleh-- stuff\r\nbar baz", "--bleh", "1.0"))
					?assertEqual({[], <<"foo: bar\r\n">>}, parse_headers(<<"\r\nfoo: bar\r\n">>)),
					?assertEqual({[{<<"foo">>, <<"barbaz">>}], <<>>}, parse_headers(<<"foo: bar\r\n baz\r\n">>)),
					?assertEqual({[], <<" foo bar baz\r\nbam">>}, parse_headers(<<"\sfoo bar baz\r\nbam">>)),
					ok
			end
		}
	].

%-define(IMAGE_MD5, <<5,253,79,13,122,119,92,33,133,121,18,149,188,241,56,81>>).
-define(IMAGE_MD5, <<110,130,37,247,39,149,224,61,114,198,227,138,113,4,198,60>>).

parse_example_mails_test_() ->
	Getmail = fun(File) ->
		{ok, Email} = file:read_file(string:concat("testdata/", File)),
		%Email = binary_to_list(Bin),
		decode(Email)
	end,
	[
		{"parse a plain text email",
			fun() ->
				Decoded = Getmail("Plain-text-only.eml"),
				%?debugFmt("~p", [Decoded]),
				?assertEqual(5, tuple_size(Decoded)),
				{Type, SubType, Headers, Properties, Body} = Decoded,
				?assertEqual({<<"text">>, <<"plain">>}, {Type, SubType}),
				?assertEqual(<<"This message contains only plain text.\r\n">>, Body)
			end
		},
		{"parse a plain text email with no MIME header",
			fun() ->
				?assertError(non_mime, Getmail("Plain-text-only-no-MIME.eml"))
			end
		},
		{"rich text",
			fun() ->
				%% pardon my naming here.  apparently 'rich text' in mac mail
				%% means 'html'.
				Decoded = Getmail("rich-text.eml"),
				?assertEqual(5, tuple_size(Decoded)),
				{Type, SubType, Headers, Properties, Body} = Decoded,
				?assertEqual({<<"multipart">>, <<"alternative">>}, {Type, SubType}),
				?assertEqual(2, length(Body)),
				[Plain, Html] = Body,
				?assertEqual({5, 5}, {tuple_size(Plain), tuple_size(Html)}),
				?assertMatch({<<"text">>, <<"plain">>, _, _, <<"This message contains rich text.">>}, Plain),
				?assertMatch({<<"text">>, <<"html">>, _, _, <<"<html><body style=\"word-wrap: break-word; -webkit-nbsp-mode: space; -webkit-line-break: after-white-space; \"><b>This </b><i>message </i><span class=\"Apple-style-span\" style=\"text-decoration: underline;\">contains </span>rich text.</body></html>">>}, Html)
			end
		},
		{"rich text no boundary",
			fun() ->
				?assertError(no_boundary, Getmail("rich-text-no-boundary.eml"))
			end
		},
		{"rich text missing first boundary",
			fun() ->
				% TODO - should we handle this more elegantly?
				Decoded = Getmail("rich-text-missing-first-boundary.eml"),
				?assertEqual(5, tuple_size(Decoded)),
				{Type, SubType, Headers, Properties, Body} = Decoded,
				?assertEqual({<<"multipart">>, <<"alternative">>}, {Type, SubType}),
				?assertEqual(1, length(Body)),
				[Html] = Body,
				?assertEqual(5, tuple_size(Html)),
				?assertMatch({<<"text">>, <<"html">>, _, _, <<"<html><body style=\"word-wrap: break-word; -webkit-nbsp-mode: space; -webkit-line-break: after-white-space; \"><b>This </b><i>message </i><span class=\"Apple-style-span\" style=\"text-decoration: underline;\">contains </span>rich text.</body></html>">>}, Html)
			end
		},
		{"rich text missing last boundary",
			fun() ->
				?assertError(bad_boundary, Getmail("rich-text-missing-last-boundary.eml"))
			end
		},
		{"rich text missing last boundary",
			fun() ->
				?assertError(bad_boundary, Getmail("rich-text-broken-last-boundary.eml"))
			end
		},
		{"rich text missing text content type",
			fun() ->
				%% pardon my naming here.  apparently 'rich text' in mac mail
				%% means 'html'.
				Decoded = Getmail("rich-text-no-text-contenttype.eml"),
				?assertEqual(5, tuple_size(Decoded)),
				{Type, SubType, Headers, Properties, Body} = Decoded,
				?assertEqual({<<"multipart">>, <<"alternative">>}, {Type, SubType}),
				?assertEqual(2, length(Body)),
				[Plain, Html] = Body,
				?assertEqual({5, 5}, {tuple_size(Plain), tuple_size(Html)}),
				?assertMatch({<<"text">>, <<"plain">>, _, _, <<"This message contains rich text.">>}, Plain),
				?assertMatch({<<"text">>, <<"html">>, _, _, <<"<html><body style=\"word-wrap: break-word; -webkit-nbsp-mode: space; -webkit-line-break: after-white-space; \"><b>This </b><i>message </i><span class=\"Apple-style-span\" style=\"text-decoration: underline;\">contains </span>rich text.</body></html>">>}, Html)
			end
		},
		{"text attachment only",
			fun() ->
				Decoded = Getmail("text-attachment-only.eml"),
				?assertEqual(5, tuple_size(Decoded)),
				{Type, SubType, Headers, Properties, Body} = Decoded,
				?assertEqual({<<"multipart">>, <<"mixed">>}, {Type, SubType}),
				%?debugFmt("~p", [Body]),
				?assertEqual(1, length(Body)),
				Rich = <<"{\\rtf1\\ansi\\ansicpg1252\\cocoartf949\\cocoasubrtf460\r\n{\\fonttbl\\f0\\fswiss\\fcharset0 Helvetica;}\r\n{\\colortbl;\\red255\\green255\\blue255;}\r\n\\margl1440\\margr1440\\vieww9000\\viewh8400\\viewkind0\r\n\\pard\\tx720\\tx1440\\tx2160\\tx2880\\tx3600\\tx4320\\tx5040\\tx5760\\tx6480\\tx7200\\tx7920\\tx8640\\ql\\qnatural\\pardirnatural\r\n\r\n\\f0\\fs24 \\cf0 This is a basic rtf file.}">>,
				?assertMatch([{<<"text">>, <<"rtf">>, _, _, Rich}], Body)
			end
		},
		{"image attachment only",
			fun() ->
				Decoded = Getmail("image-attachment-only.eml"),
				?assertEqual(5, tuple_size(Decoded)),
				{Type, SubType, Headers, Properties, Body} = Decoded,
				?assertEqual({<<"multipart">>, <<"mixed">>}, {Type, SubType}),
				%?debugFmt("~p", [Body]),
				?assertEqual(1, length(Body)),
				?assertMatch([{<<"image">>, <<"jpeg">>, _, _, _}], Body),
				[H | _] = Body,
				[{<<"image">>, <<"jpeg">>, _, Parameters, Image}] = Body,
				?assertEqual(?IMAGE_MD5, erlang:md5(element(5, H))),
				?assertEqual(<<"inline">>, proplists:get_value(<<"disposition">>, Parameters)),
				?assertEqual(<<"spice-logo.jpg">>, proplists:get_value(<<"filename">>, proplists:get_value(<<"disposition-params">>, Parameters))),
				?assertEqual(<<"spice-logo.jpg">>, proplists:get_value(<<"name">>, proplists:get_value(<<"content-type-params">>, Parameters)))
			end
		},
		{"message attachment only",
			fun() ->
				Decoded = Getmail("message-as-attachment.eml"),
				?assertMatch({<<"multipart">>, <<"mixed">>, _, _, _}, Decoded),
				[Body] = element(5, Decoded),
				%?debugFmt("~p", [Body]),
				?assertMatch({<<"message">>, <<"rfc822">>, _, _, _}, Body),
				Subbody = element(5, Body),
				?assertMatch({<<"text">>, <<"plain">>, _, _, _}, Subbody),
				?assertEqual(<<"This message contains only plain text.\r\n">>, element(5, Subbody))
			end
		},
		{"message, image, and rtf attachments.",
			fun() ->
				Decoded = Getmail("message-image-text-attachments.eml"),
				?assertMatch({<<"multipart">>, <<"mixed">>, _, _, _}, Decoded),
				?assertEqual(3, length(element(5, Decoded))),
				[Message, Rtf, Image] = element(5, Decoded),
				?assertMatch({<<"message">>, <<"rfc822">>, _, _, _}, Message),
				Submessage = element(5, Message),
				?assertMatch({<<"text">>, <<"plain">>, _, _, <<"This message contains only plain text.\r\n">>}, Submessage),
				
				?assertMatch({<<"text">>, <<"rtf">>, _, _, _}, Rtf),
				?assertEqual(<<"{\\rtf1\\ansi\\ansicpg1252\\cocoartf949\\cocoasubrtf460\r\n{\\fonttbl\\f0\\fswiss\\fcharset0 Helvetica;}\r\n{\\colortbl;\\red255\\green255\\blue255;}\r\n\\margl1440\\margr1440\\vieww9000\\viewh8400\\viewkind0\r\n\\pard\\tx720\\tx1440\\tx2160\\tx2880\\tx3600\\tx4320\\tx5040\\tx5760\\tx6480\\tx7200\\tx7920\\tx8640\\ql\\qnatural\\pardirnatural\r\n\r\n\\f0\\fs24 \\cf0 This is a basic rtf file.}">>, element(5, Rtf)),
				
				?assertMatch({<<"image">>, <<"jpeg">>, _, _, _}, Image),
				?assertEqual(?IMAGE_MD5, erlang:md5(element(5, Image)))				
			end
		},
		{"Outlook 2007 with leading tabs in quoted-printable.",
			fun() ->
				Decoded = Getmail("outlook-2007.eml"),
				?assertMatch({<<"multipart">>, <<"alternative">>, _, _, _}, Decoded)
			end
		},
		{"The gamut",
			fun() ->
				% multipart/alternative
				%	text/plain
				%	multipart/mixed
				%		text/html
				%		message/rf822
				%			multipart/mixed
				%				message/rfc822
				%					text/plain
				%		text/html
				%		message/rtc822
				%			text/plain
				%		text/html
				%		image/jpeg
				%		text/html
				%		text/rtf
				%		text/html
				Decoded = Getmail("the-gamut.eml"),
				?assertMatch({<<"multipart">>, <<"alternative">>, _, _, _}, Decoded),
				?assertEqual(2, length(element(5, Decoded))),
				[Toptext, Topmultipart] = element(5, Decoded),
				?assertMatch({<<"text">>, <<"plain">>, _, _, _}, Toptext),
				?assertEqual(<<"This is rich text.\r\n\r\nThe list is html.\r\n\r\nAttchments:\r\nan email containing an attachment of an email.\r\nan email of only plain text.\r\nan image\r\nan rtf file.\r\n">>, element(5, Toptext)),
				?assertEqual(9, length(element(5, Topmultipart))),
				[Html, Messagewithin, _Brhtml, Message, _Brhtml, Image, _Brhtml, Rtf, _Brhtml] = element(5, Topmultipart),
				?assertMatch({<<"text">>, <<"html">>, _, _, _}, Html),
				?assertEqual(<<"<html><body style=\"word-wrap: break-word; -webkit-nbsp-mode: space; -webkit-line-break: after-white-space; \"><b>This</b> is <i>rich</i> text.<div><br></div><div>The list is html.</div><div><br></div><div>Attchments:</div><div><ul class=\"MailOutline\"><li>an email containing an attachment of an email.</li><li>an email of only plain text.</li><li>an image</li><li>an rtf file.</li></ul></div><div></div></body></html>">>, element(5, Html)),
				
				?assertMatch({<<"message">>, <<"rfc822">>, _, _, _}, Messagewithin),
				%?assertEqual(1, length(element(5, Messagewithin))),
				%?debugFmt("~p", [element(5, Messagewithin)]),
				?assertMatch({<<"multipart">>, <<"mixed">>, _, _, [{<<"message">>, <<"rfc822">>, _, _, {<<"text">>, <<"plain">>, _, _, <<"This message contains only plain text.\r\n">>}}]}, element(5, Messagewithin)),
				
				?assertMatch({<<"image">>, <<"jpeg">>, _, _, _}, Image),
				?assertEqual(?IMAGE_MD5, erlang:md5(element(5, Image))),
				
				?assertMatch({<<"text">>, <<"rtf">>, _, _, _}, Rtf),
				?assertEqual(<<"{\\rtf1\\ansi\\ansicpg1252\\cocoartf949\\cocoasubrtf460\r\n{\\fonttbl\\f0\\fswiss\\fcharset0 Helvetica;}\r\n{\\colortbl;\\red255\\green255\\blue255;}\r\n\\margl1440\\margr1440\\vieww9000\\viewh8400\\viewkind0\r\n\\pard\\tx720\\tx1440\\tx2160\\tx2880\\tx3600\\tx4320\\tx5040\\tx5760\\tx6480\\tx7200\\tx7920\\tx8640\\ql\\qnatural\\pardirnatural\r\n\r\n\\f0\\fs24 \\cf0 This is a basic rtf file.}">>, element(5, Rtf))
				
			end
		},
		{"Plain text and 2 identical attachments",
			fun() ->
				Decoded = Getmail("plain-text-and-two-identical-attachments.eml"),
				?assertMatch({<<"multipart">>, <<"mixed">>, _, _, _}, Decoded),
				?assertEqual(3, length(element(5, Decoded))),
				[Plain, Attach1, Attach2] = element(5, Decoded),
				?assertEqual(Attach1, Attach2),
				?assertMatch({<<"text">>, <<"plain">>, _, _, _}, Plain),
				?assertEqual(<<"This message contains only plain text.\r\n">>, element(5, Plain))
			end
		},
		{"no \\r\\n before first boundary",
			fun() ->
				{ok, Bin} = file:read_file("testdata/html.eml"),
				Email = binary_to_list(Bin),
				{Headers, B} = parse_headers(Bin),
				Body = binstr:strip(binstr:strip(B, left, $\r), left, $\n),
				Decoded = decode(Headers, Body),
				%?debugFmt("~p", [Decoded]),
				?assertEqual(2, length(element(5, Decoded)))
			end
		},
		{"testcase1",
			fun() ->
				Multipart = <<"multipart">>,
				Alternative = <<"alternative">>,
				Related = <<"related">>,
				Mixed = <<"mixed">>,
				Text = <<"text">>,
				Html = <<"html">>,
				Plain = <<"plain">>,
				Message = <<"message">>,
				Ref822 = <<"rfc822">>,
				Image = <<"image">>,
				Jpeg = <<"jpeg">>,
				%Imagemd5 = <<69,175,198,78,52,72,6,233,147,22,50,137,128,180,169,50>>,
				Imagemd5 = <<179,151,42,139,78,14,182,78,24,160,123,221,217,14,141,5>>,
				Decoded = Getmail("testcase1"),
				?assertMatch({Multipart, Mixed, _, _, [_, _]}, Decoded),
				[Multi1, Message1] = element(5, Decoded),
				?assertMatch({Multipart, Alternative, _, _, [_, _]}, Multi1),
				[Plain1, Html1] = element(5, Multi1),
				?assertMatch({Text, Plain, _, _, _}, Plain1),
				?assertMatch({Text, Html, _, _, _}, Html1),
				?assertMatch({Message, Ref822, _, _, _}, Message1),
				Multi2 = element(5, Message1),
				%?debugFmt("~p", [length(element(5, Multi2))]),
				?assertMatch({Multipart, Alternative, _, _, [_, _]}, Multi2),
				[Plain2, Related1] = element(5, Multi2),
				?assertMatch({Text, Plain, _, _, _}, Plain2),
				?assertMatch({Multipart, Related, _, _, [_, _]}, Related1),
				[Html2, Image1] = element(5, Related1),
				?assertMatch({Text, Html, _, _, _}, Html2),
				?assertMatch({Image, Jpeg, _, _, _}, Image1),
				Resimage = erlang:md5(element(5, Image1)),
				?assertEqual(Imagemd5, Resimage)
			end
		},
		{"testcase2",
			fun() ->
				Multipart = <<"multipart">>,
				Alternative = <<"alternative">>,
				Related = <<"related">>,
				Mixed = <<"mixed">>,
				Text = <<"text">>,
				Html = <<"html">>,
				Plain = <<"plain">>,
				Message = <<"message">>,
				Ref822 = <<"rfc822">>,
				Image = <<"image">>,
				Jpeg = <<"jpeg">>,
				Application = <<"application">>,
				Octetstream = <<"octet-stream">>,
				Decoded = Getmail("testcase2"),
				?assertMatch({Multipart, Mixed, _, _, [_, _, _]}, Decoded),
				[Plain1, Stream1, Message1] = element(5, Decoded),
				?assertMatch({Text, Plain, _, _, _}, Plain1),
				?assertMatch({Application, Octetstream, _, _, _}, Stream1),
				?assertMatch({Message, Ref822, _, _, _}, Message1),
				Multi1 = element(5, Message1),
				?assertMatch({Multipart, Alternative, _, _, [_, _]}, Multi1),
				[Plain2, Html1] = element(5, Multi1),
				?assertMatch({Text, Plain, _, _, _}, Plain2),
				?assertMatch({Text, Html, _, _, _}, Html1)
			end
		}
	].

decode_quoted_printable_test_() ->
	[
		{"bleh",
			fun() ->
					?assertEqual("!", decode_quoted_printable_line(<<"=21">>, "")),
					?assertEqual("!!", decode_quoted_printable_line(<<"=21=21">>, "")),
					?assertEqual("=:=", decode_quoted_printable_line(<<"=3D:=3D">>, "")),
					?assertEqual("Thequickbrownfoxjumpedoverthelazydog.", decode_quoted_printable_line(<<"Thequickbrownfoxjumpedoverthelazydog.">>, ""))
			end
		},
		{"input with spaces",
			fun() ->
					?assertEqual("The quick brown fox jumped over the lazy dog.", decode_quoted_printable_line(<<"The quick brown fox jumped over the lazy dog.">>, ""))
			end
		},
		{"input with tabs",
			fun() ->
					?assertEqual("The\tquick brown fox jumped over\tthe lazy dog.", decode_quoted_printable_line(<<"The\tquick brown fox jumped over\tthe lazy dog.">>, ""))
			end
		},
		{"input with trailing spaces",
			fun() ->
					?assertEqual("The quick brown fox jumped over the lazy dog.", decode_quoted_printable_line(<<"The quick brown fox jumped over the lazy dog.       ">>, ""))
			end
		},
		{"input with non-strippable trailing whitespace",
			fun() ->
					?assertEqual("The quick brown fox jumped over the lazy dog.        ", decode_quoted_printable_line(<<"The quick brown fox jumped over the lazy dog.       =20">>, "")),
					?assertEqual("The quick brown fox jumped over the lazy dog.       \t", decode_quoted_printable_line(<<"The quick brown fox jumped over the lazy dog.       =09">>, "")),
					?assertEqual("The quick brown fox jumped over the lazy dog.\t \t \t \t ", decode_quoted_printable_line(<<"The quick brown fox jumped over the lazy dog.\t \t \t =09=20">>, "")),
					?assertEqual("The quick brown fox jumped over the lazy dog.\t \t \t \t ", decode_quoted_printable_line(<<"The quick brown fox jumped over the lazy dog.\t \t \t =09=20\t                  \t">>, ""))
			end
		},
		{"input with trailing tabs",
			fun() ->
					?assertEqual("The quick brown fox jumped over the lazy dog.", decode_quoted_printable_line(<<"The quick brown fox jumped over the lazy dog.\t\t\t\t\t">>, ""))
			end
		},
		{"soft new line",
			fun() ->
					?assertEqual("The quick brown fox jumped over the lazy dog.       ", decode_quoted_printable_line(<<"The quick brown fox jumped over the lazy dog.       =">>, ""))
			end
		},
		{"soft new line with trailing whitespace",
			fun() ->
					?assertEqual("The quick brown fox jumped over the lazy dog.       ", decode_quoted_printable_line(<<"The quick brown fox jumped over the lazy dog.       =  	">>, ""))
			end
		},
		{"multiline stuff",
			fun() ->
					?assertEqual(<<"Now's the time for all folk to come to the aid of their country.">>, decode_quoted_printable(<<"Now's the time =\r\nfor all folk to come=\r\n to the aid of their country.">>)),
					?assertEqual(<<"Now's the time\r\nfor all folk to come\r\n to the aid of their country.">>, decode_quoted_printable(<<"Now's the time\r\nfor all folk to come\r\n to the aid of their country.">>)),
					?assertEqual(<<"hello world">>, decode_quoted_printable(<<"hello world">>)),
					?assertEqual(<<"hello\r\n\r\nworld">>, decode_quoted_printable(<<"hello\r\n\r\nworld">>))
			end
		},
		{"invalid input",
			fun() ->
					?assertThrow(badchar, decode_quoted_printable_line(<<"=21=G1">>, "")),
					?assertThrow(badchar, decode_quoted_printable(<<"=21=D1 = g ">>))
			end
		}
	].

encode_quoted_printable_test_() ->
	[
		{"bleh",
			fun() ->
					?assertEqual("!", encode_quoted_printable("!", [], 0)),
					?assertEqual("!!", encode_quoted_printable("!!", [], 0)),
					?assertEqual("=3D:=3D", encode_quoted_printable("=:=", [], 0)),
					?assertEqual("Thequickbrownfoxjumpedoverthelazydog.", encode_quoted_printable("Thequickbrownfoxjumpedoverthelazydog.", [], 0))
			end
		},
		{"input with spaces",
			fun() ->
					?assertEqual("The quick brown fox jumped over the lazy dog.", encode_quoted_printable("The quick brown fox jumped over the lazy dog.", "", 0))
			end
		},
		{"input with tabs",
			fun() ->
					?assertEqual("The\tquick brown fox jumped over\tthe lazy dog.", encode_quoted_printable("The\tquick brown fox jumped over\tthe lazy dog.", "", 0))
			end
		},
		{"input with trailing spaces",
			fun() ->
					?assertEqual("The quick brown fox jumped over the lazy dog.      =20\r\n", encode_quoted_printable("The quick brown fox jumped over the lazy dog.       \r\n", "", 0))
			end
		},
		{"add soft newlines",
			fun() ->
					?assertEqual("The quick brown fox jumped over the lazy dog. The quick brown fox jumped =\r\nover the lazy dog.", encode_quoted_printable("The quick brown fox jumped over the lazy dog. The quick brown fox jumped over the lazy dog.", "", 0)),
					?assertEqual("The_quick_brown_fox_jumped_over_the_lazy_dog._The_quick_brown_fox_jumped_ov=\r\ner_the_lazy_dog.", encode_quoted_printable("The_quick_brown_fox_jumped_over_the_lazy_dog._The_quick_brown_fox_jumped_over_the_lazy_dog.", "", 0)),
					?assertEqual("The_quick_brown_fox_jumped_over_the_lazy_dog._The_quick_brown_fox_jumped_o=\r\n=3Dver_the_lazy_dog.", encode_quoted_printable("The_quick_brown_fox_jumped_over_the_lazy_dog._The_quick_brown_fox_jumped_o=ver_the_lazy_dog.", "", 0)),
					?assertEqual("The_quick_brown_fox_jumped_over_the_lazy_dog._The_quick_brown_fox_jumped_=\r\n=3Dover_the_lazy_dog.", encode_quoted_printable("The_quick_brown_fox_jumped_over_the_lazy_dog._The_quick_brown_fox_jumped_=over_the_lazy_dog.", "", 0)),
					?assertEqual("The_quick_brown_fox_jumped_over_the_lazy_dog._The_quick_brown_fox_jumped_o =\r\nver_the_lazy_dog.", encode_quoted_printable("The_quick_brown_fox_jumped_over_the_lazy_dog._The_quick_brown_fox_jumped_o ver_the_lazy_dog.", "", 0))
			end
		}
	].

rfc2047_test_() ->
	[
		{"Simple tests",
			fun() ->
					?assertEqual(<<"Keith Moore <moore@cs.utk.edu>">>, decode_header(<<"=?US-ASCII?Q?Keith_Moore?= <moore@cs.utk.edu>">>, "utf-8")),
					?assertEqual(<<"Keld J", 248, "rn Simonsen <keld@dkuug.dk>">>, decode_header(<<"=?ISO-8859-1?Q?Keld_J=F8rn_Simonsen?= <keld@dkuug.dk>">>, "utf-8")),
					?assertEqual(<<"Olle J", 228, "rnefors <ojarnef@admin.kth.se>">>, decode_header(<<"=?ISO-8859-1?Q?Olle_J=E4rnefors?= <ojarnef@admin.kth.se>">>, "utf-8")),
					?assertEqual(<<"Andr", 233, " Pirard <PIRARD@vm1.ulg.ac.be>">>, decode_header(<<"=?ISO-8859-1?Q?Andr=E9?= Pirard <PIRARD@vm1.ulg.ac.be>">>, "utf-8"))
			end
		},
		{"encoded words seperated by whitespace should have whitespace removed",
			fun() ->
					?assertEqual(<<"If you can read this you understand the example.">>, decode_header(<<"=?ISO-8859-1?B?SWYgeW91IGNhbiByZWFkIHRoaXMgeW8=?= =?ISO-8859-2?B?dSB1bmRlcnN0YW5kIHRoZSBleGFtcGxlLg==?=">>, "utf-8")),
					?assertEqual(<<"ab">>, decode_header(<<"=?ISO-8859-1?Q?a?= =?ISO-8859-1?Q?b?=">>, "utf-8")),
					?assertEqual(<<"ab">>, decode_header(<<"=?ISO-8859-1?Q?a?=  =?ISO-8859-1?Q?b?=">>, "utf-8")),
					?assertEqual(<<"ab">>, decode_header(<<"=?ISO-8859-1?Q?a?=
		=?ISO-8859-1?Q?b?=">>, "utf-8"))
			end
		},
		{"underscores expand to spaces",
			fun() ->
					?assertEqual(<<"a b">>, decode_header(<<"=?ISO-8859-1?Q?a_b?=">>, "utf-8")),
					?assertEqual(<<"a b">>, decode_header(<<"=?ISO-8859-1?Q?a?= =?ISO-8859-2?Q?_b?=">>, "utf-8"))
			end
		},
		{"edgecases",
			fun() ->
					?assertEqual(<<"this is some text">>, decode_header(<<"=?iso-8859-1?q?this=20is=20some=20text?=">>, "utf-8")),
					?assertEqual(<<"=?iso-8859-1?q?this is some text?=">>, decode_header(<<"=?iso-8859-1?q?this is some text?=">>, "utf-8"))
			end
		}
	].


roundtrip_test_disabled() ->
	[
		{"roundtrip test for the gamut",
			fun() ->
					{ok, Bin} = file:read_file("testdata/the-gamut.eml"),
					Email = binary_to_list(Bin),
					Decoded = decode(Email),
					Encoded = encode(Decoded),
					%{ok, F1} = file:open("f1", [write]),
					%{ok, F2} = file:open("f2", [write]),
					%file:write(F1, Email),
					%file:write(F2, Encoded),
					%file:close(F1),
					%file:close(F2),
					?assertEqual(Email, Encoded)
			end
		},
		{"round trip plain text only email",
			fun() ->
					{ok, Bin} = file:read_file("testdata/Plain-text-only.eml"),
					Email = binary_to_list(Bin),
					Decoded = decode(Email),
					Encoded = encode(Decoded),
					%{ok, F1} = file:open("f1", [write]),
					%{ok, F2} = file:open("f2", [write]),
					%file:write(F1, Email),
					%file:write(F2, Encoded),
					%file:close(F1),
					%file:close(F2),
					?assertEqual(Email, Encoded)
			end
		},
		{"round trip quoted-printable email",
			fun() ->
					{ok, Bin} = file:read_file("testdata/testcase1"),
					Email = binary_to_list(Bin),
					Decoded = decode(Email),
					Encoded = encode(Decoded),
					{ok, F1} = file:open("f1", [write]),
					{ok, F2} = file:open("f2", [write]),
					%file:write(F1, Email),
					%file:write(F2, Encoded),
					%file:close(F1),
					%file:close(F2),
					%?assertEqual(Email, Encoded)
					ok
			end
		}
	].


-endif.

