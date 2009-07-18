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
-module(mimemail_encode).

-export([encode/1]).

encode({ContentType1, ContentType2, Headers, ContentTypeParams, Parts}) ->
	io:format("Decoding: ~p/~p~n", [ContentType1, ContentType2]),
	HeaderLines = lists:map(fun({K,V}) -> K++": "++V end, Headers),
	DataLines 	= lists:map(fun(Part) -> encode_part(ContentTypeParams, Part) end, Parts),
	HeaderLines ++ ["", ""] ++ DataLines;

encode(_) ->
	io:format("Not a mime-decoded message~n").

encode_part(ContentTypeParams,
					 {ContentType1, ContentType2,
	 					PartHeaders, PartParams, Content}) ->
	case ContentTypeParams of
		[ {"content-type-params", [{"boundary", Boundary}]},
			{"disposition", "inline"},
			{"disposition-params", []}
		] ->
			[ Boundary,
				"Content-Type: "++ContentType1++"/"++ContentType2,
				Content
			];

		% [ {"content-type-params", [{"boundary", Boundary}]},
		%       {"disposition","attachment"},
		%      	{"disposition-params",[{"filename", Fiilename}]}
		% ] ->
		% 	[ Boundary,
		% 		"Content-Type: "++ContentType1++"/"++ContentType2,
		% 		Content
		% 	];
		% 
		Other ->
			io:format("encode_part: No Match~n"),
			Other
	end.
          % [{"content-type-params",[{"boundary","Apple-Mail-28--711949187"}]},
          %  {"disposition","inline"},
          %  {"disposition-params",[]}],
          % [{"text","plain",
          %   [{"Content-Type","text/plain;charset=US-ASCII;format=flowed"},
          %    {"Content-Transfer-Encoding","7bit"}],
          %   [{"content-type-params",
          %     [{"charset","US-ASCII"},{"format","flowed"}]},
          %    {"disposition","inline"},
          %    {"disposition-params",[]}],
          %   "This is rich text.\r\n\r\nThe list is html.\r\n\r\nAttchments:\r\nan email containing an attachment of an email.\r\nan email of only plain text.\r\nan image\r\nan rtf file.\r\n"},
          %  {"multipart","mixed",
          %   [{"Content-Type",
          %     "multipart/mixed;boundary=Apple-Mail-29--711949186"}],
          %   [{"content-type-params",[{"boundary","Apple-Mail-29--711949186"}]},
          %    {"disposition","inline"},

					% --Apple-Mail-28--711949187
					% Content-Type: text/plain;
					% 	charset=US-ASCII;
					% 	format=flowed
					% Content-Transfer-Encoding: 7bit
					% 
					% This is rich text.
					% 
					% The list is html.
					% 
					% Attchments:
					% an email containing an attachment of an email.
					% an email of only plain text.
					% an image
					% an rtf file.
					% 
					% --Apple-Mail-28--711949187
					% Content-Type: multipart/mixed;
					% 	boundary=Apple-Mail-29--711949186

find_boundary(ContentTypeParams) ->
	case ContentTypeParams of
		[{"content-type-params", [{"boundary", Boundary}]},_,_] -> Boundary;
	  _ -> erlang:error("No Boundary Found")
  end.
	

decode(All) ->
	{Headers, Body} = parse_headers(All),
	decode(Headers, Body).

decode(Headers, Body) ->
	FixedHeaders = fix_headers(Headers),
	case parse_with_comments(proplists:get_value("MIME-Version", FixedHeaders)) of
		undefined ->
			erlang:error(non_mime);
		Other ->
			decode_component(FixedHeaders, Body, Other)
	end.

decode_component(Headers, Body, MimeVsn) when MimeVsn =:= "1.0" ->
	case parse_content_disposition(proplists:get_value("Content-Disposition", Headers)) of
		{Disposition, DispositionParams} ->
			ok;
		_ -> % defaults
			Disposition = "inline",
			DispositionParams = []
	end,

	case parse_content_type(proplists:get_value("Content-Type", Headers)) of
		{"multipart", SubType, Parameters} ->
			case proplists:get_value("boundary", Parameters) of
				undefined ->
					erlang:error(no_boundary);
				Boundary ->
					% io:format("this is a multipart email of type:  ~s and boundary ~s~n", [SubType, Boundary]),
					Parameters2 = [{"content-type-params", Parameters}, {"disposition", Disposition}, {"disposition-params", DispositionParams}],
					{"multipart", SubType, Headers, Parameters2, split_body_by_boundary(Body, "--"++Boundary, MimeVsn)}
			end;
		{"message", "rfc822", Parameters} ->
			{NewHeaders, NewBody} = parse_headers(Body),
			Parameters2 = [{"content-type-params", Parameters}, {"disposition", Disposition}, {"disposition-params", DispositionParams}],
			{"message", "rfc822", Headers, Parameters2, decode(NewHeaders, NewBody)};
		{Type, SubType, Parameters} ->
			%io:format("body is ~s/~s~n", [Type, SubType]),
			Parameters2 = [{"content-type-params", Parameters}, {"disposition", Disposition}, {"disposition-params", DispositionParams}],
			{Type, SubType, Headers, Parameters2, decode_body(proplists:get_value("Content-Transfer-Encoding", Headers), Body)};
		undefined -> % defaults
			Type = "text",
			SubType = "plain",
			Parameters = [{"content-type-params", {"charset", "us-ascii"}}, {"disposition", Disposition}, {"disposition-params", DispositionParams}],
			{Type, SubType, Headers, Parameters, Body};
		error ->
			error
	end;
decode_component(Headers, Body, Other) ->
	% io:format("Unknown mime version ~s~n", [Other]),
	error.


%%% @doc - fix the casing on relevant headers to match RFC2045
fix_headers(Headers) ->
	F =
	fun({Header, Value}) ->
			NewHeader = case string:to_lower(Header) of
				"mime-version" ->
					"MIME-Version";
				"content-type" ->
					"Content-Type";
				"content-disposition" ->
					"Content-Disposition";
				"content-transfer-encoding" ->
					"Content-Transfer-Encoding";
				Other ->
					Header
			end,
			{NewHeader, Value}
	end,
	lists:map(F, Headers).

parse_with_comments(Value) when is_list(Value) ->
	parse_with_comments(Value, "", 0, false);
parse_with_comments(Value) ->
	Value.

parse_with_comments([], Acc, Depth, Quotes) when Depth > 0; Quotes ->
	error;
parse_with_comments([], Acc, Depth, _Quotes) ->
	string:strip(lists:reverse(Acc));
parse_with_comments([$\\ | Tail], Acc, Depth, Quotes) when Depth > 0 ->
	[H | T2] = Tail,
	case H of
		_ when H > 32, H < 127 ->
			parse_with_comments(T2, Acc, Depth, Quotes);
		_ ->
			parse_with_comments(Tail, Acc, Depth, Quotes)
	end;
parse_with_comments([$\\ | Tail], Acc, Depth, Quotes) ->
	[H | T2] = Tail,
	case H of
		_ when H > 32, H < 127 ->
			parse_with_comments(T2, [H | Acc], Depth, Quotes);
		_ ->
			parse_with_comments(Tail, [$\\ | Acc], Depth, Quotes)
	end;
parse_with_comments([$( | Tail], Acc, Depth, Quotes) when not Quotes ->
	parse_with_comments(Tail, Acc, Depth + 1, Quotes);
parse_with_comments([$) | Tail], Acc, Depth, Quotes) when Depth > 0, not Quotes ->
	parse_with_comments(Tail, Acc, Depth - 1, Quotes);
parse_with_comments([_H | Tail], Acc, Depth, Quotes) when Depth > 0 ->
	parse_with_comments(Tail, Acc, Depth, Quotes);
parse_with_comments([$" | T], Acc, Depth, true) -> %"
	parse_with_comments(T, Acc, Depth, false);
parse_with_comments([$" | T], Acc, Depth, false) -> %"
	parse_with_comments(T, Acc, Depth, true);
parse_with_comments([H | Tail], Acc, Depth, Quotes) ->
	parse_with_comments(Tail, [H | Acc], Depth, Quotes).

parse_content_type(undefined) ->
	undefined;
parse_content_type(String) ->
	try parse_content_disposition(String) of
		{RawType, Parameters} ->
			case string:str(RawType, "/") of
				Index when Index < 2 ->
					throw(bad_content_type);
				Index ->
					Type = string:substr(RawType, 1, Index - 1),
					SubType = string:substr(RawType, Index + 1),
					{string:to_lower(Type), string:to_lower(SubType), Parameters}
			end
		catch
			bad_disposition ->
				throw(bad_content_type)
	end.

parse_content_disposition(undefined) ->
	undefined;
parse_content_disposition(String) ->
	[Disposition | Parameters] = string:tokens(parse_with_comments(String), ";"),
	F =
	fun(X) ->
		Y = string:strip(string:strip(X), both, $\t),
		case string:str(Y, "=") of
			Index when Index < 2 ->
				throw(bad_disposition);
			Index ->
				Key = string:substr(Y, 1, Index - 1),
				Value = string:substr(Y, Index + 1),
				{string:to_lower(Key), Value}
		end
	end,
	Params = lists:map(F, Parameters),
	{string:to_lower(Disposition), Params}.

split_body_by_boundary(Body, Boundary, MimeVsn) ->
	% find the indices of the first and last boundary
	case [string:str(Body, Boundary), string:str(Body, Boundary++"--")] of
		[Start, End] when Start =:= 0; End =:= 0 ->
			erlang:error(bad_boundary);
		[Start, End] ->
			NewBody = string:substr(Body, Start + length(Boundary), End - Start),
			% from now on, we can be sure that each boundary is preceeded by a CRLF
			Parts = split_body_by_boundary_(NewBody, "\r\n" ++ Boundary, []),
			Res = lists:filter(fun({Headers, Body}) -> length(Body) =/= 0 end, Parts),
			lists:map(fun({Headers, Body}) -> decode_component(fix_headers(Headers), Body, MimeVsn) end, Res)
	end.

split_body_by_boundary_([], _Boundary, Acc) ->
	lists:reverse(Acc);
split_body_by_boundary_(Body, Boundary, Acc) ->
	% trim the incomplete first line
	TrimmedBody = string:substr(Body, string:str(Body, "\r\n") + 2),
	case string:str(TrimmedBody, Boundary) of
		0 ->
			lists:reverse([{[], TrimmedBody} | Acc]);
		Index ->
			split_body_by_boundary_(string:substr(TrimmedBody, Index + length(Boundary)), Boundary,
				[parse_headers(string:substr(TrimmedBody, 1, Index - 1)) | Acc])
	end.

parse_headers(Body) ->
	case string:str(Body, "\r\n") of
		0 ->
			{[], Body};
		1 ->
			{[], string:substr(Body, 3)};
		Index ->
			parse_headers(string:substr(Body, Index+2), string:substr(Body, 1, Index - 1), [])
	end.


parse_headers(Body, [H | T] = Line, []) when H =:= $\s; H =:= $\t ->
	% folded headers
	{[], Line++"\r\n"++Body};
parse_headers(Body, [H | T] = Line, Headers) when H =:= $\s; H =:= $\t ->
	% folded headers
	[{FieldName, OldFieldValue} | OtherHeaders] = Headers,
	FieldValue = string:concat(OldFieldValue, T),
	%?debugFmt("~p = ~p~n", [FieldName, FieldValue]),
	case string:str(Body, "\r\n") of
		0 ->
			{lists:reverse([{FieldName, FieldValue} | OtherHeaders]), Body};
		1 ->
			{lists:reverse([{FieldName, FieldValue} | OtherHeaders]), string:substr(Body, 3)};
		Index2 ->
			parse_headers(string:substr(Body, Index2 + 2), string:substr(Body, 1, Index2 - 1), [{FieldName, FieldValue} | OtherHeaders])
	end;
parse_headers(Body, Line, Headers) ->
	%?debugFmt("line: ~p, nextpart ~p~n", [Line, string:substr(Body, 1, 10)]),
	case string:str(Line, ":") of
		0 ->
			{lists:reverse(Headers), Line++"\r\n"++Body};
		Index ->
			FieldName = string:substr(Line, 1, Index - 1),
			F = fun(X) -> X > 32 andalso X < 127 end,
			case lists:all(F, FieldName) of
				true ->
					FieldValue = string:strip(string:substr(Line, Index+1)),
					case string:str(Body, "\r\n") of
						0 ->
							{lists:reverse([{FieldName, FieldValue} | Headers]), Body};
						1 ->
							{lists:reverse([{FieldName, FieldValue} | Headers]), string:substr(Body, 3)};
						Index2 ->
							parse_headers(string:substr(Body, Index2 + 2), string:substr(Body, 1, Index2 - 1), [{FieldName, FieldValue} | Headers])
					end;
				false ->
					{lists:reverse(Headers), Line++"\r\n"++Body}
			end
	end.

decode_body(undefined, Body) ->
	Body;
decode_body(Type, Body) ->
	case string:to_lower(Type) of
		"quoted-printable" ->
			decode_quoted_printable(Body);
		"base64" ->
			decode_base64(Body);
		Other ->
			Body
	end.

decode_base64(Body) ->
	base64:mime_decode_to_string(Body).

decode_quoted_printable(Body) ->
	case string:str(Body, "\r\n") of
		0 ->
			decode_quoted_printable(Body, [], []);
		Index ->
			decode_quoted_printable(string:substr(Body, 1, Index +1), string:substr(Body, Index + 2), [])
	end.

decode_quoted_printable([], [], Acc) ->
	string:join(lists:reverse(Acc), "");
decode_quoted_printable(Line, Rest, Acc) ->
	%?debugFmt("line ~p~n", [Line]),
	%?debugFmt("rest ~p~n", [Rest]),
	case string:str(Rest, "\r\n") of
		0 ->
			decode_quoted_printable(Rest, [], [decode_quoted_printable_line(Line, []) | Acc]);
		Index ->
			%?debugFmt("next line ~p~nnext rest ~p~n", [string:substr(Rest, 1, Index +1), string:substr(Rest, Index + 2)]),
			decode_quoted_printable(string:substr(Rest, 1, Index +1), string:substr(Rest, Index + 2),
				[decode_quoted_printable_line(Line, []) | Acc])
	end.

decode_quoted_printable_line([], Acc) ->
	lists:reverse(Acc);
decode_quoted_printable_line([$\r, $\n], Acc) ->
	string:concat(lists:reverse(Acc), "\r\n");
decode_quoted_printable_line([$=, C | T], Acc) when C =:= $\s orelse C =:= $\t ->
	case lists:all(fun(X) -> X =:= $\s orelse X =:= $\t end, T) of
		true ->
			lists:reverse(Acc);
		false ->
			throw(badchar)
	end;
decode_quoted_printable_line([$=, $\r, $\n], Acc) ->
	lists:reverse(Acc);
decode_quoted_printable_line([$=, X, Y | T], Acc) ->
	case lists:all(fun(C) -> (C >= $0 andalso C =< $9) orelse (C >= $A andalso C =< $F) end, [X, Y]) of
		true ->
			{ok, [C | []], []} = io_lib:fread("~16u", [X, Y]),
			decode_quoted_printable_line(T, [C | Acc]);
		false ->
			throw(badchar)
	end;
decode_quoted_printable_line([$=], Acc) ->
	% soft newline
	lists:reverse(Acc);
decode_quoted_printable_line([H | T], Acc) when H >= $! andalso H =< $< ->
	decode_quoted_printable_line(T, [H | Acc]);
decode_quoted_printable_line([H | T], Acc) when H >= $> andalso H =< $~ ->
	decode_quoted_printable_line(T, [H | Acc]);
decode_quoted_printable_line([$\s | T], Acc) ->
	% if the rest of the line is whitespace, truncate it
	case lists:all(fun(X) -> X =:= $\s orelse X =:= $\t end, T) of
		true ->
			lists:reverse(Acc);
		false ->
			decode_quoted_printable_line(T, [$\s | Acc])
	end.