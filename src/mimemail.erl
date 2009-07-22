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


encode({ContentType1, ContentType2, Headers, ContentTypeParams, Parts}) ->
	{
		encode_headers(Headers),
		encode_component(Headers, ContentTypeParams, Parts) ++ [""]
	};

encode(_) ->
	io:format("Not a mime-decoded DATA~n"),
	erlang:error(non_mime).

encode_headers(Headers) ->
	encode_headers(Headers, []).
encode_headers([], EncodedHeaders) ->
	EncodedHeaders;
encode_headers([{Key, Value}|T] = Headers, EncodedHeaders) ->
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

encode_component(Headers, Params, Parts) ->
	case Params of
		% is this a multipart component?
		[	{"content-type-params", [{"boundary", Boundary}]},
			{"disposition", "inline"},
			{"disposition-params", []}
		] ->
			[""] ++  % blank line before start of component
			lists:flatmap(
				fun(PartLines) ->
					["--"++Boundary] ++ % start with the boundary
					PartLines
				end,
				encode_component_parts(Params, Parts)
			) ++ ["--"++Boundary++"--"]; % final boundary (with /--$/)
		% is this a simple inline component?
		[	{"content-type-params", ParamHeaders},
			{"disposition", "inline"},
			{"disposition-params", []}
		] ->
			% this is a string split by newlines
			string:tokens(Parts, "\r\n");

	  Other -> [Parts]
	end.

encode_component_parts(Params, Parts) ->
	lists:map(
		fun(Part) -> encode_component_part(Part) end,
		Parts
	).

encode_component_part(Part) ->
	case Part of
		{"multipart", _, Headers, PartParams, Body} ->
			encode_headers(Headers) ++ encode_component(Headers, PartParams, Body);

		{"message", "rfc822", Headers,
		[{"content-type-params", TypeParams},
		 {"disposition", "attachment"}, _],
		Body} ->
			PartData = case Body of
				{_,_,_,_,_} -> encode_component_part(Body);
				String      -> [String]
			end,
			encode_headers(Headers) ++ [""] ++ PartData;

		{Type, SubType, Headers, PartParams, Body} ->
			PartData = case Body of
				{_,_,_,_,_} -> encode_component_part(Body);
				String      -> [String]
			end,
			encode_headers(Headers) ++ [""] ++ encode_body(
																						proplists:get_value("Content-Transfer-Encoding", Headers),
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
			% TODO: examine whether this could be necessary to implement
			% encode_quoted_printable(Body);
			Body;
		"base64" ->
			[InnerBody] = Body,
			wrap_to_76(base64:encode_to_string(InnerBody));
		Other ->
			Body
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


-ifdef(EUNIT).

parse_with_comments_test_() ->
	[
		{"bleh",
			fun() ->
					?assertEqual("1.0", parse_with_comments("1.0")),
					?assertEqual("1.0", parse_with_comments("1.0  (produced by MetaSend Vx.x)")),
					?assertEqual("1.0", parse_with_comments("(produced by MetaSend Vx.x) 1.0")),
					?assertEqual("1.0", parse_with_comments("1.(produced by MetaSend Vx.x)0"))
			end
		},
		{"comments that parse as empty",
			fun() ->
					?assertEqual([], parse_with_comments("(comment (nested (deeply)) (and (oh no!) again))")),
					?assertEqual([], parse_with_comments("(\\)\\\\)")),
					?assertEqual([], parse_with_comments("(by way of Whatever <redir@my.org>)    (generated by Eudora)"))
			end
		},
		{"some more",
			fun() ->
					?assertEqual(":sysmail@  group. org, Muhammed. Ali @Vegas.WBA", parse_with_comments("\":sysmail\"@  group. org, Muhammed.(the greatest) Ali @(the)Vegas.WBA")),
					?assertEqual("Pete <pete@silly.test>", parse_with_comments("Pete(A wonderful \\) chap) <pete(his account)@silly.test(his host)>"))
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
				?assertEqual("Height (from xkcd).eml", parse_with_comments("\"Height (from xkcd).eml\"")),
				?assertEqual("Height (from xkcd).eml", parse_with_comments("\"Height \(from xkcd\).eml\""))
			end
		},
		{"Escaped quotes are handled correctly",
			fun() ->
					?assertEqual("Hello \"world\"", parse_with_comments("Hello \\\"world\\\"")),
					?assertEqual("<boss@nil.test>, Giant; \"Big\" Box <sysservices@example.net>", parse_with_comments("<boss@nil.test>, \"Giant; \\\"Big\\\" Box\" <sysservices@example.net>"))
			end
		},
		{"backslash not part of a quoted pair",
			fun() ->
					?assertEqual("AC \\ DC", parse_with_comments("AC \\ DC")),
					?assertEqual("AC  DC", parse_with_comments("AC ( \\ ) DC"))
			end
		},
		{"Unterminated quotes or comments",
			fun() ->
					?assertEqual(error, parse_with_comments("\"Hello there ")),
					?assertEqual(error, parse_with_comments("\"Hello there \\\"")),
					?assertEqual(error, parse_with_comments("(Hello there ")),
					?assertEqual(error, parse_with_comments("(Hello there \\\)"))
			end
		}
	].
	
parse_content_type_test_() ->
	[
		{"parsing content types",
			fun() ->
					?assertEqual({"text", "plain", [{"charset", "us-ascii"}]}, parse_content_type("text/plain; charset=us-ascii (Plain text)")),
					?assertEqual({"text", "plain", [{"charset", "us-ascii"}]}, parse_content_type("text/plain; charset=\"us-ascii\"")),
					?assertEqual({"text", "plain", [{"charset", "us-ascii"}]}, parse_content_type("Text/Plain; Charset=\"us-ascii\"")),
					?assertEqual({"multipart", "mixed", [{"boundary", "----_=_NextPart_001_01C9DCAE.1F2CB390"}]},
						parse_content_type("multipart/mixed; boundary=\"----_=_NextPart_001_01C9DCAE.1F2CB390\""))
			end
		},
		{"parsing content type with a tab in it",
			fun() ->
					?assertEqual({"text", "plain", [{"charset", "us-ascii"}]}, parse_content_type("text/plain;\tcharset=us-ascii")),
					?assertEqual({"text", "plain", [{"charset", "us-ascii"}, {"foo", "bar"}]}, parse_content_type("text/plain;\tcharset=us-ascii;\tfoo=bar"))
			end
		},
		{"invalid content types",
			fun() ->
					?assertThrow(bad_content_type, parse_content_type("text\\plain; charset=us-ascii")),
					?assertThrow(bad_content_type, parse_content_type("text/plain; charset us-ascii"))
				end
			}
	].

parse_content_disposition_test_() ->
	[
		{"parsing valid dispositions",
			fun() ->
					?assertEqual({"inline", []}, parse_content_disposition("inline")),
					?assertEqual({"inline", []}, parse_content_disposition("inline;")),
					?assertEqual({"attachment", [{"filename", "genome.jpeg"}, {"modification-date", "Wed, 12 Feb 1997 16:29:51 -0500"}]}, parse_content_disposition("attachment; filename=genome.jpeg;modification-date=\"Wed, 12 Feb 1997 16:29:51 -0500\";")),
					?assertEqual({"text/plain", [{"charset", "us-ascii"}]}, parse_content_disposition("text/plain; charset=us-ascii (Plain text)"))
			end
		},
		{"invalid dispositions",
			fun() ->
					?assertThrow(bad_disposition, parse_content_disposition("inline; =bar")),
					?assertThrow(bad_disposition, parse_content_disposition("inline; bar"))
			end
		}
	].

various_parsing_test_() ->
	[
		{"split_body_by_boundary test",
			fun() ->
					?assertEqual([{[], "foo bar baz"}], split_body_by_boundary_("stuff\r\nfoo bar baz", "--bleh", [])),
					?assertEqual([{[], "foo\r\n"}, {[], []}, {[], []}, {[], "bar baz"}], split_body_by_boundary_("stuff\r\nfoo\r\n--bleh\r\n--bleh\r\n--bleh-- stuff\r\nbar baz", "--bleh", [])),
					%?assertEqual([{[], []}, {[], []}, {[], "bar baz"}], split_body_by_boundary_("\r\n--bleh\r\n--bleh\r\n", "--bleh", [])),
					%?debugFmt("~p~n", [split_body_by_boundary("stuff\r\nfoo\r\n--bleh\r\n--bleh\r\n--bleh-- stuff\r\nbar baz", "--bleh", "1.0")]),
					%?assertMatch([{"text", "plain", [], _,"foo\r\n"}], split_body_by_boundary("stuff\r\nfoo\r\n--bleh\r\n--bleh\r\n--bleh-- stuff\r\nbar baz", "--bleh", "1.0"))
					?assertEqual({[], "foo: bar\r\n"}, parse_headers("\r\nfoo: bar\r\n")),
					?assertEqual({[{"foo", "barbaz"}], []}, parse_headers("foo: bar\r\n baz\r\n")),
					?assertEqual({[], " foo bar baz\r\nbam"}, parse_headers("\sfoo bar baz\r\nbam")),
					ok
			end
		}
	].

%-define(IMAGE_MD5, <<5,253,79,13,122,119,92,33,133,121,18,149,188,241,56,81>>).
-define(IMAGE_MD5, <<110,130,37,247,39,149,224,61,114,198,227,138,113,4,198,60>>).

parse_example_mails_test_() ->
	Getmail = fun(File) ->
		{ok, Bin} = file:read_file(string:concat("testdata/", File)),
		Email = binary_to_list(Bin),
		decode(Email)
	end,
	[
		{"parse a plain text email",
			fun() ->
				Decoded = Getmail("Plain-text-only.eml"),
				%?debugFmt("~p", [Decoded]),
				?assertEqual(5, tuple_size(Decoded)),
				{Type, SubType, Headers, Properties, Body} = Decoded,
				?assertEqual({"text", "plain"}, {Type, SubType}),
				?assertEqual("This message contains only plain text.\r\n", Body)
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
				?assertEqual({"multipart", "alternative"}, {Type, SubType}),
				?assertEqual(2, length(Body)),
				[Plain, Html] = Body,
				?assertEqual({5, 5}, {tuple_size(Plain), tuple_size(Html)}),
				?assertMatch({"text", "plain", _, _, "This message contains rich text."}, Plain),
				?assertMatch({"text", "html", _, _, "<html><body style=\"word-wrap: break-word; -webkit-nbsp-mode: space; -webkit-line-break: after-white-space; \"><b>This </b><i>message </i><span class=\"Apple-style-span\" style=\"text-decoration: underline;\">contains </span>rich text.</body></html>"}, Html)
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
				?assertEqual({"multipart", "alternative"}, {Type, SubType}),
				?assertEqual(1, length(Body)),
				[Html] = Body,
				?assertEqual(5, tuple_size(Html)),
				?assertMatch({"text", "html", _, _, "<html><body style=\"word-wrap: break-word; -webkit-nbsp-mode: space; -webkit-line-break: after-white-space; \"><b>This </b><i>message </i><span class=\"Apple-style-span\" style=\"text-decoration: underline;\">contains </span>rich text.</body></html>"}, Html)
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
				?assertEqual({"multipart", "alternative"}, {Type, SubType}),
				?assertEqual(2, length(Body)),
				[Plain, Html] = Body,
				?assertEqual({5, 5}, {tuple_size(Plain), tuple_size(Html)}),
				?assertMatch({"text", "plain", _, _, "This message contains rich text."}, Plain),
				?assertMatch({"text", "html", _, _, "<html><body style=\"word-wrap: break-word; -webkit-nbsp-mode: space; -webkit-line-break: after-white-space; \"><b>This </b><i>message </i><span class=\"Apple-style-span\" style=\"text-decoration: underline;\">contains </span>rich text.</body></html>"}, Html)
			end
		},
		{"text attachment only",
			fun() ->
				Decoded = Getmail("text-attachment-only.eml"),
				?assertEqual(5, tuple_size(Decoded)),
				{Type, SubType, Headers, Properties, Body} = Decoded,
				?assertEqual({"multipart", "mixed"}, {Type, SubType}),
				%?debugFmt("~p", [Body]),
				?assertEqual(1, length(Body)),
				Rich = "{\\rtf1\\ansi\\ansicpg1252\\cocoartf949\\cocoasubrtf460\r\n{\\fonttbl\\f0\\fswiss\\fcharset0 Helvetica;}\r\n{\\colortbl;\\red255\\green255\\blue255;}\r\n\\margl1440\\margr1440\\vieww9000\\viewh8400\\viewkind0\r\n\\pard\\tx720\\tx1440\\tx2160\\tx2880\\tx3600\\tx4320\\tx5040\\tx5760\\tx6480\\tx7200\\tx7920\\tx8640\\ql\\qnatural\\pardirnatural\r\n\r\n\\f0\\fs24 \\cf0 This is a basic rtf file.}",
				?assertMatch([{"text", "rtf", _, _, Rich}], Body)
			end
		},
		{"image attachment only",
			fun() ->
				Decoded = Getmail("image-attachment-only.eml"),
				?assertEqual(5, tuple_size(Decoded)),
				{Type, SubType, Headers, Properties, Body} = Decoded,
				?assertEqual({"multipart", "mixed"}, {Type, SubType}),
				%?debugFmt("~p", [Body]),
				?assertEqual(1, length(Body)),
				?assertMatch([{"image", "jpeg", _, _, _}], Body),
				[H | _] = Body,
				[{"image", "jpeg", _, Parameters, Image}] = Body,
				?assertEqual(?IMAGE_MD5, erlang:md5(element(5, H))),
				?assertEqual("inline", proplists:get_value("disposition", Parameters)),
				?assertEqual("spice-logo.jpg", proplists:get_value("filename", proplists:get_value("disposition-params", Parameters))),
				?assertEqual("spice-logo.jpg", proplists:get_value("name", proplists:get_value("content-type-params", Parameters)))
			end
		},
		{"message attachment only",
			fun() ->
				Decoded = Getmail("message-as-attachment.eml"),
				?assertMatch({"multipart", "mixed", _, _, _}, Decoded),
				[Body] = element(5, Decoded),
				%?debugFmt("~p", [Body]),
				?assertMatch({"message", "rfc822", _, _, _}, Body),
				Subbody = element(5, Body),
				?assertMatch({"text", "plain", _, _, _}, Subbody),
				?assertEqual("This message contains only plain text.\r\n", element(5, Subbody))
			end
		},
		{"message, image, and rtf attachments.",
			fun() ->
				Decoded = Getmail("message-image-text-attachments.eml"),
				?assertMatch({"multipart", "mixed", _, _, _}, Decoded),
				?assertEqual(3, length(element(5, Decoded))),
				[Message, Rtf, Image] = element(5, Decoded),
				?assertMatch({"message", "rfc822", _, _, _}, Message),
				Submessage = element(5, Message),
				?assertMatch({"text", "plain", _, _, "This message contains only plain text.\r\n"}, Submessage),
				
				?assertMatch({"text", "rtf", _, _, _}, Rtf),
				?assertEqual("{\\rtf1\\ansi\\ansicpg1252\\cocoartf949\\cocoasubrtf460\r\n{\\fonttbl\\f0\\fswiss\\fcharset0 Helvetica;}\r\n{\\colortbl;\\red255\\green255\\blue255;}\r\n\\margl1440\\margr1440\\vieww9000\\viewh8400\\viewkind0\r\n\\pard\\tx720\\tx1440\\tx2160\\tx2880\\tx3600\\tx4320\\tx5040\\tx5760\\tx6480\\tx7200\\tx7920\\tx8640\\ql\\qnatural\\pardirnatural\r\n\r\n\\f0\\fs24 \\cf0 This is a basic rtf file.}", element(5, Rtf)),
				
				?assertMatch({"image", "jpeg", _, _, _}, Image),
				?assertEqual(?IMAGE_MD5, erlang:md5(element(5, Image)))				
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
				?assertMatch({"multipart", "alternative", _, _, _}, Decoded),
				?assertEqual(2, length(element(5, Decoded))),
				[Toptext, Topmultipart] = element(5, Decoded),
				?assertMatch({"text", "plain", _, _, _}, Toptext),
				?assertEqual("This is rich text.\r\n\r\nThe list is html.\r\n\r\nAttchments:\r\nan email containing an attachment of an email.\r\nan email of only plain text.\r\nan image\r\nan rtf file.\r\n", element(5, Toptext)),
				?assertEqual(9, length(element(5, Topmultipart))),
				[Html, Messagewithin, _Brhtml, Message, _Brhtml, Image, _Brhtml, Rtf, _Brhtml] = element(5, Topmultipart),
				?assertMatch({"text", "html", _, _, _}, Html),
				?assertEqual("<html><body style=\"word-wrap: break-word; -webkit-nbsp-mode: space; -webkit-line-break: after-white-space; \"><b>This</b> is <i>rich</i> text.<div><br></div><div>The list is html.</div><div><br></div><div>Attchments:</div><div><ul class=\"MailOutline\"><li>an email containing an attachment of an email.</li><li>an email of only plain text.</li><li>an image</li><li>an rtf file.</li></ul></div><div></div></body></html>", element(5, Html)),
				
				?assertMatch({"message", "rfc822", _, _, _}, Messagewithin),
				%?assertEqual(1, length(element(5, Messagewithin))),
				%?debugFmt("~p", [element(5, Messagewithin)]),
				?assertMatch({"multipart", "mixed", _, _, [{"message", "rfc822", _, _, {"text", "plain", _, _, "This message contains only plain text.\r\n"}}]}, element(5, Messagewithin)),
				
				?assertMatch({"image", "jpeg", _, _, _}, Image),
				?assertEqual(?IMAGE_MD5, erlang:md5(element(5, Image))),
				
				?assertMatch({"text", "rtf", _, _, _}, Rtf),
				?assertEqual("{\\rtf1\\ansi\\ansicpg1252\\cocoartf949\\cocoasubrtf460\r\n{\\fonttbl\\f0\\fswiss\\fcharset0 Helvetica;}\r\n{\\colortbl;\\red255\\green255\\blue255;}\r\n\\margl1440\\margr1440\\vieww9000\\viewh8400\\viewkind0\r\n\\pard\\tx720\\tx1440\\tx2160\\tx2880\\tx3600\\tx4320\\tx5040\\tx5760\\tx6480\\tx7200\\tx7920\\tx8640\\ql\\qnatural\\pardirnatural\r\n\r\n\\f0\\fs24 \\cf0 This is a basic rtf file.}", element(5, Rtf))
				
			end
		},
		{"Plain text and 2 identical attachments",
			fun() ->
				Decoded = Getmail("plain-text-and-two-identical-attachments.eml"),
				?assertMatch({"multipart", "mixed", _, _, _}, Decoded),
				?assertEqual(3, length(element(5, Decoded))),
				[Plain, Attach1, Attach2] = element(5, Decoded),
				?assertEqual(Attach1, Attach2),
				?assertMatch({"text", "plain", _, _, _}, Plain),
				?assertEqual("This message contains only plain text.\r\n", element(5, Plain))
			end
		},
		{"no \\r\\n before first boundary",
			fun() ->
				{ok, Bin} = file:read_file("testdata/html.eml"),
				Email = binary_to_list(Bin),
				{Headers, B} = parse_headers(Email),
				Body = string:strip(string:strip(B, left, $\r), left, $\n),
				Decoded = decode(Headers, Body),
				%?debugFmt("~p", [Decoded]),
				?assertEqual(2, length(element(5, Decoded)))
			end
		},
		{"testcase1",
			fun() ->
				Multipart = "multipart",
				Alternative = "alternative",
				Related = "related",
				Mixed = "mixed",
				Text = "text",
				Html = "html",
				Plain = "plain",
				Message = "message",
				Ref822 = "rfc822",
				Image = "image",
				Jpeg = "jpeg",
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
				Multipart = "multipart",
				Alternative = "alternative",
				Related = "related",
				Mixed = "mixed",
				Text = "text",
				Html = "html",
				Plain = "plain",
				Message = "message",
				Ref822 = "rfc822",
				Image = "image",
				Jpeg = "jpeg",
				Application = "application",
				Octetstream = "octet-stream",
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
					?assertEqual("!", decode_quoted_printable_line("=21", "")),
					?assertEqual("!!", decode_quoted_printable_line("=21=21", "")),
					?assertEqual("=:=", decode_quoted_printable_line("=3D:=3D", "")),
					?assertEqual("Thequickbrownfoxjumpedoverthelazydog.", decode_quoted_printable_line("Thequickbrownfoxjumpedoverthelazydog.", ""))
			end
		},
		{"input with spaces",
			fun() ->
					?assertEqual("The quick brown fox jumped over the lazy dog.", decode_quoted_printable_line("The quick brown fox jumped over the lazy dog.", ""))
			end
		},
		{"input with trailing spaces",
			fun() ->
					?assertEqual("The quick brown fox jumped over the lazy dog.", decode_quoted_printable_line("The quick brown fox jumped over the lazy dog.       ", ""))
			end
		},
		{"soft new line",
			fun() ->
					?assertEqual("The quick brown fox jumped over the lazy dog.       ", decode_quoted_printable_line("The quick brown fox jumped over the lazy dog.       =", ""))
			end
		},
		{"soft new line with trailing whitespace",
			fun() ->
					?assertEqual("The quick brown fox jumped over the lazy dog.       ", decode_quoted_printable_line("The quick brown fox jumped over the lazy dog.       =  	", ""))
			end
		},
		{"multiline stuff",
			fun() ->
					?assertEqual("Now's the time for all folk to come to the aid of their country.", decode_quoted_printable("Now's the time =\r\nfor all folk to come=\r\n to the aid of their country.")),
					?assertEqual("Now's the time\r\nfor all folk to come\r\n to the aid of their country.", decode_quoted_printable("Now's the time\r\nfor all folk to come\r\n to the aid of their country.")),
					?assertEqual("hello world", decode_quoted_printable("hello world")),
					?assertEqual("hello\r\n\r\nworld", decode_quoted_printable("hello\r\n\r\nworld"))
			end
		},
		{"invalid input",
			fun() ->
					?assertThrow(badchar, decode_quoted_printable_line("=21=G1", "")),
					?assertThrow(badchar, decode_quoted_printable("=21=D1 = g "))
			end
		}
	].

-endif.

