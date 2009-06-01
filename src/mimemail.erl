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

-export([encode/2, decode/2]).

encode(Headers, BodyList) ->
	ok.

decode(Headers, Body) ->
	FixedHeaders = fix_headers(Headers),
	case parse_with_comments(proplists:get_value("MIME-Version", FixedHeaders)) of
		undefined ->
			io:format("Non-MIME email~n");
		Other ->
			decode_component(FixedHeaders, Body, Other)
	end.

decode_component(Headers, Body, MimeVsn) when MimeVsn =:= "1.0" ->
	io:format("MIME 1.0 email~n"),
	case parse_contenttype(proplists:get_value("Content-Type", Headers)) of
		{"multipart", SubType, Parameters} ->
			case proplists:get_value("boundary", Parameters) of
				undefined ->
					io:format("multipart email of type ~s doesn't have a boundary!~n", [SubType]),
					io:format("Headers: ~p, Body: ~p~n", [Headers, Body]),
					erlang:error(boundary);
				Boundary ->
					io:format("this is a multipart email of type:  ~s and boundary ~s~n", [SubType, Boundary]),
					{"multipart", SubType, Headers, Parameters, split_body_by_boundary(Body, "\r\n--"++Boundary, MimeVsn)}
			end;
		{"message", "rfc822", Parameters} ->
			{NewHeaders, NewBody} = parse_headers(Body),
			{"message", "rfc822", Headers, Parameters, decode(NewHeaders, NewBody)};
		{Type, SubType, Parameters} ->
			io:format("body is ~s/~s~n", [Type, SubType]),
			{Type, SubType, Headers, Parameters, Body};
		undefined -> % defaults
			Type = "text",
			SubType = "plain",
			Parameters = [{"charset", "us-ascii"}],
			{Type, SubType, Headers, Parameters, Body};
		error ->
			error
	end;
decode_component(Headers, Body, Other) ->
	io:format("Unknown mime version ~s~n", [Other]).


%%% @doc - fix the casing on relevant headers to match RFC2045
fix_headers(Headers) ->
	F =
	fun({Header, Value}) ->
			NewHeader = case string:to_lower(Header) of
				"mime-version" ->
					"MIME-Version";
				"content-type" ->
					"Content-Type";
				Other ->
					Header
			end,
			{NewHeader, Value}
	end,
	lists:map(F, Headers).

parse_with_comments(Value) when is_list(Value) ->
	parse_with_comments(Value, "", 0);
parse_with_comments(Value) ->
	Value.

parse_with_comments([], Acc, Depth) when Depth > 0 ->
	error;
parse_with_comments([], Acc, Depth) ->
	string:strip(lists:reverse(Acc));
parse_with_comments([$\\ | Tail], Acc, Depth) when Depth > 0 ->
	[_H | T2] = Tail,
	parse_with_comments(T2, Acc, Depth);
parse_with_comments([$\\ | Tail], Acc, Depth) ->
	[H | T2] = Tail,
	parse_with_comments(T2, [H | Acc], Depth);
parse_with_comments([$( | Tail], Acc, Depth) ->
	parse_with_comments(Tail, Acc, Depth + 1);
parse_with_comments([$) | Tail], Acc, Depth) when Depth > 0 ->
	parse_with_comments(Tail, Acc, Depth - 1);
parse_with_comments([_H | Tail], Acc, Depth) when Depth > 0 ->
	parse_with_comments(Tail, Acc, Depth);
parse_with_comments([$" | T], Acc, Depth) -> %"
	parse_with_comments(T, Acc, Depth);
parse_with_comments([H | Tail], Acc, Depth) ->
	parse_with_comments(Tail, [H | Acc], Depth).

parse_contenttype(String) ->
	[RawType | Parameters] = string:tokens(parse_with_comments(String), ";"),
	case string:str(RawType, "/") of
		0 ->
			error;
		Index ->
			Type = string:substr(RawType, 1, Index - 1),
			SubType = string:substr(RawType, Index + 1),
			F =
			fun(X) ->
					Y = string:strip(string:strip(X), both, $\t),
					case string:str(Y, "=") of
						0 ->
							error;
						Index2 ->
							Key = string:substr(Y, 1, Index2 - 1),
							Value = string:substr(Y, Index2 + 1),
							{string:to_lower(Key), Value}
					end
			end,
			Params = lists:map(F, Parameters),
			case lists:member(error, Params) of
				true ->
					error;
				false ->
					{string:to_lower(Type), string:to_lower(SubType), Params}
			end
	end.

split_body_by_boundary(Body, Boundary, MimeVsn) ->
	% find the indices of the first and last boundary
	case [string:str(Body, Boundary), string:str(Body, Boundary++"--")] of
		[Start, End] when Start =:= 0; End =:= 0 ->
			error;
		[Start, End] ->
			NewBody = string:substr(Body, Start + length(Boundary), End - Start),
			Parts = split_body_by_boundary_(NewBody, Boundary, []),
			lists:map(fun({Headers, Body}) -> decode_component(Headers, Body, MimeVsn) end, Parts)
	end.

split_body_by_boundary_([], _Boundary, Acc) ->
	lists:reverse(Acc);
split_body_by_boundary_(Body, Boundary, Acc) ->
	% trim the incomplete first line
	TrimmedBody = string:substr(Body, string:str(Body, "\r\n") + 2),
	case string:str(TrimmedBody, Boundary) of
		0 ->
			lists:reverse(Acc);
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

parse_headers(Body, Line, Headers) ->
	%?debugFmt("line: ~p, nextpart ~p~n", [Line, string:substr(Body, 1, 10)]),
	case Line of
		[H | T] when H =:= $\s; H =:= $\t ->
		%?debugFmt("folded header~n", []),
			case length(Headers) of
				0 ->
					{[], Line++"\r\n"++Body};
				_ ->
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
					end
			end;
		_ ->
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
			end
	end.


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
					?assertEqual(":sysmail@  group. org, Muhammed. Ali @Vegas.WBA", parse_with_comments("\":sysmail\"@  group. org, Muhammed.(the greatest) Ali @(the)Vegas.WBA"))
			end
		},
		{"non list values",
			fun() ->
					?assertEqual(undefined, parse_with_comments(undefined)),
					?assertEqual(17, parse_with_comments(17))
			end
		}
	].
parse_contenttype_test_() ->
	[
		{"parsing contenttypes",
			fun() ->
					?assertEqual({"text", "plain", [{"charset", "us-ascii"}]}, parse_contenttype("text/plain; charset=us-ascii (Plain text)")),
					?assertEqual({"text", "plain", [{"charset", "us-ascii"}]}, parse_contenttype("text/plain; charset=\"us-ascii\"")),
					?assertEqual({"text", "plain", [{"charset", "us-ascii"}]}, parse_contenttype("Text/Plain; Charset=\"us-ascii\"")),
					?assertEqual({"multipart", "mixed", [{"boundary", "----_=_NextPart_001_01C9DCAE.1F2CB390"}]},
						parse_contenttype("multipart/mixed; boundary=\"----_=_NextPart_001_01C9DCAE.1F2CB390\""))
			end
		},
		{"parsing contenttype with a tab in it",
			fun() ->
					?assertEqual({"text", "plain", [{"charset", "us-ascii"}]}, parse_contenttype("text/plain;\tcharset=us-ascii"))
			end
		}
	].

parse_full_email_test_() ->
	[
		{"parse a random email",
			fun() ->
					{ok, Contents} = file:read_file("testdata/testcase2"),
					StringContents = binary_to_list(Contents),
					{Headers, Body} = parse_headers(StringContents),
					?debugFmt("Headers: ~p~nBody: ~p~n", [Headers, Body]),
					?debugFmt("decoded: ~p~n", [decode(Headers, Body)])
			end
		}
	].

parse_example_mails_test_() ->
	Getmail = fun(File) ->
		{ok, Bin} = file:read_file(string:concat("testdata/", File)),
		Email = binary_to_list(Bin),
		{Headers, Body} = parse_headers(Email),
		decode(Headers, Body)
	end,
	[
		{"parse a plain text email",
			fun() ->
				Decoded = Getmail("Plain-text-only.eml"),
%				?debugFmt("~p", [Decoded]),
%				?assert(false),
				?assertEqual(5, tuple_size(Decoded)),
				{Type, SubType, Headers, Properties, Body} = Decoded,
				?assertEqual({"text", "plain"}, {Type, SubType}),
				?assertEqual("This message contains only plain text.\r\n", Body)
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
		}
	].

-endif.





