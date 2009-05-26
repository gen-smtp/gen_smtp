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
			decode_component(Headers, Body, Other)
	end.

decode_component(Headers, Body, MimeVsn) when MimeVsn =:= "1.0" ->
	io:format("MIME 1.0 email~n"),
	case parse_contenttype(proplists:get_value("Content-Type", FixedHeaders)) of
		{"multipart", SubType, Parameters} ->
			case proplists:get_value("boundary", Parameters) of
				Boundary ->
					io:format("this is a multipart email of type:  ~s and boundary ~s~n", [SubType, Boundary]);
				undefined ->
					io:format("multipart email of type ~s doesn't have a boundary!~n", [SubType])
			end;
		{Type, SubType, Parameters} ->
			io:format("body is ~s/~s~n", [Type, SubType]);
		error ->
			error;
		undefined ->

	end;
decode(Headers, Body, Other) ->
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
parse_with_comments([$" | T], Acc, Depth) ->
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
					Y = string:strip(X),
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
		}
	].
-endif.





