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

-export([encode/2, decode/2, decode/1]).

encode(Headers, BodyList) ->
	ok.

decode(All) ->
	{Headers, Body} = parse_headers(All),
	decode(Headers, Body).

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
					{"multipart", SubType, Headers, Parameters, split_body_by_boundary(Body, "--"++Boundary, MimeVsn)}
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
			% from now on, we can be sure that each boundary is preceeded by a CRLF
			Parts = split_body_by_boundary_(NewBody, "\r\n" ++ Boundary, []),
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

-define(IMAGE_MD5, <<5,253,79,13,122,119,92,33,133,121,18,149,188,241,56,81>>).

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
				?debugFmt("~p", [Decoded]),
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
		},
		{"text attachment only",
			fun() ->
				Decoded = Getmail("text-attachment-only.eml"),
				?assertEqual(5, tuple_size(Decoded)),
				{Type, SubType, Headers, Properties, Body} = Decoded,
				?assertEqual({"multipart", "mixed"}, {Type, SubType}),
				?debugFmt("~p", [Body]),
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
				?debugFmt("~p", [Body]),
				?assertEqual(1, length(Body)),
				?assertMatch([{"image", "jpeg", _, _, _}], Body),
				[H | _] = Body,
				?assertEqual(?IMAGE_MD5, erlang:md5(element(5, H)))
			end
		},
		{"message attachment only",
			fun() ->
				Decoded = Getmail("message-as-attachment.eml"),
				?assertMatch({"multipart", "mixed", _, _, _}, Decoded),
				[Body] = element(5, Decoded),
				?debugFmt("~p", [Body]),
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
				?debugFmt("~p", [element(5, Messagewithin)]),
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
		{"no \r\n before first boundary",
			fun() ->
				{ok, Bin} = file:read_file("testdata/html.eml"),
				Email = binary_to_list(Bin),
				{Headers, B} = parse_headers(Email),
				Body = string:strip(string:strip(B, left, $\r), left, $\n),
				Decoded = decode(Headers, Body),
				?debugFmt("~p", [Decoded]),
				?assertEqual(2, length(element(5, Decoded)))
			end
		}
	].

-endif.





