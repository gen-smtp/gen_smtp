%% @doc property-based tests for `mimemail' module
%%
%% Following limitations of mimemail are discovered and modelled in this suite:
%% * We may truncate leading and trailing whitespaces " " from header values
%% * We may truncate trailing tabs and whitespaces from payload when Content-Transfer-Encoding is not base64
%% * For binary payload it's highly recommended to set `#{transfer_encoding => <<"base64">>}' explicitly
-module(prop_mimemail).

-export([
	prop_plaintext_encode_no_crash/1,
	prop_multipart_encode_no_crash/1,
	prop_plaintext_encode_decode_match/1,
	prop_multipart_encode_decode_match/1,
	prop_encode_decode_no_mime_version_match/1,
	prop_quoted_printable/1,
	prop_smtp_compatible/1
]).

-include_lib("proper/include/proper.hrl").
-include_lib("stdlib/include/assert.hrl").

prop_plaintext_encode_no_crash(doc) ->
    "Check that any plaintext mail can be encoded without crash".

prop_plaintext_encode_no_crash() ->
    ?FORALL(
       Mail,
       gen_plaintext_mail(),
       is_binary(mimemail:encode(Mail))
    ).

prop_multipart_encode_no_crash(doc) ->
    "Check that any multipart mail can be encoded without crash".

prop_multipart_encode_no_crash() ->
    ?FORALL(
       Mail,
       gen_multipart_mail(),
       is_binary(mimemail:encode(Mail))
    ).

prop_plaintext_encode_decode_match(doc) ->
    "Check that any plaintext mail can be encoded and decoded without"
		" information loss or corruption".

prop_plaintext_encode_decode_match() ->
    ?FORALL(
       Mail,
       gen_plaintext_mail(),
	   begin
		   Encoded = mimemail:encode(Mail),
		   Recoded = mimemail:decode(Encoded),
		   ?WHENFAIL(
			  io:format("Orig:~n~p~nEncoded:~n~p~nRecoded:~n~p~n",
						[Mail, Encoded, Recoded]),
			  match(Mail, Recoded))
	   end
    ).

prop_multipart_encode_decode_match(doc) ->
    "Check that any plaintext mail can be encoded and decoded without"
		" information loss or corruption".

prop_multipart_encode_decode_match() ->
    ?FORALL(
       Mail,
       gen_multipart_mail(),
	   begin
		   Encoded = mimemail:encode(Mail),
		   Recoded = mimemail:decode(Encoded),
		   ?WHENFAIL(
			  io:format("Orig:~n~p~nEncoded:~n~p~nRecoded:~n~p~n",
						[Mail, Encoded, Recoded]),
			  match(Mail, Recoded))
	   end
    ).

prop_encode_decode_no_mime_version_match(doc) ->
	"Make sure decoder is able to recover from situation when 'mime-version' header is missing".

prop_encode_decode_no_mime_version_match() ->
    ?FORALL(
       Mail,
       proper_types:oneof([gen_plaintext_mail(), gen_multipart_mail()]),
	   begin
		   Encoded = mimemail:encode(Mail),
		   Recoded = mimemail:decode(strip_mime_version(Encoded),
									 [{allow_missing_version, true},
									  {encoding, <<"utf-8">>}]),
		   ?WHENFAIL(
			  io:format("Orig:~n~p~nEncoded:~n~p~nRecoded:~n~p~n",
						[Mail, Encoded, Recoded]),
			  match(Mail, Recoded))
	   end
    ).


match({TypeA, SubTypeA, HeadersA, ParamsA, BodyA},
	  {TypeB, SubTypeB, HeadersB, ParamsB, BodyB}) ->
	?assertEqual(TypeA, TypeB),
	?assertEqual(SubTypeA, SubTypeB),
	?assert(is_map(ParamsA)),
	?assert(is_map(ParamsB)),
	maps:fold(fun(transfer_encoding, _, _) ->
					  [];						%never added during decoding
				 (disposition, _, _) when not is_binary(BodyA);
										  BodyA =:= <<>> ->
					  [];
				 (disposition = K, V, _) when is_binary(BodyA) ->
					  %% disposition only applied for non-empty bodies
					  case re:replace(BodyA, "\s+", "", [global, {return, binary}]) of
						  <<>> -> [];
						  _ ->
							  ?assertEqual(V, maps:get(K, ParamsB))
					  end;
				 (K, KVA, _) when K =:= content_type_params;
								 K =:= disposition_params ->
					  %% assert all Content-Type/Disposition from original mime do present in
					  %% recoded mime; keys should be lowercased
					  KVB = maps:get(K, ParamsB),
					  lists:foreach(fun({PKA, PVA}) ->
											?assert(lists:member({binstr:to_lower(PKA), PVA}, KVB))
									end, KVA);
				 (K, V, _) ->
					  ?assertEqual(V, maps:get(K, ParamsB))
			  end, [], ParamsA),
	%% XXX: we have to strip values of the body and headers, because it seems some types of
	%% encoding do remove some of whitespaces from payload. Not sure if it's ok...
	lists:foreach(
	  fun({K, VA}) ->
			  VB = proplists:get_value(K, HeadersB),
			  ?assertEqual(string:trim(VA, both, " "),
						   string:trim(VB, both, " "),
						   #{header => K,
							 b_headers => HeadersB})
	  end, HeadersA),
	case is_binary(BodyA) of
		true ->
			?assertEqual(BodyA, BodyB),
			true;
		false ->
			Bodies = lists:zip(BodyA, BodyB),
			lists:all(
			  fun({SubBodyA, SubBodyB}) ->
					  match(SubBodyA, SubBodyB)
			  end, Bodies)
	end.

prop_quoted_printable(doc) ->
	"Make sure quoted-printable encoder works as expected: "
		"* No lines longer than 76 chars "
		"* decode(encode(data)) returns the same result as original input".

prop_quoted_printable() ->
	?FORALL(
	   Body,
	   proper_types:oneof([?SIZED(Size, printable_ascii(Size * 50)),
						   ?SIZED(Size, printable_ascii_and_cariage(Size * 50)),
						   printable_ascii(),
						   printable_ascii_and_cariage(),
						   nonull_utf8(),
						   proper_types:binary()]),
	   begin
		   [QPEncoded] = mimemail:encode_quoted_printable(Body),
		   ?assertEqual(Body, mimemail:decode_quoted_printable(QPEncoded)),
		   ?assertNot(has_lines_over(QPEncoded, 76), #{encoded => QPEncoded, orig => Body}),
		   true
	   end).

prop_smtp_compatible(doc) ->
    "Makes sure mimemail never produces output that is not compatible with SMTP, "
		"See https://tools.ietf.org/html/rfc2045 and https://tools.ietf.org/html/rfc2049:"
		"* Should not contain bare '\r' or '\n' (ie, $\r or $\n in any other form than '\r\n' pair). "
		"* Should not contain ASCII codes above 127"
		"* Should not contain 0 byte"
		"* Should not have too long (over 1000 chars) lines".

prop_smtp_compatible() ->
    ?FORALL(
       Mail,
       proper_types:oneof([gen_multipart_mail(), gen_plaintext_mail()]),
	   begin
		   SevenByte = mimemail:encode(Mail),
		   ?assertNot(has_bare_cr_or_lf(SevenByte), SevenByte),
		   ?assertNot(has_bytes_above_127(SevenByte), SevenByte),
		   ?assertNot(has_zero_byte(SevenByte), SevenByte),
		   ?assertNot(has_lines_over(SevenByte, 1000), SevenByte),
		   true
	   end
    ).

has_bare_cr_or_lf(Mime) ->
	WithoutCRLF = binary:replace(Mime, <<"\r\n">>, <<"">>, [global]),
	case binary:match(WithoutCRLF, [<<"\r">>, <<"\n">>]) of
		nomatch -> false;
		{_, _} -> true
	end.

has_bytes_above_127(<<C, _/binary>>) when C > 127 ->
	true;
has_bytes_above_127(<<_, Tail/binary>>) ->
	has_bytes_above_127(Tail);
has_bytes_above_127(<<>>) ->
	false.

has_zero_byte(Mime) ->
	case binary:match(Mime, <<0>>) of
		nomatch -> false;
		{match, _} -> true
	end.

has_lines_over(Mime, Limit) ->
	lists:any(fun(Line) ->
					  byte_size(Line) > Limit
			  end, binary:split(Mime, <<"\r\n">>, [global])).

strip_mime_version(MimeBin) ->
	binary:replace(MimeBin, <<"MIME-Version: 1.0\r\n">>, <<>>).
	%% re:replace(MimeBin, "mime-version: 1\\.0\\s*", "", [caseless, {return, binary}]).

%%
%% Generators
%%

%% top-level multipart mimemail()
gen_multipart_mail() ->
	{<<"multipart">>,
	 proper_types:oneof([<<"mixed">>, <<"alternative">>]),
	 gen_top_headers(),
	 gen_props(outer),
	 %% Resizing to not create too many sub-bodies, because it's slow
	 ?SIZED(Size,
			proper_types:resize(
			  max(1, Size div 2),
			  proper_types:list(
				proper_types:oneof(
				  [gen_embedded_plaintext_mail(),
				   gen_embedded_html_mail(),
				   gen_embedded_attachment_mail()]))))
	}.

%% top-level plaintext mimemail()
gen_plaintext_mail() ->
    {<<"text">>, <<"plain">>,
     gen_top_headers(),
     gen_props(outer),
     proper_types:oneof([gen_body(), gen_nonempty_body()])}.

%% Plaintext mimemail(), that is safe to use inside multipart mails
gen_embedded_plaintext_mail() ->
	{<<"text">>, <<"plain">>,
     gen_headers(),
     gen_props(embedded),
     gen_nonempty_body()}.

%% Pseudo-HTML mimemail(), that is safe to use inside multipart mails
gen_embedded_html_mail() ->
	{<<"text">>, <<"html">>,
	 gen_headers(),
	 #{content_type_params => [{<<"charset">>, <<"utf-8">>}],
	   disposition => <<"inline">>},
	 ?LET(Body,
		  gen_body(),
		  <<"<!doctype html><html><body><p>", Body/binary, "</p></body></html>">>)}.

gen_embedded_attachment_mail() ->
	{<<"application">>, <<"pdf">>,
	 gen_headers(),
	 gen_attachment_props(),
	 proper_types:non_empty(proper_types:binary())}.

%% like gen_headers/0, but `From' is always there
gen_top_headers() ->
	?LET(KV, gen_headers(), lists:ukeysort(1, [{<<"From">>, <<"test@example.com">>} | KV])).

%% [{binary(), binary()}]
gen_headers() ->
	AddrHeaders = [<<"To">>, <<"Cc">>, <<"Bcc">>, <<"Reply-To">>, <<"From">>],
	ContentHeaders = [<<"Content-Type">>, <<"Content-Disposition">>, <<"Content-Transfer-Encoding">>],
	SpecialHeaders = AddrHeaders ++ ContentHeaders,
    ?LET(KV,
         proper_types:list(
		   proper_types:frequency(
			 [
			  {5,
			   ?SUCHTHAT(
				  {K, _},
				  gen_any_header(),
				  not lists:member(K, SpecialHeaders))
			  },
			  {1,
			   {proper_types:oneof(AddrHeaders), <<"to@example.com">>}
			  }
			 ])),
		 lists:ukeysort(1, KV)).

%% This can generate invalid header when it requires some specific format
gen_any_header() ->
	{header_name(),
	 proper_types:oneof(
	   [nonull_utf8(),
		printable_ascii_and_cariage(),
		printable_ascii()])}.

%% #{atom() => any()}
gen_props(Location) ->
	Disposition = case Location of
					  outer -> [];
					  embedded -> [{disposition, proper_types:oneof([<<"inline">>, <<"attachment">>])}]
				  end,
    ?LET(KV,
		 proper_types:list(
		   proper_types:oneof(
			 Disposition ++
			 [
			  {content_type_params, [{<<"charset">>, <<"utf-8">>}]},
			  {transfer_encoding, proper_types:oneof([<<"base64">>, <<"quoted-printable">>])}
			 ]
			)
		  ),
		 maps:from_list(KV)).

gen_attachment_props() ->
	?LET(KV,
		 proper_types:list(
		   proper_types:oneof(
			 [{content_type_params, gen_params()},
			  {disposition_params, gen_params()}]
			)),
		 maps:from_list([{disposition, <<"attachment">>},
						 {transfer_encoding, <<"base64">>} | KV])).

gen_params() ->
	proper_types:list(
	  {
	   header_name(),
	   header_name()
	  }).

%% binary(), guaranteed to be not `<<>>'. Also, try to generate relatively large body
gen_nonempty_body() ->
	proper_types:oneof(
	  [
	   proper_types:non_empty(?SIZED(Size, printable_ascii(Size * 30))),
	   proper_types:non_empty(?SIZED(Size, printable_ascii_and_cariage(Size * 30))),
	   proper_types:non_empty(nonull_utf8())
	  ]).

%% binary()
gen_body() ->
	proper_types:oneof(
	  [
	   printable_ascii(),
	   printable_ascii_and_cariage(),
	   nonull_utf8()
	  ]).

%% `[0-9a-zA-Z_-]*'
header_name() ->
	%% let's limit header names to 20 characters. Too long header names can easily create very long lines
	?LET(OrigHdr,
		 proper_types:non_empty(
		   binary_of("-_" ++
						 lists:seq($0, $9) ++
						 lists:seq($A, $Z) ++
						 lists:seq($a, $z))),
		 case OrigHdr of
			 <<Max20:20/binary, _/binary>> -> Max20;
			 _ -> OrigHdr
		 end).

printable_ascii_and_cariage() ->
	?SIZED(Size, printable_ascii_and_cariage(Size)).

printable_ascii_and_cariage(Size) ->
    binary_of("\t\r\n" ++ lists:seq(32, 126), Size).

printable_ascii() ->
	?SIZED(Size, printable_ascii(Size)).

printable_ascii(Size) ->
    binary_of(lists:seq(32, 126), Size).

binary_of(Bytes) ->
	?SIZED(Size, binary_of(Bytes, Size)).

binary_of(Bytes, Size) ->
	?LET(List,
         proper_types:resize(Size, proper_types:list(proper_types:oneof(Bytes))),
         list_to_binary(List)).

%% any utf-8, except 0
nonull_utf8() ->
	?SUCHTHAT(
	   Chars,
	   proper_unicode:utf8(),
	   case Chars of
		   <<>> ->
			   true;
		   _ ->
			   binary:match(Chars, <<0>>) =:= nomatch
	   end).
