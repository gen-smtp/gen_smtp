%% @doc property-based tests for `mimemail' module
%%
%% We only have 2 types of tests:
%% * Testing that we can encode valid `mimetuple()' without crashes
%% * Testing that we can encode and then decode `mimetuple()' without loosing information
-module(prop_mimemail).

-export([
    prop_plaintext_encode_no_crash/1,
    prop_multipart_encode_no_crash/1,
	prop_plaintext_encode_decode_match/1,
	prop_multipart_encode_decode_match/1
]).
-export([nonull_utf8/0]).

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

match({TypeA, SubTypeA, HeadersA, _ParamsA, BodyA},
	  {TypeB, SubTypeB, HeadersB, _ParamsB, BodyB}) ->
	?assertEqual(TypeA, TypeB),
	?assertEqual(SubTypeA, SubTypeB),
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
			?assertEqual(string:trim(BodyA, trailing, "\t "),
						 string:trim(BodyB, trailing, "\t ")),
			true;
		false ->
			Bodies = lists:zip(BodyA, BodyB),
			lists:all(
			  fun({SubBodyA, SubBodyB}) ->
					  match(SubBodyA, SubBodyB)
			  end, Bodies)
	end.

%%
%% Generators
%%

%% top-level multipart mimemail()
gen_multipart_mail() ->
	{<<"multipart">>,
	 proper_types:oneof([<<"mixed">>, <<"alternative">>]),
	 gen_top_headers(),
	 gen_props(),
	 %% Resizing to not create too many sub-bodies, because it's slow
	 ?SIZED(Size,
			proper_types:resize(
			  max(1, Size div 2),
			  proper_types:list(
				proper_types:oneof(
				  [gen_embedded_plaintext_mail(),
				   gen_embedded_html_mail()]))))
	}.

%% top-level plaintext mimemail()
gen_plaintext_mail() ->
    {<<"text">>, <<"plain">>,
     gen_top_headers(),
     gen_props(),
     gen_body()}.

%% Plaintext mimemail(), that is safe to use inside multipart mails
gen_embedded_plaintext_mail() ->
	{<<"text">>, <<"plain">>,
     gen_headers(),
     gen_props(),
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
	{proper_types:non_empty(header_name()),
	 proper_types:oneof(
	   [nonull_utf8(),
		printable_ascii()])}.

%% #{atom() => any()}
gen_props() ->
    ?LET(KV,
		 proper_types:list(
		   proper_types:oneof(
			 [
			  {content_type_params, [{<<"charset">>, <<"utf-8">>}]},
			  {disposition, proper_types:oneof([<<"inline">>, <<"attachment">>])},
			  {transfer_encoding, proper_types:oneof([<<"base64">>, <<"quoted-printable">>])}
			 ]
			)
		  ),
		 maps:from_list(KV)).

%% binary(), guaranteed to be not `<<>>'
gen_nonempty_body() ->
    proper_types:oneof(
      [
       proper_types:non_empty(printable_ascii()),
       proper_types:non_empty(nonull_utf8())
      ]).

%% binary()
gen_body() ->
    proper_types:oneof(
      [
       printable_ascii(),
       nonull_utf8()
      ]).

%% `[0-9a-zA-Z_-]*'
header_name() ->
	binary_of("-_" ++
				  lists:seq($0, $9) ++
				  lists:seq($A, $Z) ++
				  lists:seq($a, $z)).

%% Name is not very accurate, because it includes \t\r\n as well
printable_ascii() ->
    binary_of("\t\r\n" ++ lists:seq(32, 126)).

binary_of(Bytes) ->
	?LET(List,
         proper_types:list(proper_types:oneof(Bytes)),
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
