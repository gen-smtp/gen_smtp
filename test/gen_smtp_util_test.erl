%% coding: utf-8
-module(gen_smtp_util_test).

-compile([export_all, nowarn_export_all]).

-include_lib("eunit/include/eunit.hrl").

test_test() ->
    smtp_util:parse_rfc822_addresses("foo bar").

parse_rfc822_addresses_test_() ->
	F = fun smtp_util:parse_rfc822_addresses/1,
	[{"Empty address list parse_rfc2822_addresses_test",
      fun() ->
              ?assertEqual({ok, []}, F(<<>>)),
              ?assertEqual({ok, []}, F(<<"   ">>)),
              ?assertEqual({ok, []}, F(<<" \r\n\t  ">>)),
              ?assertEqual({ok, []}, F(<<"
">>))
      end},
	 {"Group parse_rfc2822_addresses_test",
	  fun() ->
			  %% XXX: this is incorrect...
			  ?assertEqual({ok, [{undefined, "undisclosed-recipients:;"}]},
						   F(<<"undisclosed-recipients:;">>))
	  end},
	 {"Multiple with comma  parse_rfc2822_addresses_test",
	  fun() ->
			  ?assertEqual({ok, [{"Jan", "a,a@a.com"}, {undefined, "b@b.com"}]},
                           F(<<"Jan <a,a@a.com>,b@b.com">>))

	  end}| parse_adresses_t(F)].

parse_rfc2822_addresses_test_() ->
	F = fun smtp_util:parse_rfc5322_addresses/1,
	[{"Group parse_rfc822_addresses_test",
	  fun() ->
			  %% rfc5322#section-3.4
			  %% empty group
			  ?assertEqual({ok, []},
						   F(<<"undisclosed-recipients:;">>)),
			  %% group with recipient list
			  ?assertEqual({ok, [{undefined, "a@a.com"}, {undefined, "b@b.com"}]},
						  F(<<"friends:a@a.com,b@b.com;">>))
	  end} | parse_adresses_t(F)].

parse_adresses_t(F) ->
	{_, FName} = erlang:fun_info(F, name),
	FStr = atom_to_list(FName),
    [
     {"Single addresses " ++ FStr,
      fun() ->
              ?assertEqual({ok, [{undefined, "john@doe.com"}]},
                           F(<<"john@doe.com">>)),
              ?assertEqual({ok, [{"Fræderik Hølljen", "me@example.com"}]},
                           F(<<"Fræderik Hølljen <me@example.com>"/utf8>>)),
              ?assertEqual({ok, [{undefined, "john@doe.com"}]},
                           F(<<"<john@doe.com>">>)),
              ?assertEqual({ok, [{"John", "john@doe.com"}]},
                           F(<<"John <john@doe.com>">>)),
              ?assertEqual({ok, [{"John Doe", "john@doe.com"}]},
                           F(<<"John Doe <john@doe.com>">>)),
              ?assertEqual({ok, [{"John Doe", "john@doe.com"}]},
                           F(<<"\"John Doe\" <john@doe.com>">>)),
              ?assertEqual({ok, [{"John \"Mighty\" Doe", "john@doe.com"}]},
                           F(<<"\"John \\\"Mighty\\\" Doe\" <john@doe.com>">>))
      end},
     {"Multiple addresses " ++ FStr,
      fun() ->
              ?assertEqual({ok, [{undefined, "a@a.com"}, {undefined, "b@b.com"}]},
                           F(<<"a@a.com,b@b.com">>)),
              ?assertEqual({ok, [{undefined, "a@a.com"}, {undefined, "b@b.com"}]},
                           F(<<"<a@a.com>,b@b.com">>)),
              ?assertEqual({ok, [{"Jan", "a@a.com"}, {undefined, "b@b.com"}]},
                           F(<<"Jan <a@a.com>,b@b.com">>)),
              ?assertEqual({ok, [{"Jan", "a@a.com"}, {"Berend Botje", "b@b.com"}]},
                           F(<<"Jan <a@a.com>,\"Berend Botje\" <b@b.com>">>))
      end}
    ].

combine_rfc822_addresses_test_() ->
    [
     {"One address",
      fun() ->
              ?assertEqual(<<"john@doe.com">>,
                           smtp_util:combine_rfc822_addresses([{undefined, "john@doe.com"}])),
              ?assertEqual(<<"John <john@doe.com>">>,
                           smtp_util:combine_rfc822_addresses([{"John", "john@doe.com"}])),
              ?assertEqual(<<"\"John \\\"Foo\" <john@doe.com>">>,
                           smtp_util:combine_rfc822_addresses([{"John \"Foo", "john@doe.com"}]))
      end},
     {"Multiple addresses",
      fun() ->
              ?assertEqual(<<"john@doe.com, foo@bar.com">>,
                           smtp_util:combine_rfc822_addresses([{undefined, "john@doe.com"}, {undefined, "foo@bar.com"}])),
              ?assertEqual(<<"John <john@doe.com>, foo@bar.com">>,
                           smtp_util:combine_rfc822_addresses([{"John", "john@doe.com"}, {undefined, "foo@bar.com"}]))
      end}
    ].

illegal_rfc822_addresses_test_() ->
    [
     {"Nested brackets",
      fun() ->
              ?assertEqual({error,{0,smtp_rfc822_parse, ["syntax error before: ","\">\""]}},
                           smtp_util:parse_rfc822_addresses("a<b<c>>"))
      end}
    ].

rfc822_addresses_roundtrip_test() ->
    Addr = <<"Jan <a,a@a.com>, Berend Botje <b@b.com>">>,
    {ok, Parsed} = smtp_util:parse_rfc822_addresses(Addr),
    ?assertEqual(Addr, smtp_util:combine_rfc822_addresses(Parsed)),
    ok.

rfc2047_utf8_encode_test() ->
    UnicodeString = unicode:characters_to_binary("€ € € € € 1234 € € € € 123 € € € € € 1234€"),
    Encoded = << "=?UTF-8?B?4oKsIOKCrCDigqwg4oKsIOKCrCAxMjM0IOKCrCDigqwg4oKsIOKCrCAxMjMg?=\r\n"
		" =?UTF-8?B?4oKsIOKCrCDigqwg4oKsIOKCrCAxMjM04oKs?=">>,
    ?assertEqual(Encoded, mimemail:rfc2047_utf8_encode(UnicodeString)).
