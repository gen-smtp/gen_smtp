-module(gen_smtp_util_test).

-compile(export_all).

-include_lib("eunit/include/eunit.hrl").

test_test() ->
    smtp_util:parse_rfc822_addresses("foo bar").

parse_rfc822_addresses_test_() ->
    [
     {"Empty address list",
      fun() ->
              ?assertEqual({ok, []}, smtp_util:parse_rfc822_addresses(<<>>)),
              ?assertEqual({ok, []}, smtp_util:parse_rfc822_addresses(<<"   ">>)),
              ?assertEqual({ok, []}, smtp_util:parse_rfc822_addresses(<<" \r\n\t  ">>)),
              ?assertEqual({ok, []}, smtp_util:parse_rfc822_addresses(<<"
">>))
      end},
     {"Single addresses",
      fun() ->
              ?assertEqual({ok, [{undefined, "john@doe.com"}]},
                           smtp_util:parse_rfc822_addresses(<<"john@doe.com">>)),
              ?assertEqual({ok, [{"Fræderik Hølljen", "me@example.com"}]},
                           smtp_util:parse_rfc822_addresses(<<"Fræderik Hølljen <me@example.com>">>)),
              ?assertEqual({ok, [{undefined, "john@doe.com"}]},
                           smtp_util:parse_rfc822_addresses(<<"<john@doe.com>">>)),
              ?assertEqual({ok, [{"John", "john@doe.com"}]},
                           smtp_util:parse_rfc822_addresses(<<"John <john@doe.com>">>)),
              ?assertEqual({ok, [{"John Doe", "john@doe.com"}]},
                           smtp_util:parse_rfc822_addresses(<<"John Doe <john@doe.com>">>)),
              ?assertEqual({ok, [{"John Doe", "john@doe.com"}]},
                           smtp_util:parse_rfc822_addresses(<<"\"John Doe\" <john@doe.com>">>)),
              ?assertEqual({ok, [{"John \"Mighty\" Doe", "john@doe.com"}]},
                           smtp_util:parse_rfc822_addresses(<<"\"John \\\"Mighty\\\" Doe\" <john@doe.com>">>))
      end},
     {"Multiple addresses",
      fun() ->
              ?assertEqual({ok, [{undefined, "a@a.com"}, {undefined, "b@b.com"}]},
                           smtp_util:parse_rfc822_addresses(<<"a@a.com,b@b.com">>)),
              ?assertEqual({ok, [{undefined, "a,a@a.com"}, {undefined, "b@b.com"}]},
                           smtp_util:parse_rfc822_addresses(<<"<a,a@a.com>,b@b.com">>)),
              ?assertEqual({ok, [{"Jan", "a,a@a.com"}, {undefined, "b@b.com"}]},
                           smtp_util:parse_rfc822_addresses(<<"Jan <a,a@a.com>,b@b.com">>)),
              ?assertEqual({ok, [{"Jan", "a,a@a.com"}, {"Berend Botje", "b@b.com"}]},
                           smtp_util:parse_rfc822_addresses(<<"Jan <a,a@a.com>,\"Berend Botje\" <b@b.com>">>))
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
    Encoded = "=?UTF-8?Q?=E2=82=AC=20=E2=82=AC=20=E2=82=AC=20=E2=82=AC=20=E2=82=AC=20123?=\r\n"
            ++ " =?UTF-8?Q?4=20=E2=82=AC=20=E2=82=AC=20=E2=82=AC=20=E2=82=AC=20123=20?=\r\n"
            ++ " =?UTF-8?Q?=E2=82=AC=20=E2=82=AC=20=E2=82=AC=20=E2=82=AC=20=E2=82=AC=20123?=\r\n"
            ++ " =?UTF-8?Q?4=E2=82=AC?=",
    ?assertEqual(Encoded, mimemail:rfc2047_utf8_encode(UnicodeString)).
