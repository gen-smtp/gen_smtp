%% @doc property-based tests for `smtp_util' rfc5322#section-3.4 and RFC-822 parser/serializer
%% Mainly tests parsing of address-lists and groups:
%% `login@domain'
%% `Name <login@domain>'
%% `Name Surname <login@domain>'
%% `Name <login1@domain1>, Name2 <login2@domain2>'
%% `group name:login@domain,Name <login2@domain2>;'
%% Also different versions of escaping of name / login / domain
-module(prop_rfc5322).

-export([
    prop_encode_no_crash/1,
    prop_encode_scan_no_crash/1,
    prop_encode_decode_match/1,
    prop_encode_decode_group/1
]).

-include_lib("proper/include/proper.hrl").
-include_lib("stdlib/include/assert.hrl").

prop_encode_no_crash(doc) ->
    "Check that any RFC-5322-compliant 'mailbox-list' can be serialized".

prop_encode_no_crash() ->
    ?FORALL(
        AddressList,
        ?LET(Opts, use_unicode(), gen_address_list(Opts)),
        is_binary(smtp_util:combine_rfc822_addresses(AddressList))
    ).

prop_encode_scan_no_crash(doc) ->
    "Check that any RFC-5322-compliant 'mailbox-list' can be serialized and then result scanned by lexer".

prop_encode_scan_no_crash() ->
    ?FORALL(
        AddressList,
        ?LET(Opts, use_unicode(), gen_address_list(Opts)),
        begin
            Encoded = smtp_util:combine_rfc822_addresses(AddressList),
            Res = smtp_rfc5322_scan:string(unicode:characters_to_list(Encoded)),
            ?WHENFAIL(
                io:format(
                    "AddrList:~n~p~nEncoded:~n~p~nRes:~n~p~n",
                    [AddressList, Encoded, Res]
                ),
                begin
                    ?assertMatch({ok, _, 1}, Res),
                    true
                end
            )
        end
    ).

prop_encode_decode_match(doc) ->
    "Check that any RFC-5322-compliant 'mailbox-list' can be serialized and parsed to the same result".

prop_encode_decode_match() ->
    ?FORALL(
        AddressList,
        ?LET(Opts, use_unicode(), gen_address_list(Opts)),
        begin
            Encoded = smtp_util:combine_rfc822_addresses(AddressList),
            Res = smtp_util:parse_rfc5322_addresses(Encoded),
            ?WHENFAIL(
                io:format(
                    "AddrList:~n~p~nEncoded:~n~p~nRes:~n~p~nScan:~n~p~n",
                    [
                        AddressList,
                        Encoded,
                        Res,
                        smtp_rfc5322_scan:string(unicode:characters_to_list(Encoded))
                    ]
                ),
                begin
                    {ok, Decoded} = Res,
                    Zip = lists:zip(AddressList, Decoded),
                    lists:all(fun match/1, Zip)
                end
            )
        end
    ).

match({{OName, OAddr}, {undefined, RAddr}}) when
    OName == undefined;
    OName == <<>>;
    OName == ""
->
    ?assertEqual(OAddr, unicode:characters_to_binary(RAddr)),
    true;
match({{OName, OAddr}, {RName, RAddr}}) ->
    %% smtp_util drops chars below 32 from "name" part. Not sure it's correct, but is probably
    %% not a big deal.
    ONameNoControl = lists:map(
        fun
            (C) when C < 32 -> 32;
            (C) -> C
        end,
        unicode:characters_to_list(OName)
    ),
    ?assertEqual(ONameNoControl, RName),
    ?assertEqual(OAddr, unicode:characters_to_binary(RAddr)),
    true.

prop_encode_decode_group(doc) ->
    "Check that any RFC-5322-compliant 'group' can be serialized and parsed to the same result".

prop_encode_decode_group() ->
    ?FORALL(
        {Name, AddressList},
        ?LET(Opts, use_unicode(), gen_group(Opts)),
        begin
            Encoded = encode_group(Name, AddressList),
            {ok, Tokens, _} = smtp_rfc5322_scan:string(unicode:characters_to_list(Encoded)),
            Res = smtp_rfc5322_parse:parse(Tokens),
            ?WHENFAIL(
                io:format(
                    "Name: '~p'~n"
                    "AddressList: ~p~n"
                    "Encoded: ~p~n"
                    "Res: ~p~n",
                    [Name, AddressList, Encoded, Res]
                ),
                begin
                    ?assertMatch({ok, {group, {_, _}}}, Res),
                    {ok, {group, {ResName, ResList0}}} = Res,
                    ResList =
                        lists:map(
                            fun({AName, {addr, Local, Domain}}) ->
                                {AName, Local ++ "@" ++ Domain}
                            end,
                            ResList0
                        ),
                    ?assertEqual(unicode:characters_to_list(Name), ResName),
                    lists:all(fun match/1, lists:zip(AddressList, ResList))
                end
            )
        end
    ).

encode_group(Name, AddressList) ->
    EncodedList = smtp_util:combine_rfc822_addresses(AddressList),
    EncName =
        case binary:match(Name, <<"\"">>) of
            nomatch -> Name;
            _ -> <<$\", (binary:replace(Name, <<"\"">>, <<"\\\"">>, [global]))/binary, $\">>
        end,
    <<EncName/binary, ":", EncodedList/binary, ";">>.

use_unicode() ->
    proper_types:oneof(
        [#{}, #{}, #{unicode => true}]
    ).

gen_group(Opts) ->
    {
        gen_phrase(Opts),
        proper_types:oneof(
            [
                gen_address_list(Opts),
                %group might be empty
                []
            ]
        )
    }.

gen_address_list(Opts) ->
    proper_types:non_empty(
        proper_types:list(
            proper_types:oneof(
                [
                    gen_anonymous_name_addr(Opts),
                    gen_named_name_addr(Opts)
                ]
            )
        )
    ).

gen_anonymous_name_addr(Opts) ->
    {
        proper_types:oneof(
            ["", <<>>, undefined]
        ),
        gen_addr_spec(Opts)
    }.

gen_named_name_addr(Opts) ->
    {gen_phrase(Opts), gen_addr_spec(Opts)}.

-define(NO_WS_CTL, (lists:seq(1, 8) ++ [11, 12] ++ lists:seq(14, 31) ++ [127])).

%% rfc5322#section-3.4
gen_addr_spec(Opts) ->
    ?LET(
        {Local, Domain},
        {gen_local_part(Opts), gen_domain(Opts)},
        <<Local/binary, "@", Domain/binary>>
    ).

gen_local_part(Opts) ->
    proper_types:oneof(
        [gen_dot_atom(Opts), gen_quoted_string(Opts)]
    ).

gen_domain(Opts) ->
    proper_types:oneof(
        [gen_dot_atom(Opts), gen_domain_literal(Opts)]
    ).

gen_domain_literal(Opts) ->
    DText = maybe_utf8(?NO_WS_CTL ++ lists:seq(33, 90) ++ lists:seq(94, 126), Opts),
    DContent = proper_types:oneof([<<"\\[">>, <<"\\]">> | DText]),
    ?LET(
        Str,
        proper_types:non_empty(proper_types:list(DContent)),
        <<"[", (unicode:characters_to_binary(Str))/binary, "]">>
    ).

%% rfc5322#section-3.2.5
gen_phrase(Opts) ->
    Word = proper_types:oneof(
        [
            gen_atom(Opts),
            gen_quoted_string(Opts)
        ]
    ),
    ?LET(
        Words,
        proper_types:non_empty(proper_types:list(Word)),
        unicode:characters_to_binary(lists:join($\s, Words))
    ).

%% rfc5322#section-3.2.5
gen_quoted_string(Opts) ->
    QText = maybe_utf8(?NO_WS_CTL ++ [33] ++ lists:seq(35, 91) ++ lists:seq(93, 126), Opts),
    %% QContent = [<<"\\\"">> | QText],
    QContent = QText,
    ?LET(
        Str,
        proper_types:non_empty(proper_types:list(proper_types:oneof(QContent))),
        unicode:characters_to_binary([$\", Str, $\"])
    ).

%% rfc5322#section-3.2.3
gen_dot_atom(Opts) ->
    ?LET(
        Parts,
        proper_types:non_empty(proper_types:list(gen_atom(Opts))),
        unicode:characters_to_binary(lists:join($\., Parts))
    ).

gen_atom(Opts) ->
    Spec = "!#$%&'*+-/=?^_`{|}~",
    Atext = maybe_utf8(lists:seq($0, $9) ++ lists:seq($A, $Z) ++ lists:seq($a, $z) ++ Spec, Opts),
    ?LET(
        Str,
        proper_types:non_empty(proper_types:list(proper_types:oneof(Atext))),
        unicode:characters_to_binary(Str)
    ).

maybe_utf8(Chars, #{unicode := true}) ->
    %% See `proper_unicode.erl'
    [
        proper_types:integer(16#80, 16#7FF),
        proper_types:integer(16#800, 16#D7FF),
        proper_types:integer(16#E000, 16#FFFD),
        proper_types:integer(16#10000, 16#10FFFF),
        proper_types:oneof(Chars)
    ];
maybe_utf8(Chars, _) ->
    Chars.
