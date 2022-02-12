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

%% @doc A module for decoding/encoding MIME 1.0 email.
%% The encoder and decoder operate on the same data structure, which is as follows:
%% A 5-tuple with the following elements: `{Type, SubType, Headers, Parameters, Body}'.
%%
%% `Type' and `SubType' are the MIME type of the email, examples are `text/plain' or
%% `multipart/alternative'. The decoder splits these into 2 fields so you can filter by
%% the main type or by the subtype.
%%
%% `Headers' consists of a list of key/value pairs of binary values eg.
%% `{<<"From">>, <<"Andrew Thompson <andrew@hijacked.us>">>}'. There is no parsing of
%% the header aside from un-wrapping the lines and splitting the header name from the
%% header value.
%%
%% `Parameters' is a list of 3 key/value tuples. The 3 keys are `<<"content-type-params">>',
%% `<<"dispisition">>' and `<<"disposition-params">>'.
%% `content-type-params' is a key/value list of parameters on the content-type header, this
%% usually consists of things like charset and the format parameters. `disposition' indicates
%% how the data wants to be displayed, this is usually 'inline'. `disposition-params' is a list of
%% disposition information, eg. the filename this section should be saved as, the modification
%% date the file should be saved with, etc.
%%
%% Finally, `Body' can be one of several different types, depending on the structure of the email.
%% For a simple email, the body will usually be a binary consisting of the message body, In the
%% case of a multipart email, its a list of these 5-tuple MIME structures. The third possibility,
%% in the case of a message/rfc822 attachment, body can be a single 5-tuple MIME structure.
%%
%% You should see the relevant RFCs (2045, 2046, 2047, etc.) for more information.
%%
%% Note that parts of this module (e.g., `decode/2') use the
%% <a href="https://hex.pm/packages/iconv"><tt>iconv</tt></a> library for string conversion,
%% which you will need to explicitly list as a dependency.

-module(mimemail).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-export([rfc2047_utf8_encode/1]).
-endif.

-export([encode/1, encode/2, decode/2, decode/1, get_header_value/2, get_header_value/3, parse_headers/1]).
-export([encode_quoted_printable/1, decode_quoted_printable/1]).

-export_type([
    mimetuple/0,
    mime_type/0,
    mime_subtype/0,
    headers/0,
    parameters/0,
    options/0,
    dkim_options/0
]).

-include_lib("kernel/include/logger.hrl").

-define(LOGGER_META, #{domain => [gen_smtp]}).

-define(DEFAULT_MIME_VERSION, <<"1.0">>).

-define(DEFAULT_OPTIONS, [
    % default encoding is utf-8 if we can find the iconv module
    {encoding, get_default_encoding()},
    % should we decode any base64/quoted printable attachments?
    {decode_attachments, true},
    % should we assume default mime version
    {allow_missing_version, true},
    % default mime version
    {default_mime_version, ?DEFAULT_MIME_VERSION}
]).

% `<<"text">>'
-type mime_type() :: binary().
% `<<"plain">>'
-type mime_subtype() :: binary().
% `[{<<"Content-Type">>, <<"text/plain">>}]'
-type headers() :: [{binary(), binary()}].
-type parameters() ::
    %% <<"7bit">> | <<"base64">> | <<"quoted-printable">> etc
    #{
        transfer_encoding => binary(),
        %% [{<<"charset">>, <<"utf-8">>} | {<<"boundary">>, binary()} | {<<"name">>, binary()} etc...]
        content_type_params => [{binary(), binary()}],
        %% <<"inline">> | <<"attachment">> etc...
        disposition => binary(),
        %% [{<<"filename">>, binary()}, ]
        disposition_params => [{binary(), binary()}]
    }.

-type mimetuple() :: {
    mime_type(),
    mime_subtype(),
    headers(),
    parameters(),
    Body :: binary() | mimetuple() | [mimetuple()]
}.

-type dkim_priv_key() ::
    {pem_plain, binary()}
    | {pem_encrypted, Key :: binary(), Passwd :: string()}.
-type dkim_options() :: [
    {h, [binary()]}
    | {d, binary()}
    | {s, binary()}
    | {t, now | calendar:datetime()}
    | {x, calendar:datetime()}
    | {c, {simple | relaxed, simple | relaxed}}
    | {a, 'rsa-sha256' | 'ed25519-sha256'}
    | {private_key, dkim_priv_key()}
].
-type options() :: [
    {encoding, binary()}
    | {decode_attachment, boolean()}
    | {dkim, dkim_options()}
    | {allow_missing_version, boolean()}
    | {default_mime_version, binary()}
].

-spec decode(Email :: binary()) -> mimetuple().
%% @doc Decode a MIME email from a binary.
decode(All) ->
    {Headers, Body} = parse_headers(All),
    decode(Headers, Body, ?DEFAULT_OPTIONS).

-spec decode(Email :: binary(), Options :: options()) -> mimetuple().
%% @doc Decode with custom options
decode(All, Options) when is_binary(All), is_list(Options) ->
    {Headers, Body} = parse_headers(All),
    decode(Headers, Body, Options).

decode(OrigHeaders, Body, Options) ->
    ?LOG_DEBUG("headers: ~p", [OrigHeaders], ?LOGGER_META),
    Encoding = proplists:get_value(encoding, Options, none),
    %FixedHeaders = fix_headers(Headers),
    Headers = decode_headers(OrigHeaders, [], Encoding),
    case parse_with_comments(get_header_value(<<"MIME-Version">>, Headers)) of
        undefined ->
            AllowMissingVersion = proplists:get_value(allow_missing_version, Options, false),
            case parse_content_type(get_header_value(<<"Content-Type">>, Headers)) of
                {<<"multipart">>, _SubType, _Parameters} when AllowMissingVersion ->
                    MimeVersion = proplists:get_value(default_mime_version, Options, ?DEFAULT_MIME_VERSION),
                    decode_component(Headers, Body, MimeVersion, Options);
                {<<"multipart">>, _SubType, _Parameters} ->
                    erlang:error(non_mime_multipart);
                {Type, SubType, CTParameters} ->
                    NewBody = decode_body(
                        get_header_value(<<"Content-Transfer-Encoding">>, Headers),
                        Body,
                        proplists:get_value(<<"charset">>, CTParameters),
                        Encoding
                    ),
                    {Disposition, DispositionParams} =
                        case parse_content_disposition(get_header_value(<<"Content-Disposition">>, Headers)) of
                            undefined ->
                                {<<"inline">>, []};
                            Disp ->
                                Disp
                        end,
                    Parameters = #{
                        content_type_params => CTParameters,
                        disposition => Disposition,
                        disposition_params => DispositionParams
                    },
                    {Type, SubType, Headers, Parameters, NewBody};
                undefined ->
                    Parameters = #{
                        content_type_params => [{<<"charset">>, <<"us-ascii">>}],
                        disposition => <<"inline">>,
                        disposition_params => []
                    },
                    {<<"text">>, <<"plain">>, Headers, Parameters,
                        decode_body(get_header_value(<<"Content-Transfer-Encoding">>, Headers), Body)}
            end;
        Other ->
            decode_component(Headers, Body, Other, Options)
    end.

-spec encode(MimeMail :: mimetuple()) -> binary().
encode(MimeMail) ->
    encode(MimeMail, []).

%% @doc Encode a MIME tuple to a binary.
encode({Type, Subtype, Headers, ContentTypeParams, Parts}, Options) ->
    {FixedParams, FixedHeaders} = ensure_content_headers(Type, Subtype, ContentTypeParams, Headers, Parts, true),
    CheckedHeaders = check_headers(FixedHeaders),
    EncodedBody = binstr:join(
        encode_component(Type, Subtype, CheckedHeaders, FixedParams, Parts),
        "\r\n"
    ),
    EncodedHeaders = encode_headers(CheckedHeaders),
    SignedHeaders =
        case proplists:get_value(dkim, Options) of
            undefined -> EncodedHeaders;
            DKIM -> dkim_sign_email(EncodedHeaders, EncodedBody, DKIM)
        end,
    list_to_binary([
        binstr:join(SignedHeaders, "\r\n"),
        "\r\n\r\n",
        EncodedBody
    ]);
encode(_, _) ->
    ?LOG_DEBUG("Not a mime-decoded DATA", ?LOGGER_META),
    erlang:error(non_mime).

decode_headers(Headers, _, none) ->
    Headers;
decode_headers([], Acc, _Charset) ->
    lists:reverse(Acc);
decode_headers([{Key, Value} | Headers], Acc, Charset) ->
    decode_headers(Headers, [{Key, decode_header(Value, Charset)} | Acc], Charset).

decode_header(Value, Charset) ->
    RTokens = tokenize_header(Value, []),
    Tokens = lists:reverse(RTokens),
    Decoded =
        try
            decode_header_tokens_strict(Tokens, Charset)
        catch
            Type:Reason:Stacktrace ->
                case decode_header_tokens_permissive(Tokens, Charset, []) of
                    {ok, Dec} ->
                        Dec;
                    error ->
                        % re-throw original error
                        erlang:raise(Type, Reason, Stacktrace)
                end
        end,
    iolist_to_binary(Decoded).

-type hdr_token() :: binary() | {Encoding :: binary(), Data :: binary()}.
-spec tokenize_header(binary(), [hdr_token()]) -> [hdr_token()].
tokenize_header(<<>>, Acc) ->
    Acc;
tokenize_header(Value, Acc) ->
    %% maybe replace "?([^\s]+)\\?" with "?([^\s]*)\\?"?
    %% see msg lvuvmm593b8s7pqqfhu7cdtqd4g4najh
    %% Subject: =?utf-8?Q??=
    %%	=?utf-8?Q?=D0=9F=D0=BE=D0=B4=D1=82=D0=B2=D0=B5=D1=80=D0=B4=D0=B8=D1=82=D0=B5=20?=
    %%	=?utf-8?Q?=D1=80=D0=B5=D0=B3=D0=B8=D1=81=D1=82=D1=80=D0=B0=D1=86=D0=B8=D1=8E=20?=
    %%	=?utf-8?Q?=D0=B2=20Moy-Rebenok.ru?=

    case re:run(Value, "=\\?([-A-Za-z0-9_]+)\\?([qQbB])\\?([^\s]+)\\?=", [ungreedy]) of
        nomatch ->
            [Value | Acc];
        {match, [{AllStart, AllLen}, {EncodingStart, EncodingLen}, {TypeStart, _}, {DataStart, DataLen}]} ->
            %% RFC 2047 #2 (encoded-word)
            Encoding = binstr:substr(Value, EncodingStart + 1, EncodingLen),
            Type = binstr:to_lower(binstr:substr(Value, TypeStart + 1, 1)),
            Data = binstr:substr(Value, DataStart + 1, DataLen),

            EncodedData =
                case Type of
                    <<"q">> ->
                        %% RFC 2047 #5. (3)
                        decode_quoted_printable(binary:replace(Data, <<"_">>, <<"=20">>, [global]));
                    <<"b">> ->
                        decode_base64(binary:replace(Data, <<"_">>, <<" ">>, [global]))
                end,

            Offset =
                case
                    re:run(
                        binstr:substr(Value, AllStart + AllLen + 1),
                        "^([\s\t\n\r]+)=\\?[-A-Za-z0-9_]+\\?[^\s]\\?[^\s]+\\?=",
                        [ungreedy]
                    )
                of
                    nomatch ->
                        % no 2047 block immediately following
                        1;
                    {match, [{_, _}, {_, WhiteSpaceLen}]} ->
                        1 + WhiteSpaceLen
                end,

            NewAcc =
                case binstr:substr(Value, 1, AllStart) of
                    <<>> -> [{fix_encoding(Encoding), EncodedData} | Acc];
                    Other -> [{fix_encoding(Encoding), EncodedData}, Other | Acc]
                end,
            tokenize_header(binstr:substr(Value, AllStart + AllLen + Offset), NewAcc)
    end.

decode_header_tokens_strict([], _) ->
    [];
decode_header_tokens_strict([{Encoding, Data} | Tokens], Charset) ->
    {ok, S} = convert(Charset, Encoding, Data),
    [S | decode_header_tokens_strict(Tokens, Charset)];
decode_header_tokens_strict([Data | Tokens], Charset) ->
    [Data | decode_header_tokens_strict(Tokens, Charset)].

%% this decoder can handle folded not-by-RFC UTF headers, when somebody split
%% multibyte string not by characters, but by bytes. It first join folded
%% string and only then decode it with iconv.
decode_header_tokens_permissive([], _, [Result]) when is_binary(Result) ->
    {ok, Result};
decode_header_tokens_permissive([], _, Stack) ->
    case lists:all(fun erlang:is_binary/1, Stack) of
        true -> {ok, lists:reverse(Stack)};
        false -> error
    end;
decode_header_tokens_permissive([{Enc, Data} | Tokens], Charset, [{Enc, PrevData} | Stack]) ->
    NewData = iolist_to_binary([PrevData, Data]),
    {ok, S} = convert(Charset, Enc, NewData),
    decode_header_tokens_permissive(Tokens, Charset, [S | Stack]);
decode_header_tokens_permissive([NextToken | _] = Tokens, Charset, [{_, _} | Stack]) when
    is_binary(NextToken) orelse is_tuple(NextToken)
->
    %% practically very rare case "=?utf-8?Q?BROKEN?=\r\n\t=?windows-1251?Q?maybe-broken?="
    %% or "=?utf-8?Q?BROKEN?= raw-ascii-string"
    %% drop broken value from stack
    decode_header_tokens_permissive(Tokens, Charset, Stack);
decode_header_tokens_permissive([Data | Tokens], Charset, Stack) ->
    decode_header_tokens_permissive(Tokens, Charset, [Data | Stack]).

%% x-binaryenc is not a real encoding and is not used for text, so let it pass through
convert(_To, <<"x-binaryenc">>, Data) ->
    {ok, Data};
convert(To, From, Data) ->
    Result = iconv:convert(From, To, Data),
    {ok, Result}.

decode_component(Headers, Body, MimeVsn = <<"1.0", _/binary>>, Options) ->
    case parse_content_disposition(get_header_value(<<"Content-Disposition">>, Headers)) of
        {Disposition, DispositionParams} ->
            ok;
        % defaults
        _ ->
            Disposition = <<"inline">>,
            DispositionParams = []
    end,

    case parse_content_type(get_header_value(<<"Content-Type">>, Headers)) of
        {<<"multipart">>, SubType, Parameters} ->
            case proplists:get_value(<<"boundary">>, Parameters) of
                undefined ->
                    erlang:error(no_boundary);
                Boundary ->
                    ?LOG_DEBUG(
                        "this is a multipart email of type:  ~s and boundary ~s", [SubType, Boundary], ?LOGGER_META
                    ),
                    Parameters2 = #{
                        content_type_params => Parameters,
                        disposition => Disposition,
                        disposition_params => DispositionParams
                    },
                    {<<"multipart">>, SubType, Headers, Parameters2,
                        split_body_by_boundary(Body, list_to_binary(["--", Boundary]), MimeVsn, Options)}
            end;
        {<<"message">>, <<"rfc822">>, Parameters} ->
            {NewHeaders, NewBody} = parse_headers(Body),
            Parameters2 = #{
                content_type_params => Parameters,
                disposition => Disposition,
                disposition_params => DispositionParams
            },
            {<<"message">>, <<"rfc822">>, Headers, Parameters2, decode(NewHeaders, NewBody, Options)};
        {Type, SubType, Parameters} ->
            ?LOG_DEBUG("body is ~s/~s", [Type, SubType], ?LOGGER_META),
            Parameters2 = #{
                content_type_params => Parameters,
                disposition => Disposition,
                disposition_params => DispositionParams
            },
            {Type, SubType, Headers, Parameters2,
                decode_body(
                    get_header_value(<<"Content-Transfer-Encoding">>, Headers),
                    Body,
                    proplists:get_value(<<"charset">>, Parameters),
                    proplists:get_value(encoding, Options, none)
                )};
        % defaults
        undefined ->
            Type = <<"text">>,
            SubType = <<"plain">>,
            Parameters = #{
                content_type_params => [{<<"charset">>, <<"us-ascii">>}],
                disposition => Disposition,
                disposition_params => DispositionParams
            },
            {Type, SubType, Headers, Parameters,
                decode_body(get_header_value(<<"Content-Transfer-Encoding">>, Headers), Body)}
    end;
decode_component(_Headers, _Body, Other, _Options) ->
    erlang:error({mime_version, Other}).

-spec get_header_value(Needle :: binary(), Headers :: [{binary(), binary()}], Default :: any()) -> binary() | any().
%% @doc Do a case-insensitive header lookup to return that header's value, or the specified default.
get_header_value(Needle, Headers, Default) ->
    ?LOG_DEBUG("Headers: ~p", [Headers], ?LOGGER_META),
    NeedleLower = binstr:to_lower(Needle),
    F =
        fun({Header, _Value}) ->
            binstr:to_lower(Header) =:= NeedleLower
        end,
    case lists:search(F, Headers) of
        % TODO if there's duplicate headers, should we use the first or the last?
        {value, {_Header, Value}} ->
            Value;
        false ->
            Default
    end.

-spec get_header_value(Needle :: binary(), Headers :: [{binary(), binary()}]) -> binary() | 'undefined'.
%% @doc Do a case-insensitive header lookup to return the header's value, or `undefined'.
get_header_value(Needle, Headers) ->
    get_header_value(Needle, Headers, undefined).

-spec parse_with_comments
    (Value :: binary()) -> binary() | no_return();
    (Value :: atom()) -> atom().
parse_with_comments(Value) when is_binary(Value) ->
    parse_with_comments(Value, [], 0, false);
parse_with_comments(Value) ->
    Value.

-spec parse_with_comments(Value :: binary(), Acc :: list(), Depth :: non_neg_integer(), Quotes :: boolean()) ->
    binary() | no_return().
parse_with_comments(<<>>, _Acc, _Depth, Quotes) when Quotes ->
    erlang:error(unterminated_quotes);
parse_with_comments(<<>>, _Acc, Depth, _Quotes) when Depth > 0 ->
    erlang:error(unterminated_comment);
parse_with_comments(<<>>, Acc, _Depth, _Quotes) ->
    binstr:strip(list_to_binary(lists:reverse(Acc)));
parse_with_comments(<<$\\, H, Tail/binary>>, Acc, Depth, Quotes) when Depth > 0, H > 32, H < 127 ->
    parse_with_comments(Tail, Acc, Depth, Quotes);
parse_with_comments(<<$\\, Tail/binary>>, Acc, Depth, Quotes) when Depth > 0 ->
    parse_with_comments(Tail, Acc, Depth, Quotes);
parse_with_comments(<<$\\, H, Tail/binary>>, Acc, Depth, Quotes) when H > 32, H < 127 ->
    parse_with_comments(Tail, [H | Acc], Depth, Quotes);
parse_with_comments(<<$\\, Tail/binary>>, Acc, Depth, Quotes) ->
    parse_with_comments(Tail, [$\\ | Acc], Depth, Quotes);
parse_with_comments(<<$(, Tail/binary>>, Acc, Depth, Quotes) when not Quotes ->
    parse_with_comments(Tail, Acc, Depth + 1, Quotes);
parse_with_comments(<<$), Tail/binary>>, Acc, Depth, Quotes) when Depth > 0, not Quotes ->
    parse_with_comments(Tail, Acc, Depth - 1, Quotes);
parse_with_comments(<<_, Tail/binary>>, Acc, Depth, Quotes) when Depth > 0 ->
    parse_with_comments(Tail, Acc, Depth, Quotes);
%"
parse_with_comments(<<$", T/binary>>, Acc, Depth, true) ->
    parse_with_comments(T, Acc, Depth, false);
%"
parse_with_comments(<<$", T/binary>>, Acc, Depth, false) ->
    parse_with_comments(T, Acc, Depth, true);
parse_with_comments(<<H, Tail/binary>>, Acc, Depth, Quotes) ->
    parse_with_comments(Tail, [H | Acc], Depth, Quotes).

-spec parse_content_type
    (Value :: 'undefined') -> 'undefined';
    (Value :: binary()) -> {binary(), binary(), [{binary(), binary()}]}.
parse_content_type(undefined) ->
    undefined;
parse_content_type(String) ->
    try parse_content_disposition(String) of
        {RawType, Parameters} ->
            case binstr:strchr(RawType, $/) of
                Index when Index < 2 ->
                    throw(bad_content_type);
                Index ->
                    Type = binstr:substr(RawType, 1, Index - 1),
                    SubType = binstr:substr(RawType, Index + 1),
                    {binstr:to_lower(Type), binstr:to_lower(SubType), Parameters}
            end
    catch
        bad_disposition ->
            throw(bad_content_type)
    end.

-spec parse_content_disposition
    (Value :: 'undefined') -> 'undefined';
    (String :: binary()) -> {binary(), [{binary(), binary()}]}.
parse_content_disposition(undefined) ->
    undefined;
parse_content_disposition(String) ->
    [Disposition | Parameters] = binstr:split(parse_with_comments(String), <<";">>),
    F =
        fun(X) ->
            Y = binstr:strip(binstr:strip(X), both, $\t),
            case binstr:strchr(Y, $=) of
                Index when Index < 2 ->
                    throw(bad_disposition);
                Index ->
                    Key = binstr:substr(Y, 1, Index - 1),
                    Value = binstr:substr(Y, Index + 1),
                    {binstr:to_lower(Key), Value}
            end
        end,
    Params = lists:map(F, Parameters),
    {binstr:to_lower(Disposition), Params}.

split_body_by_boundary(Body, Boundary, MimeVsn, Options) ->
    % find the indices of the first and last boundary
    case {binstr:strpos(Body, Boundary), binstr:strpos(Body, list_to_binary([Boundary, "--"]))} of
        {0, _} ->
            erlang:error(missing_boundary);
        {_, 0} ->
            erlang:error(missing_last_boundary);
        {Start, End} ->
            NewBody = binstr:substr(Body, Start + byte_size(Boundary), End - Start),
            % from now on, we can be sure that each boundary is preceded by a CRLF
            Parts = split_body_by_boundary_(NewBody, list_to_binary(["\r\n", Boundary]), [], Options),
            [
                decode_component(Headers, Body2, MimeVsn, Options)
             || {Headers, Body2} <- [V || {_, Body3} = V <- Parts, byte_size(Body3) =/= 0]
            ]
    end.

split_body_by_boundary_(<<>>, _Boundary, Acc, _Options) ->
    lists:reverse(Acc);
split_body_by_boundary_(Body, Boundary, Acc, Options) ->
    % trim the incomplete first line
    TrimmedBody = binstr:substr(Body, binstr:strpos(Body, "\r\n") + 2),
    case binstr:strpos(TrimmedBody, Boundary) of
        0 ->
            lists:reverse([{[], TrimmedBody} | Acc]);
        Index ->
            {ParsedHdrs, BodyRest} = parse_headers(binstr:substr(TrimmedBody, 1, Index - 1)),
            DecodedHdrs = decode_headers(ParsedHdrs, [], proplists:get_value(encoding, Options, none)),
            split_body_by_boundary_(
                binstr:substr(TrimmedBody, Index + byte_size(Boundary)),
                Boundary,
                [{DecodedHdrs, BodyRest} | Acc],
                Options
            )
    end.

-spec parse_headers(Body :: binary()) -> {[{binary(), binary()}], binary()}.
%% @doc Parse the headers off of a message and return a list of headers and the trailing body.
parse_headers(Body) ->
    case binstr:strpos(Body, "\r\n") of
        0 ->
            {[], Body};
        1 ->
            {[], binstr:substr(Body, 3)};
        Index ->
            parse_headers(binstr:substr(Body, Index + 2), binstr:substr(Body, 1, Index - 1), [])
    end.

parse_headers(Body, <<H, Tail/binary>>, []) when H =:= $\s; H =:= $\t ->
    % folded headers
    {[], list_to_binary([H, Tail, "\r\n", Body])};
parse_headers(Body, <<H, T/binary>>, Headers) when H =:= $\s; H =:= $\t ->
    % folded headers
    [{FieldName, OldFieldValue} | OtherHeaders] = Headers,
    FieldValue = list_to_binary([OldFieldValue, T]),
    ?LOG_DEBUG("~p = ~p", [FieldName, FieldValue], ?LOGGER_META),
    case binstr:strpos(Body, "\r\n") of
        0 ->
            {lists:reverse([{FieldName, FieldValue} | OtherHeaders]), Body};
        1 ->
            {lists:reverse([{FieldName, FieldValue} | OtherHeaders]), binstr:substr(Body, 3)};
        Index2 ->
            parse_headers(binstr:substr(Body, Index2 + 2), binstr:substr(Body, 1, Index2 - 1), [
                {FieldName, FieldValue} | OtherHeaders
            ])
    end;
parse_headers(Body, Line, Headers) ->
    ?LOG_DEBUG("line: ~p", [Line], ?LOGGER_META),
    case binstr:strchr(Line, $:) of
        0 ->
            {lists:reverse(Headers), list_to_binary([Line, "\r\n", Body])};
        Index ->
            FieldName = binstr:substr(Line, 1, Index - 1),
            F = fun(X) -> X > 32 andalso X < 127 end,
            case binstr:all(F, FieldName) of
                true ->
                    F2 = fun(X) -> (X > 31 andalso X < 127) orelse X == 9 end,
                    FValue = binstr:strip(binstr:substr(Line, Index + 1)),
                    FieldValue =
                        case binstr:all(F2, FValue) of
                            true ->
                                FValue;
                            _ ->
                                % I couldn't figure out how to use a pure binary comprehension here :(
                                list_to_binary([filter_non_ascii(C) || <<C:8>> <= FValue])
                        end,
                    case binstr:strpos(Body, "\r\n") of
                        0 ->
                            {lists:reverse([{FieldName, FieldValue} | Headers]), Body};
                        1 ->
                            {lists:reverse([{FieldName, FieldValue} | Headers]), binstr:substr(Body, 3)};
                        Index2 ->
                            parse_headers(binstr:substr(Body, Index2 + 2), binstr:substr(Body, 1, Index2 - 1), [
                                {FieldName, FieldValue} | Headers
                            ])
                    end;
                false ->
                    {lists:reverse(Headers), list_to_binary([Line, "\r\n", Body])}
            end
    end.

filter_non_ascii(C) when (C > 31 andalso C < 127); C == 9 ->
    <<C>>;
filter_non_ascii(_C) ->
    <<"?">>.

decode_body(Type, Body, _InEncoding, none) ->
    decode_body(Type, <<<<X/integer>> || <<X>> <= Body, X < 128>>);
decode_body(Type, Body, undefined, _OutEncoding) ->
    decode_body(Type, <<<<X/integer>> || <<X>> <= Body, X < 128>>);
decode_body(Type, Body, <<"x-binaryenc">>, _OutEncoding) ->
    % Not IANA and does not represent text, so we pass it through
    decode_body(Type, Body);
decode_body(Type, Body, InEncoding, OutEncoding) ->
    NewBody = decode_body(Type, Body),
    InEncodingFixed = fix_encoding(InEncoding),
    {ok, ConvertedBody} = convert(OutEncoding, InEncodingFixed, NewBody),
    ConvertedBody.

-spec decode_body(Type :: binary() | 'undefined', Body :: binary()) -> binary().
decode_body(undefined, Body) ->
    Body;
decode_body(Type, Body) ->
    case binstr:to_lower(Type) of
        <<"quoted-printable">> ->
            decode_quoted_printable(Body);
        <<"base64">> ->
            decode_base64(Body);
        _Other ->
            Body
    end.

decode_base64(Body) ->
    base64:mime_decode(Body).

decode_quoted_printable(Body) ->
    decode_quoted_printable(Body, false, <<>>, <<>>).

%% End of Body
decode_quoted_printable(<<>>, _HasSoftEOL, _WSPs, Acc) ->
    Acc;
%% CRLF after Soft Linebreak
decode_quoted_printable(<<$\r, $\n, More/binary>>, true, _WSPs, Acc) ->
    decode_quoted_printable(More, false, <<>>, Acc);
%% Space or Tab after Soft Linebreak
decode_quoted_printable(<<C, More/binary>>, true, _WSPs, Acc) when C =:= $\s; C =:= $\t ->
    decode_quoted_printable(More, true, <<>>, Acc);
%% Other character after Soft Linebreak
decode_quoted_printable(_Body, true, _WSPs, _Acc) ->
    throw(badchar);
%% CRLF
decode_quoted_printable(<<$\r, $\n, More/binary>>, false, _WSPs, Acc) ->
    decode_quoted_printable(More, false, <<>>, <<Acc/binary, $\r, $\n>>);
%% Space or Tab
decode_quoted_printable(<<C, More/binary>>, false, WSPs, Acc) when C =:= $\s; C =:= $\t ->
    decode_quoted_printable(More, false, <<WSPs/binary, C>>, Acc);
%% Encoded char
decode_quoted_printable(<<$=, C1, C2, More/binary>>, false, WSPs, Acc) when
    C1 >= $0 andalso C1 =< $9 orelse C1 >= $A andalso C1 =< $F orelse C1 >= $a andalso C1 =< $f,
    C2 >= $0 andalso C2 =< $9 orelse C2 >= $A andalso C2 =< $F orelse C2 >= $a andalso C2 =< $f
->
    decode_quoted_printable(More, false, <<>>, <<Acc/binary, WSPs/binary, (unhex(C1)):4, (unhex(C2)):4>>);
%% Soft Linebreak
decode_quoted_printable(<<$=, More/binary>>, false, WSPs, Acc) ->
    decode_quoted_printable(More, true, <<>>, <<Acc/binary, WSPs/binary>>);
%% Plain character
decode_quoted_printable(<<C, More/binary>>, false, WSPs, Acc) ->
    decode_quoted_printable(More, false, <<>>, <<Acc/binary, WSPs/binary, C>>).

check_headers(Headers) ->
    Checked = [<<"MIME-Version">>, <<"Date">>, <<"From">>, <<"Message-ID">>, <<"References">>, <<"Subject">>],
    check_headers(Checked, lists:reverse(Headers)).

check_headers([], Headers) ->
    lists:reverse(Headers);
check_headers([Header | Tail], Headers) ->
    case get_header_value(Header, Headers) of
        undefined when Header == <<"MIME-Version">> ->
            check_headers(Tail, [{<<"MIME-Version">>, <<"1.0">>} | Headers]);
        undefined when Header == <<"Date">> ->
            check_headers(Tail, [{<<"Date">>, list_to_binary(smtp_util:rfc5322_timestamp())} | Headers]);
        undefined when Header == <<"From">> ->
            erlang:error(missing_from);
        undefined when Header == <<"Message-ID">> ->
            check_headers(Tail, [{<<"Message-ID">>, list_to_binary(smtp_util:generate_message_id())} | Headers]);
        undefined when Header == <<"References">> ->
            case get_header_value(<<"In-Reply-To">>, Headers) of
                undefined ->
                    % ok, whatever
                    check_headers(Tail, Headers);
                ReplyID ->
                    check_headers(Tail, [{<<"References">>, ReplyID} | Headers])
            end;
        References when Header == <<"References">> ->
            % check if the in-reply-to header, if present, is in references
            case get_header_value(<<"In-Reply-To">>, Headers) of
                undefined ->
                    % ok, whatever
                    check_headers(Tail, Headers);
                ReplyID ->
                    case binstr:strpos(binstr:to_lower(References), binstr:to_lower(ReplyID)) of
                        0 ->
                            % okay, tack on the reply-to to the end of References
                            check_headers(Tail, [
                                {<<"References">>, list_to_binary([References, " ", ReplyID])}
                                | proplists:delete(<<"References">>, Headers)
                            ]);
                        _Index ->
                            % nothing to do
                            check_headers(Tail, Headers)
                    end
            end;
        _ ->
            check_headers(Tail, Headers)
    end.

ensure_content_headers(Type, SubType, Parameters, Headers, Body, Toplevel) ->
    CheckHeaders = [<<"Content-Type">>, <<"Content-Disposition">>, <<"Content-Transfer-Encoding">>],
    CheckHeadersValues = [{Name, get_header_value(Name, Headers)} || Name <- CheckHeaders],
    ensure_content_headers(CheckHeadersValues, Type, SubType, Parameters, lists:reverse(Headers), Body, Toplevel).

ensure_content_headers([], _, _, Parameters, Headers, _, _) ->
    {Parameters, lists:reverse(Headers)};
ensure_content_headers(
    [{<<"Content-Type">>, undefined} | Tail], Type, SubType, Parameters, Headers, Body, Toplevel
) when
    (Type == <<"text">> andalso SubType =/= <<"plain">>) orelse Type =/= <<"text">>
->
    %% no content-type header, and its not text/plain
    CT = io_lib:format("~s/~s", [Type, SubType]),
    CTP =
        case Type of
            <<"multipart">> ->
                Boundary =
                    case proplists:get_value(<<"boundary">>, maps:get(content_type_params, Parameters, [])) of
                        undefined ->
                            list_to_binary(smtp_util:generate_message_boundary());
                        B ->
                            B
                    end,
                [
                    {<<"boundary">>, Boundary}
                    | proplists:delete(<<"boundary">>, maps:get(content_type_params, Parameters, []))
                ];
            <<"text">> ->
                Charset =
                    case proplists:get_value(<<"charset">>, maps:get(content_type_params, Parameters, [])) of
                        undefined ->
                            guess_charset(Body);
                        C ->
                            C
                    end,
                [
                    {<<"charset">>, Charset}
                    | proplists:delete(<<"charset">>, maps:get(content_type_params, Parameters, []))
                ];
            _ ->
                maps:get(content_type_params, Parameters, [])
        end,

    %%CTP = proplists:get_value(<<"content-type-params">>, Parameters, [guess_charset(Body)]),
    CTH = binstr:join([CT | encode_parameters(CTP)], ";"),
    NewParameters = Parameters#{content_type_params => CTP},
    ensure_content_headers(Tail, Type, SubType, NewParameters, [{<<"Content-Type">>, CTH} | Headers], Body, Toplevel);
ensure_content_headers(
    [{<<"Content-Type">>, undefined} | Tail],
    <<"text">> = Type,
    <<"plain">> = SubType,
    Parameters,
    Headers,
    Body,
    Toplevel
) ->
    %% no content-type header and its text/plain
    Charset =
        case proplists:get_value(<<"charset">>, maps:get(content_type_params, Parameters, [])) of
            undefined ->
                guess_charset(Body);
            C ->
                binstr:to_lower(C)
        end,
    case Charset of
        <<"us-ascii">> ->
            % the default
            ensure_content_headers(Tail, Type, SubType, Parameters, Headers, Body, Toplevel);
        _ ->
            CTP = [
                {<<"charset">>, Charset}
                | proplists:delete(<<"charset">>, maps:get(content_type_params, Parameters, []))
            ],
            CTH = binstr:join([<<"text/plain">> | encode_parameters(CTP)], ";"),
            NewParameters = Parameters#{content_type_params => CTP},
            ensure_content_headers(
                Tail, Type, SubType, NewParameters, [{<<"Content-Type">>, CTH} | Headers], Body, Toplevel
            )
    end;
ensure_content_headers(
    [{<<"Content-Transfer-Encoding">>, undefined} | Tail], Type, SubType, Parameters, Headers, Body, Toplevel
) when
    Type =/= <<"multipart">>
->
    Enc =
        case maps:get(transfer_encoding, Parameters, undefined) of
            undefined ->
                guess_best_encoding(Body);
            Value ->
                Value
        end,
    case Enc of
        <<"7bit">> ->
            ensure_content_headers(Tail, Type, SubType, Parameters, Headers, Body, Toplevel);
        _ ->
            ensure_content_headers(
                Tail, Type, SubType, Parameters, [{<<"Content-Transfer-Encoding">>, Enc} | Headers], Body, Toplevel
            )
    end;
ensure_content_headers(
    [{<<"Content-Disposition">>, undefined} | Tail], Type, SubType, Parameters, Headers, Body, false = Toplevel
) ->
    CD = maps:get(disposition, Parameters, <<"inline">>),
    CDP = maps:get(disposition_params, Parameters, []),
    CDH = binstr:join([CD | encode_parameters(CDP)], ";"),
    ensure_content_headers(
        Tail, Type, SubType, Parameters, [{<<"Content-Disposition">>, CDH} | Headers], Body, Toplevel
    );
ensure_content_headers([_ | Tail], Type, SubType, Parameters, Headers, Body, Toplevel) ->
    ensure_content_headers(Tail, Type, SubType, Parameters, Headers, Body, Toplevel).

guess_charset(Body) ->
    case binstr:all(fun(X) -> X < 128 end, Body) of
        true -> <<"us-ascii">>;
        false -> <<"utf-8">>
    end.

guess_best_encoding(Body) ->
    case valid_7bit(Body) of
        true ->
            <<"7bit">>;
        false ->
            choose_transformation(Body)
    end.

choose_transformation(<<Chunk:200/binary, _, _/binary>>) ->
    %% Optimization - only analyze 1st 200 bytes
    choose_transformation(Chunk);
choose_transformation(Body) ->
    {Readable, Encoded} = partition_count_bytes(
        fun(C) ->
            C >= 16#20 andalso C =< 16#7E orelse C =:= $\r orelse C =:= $\n
        end,
        Body
    ),

    %based on the % of printable characters, choose an encoding
    if
        % same as 100 * Readable / (Readable + Encoded) >= 80, but avoiding division
        Readable >= 4 * Encoded ->
            %% >80% printable characters
            <<"quoted-printable">>;
        true ->
            %% =<80% printable characters
            <<"base64">>
    end.

%% https://tools.ietf.org/html/rfc2045#section-2.7:
%% * ASCII codes from 1 to 127
%% * \r and \n are only allowed as `\r\n' pair, but not standalone (bare)
%% * No lines over 998 chars
%%
%% Unfortunately, any string that ends with `\n` matches the regexp, so, we need some pre-checks
valid_7bit(<<"\n">>) ->
    false;
valid_7bit(<<"\r">>) ->
    false;
valid_7bit(<<>>) ->
    true;
valid_7bit(<<_>>) ->
    true;
valid_7bit(Body) ->
    Size = byte_size(Body),
    case binary:at(Body, Size - 1) =:= $\n andalso binary:at(Body, Size - 2) =/= $\r of
        true ->
            %% last element is \n, but the one before the last is not \r
            false;
        false ->
            %% So: (all except `\r` and `\n` in 1-127 range) OR (`\r\n`)
            case re:run(Body, "^([\x01-\x09\x0b-\x0c\x0e-\x7f]|(\r\n))*$", [{capture, none}]) of
                match -> not has_lines_over_998(Body);
                nomatch -> false
            end
    end.

%% @doc If `Body' has at least one line (ending with `\r\n') that is longer than 998 chars
has_lines_over_998(Body) ->
    Pattern = binary:compile_pattern(<<"\r\n">>),
    has_lines_over_998(Body, binary:match(Body, Pattern), 0, Pattern).

has_lines_over_998(Bin, nomatch, Offset, _) ->
    %% Last line is over 998?
    (byte_size(Bin) - Offset) >= 998;
has_lines_over_998(_Bin, {FoundAt, 2}, Offset, _Patern) when (FoundAt - Offset) >= 998 ->
    true;
has_lines_over_998(Bin, {FoundAt, 2}, _, Pattern) ->
    NewOffset = FoundAt + 2,
    Len = byte_size(Bin) - NewOffset,
    has_lines_over_998(
        Bin, binary:match(Bin, Pattern, [{scope, {NewOffset, Len}}]), NewOffset, Pattern
    ).

encode_parameters([[]]) ->
    [];
encode_parameters(Parameters) ->
    [encode_parameter(Parameter) || Parameter <- Parameters].

encode_parameter({X, Y}) ->
    YEnc = rfc2047_utf8_encode(Y, byte_size(X) + 3, <<"\t">>),
    case escape_tspecial(YEnc, false, <<>>) of
        {true, Special} -> [X, $=, $", Special, $"];
        false -> [X, $=, YEnc]
    end.

% See also: http://www.ietf.org/rfc/rfc2045.txt section 5.1
escape_tspecial(<<>>, false, _Acc) ->
    false;
escape_tspecial(<<>>, IsSpecial, Acc) ->
    {IsSpecial, Acc};
escape_tspecial(<<C, Rest/binary>>, _IsSpecial, Acc) when C =:= $" ->
    escape_tspecial(Rest, true, <<Acc/binary, $\\, $">>);
escape_tspecial(<<C, Rest/binary>>, _IsSpecial, Acc) when C =:= $\\ ->
    escape_tspecial(Rest, true, <<Acc/binary, $\\, $\\>>);
escape_tspecial(<<C, Rest/binary>>, _IsSpecial, Acc) when
    C =:= $(;
    C =:= $);
    C =:= $<;
    C =:= $>;
    C =:= $@;
    C =:= $,;
    C =:= $;;
    C =:= $:;
    C =:= $/;
    C =:= $[;
    C =:= $];
    C =:= $?;
    C =:= $=;
    C =:= $\s
->
    escape_tspecial(Rest, true, <<Acc/binary, C>>);
escape_tspecial(<<C, Rest/binary>>, IsSpecial, Acc) ->
    escape_tspecial(Rest, IsSpecial, <<Acc/binary, C>>).

encode_headers([]) ->
    [];
encode_headers([{Key, Value} | T] = _Headers) ->
    EncodedHeader = maybe_encode_folded_header(Key, list_to_binary([Key, ": ", encode_header_value(Key, Value)])),
    [EncodedHeader | encode_headers(T)].

maybe_encode_folded_header(H, Hdr) when
    H =:= <<"To">>;
    H =:= <<"Cc">>;
    H =:= <<"Bcc">>;
    H =:= <<"Reply-To">>;
    H =:= <<"From">>
->
    Hdr;
maybe_encode_folded_header(_H, Hdr) ->
    encode_folded_header(Hdr, <<>>).

encode_folded_header(Rest, Acc) ->
    case binstr:split(Rest, <<$;>>, 2) of
        [_] ->
            <<Acc/binary, Rest/binary>>;
        [Before, After] ->
            NewPart =
                case After of
                    <<$\t, _Rest/binary>> ->
                        <<Before/binary, ";\r\n">>;
                    _ ->
                        <<Before/binary, ";\r\n\t">>
                end,
            encode_folded_header(After, <<Acc/binary, NewPart/binary>>)
    end.

encode_header_value(H, Value) when
    H =:= <<"To">>;
    H =:= <<"Cc">>;
    H =:= <<"Bcc">>;
    H =:= <<"Reply-To">>;
    H =:= <<"From">>
->
    {ok, Addresses} = smtp_util:parse_rfc5322_addresses(Value),
    {Names, Emails} = lists:unzip(Addresses),
    NewNames = lists:map(
        fun
            (undefined) ->
                undefined;
            (Name) ->
                %% `Name' contains codepoints, but we need bytes
                rfc2047_utf8_encode(unicode:characters_to_binary(Name))
        end,
        Names
    ),
    smtp_util:combine_rfc822_addresses(lists:zip(NewNames, Emails));
encode_header_value(H, Value) when H =:= <<"Content-Type">>; H =:= <<"Content-Disposition">> ->
    % Parameters are already encoded.
    Value;
encode_header_value(_, Value) ->
    rfc2047_utf8_encode(Value).

encode_component(_Type, _SubType, _Headers, Params, Body) when is_list(Body) ->
    % is this a multipart component?
    Boundary = proplists:get_value(<<"boundary">>, maps:get(content_type_params, Params)),
    % blank line before start of component
    [<<>>] ++
        lists:flatmap(
            fun(Part) ->
                % start with the boundary
                [list_to_binary([<<"--">>, Boundary])] ++
                    encode_component_part(Part)
            end,
            Body
            % final boundary (with /--$/)
        ) ++ [list_to_binary([<<"--">>, Boundary, <<"--">>])] ++
        % blank line at the end of the multipart component
        [<<>>];
encode_component(_Type, _SubType, Headers, _Params, Body) ->
    % or an inline component?
    %encode_component_part({Type, SubType, Headers, Params, Body})
    encode_body(
        get_header_value(<<"Content-Transfer-Encoding">>, Headers),
        [Body]
    ).

encode_component_part({<<"multipart">>, SubType, Headers, PartParams, Body}) ->
    {FixedParams, FixedHeaders} = ensure_content_headers(<<"multipart">>, SubType, PartParams, Headers, Body, false),
    encode_headers(FixedHeaders) ++
        encode_component(<<"multipart">>, SubType, FixedHeaders, FixedParams, Body);
encode_component_part({Type, SubType, Headers, PartParams, Body}) ->
    PartData =
        case Body of
            {_, _, _, _, _} -> encode_component_part(Body);
            String -> [String]
        end,
    {_FixedParams, FixedHeaders} = ensure_content_headers(Type, SubType, PartParams, Headers, Body, false),
    encode_headers(FixedHeaders) ++ [<<>>] ++
        encode_body(
            get_header_value(<<"Content-Transfer-Encoding">>, FixedHeaders),
            PartData
        );
encode_component_part(Part) ->
    ?LOG_DEBUG("encode_component_part couldn't match Part to: ~p", [Part], ?LOGGER_META),
    [].

encode_body(undefined, Body) ->
    Body;
encode_body(Type, Body) ->
    case binstr:to_lower(Type) of
        <<"quoted-printable">> ->
            [InnerBody] = Body,
            encode_quoted_printable(InnerBody);
        <<"base64">> ->
            [InnerBody] = Body,
            wrap_to_76(base64:encode(InnerBody));
        _ ->
            Body
    end.

wrap_to_76(String) ->
    [wrap_to_76(String, [])].

wrap_to_76(<<>>, Acc) ->
    list_to_binary(lists:reverse(Acc));
wrap_to_76(<<Head:76/binary, Tail/binary>>, Acc) ->
    wrap_to_76(Tail, [<<"\r\n">>, Head | Acc]);
wrap_to_76(Head, Acc) ->
    list_to_binary(lists:reverse([<<"\r\n">>, Head | Acc])).

encode_quoted_printable(Body) ->
    [encode_quoted_printable(Body, <<>>, 0, false, <<>>, 0)].

% End of body (this should only happen if the body was empty to begin with)
encode_quoted_printable(<<>>, Acc, _LineLen, _HasWSP, WordAcc, _WordLen) ->
    <<Acc/binary, WordAcc/binary>>;
% CRLF
encode_quoted_printable(<<$\r, $\n, More/binary>>, Acc, _LineLen, _HasWSP, WordAcc, _WordLen) ->
    encode_quoted_printable(More, <<Acc/binary, WordAcc/binary, $\r, $\n>>, 0, false, <<>>, 0);
% WSP in last position
encode_quoted_printable(<<C>>, Acc, LineLen, _HasWSP, WordAcc, WordLen) when C =:= $\s; C =:= $\t ->
    Enc = encode_quoted_printable_char(C, true),
    case LineLen + WordLen + 3 > 76 of
        true ->
            % line would become too long -> soft-break before WSP
            <<Acc/binary, WordAcc/binary, $=, $\r, $\n, Enc/binary>>;
        false ->
            % character fits on current line
            <<Acc/binary, WordAcc/binary, Enc/binary>>
    end;
% WSP before CRLF
encode_quoted_printable(<<C, $\r, $\n, More/binary>>, Acc, LineLen, _HasWSP, WordAcc, WordLen) when
    C =:= $\s; C =:= $\t
->
    Enc = encode_quoted_printable_char(C, true),
    case LineLen + WordLen + 3 > 76 of
        true ->
            % line would become too long -> soft-break before WSP
            encode_quoted_printable(
                More, <<Acc/binary, WordAcc/binary, $=, $\r, $\n, Enc/binary, $\r, $\n>>, 0, false, <<>>, 0
            );
        false ->
            % character fits on current line
            encode_quoted_printable(More, <<Acc/binary, WordAcc/binary, Enc/binary, $\r, $\n>>, 0, false, <<>>, 0)
    end;
% Character elsewhere
encode_quoted_printable(<<C, More/binary>>, Acc, LineLen, HasWSP, WordAcc, WordLen) ->
    Enc = encode_quoted_printable_char(C, false),
    EncLen = byte_size(Enc),
    % mind the 75 here, we need the 76th place for the soft linebreak
    case LineLen + WordLen + EncLen > 75 of
        true when C =:= $\s; C =:= $\t ->
            % line would become too long, current char is WSP -> soft-break here (remember we have a WSP)
            encode_quoted_printable(
                More, <<Acc/binary, WordAcc/binary, $=, $\r, $\n, Enc/binary>>, EncLen, true, <<>>, 0
            );
        true when HasWSP, WordLen + EncLen =< 75 ->
            % line would become too long, we have an earlier WSP and word plus encoded character will fit on a new line -> soft-break at earlier WSP
            encode_quoted_printable(
                More, <<Acc/binary, $=, $\r, $\n, WordAcc/binary, Enc/binary>>, WordLen + EncLen, false, <<>>, 0
            );
        true ->
            % line would become too long, we have no earlier WSP or word plus encoded character will not fit on a new line -> soft break here
            encode_quoted_printable(
                More, <<Acc/binary, WordAcc/binary, $=, $\r, $\n, Enc/binary>>, EncLen, false, <<>>, 0
            );
        false when C =:= $\s; C =:= $\t ->
            % WSP character fits on line -> move word and WSP to Acc (remember we have a WSP)
            encode_quoted_printable(
                More, <<Acc/binary, WordAcc/binary, Enc/binary>>, LineLen + WordLen + EncLen, true, <<>>, 0
            );
        false ->
            % non-WSP character fits on line -> add character to word
            encode_quoted_printable(More, Acc, LineLen, HasWSP, <<WordAcc/binary, Enc/binary>>, WordLen + EncLen)
    end.

encode_quoted_printable_char(C, true) ->
    <<$=, (hex(C div 16#10)), (hex(C rem 16#10))>>;
encode_quoted_printable_char($\s, false) ->
    <<$\s>>;
encode_quoted_printable_char($\t, false) ->
    <<$\t>>;
encode_quoted_printable_char($=, _Force) ->
    <<$=, $3, $D>>;
encode_quoted_printable_char(C, _Force) when C =< 16#20; C >= 16#7F ->
    encode_quoted_printable_char(C, true);
encode_quoted_printable_char(C, false) ->
    <<C>>.

get_default_encoding() ->
    <<"utf-8//IGNORE">>.

% convert some common invalid character names into the correct ones
fix_encoding(Encoding) when Encoding == <<"utf8">>; Encoding == <<"UTF8">> ->
    <<"UTF-8">>;
fix_encoding(Encoding) ->
    Encoding.

% Characters allowed to appear unencoded (RFC 2047 Sections 4.2 and 5):
%   * lowercase ASCII letters
%   * uppercase ASCII letters
%   * decimal digits
%   * "!"
%   * "*"
%   * "+"
%   * "-"
%   * "/"
% SPACE is not really an allowed letter, but since it encodes to "_"
% and thereby a single byte, we list it as allowed here
-define(is_rfc2047_q_allowed(C),
    (C =:= $\s orelse (C >= $a andalso C =< $z) orelse (C >= $A andalso C =< $Z) orelse
        (C >= $0 andalso C =< $9) orelse C =:= $! orelse C =:= $* orelse C =:= $+ orelse
        C =:= $- orelse C =:= $/)
).

%% @doc Encode a binary or list according to RFC 2047. Input is
%% assumed to be in UTF-8 encoding bytes; not codepoints.
rfc2047_utf8_encode(Value) ->
    rfc2047_utf8_encode(Value, 0, <<" ">>).

rfc2047_utf8_encode(Value, PrefixLen, LineIndent) when is_binary(Value) ->
    case is_ascii_printable(Value) of
        true ->
            % don't encode if all characters are printable ASCII
            Value;
        false ->
            {Readable, Encoded} = partition_count_bytes(fun(C) -> ?is_rfc2047_q_allowed(C) end, Value),
            Enc =
                if
                    Readable >= Encoded ->
                        % most characters would be readable in Q-Encoding,
                        % so we use it
                        q;
                    true ->
                        % most characters would have to be encoded in Q-Encoding,
                        % so we use B-Encoding instead
                        b
                end,
            rfc2047_utf8_encode(Enc, Value, <<>>, PrefixLen, LineIndent)
    end;
rfc2047_utf8_encode(Value, PrefixLen, LineIndent) ->
    rfc2047_utf8_encode(list_to_binary(Value), PrefixLen, LineIndent).

rfc2047_utf8_encode(_Enc, <<>>, Acc, _PrefixLen, _LineIndent) ->
    Acc;
rfc2047_utf8_encode(b, More, Acc, PrefixLen, LineIndent) ->
    % B-Encoding
    % An encoded word must not be longer than 75 bytes,
    % including the leading "=?", charset name, "?B?" and
    % the trailing "?=". Since the charset name is fixed to
    % "UTF-8", 63 remain for encoded text. Using Base64,
    % a maximum of 45 raw bytes can be encoded in 63 bytes.
    rfc2047_utf8_encode(b, More, Acc, <<>>, byte_size(LineIndent), LineIndent, 46 - PrefixLen);
rfc2047_utf8_encode(q, More, Acc, PrefixLen, LineIndent) ->
    % Q-Encoding
    % An encoded word must not be longer than 75 bytes,
    % including the leading "=?", charset name, "=?UTF-8?Q?" and
    % the trailing "?=". Since the charset name is fixed to
    % "UTF-8", 63 remain for encoded text. Using Quoted-Printable,
    % between 21 and 63 raw bytes can be encoded in 63 bytes.
    rfc2047_utf8_encode(q, More, Acc, <<>>, byte_size(LineIndent), LineIndent, 63 - PrefixLen).

rfc2047_utf8_encode(Enc, <<>>, Acc, WordAcc, _PrefixLen, LineIndent, _Left) ->
    rfc2047_append_word(Acc, WordAcc, Enc, LineIndent);
rfc2047_utf8_encode(Enc, All = <<C/utf8, More/binary>>, Acc, WordAcc, PrefixLen, LineIndent, Left) ->
    % convert codepoint back to UTF-8 encoded bytes
    Bytes = <<C/utf8>>,
    Size = byte_size(Bytes),
    Reqd =
        case Enc of
            q when not ?is_rfc2047_q_allowed(C) ->
                3 * Size;
            q ->
                Size;
            b ->
                Size
        end,
    case Left >= Reqd of
        true ->
            rfc2047_utf8_encode(Enc, More, Acc, <<WordAcc/binary, Bytes/binary>>, PrefixLen, LineIndent, Left - Reqd);
        false ->
            rfc2047_utf8_encode(Enc, All, rfc2047_append_word(Acc, WordAcc, Enc, LineIndent), PrefixLen, LineIndent)
    end.

rfc2047_append_word(Acc, <<>>, _Enc, _LineIndent) ->
    % empty word
    Acc;
rfc2047_append_word(<<>>, Word, Enc, _LineIndent) ->
    % first word in Acc
    rfc2047_encode_word(Word, Enc);
rfc2047_append_word(Acc, Word, Enc, LineIndent) ->
    % subsequent word in Acc
    <<Acc/binary, $\r, $\n, LineIndent/binary, (rfc2047_encode_word(Word, Enc))/binary>>.

rfc2047_encode_word(Word, q) ->
    <<"=?UTF-8?Q?", (rfc2047_q_encode(Word))/binary, "?=">>;
rfc2047_encode_word(Word, b) ->
    <<"=?UTF-8?B?", (base64:encode(Word))/binary, "?=">>.

rfc2047_q_encode(<<>>) ->
    <<>>;
rfc2047_q_encode(<<$\s, More/binary>>) ->
    % SPACE -> _
    <<$_, (rfc2047_q_encode(More))/binary>>;
rfc2047_q_encode(<<C, More/binary>>) when ?is_rfc2047_q_allowed(C) ->
    % character which needs no encoding
    <<C, (rfc2047_q_encode(More))/binary>>;
rfc2047_q_encode(<<N1:4, N2:4, More/binary>>) ->
    % characters which need encoding -> =XY
    <<$=, (hex(N1)), (hex(N2)), (rfc2047_q_encode(More))/binary>>.

is_ascii_printable(<<>>) ->
    'true';
is_ascii_printable(<<H, T/binary>>) when H >= 32 andalso H =< 126 ->
    is_ascii_printable(T);
is_ascii_printable(_) ->
    'false'.

hex(N) when N >= 10 -> N + $A - 10;
hex(N) -> N + $0.

unhex(C) when C >= $a -> C - $a + 10;
unhex(C) when C >= $A -> C - $A + 10;
unhex(C) -> C - $0.

partition_count_bytes(Fun, Bin) ->
    partition_count_bytes(Fun, Bin, {0, 0}).

partition_count_bytes(_Fun, <<>>, PartitionCounts) ->
    PartitionCounts;
partition_count_bytes(Fun, <<C, More/binary>>, {Trues, Falses}) ->
    NewPartitionCounts =
        case Fun(C) of
            true -> {Trues + 1, Falses};
            false -> {Trues, Falses + 1}
        end,
    partition_count_bytes(Fun, More, NewPartitionCounts).

%% @doc DKIM sign an email
%% DKIM sign functions
%% RFC 6376
%% `h' - list of headers to sign (lowercased binary)
%% `c' - {Headers, Body} canonicalization type. Only {simple, simple} and
%% {relaxed, simple} supported for now.
%% be located in "foo.bar._domainkey.example.com" (see RFC-6376 #3.6.2.1).
%% `t' - signature timestamp: 'now' or UTC {Date, Time}
%% `x' - signature expiration time: UTC {Date, Time}
%% `a` - signing algorithm (default: `rsa-sha256`):
%% `private_key' - private key, to sign emails. May be of 2 types: encrypted and
%% plain in PEM format:
%% RSA
%% `{pem_plain, KeyBinary}' - generated by <code>openssl genrsa -out out-file.pem 1024</code>
%% `{pem_encrypted, KeyBinary, Password}' - generated by, eg
%%  <code>openssl genrsa -des3 -out out-file.pem 1024</code>
%% RFC8463
%% Ed25519 - Erlang/OTP 24.1+ only!
%% `{pem_plain, KeyBinary}' - generated by <code>openssl genpkey -algorithm ed25519 -out out-file.pem</code>
%% `{pem_encrypted, KeyBinary, Password}' - generated by, eg
%%  <code>openssl genpkey -des3 -algorithm ed25519 -out out-file.pem</code>
%%  3rd paramerter is password to decrypt the key.
-spec dkim_sign_email([binary()], binary(), dkim_options()) -> [binary()].
dkim_sign_email(Headers, Body, Opts) ->
    HeadersToSign = proplists:get_value(h, Opts, [<<"from">>, <<"to">>, <<"subject">>, <<"date">>]),
    SDID = proplists:get_value(d, Opts),
    Selector = proplists:get_value(s, Opts),
    %% BodyLength = proplists:get_value(l, Opts),
    OptionalTags = lists:foldl(
        fun(Key, Acc) ->
            case proplists:get_value(Key, Opts) of
                undefined -> Acc;
                Value -> [{Key, Value} | Acc]
            end
        end,
        [],
        [t, x]
    ),
    {HdrsCanT, BodyCanT} = Can = proplists:get_value(c, Opts, {relaxed, simple}),
    Algorithm = proplists:get_value(a, Opts, 'rsa-sha256'),
    PrivateKey = proplists:get_value(private_key, Opts),

    %% hash body
    CanBody = dkim_canonicalize_body(Body, BodyCanT),
    BodyHash = dkim_hash_body(CanBody),
    %% {b, <<>>},
    Tags = [
        {v, 1},
        {a, Algorithm},
        {bh, BodyHash},
        {c, Can},
        {d, SDID},
        {h, HeadersToSign},
        {s, Selector}
        | OptionalTags
    ],
    %% hash headers
    Headers1 = dkim_filter_headers(Headers, HeadersToSign),
    CanHeaders = dkim_canonicalize_headers(Headers1, HdrsCanT),
    [DkimHeaderNoB] = dkim_canonicalize_headers([dkim_make_header([{b, undefined} | Tags])], HdrsCanT),
    DataHash = dkim_hash_data(CanHeaders, DkimHeaderNoB),
    %% sign
    Signature = dkim_sign(DataHash, Algorithm, PrivateKey),
    DkimHeader = dkim_make_header([{b, Signature} | Tags]),
    [DkimHeader | Headers].

dkim_filter_headers(Headers, HeadersToSign) ->
    KeyedHeaders = [
        begin
            [Name, _] = binary:split(Hdr, <<":">>),
            {binstr:strip(binstr:to_lower(Name)), Hdr}
        end
     || Hdr <- Headers
    ],
    WithUndef = [get_header_value(binstr:to_lower(Name), KeyedHeaders) || Name <- HeadersToSign],
    [Hdr || Hdr <- WithUndef, Hdr =/= undefined].

dkim_canonicalize_headers(Headers, simple) ->
    Headers;
dkim_canonicalize_headers(Headers, relaxed) ->
    dkim_canonic_hdrs_relaxed(Headers).

dkim_canonic_hdrs_relaxed([Hdr | Rest]) ->
    [Name, Value] = binary:split(Hdr, <<":">>),
    LowStripName = binstr:to_lower(binstr:strip(Name)),

    UnfoldedHdrValue = binary:replace(Value, <<"\r\n">>, <<>>, [global]),
    SingleWSValue = re:replace(UnfoldedHdrValue, "[\t ]+", " ", [global, {return, binary}]),
    StrippedWithName = <<LowStripName/binary, ":", (binstr:strip(SingleWSValue))/binary>>,
    [StrippedWithName | dkim_canonic_hdrs_relaxed(Rest)];
dkim_canonic_hdrs_relaxed([]) ->
    [].

dkim_canonicalize_body(<<>>, simple) ->
    <<"\r\n">>;
dkim_canonicalize_body(Body, simple) ->
    re:replace(Body, "(\r\n)*$", "\r\n", [{return, binary}]);
dkim_canonicalize_body(_Body, relaxed) ->
    throw({not_supported, dkim_body_relaxed}).

dkim_hash_body(CanonicBody) ->
    crypto:hash(sha256, CanonicBody).
%% crypto:sha256(CanonicBody).

%% RFC 5.5 & 3.7
dkim_hash_data(CanonicHeaders, DkimHeader) ->
    JoinedHeaders = <<<<Hdr/binary, "\r\n">> || Hdr <- CanonicHeaders>>,
    crypto:hash(sha256, <<JoinedHeaders/binary, DkimHeader/binary>>).

%% TODO: Remove once we require Erlang/OTP 24.1+
%% Related Erlang/OTP bug: https://github.com/erlang/otp/pull/5157
ed25519_supported() ->
    {ok, PublicKeyAppVersionString} = application:get_key(public_key, vsn),
    PublicKeyAppVersionList =
        lists:map(fun erlang:list_to_integer/1, string:tokens(PublicKeyAppVersionString, ".")),
    PublicKeyAppVersionList >= [1, 11, 2].

dkim_get_algorithm_digest(Algorithm) ->
    case Algorithm of
        'rsa-sha256' ->
            sha256;
        'ed25519-sha256' ->
            case ed25519_supported() of
                true ->
                    none;
                false ->
                    throw("DKIM with Ed25519 requires Erlang/OTP 24.1+")
            end
    end.

dkim_sign(DataHash, Algorithm, {pem_plain, PrivBin}) ->
    [PrivEntry] = public_key:pem_decode(PrivBin),
    Digest = dkim_get_algorithm_digest(Algorithm),
    Key = public_key:pem_entry_decode(PrivEntry),
    public_key:sign({digest, DataHash}, Digest, Key);
dkim_sign(DataHash, Algorithm, {pem_encrypted, EncPrivBin, Passwd}) ->
    [EncPrivEntry] = public_key:pem_decode(EncPrivBin),
    Digest = dkim_get_algorithm_digest(Algorithm),
    Key = public_key:pem_entry_decode(EncPrivEntry, Passwd),
    public_key:sign({digest, DataHash}, Digest, Key).

dkim_make_header(Tags) ->
    %so {b, ...} became last tag
    RevTags = lists:reverse(Tags),
    EncodedTags = binstr:join([dkim_encode_tag(K, V) || {K, V} <- RevTags], <<"; ">>),
    binstr:join(encode_headers([{<<"DKIM-Signature">>, EncodedTags}]), <<"\r\n">>).

%% RFC #3.5
dkim_encode_tag(v, 1) ->
    %% version
    <<"v=1">>;
dkim_encode_tag(a, Algorithm) ->
    %% algorithm
    <<"a=", (atom_to_binary(Algorithm, utf8))/binary>>;
dkim_encode_tag(b, undefined) ->
    %% signature (when hashing with no digest)
    <<"b=">>;
dkim_encode_tag(b, V) ->
    %% signature
    B64Sign = base64:encode(V),
    <<"b=", B64Sign/binary>>;
dkim_encode_tag(bh, V) ->
    %% body hash
    B64Sign = base64:encode(V),
    <<"bh=", B64Sign/binary>>;
% 'relaxed' for body not supported yet
dkim_encode_tag(c, {Hdrs, simple}) ->
    %% canonicalization type
    <<"c=", (atom_to_binary(Hdrs, utf8))/binary, "/simple">>;
dkim_encode_tag(d, Domain) ->
    %% SDID (domain)
    <<"d=", Domain/binary>>;
dkim_encode_tag(h, Hdrs) ->
    %% headers fields (case-insensitive, ":" separated)
    Joined = binstr:join([binstr:to_lower(H) || H <- Hdrs], <<":">>),
    <<"h=", Joined/binary>>;
dkim_encode_tag(i, V) ->
    %% AUID
    QPValue = dkim_qp_tag_value(V),
    <<"i=", QPValue/binary>>;
dkim_encode_tag(l, IntVal) ->
    %% body length count
    BinVal = list_to_binary(integer_to_list(IntVal)),
    <<"l=", (BinVal)/binary>>;
dkim_encode_tag(q, [<<"dns/txt">>]) ->
    %% query methods (':' separated)
    <<"q=dns/txt">>;
dkim_encode_tag(s, Selector) ->
    %% selector
    <<"s=", Selector/binary>>;
dkim_encode_tag(t, now) ->
    dkim_encode_tag(t, calendar:universal_time());
dkim_encode_tag(t, DateTime) ->
    %% timestamp
    BinTs = datetime_to_bin_timestamp(DateTime),
    <<"t=", BinTs/binary>>;
dkim_encode_tag(x, DateTime) ->
    %% signature expiration
    BinTs = datetime_to_bin_timestamp(DateTime),
    <<"x=", BinTs/binary>>;
%% dkim_encode_tag(z, Hdrs) ->
%%	   %% copied header fields
%%	   Joined = dkim_qp_tag_value(binstr:join([(H) || H <- Hdrs], <<"|">>)),
%%	   <<"z=", Joined/binary>>;
dkim_encode_tag(K, V) when is_binary(K), is_binary(V) ->
    <<K/binary, V/binary>>.

dkim_qp_tag_value(Value) ->
    %% XXX: this not fully satisfy #2.11
    [QPValue] = encode_quoted_printable(Value),
    binary:replace(QPValue, <<";">>, <<"=3B">>).

datetime_to_bin_timestamp(DateTime) ->
    % calendar:datetime_to_gregorian_seconds({{1970,1,1}, {0,0,0}})
    EpochStart = 62167219200,
    UnixTimestamp = calendar:datetime_to_gregorian_seconds(DateTime) - EpochStart,
    list_to_binary(integer_to_list(UnixTimestamp)).

%% /DKIM

-ifdef(TEST).

parse_with_comments_test_() ->
    [
        {"bleh", fun() ->
            ?assertEqual(<<"1.0">>, parse_with_comments(<<"1.0">>)),
            ?assertEqual(<<"1.0">>, parse_with_comments(<<"1.0  (produced by MetaSend Vx.x)">>)),
            ?assertEqual(<<"1.0">>, parse_with_comments(<<"(produced by MetaSend Vx.x) 1.0">>)),
            ?assertEqual(<<"1.0">>, parse_with_comments(<<"1.(produced by MetaSend Vx.x)0">>))
        end},
        {"comments that parse as empty", fun() ->
            ?assertEqual(<<>>, parse_with_comments(<<"(comment (nested (deeply)) (and (oh no!) again))">>)),
            ?assertEqual(<<>>, parse_with_comments(<<"(\\)\\\\)">>)),
            ?assertEqual(<<>>, parse_with_comments(<<"(by way of Whatever <redir@my.org>)    (generated by Eudora)">>))
        end},
        {"some more", fun() ->
            ?assertEqual(
                <<":sysmail@  group. org, Muhammed. Ali @Vegas.WBA">>,
                parse_with_comments(<<"\":sysmail\"@  group. org, Muhammed.(the greatest) Ali @(the)Vegas.WBA">>)
            ),
            ?assertEqual(
                <<"Pete <pete@silly.test>">>,
                parse_with_comments(<<"Pete(A wonderful \\) chap) <pete(his account)@silly.test(his host)>">>)
            )
        end},
        {"non list values", fun() ->
            ?assertEqual(undefined, parse_with_comments(undefined)),
            ?assertEqual(17, parse_with_comments(17))
        end},
        {"Parens within quotes ignored", fun() ->
            ?assertEqual(<<"Height (from xkcd).eml">>, parse_with_comments(<<"\"Height (from xkcd).eml\"">>)),
            ?assertEqual(<<"Height (from xkcd).eml">>, parse_with_comments(<<"\"Height \(from xkcd\).eml\"">>))
        end},
        {"Escaped quotes are handled correctly", fun() ->
            ?assertEqual(<<"Hello \"world\"">>, parse_with_comments(<<"Hello \\\"world\\\"">>)),
            ?assertEqual(
                <<"<boss@nil.test>, Giant; \"Big\" Box <sysservices@example.net>">>,
                parse_with_comments(<<"<boss@nil.test>, \"Giant; \\\"Big\\\" Box\" <sysservices@example.net>">>)
            )
        end},
        {"backslash not part of a quoted pair", fun() ->
            ?assertEqual(<<"AC \\ DC">>, parse_with_comments(<<"AC \\ DC">>)),
            ?assertEqual(<<"AC  DC">>, parse_with_comments(<<"AC ( \\ ) DC">>))
        end},
        {"Unterminated quotes or comments", fun() ->
            ?assertError(unterminated_quotes, parse_with_comments(<<"\"Hello there ">>)),
            ?assertError(unterminated_quotes, parse_with_comments(<<"\"Hello there \\\"">>)),
            ?assertError(unterminated_comment, parse_with_comments(<<"(Hello there ">>)),
            ?assertError(unterminated_comment, parse_with_comments(<<"(Hello there \\\)">>))
        end}
    ].

parse_content_type_test_() ->
    [
        {"parsing content types", fun() ->
            ?assertEqual(
                {<<"text">>, <<"plain">>, [{<<"charset">>, <<"us-ascii">>}]},
                parse_content_type(<<"text/plain; charset=us-ascii (Plain text)">>)
            ),
            ?assertEqual(
                {<<"text">>, <<"plain">>, [{<<"charset">>, <<"us-ascii">>}]},
                parse_content_type(<<"text/plain; charset=\"us-ascii\"">>)
            ),
            ?assertEqual(
                {<<"text">>, <<"plain">>, [{<<"charset">>, <<"us-ascii">>}]},
                parse_content_type(<<"Text/Plain; Charset=\"us-ascii\"">>)
            ),
            ?assertEqual(
                {<<"multipart">>, <<"mixed">>, [{<<"boundary">>, <<"----_=_NextPart_001_01C9DCAE.1F2CB390">>}]},
                parse_content_type(<<"multipart/mixed; boundary=\"----_=_NextPart_001_01C9DCAE.1F2CB390\"">>)
            )
        end},
        {"parsing content type with a tab in it", fun() ->
            ?assertEqual(
                {<<"text">>, <<"plain">>, [{<<"charset">>, <<"us-ascii">>}]},
                parse_content_type(<<"text/plain;\tcharset=us-ascii">>)
            ),
            ?assertEqual(
                {<<"text">>, <<"plain">>, [{<<"charset">>, <<"us-ascii">>}, {<<"foo">>, <<"bar">>}]},
                parse_content_type(<<"text/plain;\tcharset=us-ascii;\tfoo=bar">>)
            )
        end},
        {"invalid content types", fun() ->
            ?assertThrow(bad_content_type, parse_content_type(<<"text\\plain; charset=us-ascii">>)),
            ?assertThrow(bad_content_type, parse_content_type(<<"text/plain; charset us-ascii">>))
        end}
    ].

parse_content_disposition_test_() ->
    [
        {"parsing valid dispositions", fun() ->
            ?assertEqual({<<"inline">>, []}, parse_content_disposition(<<"inline">>)),
            ?assertEqual({<<"inline">>, []}, parse_content_disposition(<<"inline;">>)),
            ?assertEqual(
                {<<"attachment">>, [
                    {<<"filename">>, <<"genome.jpeg">>},
                    {<<"modification-date">>, <<"Wed, 12 Feb 1997 16:29:51 -0500">>}
                ]},
                parse_content_disposition(
                    <<"attachment; filename=genome.jpeg;modification-date=\"Wed, 12 Feb 1997 16:29:51 -0500\";">>
                )
            ),
            ?assertEqual(
                {<<"text/plain">>, [{<<"charset">>, <<"us-ascii">>}]},
                parse_content_disposition(<<"text/plain; charset=us-ascii (Plain text)">>)
            )
        end},
        {"invalid dispositions", fun() ->
            ?assertThrow(bad_disposition, parse_content_disposition(<<"inline; =bar">>)),
            ?assertThrow(bad_disposition, parse_content_disposition(<<"inline; bar">>))
        end}
    ].

various_parsing_test_() ->
    [
        {"split_body_by_boundary test", fun() ->
            ?assertEqual(
                [{[], <<"foo bar baz">>}], split_body_by_boundary_(<<"stuff\r\nfoo bar baz">>, <<"--bleh">>, [], [])
            ),
            ?assertEqual(
                [{[], <<"foo\r\n">>}, {[], <<>>}, {[], <<>>}, {[], <<"bar baz">>}],
                split_body_by_boundary_(
                    <<"stuff\r\nfoo\r\n--bleh\r\n--bleh\r\n--bleh-- stuff\r\nbar baz">>, <<"--bleh">>, [], []
                )
            ),
            %?assertEqual([{[], []}, {[], []}, {[], "bar baz"}], split_body_by_boundary_("\r\n--bleh\r\n--bleh\r\n", "--bleh", [], [])),
            %?assertMatch([{"text", "plain", [], _,"foo\r\n"}], split_body_by_boundary("stuff\r\nfoo\r\n--bleh\r\n--bleh\r\n--bleh-- stuff\r\nbar baz", "--bleh", "1.0", []))
            ?assertEqual({[], <<"foo: bar\r\n">>}, parse_headers(<<"\r\nfoo: bar\r\n">>)),
            ?assertEqual({[{<<"foo">>, <<"barbaz">>}], <<>>}, parse_headers(<<"foo: bar\r\n baz\r\n">>)),
            ?assertEqual({[], <<" foo bar baz\r\nbam">>}, parse_headers(<<"\sfoo bar baz\r\nbam">>)),
            ok
        end},
        {"Headers with non-ASCII characters", fun() ->
            ?assertEqual({[{<<"foo">>, <<"bar ?? baz">>}], <<>>}, parse_headers(<<"foo: bar ø baz\r\n"/utf8>>)),
            ?assertEqual({[], <<"bär: bar baz\r\n"/utf8>>}, parse_headers(<<"bär: bar baz\r\n"/utf8>>))
        end},
        {"Headers with tab characters", fun() ->
            ?assertEqual({[{<<"foo">>, <<"bar		baz">>}], <<>>}, parse_headers(<<"foo: bar		baz\r\n">>))
        end}
    ].

-define(IMAGE_MD5, <<110, 130, 37, 247, 39, 149, 224, 61, 114, 198, 227, 138, 113, 4, 198, 60>>).

parse_example_mails_test_() ->
    Getmail = fun(File) ->
        {ok, Email} = file:read_file(string:concat("test/fixtures/", File)),
        %Email = binary_to_list(Bin),
        decode(Email)
    end,
    [
        {"parse a plain text email", fun() ->
            Decoded = Getmail("Plain-text-only.eml"),
            ?assertEqual(5, tuple_size(Decoded)),
            {Type, SubType, _Headers, _Properties, Body} = Decoded,
            ?assertEqual({<<"text">>, <<"plain">>}, {Type, SubType}),
            ?assertEqual(<<"This message contains only plain text.\r\n">>, Body)
        end},
        {"parse a Python smtplib plain text email", fun() ->
            Decoded = Getmail("python-smtp-lib.eml"),
            ?assertEqual(5, tuple_size(Decoded)),
            {Type, SubType, _Headers, _Properties, Body} = Decoded,
            ?assertEqual({<<"text">>, <<"plain">>}, {Type, SubType}),
            ?assertEqual(<<"Hello world Python.\r\n">>, Body)
        end},
        {"parse a plain text email with no content type", fun() ->
            Decoded = Getmail("Plain-text-only-no-content-type.eml"),
            ?assertEqual(5, tuple_size(Decoded)),
            {Type, SubType, _Headers, _Properties, Body} = Decoded,
            ?assertEqual({<<"text">>, <<"plain">>}, {Type, SubType}),
            ?assertEqual(<<"This message contains only plain text.\r\n">>, Body)
        end},
        {"parse a plain text email with no MIME header", fun() ->
            {Type, SubType, _Headers, _Properties, Body} =
                Getmail("Plain-text-only-no-MIME.eml"),
            ?assertEqual({<<"text">>, <<"plain">>}, {Type, SubType}),
            ?assertEqual(<<"This message contains only plain text.\r\n">>, Body)
        end},
        {"parse an email that says it is multipart but contains no boundaries", fun() ->
            ?assertError(missing_boundary, Getmail("Plain-text-only-with-boundary-header.eml"))
        end},
        {"parse a multipart email with no MIME header", fun() ->
            % We now insert a default Mime for missing Mime headers
            % ?assertError(non_mime_multipart, Getmail("rich-text-no-MIME.eml"))
            ?assertMatch(
                {<<"multipart">>, <<"alternative">>, _, _, [
                    {<<"text">>, <<"plain">>, _, _, _}, {<<"text">>, <<"html">>, _, _, _}
                ]},
                Getmail("rich-text-no-MIME.eml")
            )
        end},
        {"rich text", fun() ->
            %% pardon my naming here.  apparently 'rich text' in mac mail
            %% means 'html'.
            Decoded = Getmail("rich-text.eml"),
            ?assertEqual(5, tuple_size(Decoded)),
            {Type, SubType, _Headers, _Properties, Body} = Decoded,
            ?assertEqual({<<"multipart">>, <<"alternative">>}, {Type, SubType}),
            ?assertEqual(2, length(Body)),
            [Plain, Html] = Body,
            ?assertEqual({5, 5}, {tuple_size(Plain), tuple_size(Html)}),
            ?assertMatch({<<"text">>, <<"plain">>, _, _, <<"This message contains rich text.">>}, Plain),
            ?assertMatch(
                {<<"text">>, <<"html">>, _, _,
                    <<"<html><body style=\"word-wrap: break-word; -webkit-nbsp-mode: space; -webkit-line-break: after-white-space; \"><b>This </b><i>message </i><span class=\"Apple-style-span\" style=\"text-decoration: underline;\">contains </span>rich text.</body></html>">>},
                Html
            )
        end},
        {"rich text no boundary", fun() ->
            ?assertError(no_boundary, Getmail("rich-text-no-boundary.eml"))
        end},
        {"rich text missing first boundary", fun() ->
            % TODO - should we handle this more elegantly?
            Decoded = Getmail("rich-text-missing-first-boundary.eml"),
            ?assertEqual(5, tuple_size(Decoded)),
            {Type, SubType, _Headers, _Properties, Body} = Decoded,
            ?assertEqual({<<"multipart">>, <<"alternative">>}, {Type, SubType}),
            ?assertEqual(1, length(Body)),
            [Html] = Body,
            ?assertEqual(5, tuple_size(Html)),
            ?assertMatch(
                {<<"text">>, <<"html">>, _, _,
                    <<"<html><body style=\"word-wrap: break-word; -webkit-nbsp-mode: space; -webkit-line-break: after-white-space; \"><b>This </b><i>message </i><span class=\"Apple-style-span\" style=\"text-decoration: underline;\">contains </span>rich text.</body></html>">>},
                Html
            )
        end},
        {"rich text missing last boundary", fun() ->
            ?assertError(missing_last_boundary, Getmail("rich-text-missing-last-boundary.eml"))
        end},
        {"rich text wrong last boundary", fun() ->
            ?assertError(missing_last_boundary, Getmail("rich-text-broken-last-boundary.eml"))
        end},
        {"rich text missing text content type", fun() ->
            %% pardon my naming here.  apparently 'rich text' in mac mail
            %% means 'html'.
            Decoded = Getmail("rich-text-no-text-contenttype.eml"),
            ?assertEqual(5, tuple_size(Decoded)),
            {Type, SubType, _Headers, _Properties, Body} = Decoded,
            ?assertEqual({<<"multipart">>, <<"alternative">>}, {Type, SubType}),
            ?assertEqual(2, length(Body)),
            [Plain, Html] = Body,
            ?assertEqual({5, 5}, {tuple_size(Plain), tuple_size(Html)}),
            ?assertMatch({<<"text">>, <<"plain">>, _, _, <<"This message contains rich text.">>}, Plain),
            ?assertMatch(
                {<<"text">>, <<"html">>, _, _,
                    <<"<html><body style=\"word-wrap: break-word; -webkit-nbsp-mode: space; -webkit-line-break: after-white-space; \"><b>This </b><i>message </i><span class=\"Apple-style-span\" style=\"text-decoration: underline;\">contains </span>rich text.</body></html>">>},
                Html
            )
        end},
        {"text attachment only", fun() ->
            Decoded = Getmail("text-attachment-only.eml"),
            ?assertEqual(5, tuple_size(Decoded)),
            {Type, SubType, _Headers, _Properties, Body} = Decoded,
            ?assertEqual({<<"multipart">>, <<"mixed">>}, {Type, SubType}),
            ?assertEqual(1, length(Body)),
            Rich =
                <<"{\\rtf1\\ansi\\ansicpg1252\\cocoartf949\\cocoasubrtf460\r\n{\\fonttbl\\f0\\fswiss\\fcharset0 Helvetica;}\r\n{\\colortbl;\\red255\\green255\\blue255;}\r\n\\margl1440\\margr1440\\vieww9000\\viewh8400\\viewkind0\r\n\\pard\\tx720\\tx1440\\tx2160\\tx2880\\tx3600\\tx4320\\tx5040\\tx5760\\tx6480\\tx7200\\tx7920\\tx8640\\ql\\qnatural\\pardirnatural\r\n\r\n\\f0\\fs24 \\cf0 This is a basic rtf file.}">>,
            ?assertMatch([{<<"text">>, <<"rtf">>, _, _, Rich}], Body)
        end},
        {"image attachment only", fun() ->
            Decoded = Getmail("image-attachment-only.eml"),
            ?assertEqual(5, tuple_size(Decoded)),
            {Type, SubType, _Headers, _Properties, Body} = Decoded,
            ?assertEqual({<<"multipart">>, <<"mixed">>}, {Type, SubType}),
            ?assertEqual(1, length(Body)),
            ?assertMatch([{<<"image">>, <<"jpeg">>, _, _, _}], Body),
            [H | _] = Body,
            [{<<"image">>, <<"jpeg">>, _, Parameters, _Image}] = Body,
            ?assertEqual(?IMAGE_MD5, erlang:md5(element(5, H))),
            ?assertEqual(<<"inline">>, maps:get(disposition, Parameters)),
            ?assertEqual(
                <<"chili-pepper.jpg">>, proplists:get_value(<<"filename">>, maps:get(disposition_params, Parameters))
            ),
            ?assertEqual(
                <<"chili-pepper.jpg">>, proplists:get_value(<<"name">>, maps:get(content_type_params, Parameters))
            )
        end},
        {"message attachment only", fun() ->
            Decoded = Getmail("message-as-attachment.eml"),
            ?assertMatch({<<"multipart">>, <<"mixed">>, _, _, _}, Decoded),
            [Body] = element(5, Decoded),
            ?assertMatch({<<"message">>, <<"rfc822">>, _, _, _}, Body),
            Subbody = element(5, Body),
            ?assertMatch({<<"text">>, <<"plain">>, _, _, _}, Subbody),
            ?assertEqual(<<"This message contains only plain text.\r\n">>, element(5, Subbody))
        end},
        {"message, image, and rtf attachments.", fun() ->
            Decoded = Getmail("message-image-text-attachments.eml"),
            ?assertMatch({<<"multipart">>, <<"mixed">>, _, _, _}, Decoded),
            ?assertEqual(3, length(element(5, Decoded))),
            [Message, Rtf, Image] = element(5, Decoded),
            ?assertMatch({<<"message">>, <<"rfc822">>, _, _, _}, Message),
            Submessage = element(5, Message),
            ?assertMatch({<<"text">>, <<"plain">>, _, _, <<"This message contains only plain text.\r\n">>}, Submessage),

            ?assertMatch({<<"text">>, <<"rtf">>, _, _, _}, Rtf),
            ?assertEqual(
                <<"{\\rtf1\\ansi\\ansicpg1252\\cocoartf949\\cocoasubrtf460\r\n{\\fonttbl\\f0\\fswiss\\fcharset0 Helvetica;}\r\n{\\colortbl;\\red255\\green255\\blue255;}\r\n\\margl1440\\margr1440\\vieww9000\\viewh8400\\viewkind0\r\n\\pard\\tx720\\tx1440\\tx2160\\tx2880\\tx3600\\tx4320\\tx5040\\tx5760\\tx6480\\tx7200\\tx7920\\tx8640\\ql\\qnatural\\pardirnatural\r\n\r\n\\f0\\fs24 \\cf0 This is a basic rtf file.}">>,
                element(5, Rtf)
            ),

            ?assertMatch({<<"image">>, <<"jpeg">>, _, _, _}, Image),
            ?assertEqual(?IMAGE_MD5, erlang:md5(element(5, Image)))
        end},
        {"alternative text/html with calendar attachment.", fun() ->
            Decoded = Getmail("message-text-html-attachment.eml"),
            ?assertMatch(
                {<<"multipart">>, <<"mixed">>, _, _, [
                    {<<"multipart">>, <<"alternative">>, _, _, [
                        {<<"text">>, <<"plain">>, _, _, _},
                        {<<"text">>, <<"html">>, _, _, _}
                    ]},
                    {<<"text">>, <<"calendar">>, _, _, _}
                ]},
                Decoded
            )
        end},
        {"Outlook 2007 with leading tabs in quoted-printable.", fun() ->
            Decoded = Getmail("outlook-2007.eml"),
            ?assertMatch({<<"multipart">>, <<"alternative">>, _, _, _}, Decoded)
        end},
        {"The gamut", fun() ->
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
            ?assertMatch({<<"multipart">>, <<"alternative">>, _, _, _}, Decoded),
            ?assertEqual(2, length(element(5, Decoded))),
            [Toptext, Topmultipart] = element(5, Decoded),
            ?assertMatch({<<"text">>, <<"plain">>, _, _, _}, Toptext),
            ?assertEqual(
                <<"This is rich text.\r\n\r\nThe list is html.\r\n\r\nAttchments:\r\nan email containing an attachment of an email.\r\nan email of only plain text.\r\nan image\r\nan rtf file.\r\n">>,
                element(5, Toptext)
            ),
            ?assertEqual(9, length(element(5, Topmultipart))),
            [Html, Messagewithin, Brhtml, _Message, Brhtml, Image, Brhtml, Rtf, Brhtml] = element(5, Topmultipart),
            ?assertMatch({<<"text">>, <<"html">>, _, _, _}, Html),
            ?assertEqual(
                <<"<html><body style=\"word-wrap: break-word; -webkit-nbsp-mode: space; -webkit-line-break: after-white-space; \"><b>This</b> is <i>rich</i> text.<div><br></div><div>The list is html.</div><div><br></div><div>Attchments:</div><div><ul class=\"MailOutline\"><li>an email containing an attachment of an email.</li><li>an email of only plain text.</li><li>an image</li><li>an rtf file.</li></ul></div><div></div></body></html>">>,
                element(5, Html)
            ),

            ?assertMatch({<<"message">>, <<"rfc822">>, _, _, _}, Messagewithin),
            %?assertEqual(1, length(element(5, Messagewithin))),
            ?assertMatch(
                {<<"multipart">>, <<"mixed">>, _, _, [
                    {<<"message">>, <<"rfc822">>, _, _,
                        {<<"text">>, <<"plain">>, _, _, <<"This message contains only plain text.\r\n">>}}
                ]},
                element(5, Messagewithin)
            ),

            ?assertMatch({<<"image">>, <<"jpeg">>, _, _, _}, Image),
            ?assertEqual(?IMAGE_MD5, erlang:md5(element(5, Image))),

            ?assertMatch({<<"text">>, <<"rtf">>, _, _, _}, Rtf),
            ?assertEqual(
                <<"{\\rtf1\\ansi\\ansicpg1252\\cocoartf949\\cocoasubrtf460\r\n{\\fonttbl\\f0\\fswiss\\fcharset0 Helvetica;}\r\n{\\colortbl;\\red255\\green255\\blue255;}\r\n\\margl1440\\margr1440\\vieww9000\\viewh8400\\viewkind0\r\n\\pard\\tx720\\tx1440\\tx2160\\tx2880\\tx3600\\tx4320\\tx5040\\tx5760\\tx6480\\tx7200\\tx7920\\tx8640\\ql\\qnatural\\pardirnatural\r\n\r\n\\f0\\fs24 \\cf0 This is a basic rtf file.}">>,
                element(5, Rtf)
            )
        end},
        {"Plain text and 2 identical attachments", fun() ->
            Decoded = Getmail("plain-text-and-two-identical-attachments.eml"),
            ?assertMatch({<<"multipart">>, <<"mixed">>, _, _, _}, Decoded),
            ?assertEqual(3, length(element(5, Decoded))),
            [Plain, Attach1, Attach2] = element(5, Decoded),
            ?assertEqual(Attach1, Attach2),
            ?assertMatch({<<"text">>, <<"plain">>, _, _, _}, Plain),
            ?assertEqual(<<"This message contains only plain text.\r\n">>, element(5, Plain))
        end},
        {"no \\r\\n before first boundary", fun() ->
            {ok, Bin} = file:read_file("test/fixtures/html.eml"),
            Decoded = decode(Bin),
            ?assertEqual(2, length(element(5, Decoded)))
        end},
        {"permissive malformed folded multibyte header decoder", fun() ->
            {_, _, Headers, _, Body} = Getmail("malformed-folded-multibyte-header.eml"),
            ?assertEqual(<<"Hello world\n">>, Body),
            Subject =
                <<78, 79, 68, 51, 50, 32, 83, 109, 97, 114, 116, 32, 83, 101, 99, 117, 114, 105, 116, 121, 32, 45, 32,
                    208, 177, 208, 181, 209, 129, 208, 191, 208, 187, 208, 176, 209, 130, 208, 189, 208, 176, 209, 143,
                    32, 208, 187, 208, 184, 209, 134, 208, 181, 208, 189, 208, 183, 208, 184, 209, 143>>,
            ?assertEqual(Subject, proplists:get_value(<<"Subject">>, Headers))
        end},
        {"decode headers of multipart messages", fun() ->
            {<<"multipart">>, _, _, _, [Inline, Attachment]} = Getmail("utf-attachment-name.eml"),
            {<<"text">>, _, _, _, InlineBody} = Inline,
            {<<"text">>, _, _, ContentHeaders, _AttachmentBody} = Attachment,
            ContentTypeName = proplists:get_value(
                <<"name">>,
                maps:get(
                    content_type_params, ContentHeaders
                )
            ),
            DispositionName = proplists:get_value(
                <<"filename">>,
                maps:get(
                    disposition_params, ContentHeaders
                )
            ),

            ?assertEqual(<<"Hello\r\n">>, InlineBody),
            ?assert(ContentTypeName == DispositionName),
            % Take the filename as a literal, to prevent character set issues with Erlang
            % In utf-8 the filename is:"тестовый файл.txt"
            Filename =
                <<209, 130, 208, 181, 209, 129, 209, 130, 208, 190, 208, 178, 209, 139, 208, 185, 32, 209, 132, 208,
                    176, 208, 185, 208, 187, 46, 116, 120, 116>>,
            ?assertEqual(Filename, ContentTypeName),
            ?assertEqual(Filename, DispositionName)
        end},
        {"testcase1", fun() ->
            Multipart = <<"multipart">>,
            Alternative = <<"alternative">>,
            Related = <<"related">>,
            Mixed = <<"mixed">>,
            Text = <<"text">>,
            Html = <<"html">>,
            Plain = <<"plain">>,
            Message = <<"message">>,
            Ref822 = <<"rfc822">>,
            Image = <<"image">>,
            Jpeg = <<"jpeg">>,
            %Imagemd5 = <<69,175,198,78,52,72,6,233,147,22,50,137,128,180,169,50>>,
            Imagemd5 = <<179, 151, 42, 139, 78, 14, 182, 78, 24, 160, 123, 221, 217, 14, 141, 5>>,
            Decoded = Getmail("testcase1"),
            ?assertMatch({Multipart, Mixed, _, _, [_, _]}, Decoded),
            [Multi1, Message1] = element(5, Decoded),
            ?assertMatch({Multipart, Alternative, _, _, [_, _]}, Multi1),
            [Plain1, Html1] = element(5, Multi1),
            ?assertMatch({Text, Plain, _, _, _}, Plain1),
            ?assertMatch({Text, Html, _, _, _}, Html1),
            ?assertMatch({Message, Ref822, _, _, _}, Message1),
            Multi2 = element(5, Message1),
            ?assertMatch({Multipart, Alternative, _, _, [_, _]}, Multi2),
            [Plain2, Related1] = element(5, Multi2),
            ?assertMatch({Text, Plain, _, _, _}, Plain2),
            ?assertMatch({Multipart, Related, _, _, [_, _]}, Related1),
            [Html2, Image1] = element(5, Related1),
            ?assertMatch({Text, Html, _, _, _}, Html2),
            ?assertMatch({Image, Jpeg, _, _, _}, Image1),
            Resimage = erlang:md5(element(5, Image1)),
            ?assertEqual(Imagemd5, Resimage)
        end},
        {"testcase2", fun() ->
            Multipart = <<"multipart">>,
            Alternative = <<"alternative">>,
            Mixed = <<"mixed">>,
            Text = <<"text">>,
            Html = <<"html">>,
            Plain = <<"plain">>,
            Message = <<"message">>,
            Ref822 = <<"rfc822">>,
            Application = <<"application">>,
            Octetstream = <<"octet-stream">>,
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
        end}
    ].

decode_quoted_printable_test_() ->
    [
        {"bleh", fun() ->
            ?assertEqual(<<"!">>, decode_quoted_printable(<<"=21">>)),
            ?assertEqual(<<"!!">>, decode_quoted_printable(<<"=21=21">>)),
            ?assertEqual(<<"=:=">>, decode_quoted_printable(<<"=3D:=3D">>)),
            ?assertEqual(
                <<"Thequickbrownfoxjumpedoverthelazydog.">>,
                decode_quoted_printable(<<"Thequickbrownfoxjumpedoverthelazydog.">>)
            )
        end},
        {"lowercase bleh", fun() ->
            ?assertEqual(<<"=:=">>, decode_quoted_printable(<<"=3d:=3d">>))
        end},
        {"input with spaces", fun() ->
            ?assertEqual(
                <<"The quick brown fox jumped over the lazy dog.">>,
                decode_quoted_printable(<<"The quick brown fox jumped over the lazy dog.">>)
            )
        end},
        {"input with tabs", fun() ->
            ?assertEqual(
                <<"The\tquick brown fox jumped over\tthe lazy dog.">>,
                decode_quoted_printable(<<"The\tquick brown fox jumped over\tthe lazy dog.">>)
            )
        end},
        {"input with trailing spaces", fun() ->
            ?assertEqual(
                <<"The quick brown fox jumped over the lazy dog.">>,
                decode_quoted_printable(<<"The quick brown fox jumped over the lazy dog.       ">>)
            )
        end},
        {"input with non-strippable trailing whitespace", fun() ->
            ?assertEqual(
                <<"The quick brown fox jumped over the lazy dog.        ">>,
                decode_quoted_printable(<<"The quick brown fox jumped over the lazy dog.       =20">>)
            ),
            ?assertEqual(
                <<"The quick brown fox jumped over the lazy dog.       \t">>,
                decode_quoted_printable(<<"The quick brown fox jumped over the lazy dog.       =09">>)
            ),
            ?assertEqual(
                <<"The quick brown fox jumped over the lazy dog.\t \t \t \t ">>,
                decode_quoted_printable(<<"The quick brown fox jumped over the lazy dog.\t \t \t =09=20">>)
            ),
            ?assertEqual(
                <<"The quick brown fox jumped over the lazy dog.\t \t \t \t ">>,
                decode_quoted_printable(
                    <<"The quick brown fox jumped over the lazy dog.\t \t \t =09=20\t                  \t">>
                )
            )
        end},
        {"input with trailing tabs", fun() ->
            ?assertEqual(
                <<"The quick brown fox jumped over the lazy dog.">>,
                decode_quoted_printable(<<"The quick brown fox jumped over the lazy dog.\t\t\t\t\t">>)
            )
        end},
        {"soft new line", fun() ->
            ?assertEqual(
                <<"The quick brown fox jumped over the lazy dog.       ">>,
                decode_quoted_printable(<<"The quick brown fox jumped over the lazy dog.       =">>)
            )
        end},
        {"soft new line with trailing whitespace", fun() ->
            ?assertEqual(
                <<"The quick brown fox jumped over the lazy dog.       ">>,
                decode_quoted_printable(<<"The quick brown fox jumped over the lazy dog.       =  	">>)
            )
        end},
        {"multiline stuff", fun() ->
            ?assertEqual(
                <<"Now's the time for all folk to come to the aid of their country.">>,
                decode_quoted_printable(
                    <<"Now's the time =\r\nfor all folk to come=\r\n to the aid of their country.">>
                )
            ),
            ?assertEqual(
                <<"Now's the time\r\nfor all folk to come\r\n to the aid of their country.">>,
                decode_quoted_printable(<<"Now's the time\r\nfor all folk to come\r\n to the aid of their country.">>)
            ),
            ?assertEqual(<<"hello world">>, decode_quoted_printable(<<"hello world">>)),
            ?assertEqual(<<"hello\r\n\r\nworld">>, decode_quoted_printable(<<"hello\r\n\r\nworld">>))
        end},
        {"invalid input", fun() ->
            ?assertThrow(badchar, decode_quoted_printable(<<"=21=G1">>)),
            ?assertThrow(badchar, decode_quoted_printable(<<"=21=D1 = g ">>))
        end},
        %% TODO zotonic's iconv throws eilseq here.
        % {"out of range characters should be stripped",
        % 	fun() ->
        % 		% character 150 is en-dash in windows 1252
        % 		?assertEqual(<<"Foo  bar"/utf8>>, decode_body(<<"quoted-printable">>, <<"Foo ", 150, " bar">>, "US-ASCII", "UTF-8//IGNORE"))
        % 	end
        % },
        {"out of range character in alternate charset should be converted", fun() ->
            % character 150 is en-dash in windows 1252
            ?assertEqual(
                <<"Foo ", 226, 128, 147, " bar">>,
                decode_body(<<"quoted-printable">>, <<"Foo ", 150, " bar">>, "Windows-1252", "UTF-8//IGNORE")
            )
        end},
        {"out of range character in alternate charset with no destination encoding should be stripped", fun() ->
            % character 150 is en-dash in windows 1252
            ?assertEqual(
                <<"Foo  bar">>, decode_body(<<"quoted-printable">>, <<"Foo ", 150, " bar">>, "Windows-1252", none)
            )
        end},
        {"out of range character in alternate charset with no source encoding should be stripped", fun() ->
            % character 150 is en-dash in windows 1252
            ?assertEqual(
                <<"Foo  bar">>, decode_body(<<"quoted-printable">>, <<"Foo ", 150, " bar">>, undefined, "UTF-8")
            )
        end},
        {"almost correct chatsets should work, eg. 'UTF8' instead of 'UTF-8'", fun() ->
            % character 150 is en-dash in windows 1252
            ?assertEqual(<<"Foo  bar">>, decode_body(<<"quoted-printable">>, <<"Foo  bar">>, <<"UTF8">>, "UTF-8")),
            ?assertEqual(<<"Foo  bar">>, decode_body(<<"quoted-printable">>, <<"Foo  bar">>, <<"utf8">>, "UTF-8"))
        end}
    ].

valid_smtp_mime_7bit_test() ->
    ?assert(valid_7bit(<<>>)),
    ?assert(valid_7bit(<<"abcdefghijklmnopqrstuvwxyz0123456789">>)),
    ?assert(valid_7bit(<<"abc\r\ndef">>)),
    AllValidRange =
        (lists:seq(1, $\n - 1) ++
            lists:seq($\n + 1, $\r - 1) ++
            lists:seq($\r + 1, 127)),
    ?assert(valid_7bit(list_to_binary(AllValidRange))),
    ?assertNot(valid_7bit(<<"\n">>)),
    ?assertNot(valid_7bit(<<"\r">>)),
    ?assertNot(valid_7bit(<<"abc\ndef">>)),
    ?assertNot(valid_7bit(<<"abc\rdef">>)),
    ?assertNot(valid_7bit(<<"abc\n\rdef">>)),
    ?assertNot(valid_7bit(<<128, 200, 255>>)),
    ?assertNot(valid_7bit(<<0, 0, 0>>)),
    ?assertNot(valid_7bit(<<"hello", 128, 0, 200>>)),
    %% Long lines
    Line800 = binary:copy(<<$a>>, 800),
    ?assertNot(has_lines_over_998(Line800)),
    Many800Lines = list_to_binary(lists:join("\r\n", lists:duplicate(10, Line800))),
    ?assertNot(has_lines_over_998(Many800Lines)),
    Line1000 = binary:copy(<<$a>>, 1000),
    ?assert(has_lines_over_998(Line1000)),
    Many1000Lines = list_to_binary(lists:join("\r\n", lists:duplicate(10, Line1000))),
    ?assert(has_lines_over_998(Many1000Lines)),
    ?assert(has_lines_over_998(<<Line800/binary, "\r\n", Line1000/binary>>)).

encode_quoted_printable_test_() ->
    [
        {"bleh", fun() ->
            ?assertEqual([<<"!">>], encode_quoted_printable(<<"!">>)),
            ?assertEqual([<<"!!">>], encode_quoted_printable(<<"!!">>)),
            ?assertEqual([<<"=3D:=3D">>], encode_quoted_printable(<<"=:=">>)),
            ?assertEqual(
                [<<"Thequickbrownfoxjumpedoverthelazydog.">>],
                encode_quoted_printable(<<"Thequickbrownfoxjumpedoverthelazydog.">>)
            )
        end},
        {"input with spaces", fun() ->
            ?assertEqual(
                [<<"The quick brown fox jumped over the lazy dog.">>],
                encode_quoted_printable(<<"The quick brown fox jumped over the lazy dog.">>)
            )
        end},
        {"input with tabs", fun() ->
            ?assertEqual(
                [<<"The\tquick brown fox jumped over\tthe lazy dog.">>],
                encode_quoted_printable(<<"The\tquick brown fox jumped over\tthe lazy dog.">>)
            )
        end},
        {"input with trailing spaces", fun() ->
            ?assertEqual(
                [<<"The quick brown fox jumped over the lazy dog.      =20\r\n">>],
                encode_quoted_printable(<<"The quick brown fox jumped over the lazy dog.       \r\n">>)
            ),
            ?assertEqual(
                [<<"The quick brown fox jumped over the lazy dog.      =20">>],
                encode_quoted_printable(<<"The quick brown fox jumped over the lazy dog.       ">>)
            )
        end},
        {"input with trailing tabs", fun() ->
            ?assertEqual(
                [<<"The quick brown fox jumped over the lazy dog.	=09\r\n">>],
                encode_quoted_printable(<<"The quick brown fox jumped over the lazy dog.		\r\n">>)
            ),
            ?assertEqual(
                [<<"The quick brown fox jumped over the lazy dog.	=09">>],
                encode_quoted_printable(<<"The quick brown fox jumped over the lazy dog.		">>)
            )
        end},
        {"input with non-ascii characters", fun() ->
            ?assertEqual(
                [<<"There's some n=F8n-=E1scii st=FCff in here\r\n">>],
                encode_quoted_printable(<<"There's some n", 248, "n-", 225, "scii st", 252, "ff in here\r\n">>)
            )
        end},
        {"input with invisible non-ascii characters", fun() ->
            ?assertEqual(
                [<<"There's some stuff=C2=A0in=C2=A0here\r\n">>],
                encode_quoted_printable(<<"There's some stuff in here\r\n"/utf8>>)
            )
        end},
        {"add soft newlines", fun() ->
            ?assertEqual(
                [
                    <<"The quick brown fox jumped over the lazy dog. The quick brown fox jumped =\r\nover the lazy dog.">>
                ],
                encode_quoted_printable(
                    <<"The quick brown fox jumped over the lazy dog. The quick brown fox jumped over the lazy dog.">>
                )
            ),
            ?assertEqual(
                [
                    <<"The_quick_brown_fox_jumped_over_the_lazy_dog._The_quick_brown_fox_jumped_ov=\r\ner_the_lazy_dog.">>
                ],
                encode_quoted_printable(
                    <<"The_quick_brown_fox_jumped_over_the_lazy_dog._The_quick_brown_fox_jumped_over_the_lazy_dog.">>
                )
            ),
            ?assertEqual(
                [
                    <<"The_quick_brown_fox_jumped_over_the_lazy_dog._The_quick_brown_fox_jumped_o=\r\n=3Dver_the_lazy_dog.">>
                ],
                encode_quoted_printable(
                    <<"The_quick_brown_fox_jumped_over_the_lazy_dog._The_quick_brown_fox_jumped_o=ver_the_lazy_dog.">>
                )
            ),
            ?assertEqual(
                [
                    <<"The_quick_brown_fox_jumped_over_the_lazy_dog._The_quick_brown_fox_jumped_=\r\n=3Dover_the_lazy_dog.">>
                ],
                encode_quoted_printable(
                    <<"The_quick_brown_fox_jumped_over_the_lazy_dog._The_quick_brown_fox_jumped_=over_the_lazy_dog.">>
                )
            ),
            ?assertEqual(
                [
                    <<"The_quick_brown_fox_jumped_over_the_lazy_dog._The_quick_brown_fox_jumped_o =\r\nver_the_lazy_dog.">>
                ],
                encode_quoted_printable(
                    <<"The_quick_brown_fox_jumped_over_the_lazy_dog._The_quick_brown_fox_jumped_o ver_the_lazy_dog.">>
                )
            )
        end},
        {"soft newline edge cases", fun() ->
            ?assertEqual(
                [
                    <<
                        "123456789 123456789 123456789 123456789 123456789 123456789 123456789 12345=\r\n"
                        "=20"
                    >>
                ],
                encode_quoted_printable(
                    <<"123456789 123456789 123456789 123456789 123456789 123456789 123456789 12345 ">>
                )
            ),
            ?assertEqual(
                [
                    <<
                        "123456789 123456789 123456789 123456789 123456789 123456789 123456789 12345=\r\n"
                        "=20\r\n"
                    >>
                ],
                encode_quoted_printable(
                    <<"123456789 123456789 123456789 123456789 123456789 123456789 123456789 12345 \r\n">>
                )
            ),
            ?assertEqual(
                [
                    <<
                        "123456789 123456789 123456789 123456789 123456789 123456789 123456789 12345=\r\n"
                        "=09"
                    >>
                ],
                encode_quoted_printable(
                    <<"123456789 123456789 123456789 123456789 123456789 123456789 123456789 12345	">>
                )
            ),
            ?assertEqual(
                [
                    <<
                        "123456789 123456789 123456789 123456789 123456789 123456789 123456789 12345=\r\n"
                        "=09\r\n"
                    >>
                ],
                encode_quoted_printable(
                    <<"123456789 123456789 123456789 123456789 123456789 123456789 123456789 12345	\r\n">>
                )
            ),
            ?assertEqual(
                [
                    <<
                        "123456789 123456789 123456789 123456789 123456789 123456789 123456789 =\r\n"
                        "12345=3D"
                    >>
                ],
                encode_quoted_printable(
                    <<"123456789 123456789 123456789 123456789 123456789 123456789 123456789 12345=">>
                )
            ),
            ?assertEqual(
                [
                    <<
                        " 23456789012345678901234567890123456789012345678901234567890123456789012345=\r\n"
                        "=20"
                    >>
                ],
                encode_quoted_printable(
                    <<" 23456789012345678901234567890123456789012345678901234567890123456789012345 ">>
                )
            ),
            ?assertEqual(
                [
                    <<
                        " =\r\n"
                        "234567890123456789012345678901234567890123456789012345678901234567890123456"
                    >>
                ],
                encode_quoted_printable(
                    <<" 234567890123456789012345678901234567890123456789012345678901234567890123456">>
                )
            ),
            ?assertEqual(
                [
                    <<
                        " 23456789012345678901234567890123456789012345678901234567890123456789012345=\r\n"
                        "=3D"
                    >>
                ],
                encode_quoted_printable(
                    <<" 23456789012345678901234567890123456789012345678901234567890123456789012345=">>
                )
            )
        end}
    ].

encode_parameter_test_() ->
    [
        {"Token", fun() ->
            ?assertEqual(
                [[<<"a">>, $=, <<"abcdefghijklmnopqrstuvwxyz$%&*#!">>]],
                encode_parameters([{<<"a">>, <<"abcdefghijklmnopqrstuvwxyz$%&*#!">>}])
            )
        end},
        {"TSpecial", fun() ->
            Special = " ()<>@,;:/[]?=",
            [
                ?assertEqual([[<<"a">>, $=, $", <<C>>, $"]], encode_parameters([{<<"a">>, <<C>>}]))
             || C <- Special
            ],
            ?assertEqual([[<<"a">>, $=, $", <<$\\, $">>, $"]], encode_parameters([{<<"a">>, <<$">>}])),
            ?assertEqual([[<<"a">>, $=, $", <<$\\, $\\>>, $"]], encode_parameters([{<<"a">>, <<$\\>>}]))
        end}
    ].

rfc2047_decode_test_() ->
    [
        {"Simple tests", fun() ->
            ?assertEqual(
                <<"Keith Moore <moore@cs.utk.edu>"/utf8>>,
                decode_header(<<"=?US-ASCII?Q?Keith_Moore?= <moore@cs.utk.edu>">>, "utf-8")
            ),
            ?assertEqual(
                <<"Keld Jørn Simonsen <keld@dkuug.dk>"/utf8>>,
                decode_header(<<"=?ISO-8859-1?Q?Keld_J=F8rn_Simonsen?= <keld@dkuug.dk>">>, "utf-8")
            ),
            ?assertEqual(
                <<"Olle Järnefors <ojarnef@admin.kth.se>"/utf8>>,
                decode_header(<<"=?ISO-8859-1?Q?Olle_J=E4rnefors?= <ojarnef@admin.kth.se>">>, "utf-8")
            ),
            ?assertEqual(
                <<"André Pirard <PIRARD@vm1.ulg.ac.be>"/utf8>>,
                decode_header(<<"=?ISO-8859-1?Q?Andr=E9?= Pirard <PIRARD@vm1.ulg.ac.be>">>, "utf-8")
            )
        end},
        {"encoded words separated by whitespace should have whitespace removed", fun() ->
            ?assertEqual(
                <<"If you can read this you understand the example.">>,
                decode_header(
                    <<"=?ISO-8859-1?B?SWYgeW91IGNhbiByZWFkIHRoaXMgeW8=?= =?ISO-8859-2?B?dSB1bmRlcnN0YW5kIHRoZSBleGFtcGxlLg==?=">>,
                    "utf-8"
                )
            ),
            ?assertEqual(<<"ab">>, decode_header(<<"=?ISO-8859-1?Q?a?= =?ISO-8859-1?Q?b?=">>, "utf-8")),
            ?assertEqual(<<"ab">>, decode_header(<<"=?ISO-8859-1?Q?a?=  =?ISO-8859-1?Q?b?=">>, "utf-8")),
            ?assertEqual(
                <<"ab">>,
                decode_header(
                    <<
                        "=?ISO-8859-1?Q?a?=\n"
                        "		=?ISO-8859-1?Q?b?="
                    >>,
                    "utf-8"
                )
            )
        end},
        {"underscores expand to spaces", fun() ->
            ?assertEqual(<<"a b">>, decode_header(<<"=?ISO-8859-1?Q?a_b?=">>, "utf-8")),
            ?assertEqual(<<"a b">>, decode_header(<<"=?ISO-8859-1?Q?a?= =?ISO-8859-2?Q?_b?=">>, "utf-8"))
        end},
        {"edgecases", fun() ->
            ?assertEqual(
                <<"this is some text">>, decode_header(<<"=?iso-8859-1?q?this=20is=20some=20text?=">>, "utf-8")
            ),
            ?assertEqual(
                <<"=?iso-8859-1?q?this is some text?=">>,
                decode_header(<<"=?iso-8859-1?q?this is some text?=">>, "utf-8")
            )
        end},
        {"invalid character sequence handling", fun() ->
            ?assertException(
                throw,
                eilseq,
                decode_header(<<"=?us-ascii?B?dGhpcyBjb250YWlucyBhIGNvcHlyaWdodCCpIHN5bWJvbA==?=">>, "utf-8")
            ),
            %?assertEqual(<<"this contains a copyright  symbol"/utf8>>, decode_header(<<"=?us-ascii?B?dGhpcyBjb250YWlucyBhIGNvcHlyaWdodCCpIHN5bWJvbA==?=">>, "utf-8//IGNORE")),
            ?assertEqual(
                <<"this contains a copyright © symbol"/utf8>>,
                decode_header(<<"=?iso-8859-1?B?dGhpcyBjb250YWlucyBhIGNvcHlyaWdodCCpIHN5bWJvbA==?=">>, "utf-8//IGNORE")
            )
        end},
        {"multiple unicode email addresses", fun() ->
            ?assertEqual(
                <<"Jacek Złydach <jacek.zlydach@erlang-solutions.com>, chak de planet óóóó <jz@erlang-solutions.com>, Jacek Złydach <jacek.zlydach@erlang-solutions.com>, chak de planet óóóó <jz@erlang-solutions.com>"/utf8>>,
                decode_header(
                    <<"=?UTF-8?B?SmFjZWsgWsWCeWRhY2g=?= <jacek.zlydach@erlang-solutions.com>, =?UTF-8?B?Y2hhayBkZSBwbGFuZXQgw7PDs8Ozw7M=?= <jz@erlang-solutions.com>, =?UTF-8?B?SmFjZWsgWsWCeWRhY2g=?= <jacek.zlydach@erlang-solutions.com>, =?UTF-8?B?Y2hhayBkZSBwbGFuZXQgw7PDs8Ozw7M=?= <jz@erlang-solutions.com>">>,
                    "utf-8"
                )
            )
        end},
        {"decode something I encoded myself", fun() ->
            A = <<"Jacek Złydach <jacek.zlydach@erlang-solutions.com>"/utf8>>,
            ?assertEqual(A, decode_header(rfc2047_utf8_encode(A), "utf-8"))
        end}
    ].

rfc2047_utf8_encode_test_() ->
    [
        {"Q-Encoding", fun() ->
            ?assertEqual(
                <<"=?UTF-8?Q?abcdefghijklmnopqrstuvwxyz?=">>,
                rfc2047_utf8_encode(q, <<"abcdefghijklmnopqrstuvwxyz">>, <<>>, 0, <<" ">>)
            ),
            ?assertEqual(
                <<"=?UTF-8?Q?ABCDEFGHIJKLMNOPQRSTUVWXYZ?=">>,
                rfc2047_utf8_encode(q, <<"ABCDEFGHIJKLMNOPQRSTUVWXYZ">>, <<>>, 0, <<" ">>)
            ),
            ?assertEqual(<<"=?UTF-8?Q?0123456789?=">>, rfc2047_utf8_encode(q, <<"0123456789">>, <<>>, 0, <<" ">>)),
            ?assertEqual(<<"=?UTF-8?Q?!*+-/?=">>, rfc2047_utf8_encode(q, <<"!*+-/">>, <<>>, 0, <<" ">>)),
            ?assertEqual(
                <<
                    "=?UTF-8?Q?This_text_encodes_to_more_than_63_bytes=2E_Therefore=2C_it_shou?=\r\n"
                    " =?UTF-8?Q?ld_be_encoded_in_multiple_encoded_words=2E?="
                >>,
                rfc2047_utf8_encode(
                    q,
                    <<"This text encodes to more than 63 bytes. Therefore, it should be encoded in multiple encoded words.">>,
                    <<>>,
                    0,
                    <<" ">>
                )
            ),
            ?assertEqual(
                <<
                    "=?UTF-8?Q?This_text_encodes_to_more_than_63_bytes_with_offset_f?=\r\n"
                    "\t=?UTF-8?Q?or_a_parameter=2E_Therefore=2C_it_should_be_encoded_in_multipl?=\r\n"
                    "\t=?UTF-8?Q?e_encoded_words=2E?="
                >>,
                rfc2047_utf8_encode(
                    q,
                    <<
                        "This text encodes to more than 63 bytes with offset for a parameter. "
                        "Therefore, it should be encoded in multiple encoded words."
                    >>,
                    <<>>,
                    10,
                    <<"\t">>
                )
            ),
            ?assertEqual(
                <<
                    "=?UTF-8?Q?We_place_an_UTF8_4byte_character_over_the_breaking_point_here_?=\r\n"
                    " =?UTF-8?Q?=F0=9F=80=84?="
                >>,
                rfc2047_utf8_encode(
                    q,
                    <<"We place an UTF8 4byte character over the breaking point here ", 16#F0, 16#9F, 16#80, 16#84>>,
                    <<>>,
                    0,
                    <<" ">>
                )
            )
        end},
        {"B-Encoding", fun() ->
            ?assertEqual(
                <<"=?UTF-8?B?U29tZSBzaG9ydCB0ZXh0Lg==?=">>,
                rfc2047_utf8_encode(b, <<"Some short text.">>, <<>>, 0, <<" ">>)
            ),
            ?assertEqual(
                <<
                    "=?UTF-8?B?VGhpcyB0ZXh0IGVuY29kZXMgdG8gbW9yZSB0aGFuIDYzIGJ5dGVzLiBUaGVy?=\r\n"
                    " =?UTF-8?B?ZWZvcmUsIGl0IHNob3VsZCBiZSBlbmNvZGVkIGluIG11bHRpcGxlIGVuY29k?=\r\n"
                    " =?UTF-8?B?ZWQgd29yZHMu?="
                >>,
                rfc2047_utf8_encode(
                    b,
                    <<"This text encodes to more than 63 bytes. Therefore, it should be encoded in multiple encoded words.">>,
                    <<>>,
                    1,
                    <<" ">>
                )
            ),
            ?assertEqual(
                <<
                    "=?UTF-8?B?AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKiss?=\r\n"
                    " =?UTF-8?B?LS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZ?=\r\n"
                    " =?UTF-8?B?WltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8=?="
                >>,
                rfc2047_utf8_encode(b, <<<<X>> || X <- lists:seq(0, 16#7F)>>, <<>>, 1, <<" ">>)
            ),
            ?assertEqual(
                <<
                    "=?UTF-8?B?UGxhY2UgYW4gVVRGOCA0Ynl0ZSBjaGFyYWN0ZXIgYXQgdGhlIGJyZWFr?=\r\n"
                    " =?UTF-8?B?8J+AhA==?="
                >>,
                rfc2047_utf8_encode(
                    b, <<"Place an UTF8 4byte character at the break", 16#F0, 16#9F, 16#80, 16#84>>, <<>>, 1, <<" ">>
                )
            )
        end},
        {"Pick encoding", fun() ->
            ?assertEqual(<<"asdf">>, rfc2047_utf8_encode(<<"asdf">>)),
            ?assertEqual(<<"=?UTF-8?Q?x=09?=">>, rfc2047_utf8_encode(<<"x\t">>)),
            ?assertEqual(<<"=?UTF-8?B?CXgJ?=">>, rfc2047_utf8_encode(<<"\tx\t">>))
        end}
    ].

encoding_test_() ->
    Getmail = fun(File) ->
        {ok, Email} = file:read_file(filename:join("test/fixtures/", File)),
        decode(Email)
    end,
    [
        {"Simple email", fun() ->
            Email =
                {<<"text">>, <<"plain">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"To">>, <<"you@example.com">>},
                        {<<"Subject">>, <<"This is a test">>},
                        {<<"Message-ID">>, <<"<abcd@example.com>">>},
                        {<<"MIME-Version">>, <<"1.0">>},
                        {<<"Date">>, <<"Sun, 01 Nov 2009 14:44:47 +0200">>}
                    ],
                    #{
                        content_type_params =>
                            [{<<"charset">>, <<"US-ASCII">>}],
                        disposition => <<"inline">>
                    },
                    <<"This is a plain message">>},
            Result =
                <<"From: me@example.com\r\nTo: you@example.com\r\nSubject: This is a test\r\nMessage-ID: <abcd@example.com>\r\nMIME-Version: 1.0\r\nDate: Sun, 01 Nov 2009 14:44:47 +0200\r\n\r\nThis is a plain message">>,
            ?assertEqual(Result, encode(Email))
        end},
        {"Email with UTF-8 characters", fun() ->
            Email =
                {<<"text">>, <<"plain">>,
                    [
                        {<<"Subject">>, <<"Fræderik Hølljen"/utf8>>},
                        {<<"From">>, <<"Fræderik Hølljen <me@example.com>"/utf8>>},
                        {<<"To">>, <<"you@example.com">>},
                        {<<"Message-ID">>, <<"<abcd@example.com>">>},
                        {<<"MIME-Version">>, <<"1.0">>},
                        {<<"Date">>, <<"Sun, 01 Nov 2009 14:44:47 +0200">>}
                    ],
                    #{
                        content_type_params =>
                            [{<<"charset">>, <<"US-ASCII">>}],
                        disposition => <<"inline">>
                    },
                    <<"This is a plain message">>},
            Result =
                <<"Subject: =?UTF-8?Q?Fr=C3=A6derik_H=C3=B8lljen?=\r\nFrom: =?UTF-8?Q?Fr=C3=A6derik_H=C3=B8lljen?= <me@example.com>\r\nTo: you@example.com\r\nMessage-ID: <abcd@example.com>\r\nMIME-Version: 1.0\r\nDate: Sun, 01 Nov 2009 14:44:47 +0200\r\n\r\nThis is a plain message">>,
            ?assertEqual(Result, encode(Email))
        end},
        {"Email with UTF-8 in attachment filename.", fun() ->
            FileName = <<
                "Čia labai ilgas el. laiško priedo pavadinimas su "/utf8,
                "lietuviškomis ar kokiomis kitomis ne ascii raidėmis.pdf"/utf8
            >>,
            Email =
                {<<"multipart">>, <<"mixed">>,
                    [
                        {<<"From">>, <<"k.petrauskas@erisata.lt">>},
                        {<<"Subject">>, <<"Čiobiškis"/utf8>>},
                        {<<"Date">>, <<"Thu, 17 Dec 2020 20:12:33 +0200">>},
                        {<<"Message-ID">>, <<"<47a08b7ff7d305087877361ca8eea1db@karolis.erisata.lt>">>}
                    ],
                    #{
                        content_type_params => [
                            {<<"boundary">>, <<"_=boundary-123=_">>}
                        ]
                    },
                    [
                        {<<"application">>, <<"pdf">>, [],
                            #{
                                content_type_params => [
                                    {<<"name">>, FileName},
                                    {<<"disposition">>, <<"attachment">>}
                                ],
                                disposition => <<"attachment">>,
                                disposition_params => [{<<"filename">>, FileName}]
                            },
                            <<"data">>}
                    ]},
            Result = <<
                "From: k.petrauskas@erisata.lt\r\n"
                "Subject: =?UTF-8?Q?=C4=8Ciobi=C5=A1kis?=\r\n"
                "Date: Thu, 17 Dec 2020 20:12:33 +0200\r\n"
                "Message-ID: <47a08b7ff7d305087877361ca8eea1db@karolis.erisata.lt>\r\n"
                "Content-Type: multipart/mixed;\r\n"
                "\tboundary=\"_=boundary-123=_\"\r\n"
                "MIME-Version: 1.0\r\n"
                "\r\n"
                "\r\n"
                "--_=boundary-123=_\r\n"
                "Content-Type: application/pdf;\r\n"
                "\tname=\"=?UTF-8?Q?=C4=8Cia_labai_ilgas_el=2E_lai=C5=A1ko_priedo_pavadinima?=\r\n"
                "\t=?UTF-8?Q?s_su_lietuvi=C5=A1komis_ar_kokiomis_kitomis_ne_ascii_raid?=\r\n"
                "\t=?UTF-8?Q?=C4=97mis=2Epdf?=\";\r\n"
                "\tdisposition=attachment\r\n"
                "Content-Disposition: attachment;\r\n"
                "\tfilename=\"=?UTF-8?Q?=C4=8Cia_labai_ilgas_el=2E_lai=C5=A1ko_priedo_pavadi?=\r\n"
                "\t=?UTF-8?Q?nimas_su_lietuvi=C5=A1komis_ar_kokiomis_kitomis_ne_ascii_raid?=\r\n"
                "\t=?UTF-8?Q?=C4=97mis=2Epdf?=\"\r\n"
                "\r\n"
                "data\r\n"
                "--_=boundary-123=_--\r\n"
            >>,
            ?assertEqual(Result, encode(Email))
        end},
        {"Email with special chars in From", fun() ->
            Email =
                {<<"text">>, <<"plain">>,
                    [
                        {<<"From">>, <<"\"Admin & ' ( \\\"hallo\\\" ) ; , [ ] WS\" <a@example.com>">>},
                        {<<"Message-ID">>, <<"<abcd@example.com>">>},
                        {<<"MIME-Version">>, <<"1.0">>},
                        {<<"Date">>, <<"Sun, 01 Nov 2009 14:44:47 +0200">>}
                    ],
                    #{}, <<"This is a plain message">>},
            Result =
                <<"From: \"Admin & ' ( \\\"hallo\\\" ) ; , [ ] WS\" <a@example.com>\r\nMessage-ID: <abcd@example.com>\r\nMIME-Version: 1.0\r\nDate: Sun, 01 Nov 2009 14:44:47 +0200\r\n\r\nThis is a plain message">>,
            ?assertEqual(Result, encode(Email))
        end},
        {"multipart/alternative email", fun() ->
            Email =
                {<<"multipart">>, <<"alternative">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"To">>, <<"you@example.com">>},
                        {<<"Subject">>, <<"This is a test">>},
                        {<<"MIME-Version">>, <<"1.0">>},
                        {<<"Content-Type">>, <<"multipart/alternative; boundary=wtf-123234234">>}
                    ],
                    #{
                        content_type_params =>
                            [{<<"boundary">>, <<"wtf-123234234">>}],
                        disposition => <<"inline">>,
                        disposition_params => []
                    },
                    [
                        {<<"text">>, <<"plain">>,
                            [
                                {<<"Content-Type">>, <<"text/plain;charset=US-ASCII;format=flowed">>},
                                {<<"Content-Transfer-Encoding">>, <<"7bit">>}
                            ],
                            #{
                                content_type_params =>
                                    [
                                        {<<"charset">>, <<"US-ASCII">>},
                                        {<<"format">>, <<"flowed">>}
                                    ],
                                disposition => <<"inline">>,
                                disposition_params => []
                            },
                            <<"This message contains rich text.">>},
                        {<<"text">>, <<"html">>,
                            [
                                {<<"Content-Type">>, <<"text/html;charset=US-ASCII">>},
                                {<<"Content-Transfer-Encoding">>, <<"7bit">>}
                            ],
                            #{
                                content_type_params =>
                                    [{<<"charset">>, <<"US-ASCII">>}],
                                disposition => <<"inline">>,
                                disposition_params => []
                            },
                            <<"<html><body>This message also contains HTML</body></html>">>}
                    ]},
            Result = decode(encode(Email)),
            ?assertMatch(
                {<<"multipart">>, <<"alternative">>, _, _, [
                    {<<"text">>, <<"plain">>, _, _, _}, {<<"text">>, <<"html">>, _, _, _}
                ]},
                Result
            )
        end},
        {"multipart/alternative email with encoding", fun() ->
            Email =
                {<<"multipart">>, <<"alternative">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"To">>, <<"you@example.com">>},
                        {<<"Subject">>, <<"This is a test">>},
                        {<<"MIME-Version">>, <<"1.0">>},
                        {<<"Content-Type">>, <<"multipart/alternative; boundary=wtf-123234234">>}
                    ],
                    #{
                        content_type_params =>
                            [{<<"boundary">>, <<"wtf-123234234">>}],
                        disposition => <<"inline">>,
                        disposition_params => []
                    },
                    [
                        {<<"text">>, <<"plain">>,
                            [
                                {<<"Content-Type">>, <<"text/plain;charset=US-ASCII;format=flowed">>},
                                {<<"Content-Transfer-Encoding">>, <<"quoted-printable">>}
                            ],
                            #{
                                content_type_params =>
                                    [
                                        {<<"charset">>, <<"US-ASCII">>},
                                        {<<"format">>, <<"flowed">>}
                                    ],
                                disposition => <<"inline">>,
                                disposition_params => []
                            },
                            <<"This message contains rich text.\r\n", "and is =quoted printable= encoded!">>},
                        {<<"text">>, <<"html">>,
                            [
                                {<<"Content-Type">>, <<"text/html;charset=US-ASCII">>},
                                {<<"Content-Transfer-Encoding">>, <<"base64">>}
                            ],
                            #{
                                content_type_params =>
                                    [{<<"charset">>, <<"US-ASCII">>}],
                                disposition => <<"inline">>,
                                disposition_params => []
                            },
                            <<"<html><body>This message also contains", "HTML and is base64",
                                "encoded\r\n\r\n</body></html>">>}
                    ]},
            Result = decode(encode(Email)),
            ?assertMatch(
                {<<"multipart">>, <<"alternative">>, _, _, [
                    {<<"text">>, <<"plain">>, _, _,
                        <<"This message contains rich text.\r\n", "and is =quoted printable= encoded!">>},
                    {<<"text">>, <<"html">>, _, _,
                        <<"<html><body>This message also contains", "HTML and is base64",
                            "encoded\r\n\r\n</body></html>">>}
                ]},
                Result
            )
        end},
        {"multipart/mixed email with multipart/alternative does not add an extra empty lines", fun() ->
            Email = Getmail("message-text-html-attachment.eml"),
            Encoded = encode(Email),
            Re = re:run(Encoded, "(?:\\r\\n){3}", [global, {capture, all, binary}]),
            ?assertMatch({match, [_]}, Re)
        end},
        {"Missing headers should be added", fun() ->
            Email =
                {<<"text">>, <<"plain">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"To">>, <<"you@example.com">>},
                        {<<"Subject">>, <<"This is a test">>}
                    ],
                    #{
                        content_type_params =>
                            [{<<"charset">>, <<"US-ASCII">>}],
                        disposition => <<"inline">>
                    },
                    <<"This is a plain message">>},
            Result = decode(encode(Email)),
            ?assertNot(undefined == proplists:get_value(<<"Message-ID">>, element(3, Result))),
            ?assertNot(undefined == proplists:get_value(<<"Date">>, element(3, Result))),
            ?assertEqual(undefined, proplists:get_value(<<"References">>, element(3, Result)))
        end},
        {"Reference header should be added in presence of In-Reply-To", fun() ->
            Email =
                {<<"text">>, <<"plain">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"To">>, <<"you@example.com">>},
                        {<<"In-Reply-To">>, <<"<abcd@example.com>">>},
                        {<<"Subject">>, <<"This is a test">>}
                    ],
                    #{
                        content_type_params =>
                            [{<<"charset">>, <<"US-ASCII">>}],
                        disposition => <<"inline">>
                    },
                    <<"This is a plain message">>},
            Result = decode(encode(Email)),
            ?assertEqual(<<"<abcd@example.com>">>, proplists:get_value(<<"References">>, element(3, Result)))
        end},
        {"Reference header should be appended to in presence of In-Reply-To, if appropriate", fun() ->
            Email =
                {<<"text">>, <<"plain">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"To">>, <<"you@example.com">>},
                        {<<"In-Reply-To">>, <<"<abcd@example.com>">>},
                        {<<"References">>, <<"<wxyz@example.com>">>},
                        {<<"Subject">>, <<"This is a test">>}
                    ],
                    #{
                        content_type_params =>
                            [{<<"charset">>, <<"US-ASCII">>}],
                        disposition => <<"inline">>
                    },
                    <<"This is a plain message">>},
            Result = decode(encode(Email)),
            ?assertEqual(
                <<"<wxyz@example.com> <abcd@example.com>">>, proplists:get_value(<<"References">>, element(3, Result))
            )
        end},
        {"Reference header should NOT be appended to in presence of In-Reply-To, if already present", fun() ->
            Email =
                {<<"text">>, <<"plain">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"To">>, <<"you@example.com">>},
                        {<<"In-Reply-To">>, <<"<abcd@example.com>">>},
                        {<<"References">>, <<"<wxyz@example.com> <abcd@example.com>">>},
                        {<<"Subject">>, <<"This is a test">>}
                    ],
                    #{
                        content_type_params =>
                            [{<<"charset">>, <<"US-ASCII">>}],
                        disposition => <<"inline">>
                    },
                    <<"This is a plain message">>},
            Result = decode(encode(Email)),
            ?assertEqual(
                <<"<wxyz@example.com> <abcd@example.com>">>, proplists:get_value(<<"References">>, element(3, Result))
            )
        end},
        {"Content-Transfer-Encoding header should be added if missing and appropriate", fun() ->
            Email =
                {<<"text">>, <<"plain">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"To">>, <<"you@example.com">>},
                        {<<"Subject">>, <<"This is a test">>}
                    ],
                    #{}, <<"This is a plain message with some non-ascii characters øÿ\r\nso there"/utf8>>},
            Encoded = encode(Email),
            Result = decode(Encoded),
            ?assertEqual(
                <<"quoted-printable">>, proplists:get_value(<<"Content-Transfer-Encoding">>, element(3, Result))
            ),
            Email2 =
                {<<"text">>, <<"plain">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"To">>, <<"you@example.com">>},
                        {<<"Subject">>, <<"This is a test">>}
                    ],
                    #{}, <<"This is a plain message with no non-ascii characters">>},
            Encoded2 = encode(Email2),
            Result2 = decode(Encoded2),
            ?assertEqual(undefined, proplists:get_value(<<"Content-Transfer-Encoding">>, element(3, Result2))),
            Email3 =
                {<<"text">>, <<"plain">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"To">>, <<"you@example.com">>},
                        {<<"Subject">>, <<"This is a test">>}
                    ],
                    #{transfer_encoding => <<"base64">>}, <<"This is a plain message with no non-ascii characters">>},
            Encoded3 = encode(Email3),
            Result3 = decode(Encoded3),
            ?assertEqual(<<"base64">>, proplists:get_value(<<"Content-Transfer-Encoding">>, element(3, Result3)))
        end},
        {"Content-Type header should be added if missing and appropriate", fun() ->
            Email =
                {<<"text">>, <<"html">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"To">>, <<"you@example.com">>},
                        {<<"Subject">>, <<"This is a test">>}
                    ],
                    #{}, <<"This is a HTML message with some non-ascii characters øÿ\r\nso there"/utf8>>},
            Encoded = encode(Email),
            Result = decode(Encoded),
            ?assertEqual(
                <<"quoted-printable">>, proplists:get_value(<<"Content-Transfer-Encoding">>, element(3, Result))
            ),
            ?assertMatch(<<"text/html;charset=utf-8">>, proplists:get_value(<<"Content-Type">>, element(3, Result))),
            Email2 =
                {<<"text">>, <<"html">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"To">>, <<"you@example.com">>},
                        {<<"Subject">>, <<"This is a test">>}
                    ],
                    #{}, <<"This is a HTML message with no non-ascii characters\r\nso there">>},
            Encoded2 = encode(Email2),
            Result2 = decode(Encoded2),
            ?assertMatch(
                <<"text/html;charset=us-ascii">>, proplists:get_value(<<"Content-Type">>, element(3, Result2))
            ),
            Email3 =
                {<<"text">>, <<"html">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"To">>, <<"you@example.com">>},
                        {<<"Subject">>, <<"This is a test">>}
                    ],
                    #{}, <<"This is a text message with some invisible non-ascii characters\r\nso there"/utf8>>},
            Encoded3 = encode(Email3),
            Result3 = decode(Encoded3),
            ?assertMatch(<<"text/html;charset=utf-8">>, proplists:get_value(<<"Content-Type">>, element(3, Result3)))
        end},
        {"Content-Type header should be added for subparts too, if missing and appropriate", fun() ->
            Email4 =
                {<<"multipart">>, <<"alternative">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"To">>, <<"you@example.com">>},
                        {<<"Subject">>, <<"This is a test">>}
                    ],
                    #{}, [
                        {<<"text">>, <<"plain">>, [], #{},
                            <<"This is a multipart message with some invisible non-ascii characters\r\nso there"/utf8>>}
                    ]},
            Encoded4 = encode(Email4),
            Result4 = decode(Encoded4),
            ?assertMatch(
                <<"text/plain;charset=utf-8">>,
                proplists:get_value(<<"Content-Type">>, element(3, lists:nth(1, element(5, Result4))))
            )
        end},
        {"Content-Type header should be not added for subparts if they're text/plain us-ascii", fun() ->
            Email4 =
                {<<"multipart">>, <<"alternative">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"To">>, <<"you@example.com">>},
                        {<<"Subject">>, <<"This is a test">>}
                    ],
                    #{}, [
                        {<<"text">>, <<"plain">>, [], #{},
                            <<"This is a multipart message with no non-ascii characters\r\nso there">>}
                    ]},
            Encoded4 = encode(Email4),
            Result4 = decode(Encoded4),
            ?assertMatch(
                undefined, proplists:get_value(<<"Content-Type">>, element(3, lists:nth(1, element(5, Result4))))
            )
        end},
        {"Content-Type header should be added for subparts if they're text/html us-ascii", fun() ->
            Email4 =
                {<<"multipart">>, <<"alternative">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"To">>, <<"you@example.com">>},
                        {<<"Subject">>, <<"This is a test">>}
                    ],
                    #{}, [
                        {<<"text">>, <<"html">>, [], #{},
                            <<"This is a multipart message with no non-ascii characters\r\nso there">>}
                    ]},
            Encoded4 = encode(Email4),
            Result4 = decode(Encoded4),
            ?assertMatch(
                <<"text/html;charset=us-ascii">>,
                proplists:get_value(<<"Content-Type">>, element(3, lists:nth(1, element(5, Result4))))
            )
        end},
        {"A boundary should be generated if applicable", fun() ->
            Email =
                {<<"multipart">>, <<"alternative">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"To">>, <<"you@example.com">>},
                        {<<"Subject">>, <<"This is a test">>}
                    ],
                    #{}, [
                        {<<"text">>, <<"plain">>, [], #{},
                            <<"This message contains rich text.\r\n", "and is =quoted printable= encoded!">>},
                        {<<"text">>, <<"html">>, [], #{},
                            <<"<html><body>This message also contains", "HTML and is base64",
                                "encoded\r\n\r\n</body></html>">>}
                    ]},
            Encoded = encode(Email),
            Result = decode(Encoded),
            Boundary = proplists:get_value(<<"boundary">>, maps:get(content_type_params, element(4, Result))),
            ?assert(is_binary(Boundary)),
            % ensure we don't add the header multiple times
            ?assertEqual(1, length(proplists:get_all_values(<<"Content-Type">>, element(3, Result)))),
            % headers should be appended, not prepended
            ?assertMatch({<<"From">>, _}, lists:nth(1, element(3, Result))),
            ok
        end}
    ].

roundtrip_test_() ->
    [
        {"roundtrip test for the gamut", fun() ->
            {ok, Email} = file:read_file("test/fixtures/the-gamut.eml"),
            Decoded = decode(Email),
            _Encoded = encode(Decoded),
            %{ok, F1} = file:open("f1", [write]),
            %{ok, F2} = file:open("f2", [write]),
            %file:write(F1, Email),
            %file:write(F2, Encoded),
            %file:close(F1),
            %file:close(F2),
            %?assertEqual(Email, Email),
            ok
        end},
        {"round trip plain text only email", fun() ->
            {ok, Email} = file:read_file("test/fixtures/Plain-text-only.eml"),
            Decoded = decode(Email),
            _Encoded = encode(Decoded),
            %{ok, F1} = file:open("f1", [write]),
            %{ok, F2} = file:open("f2", [write]),
            %file:write(F1, Email),
            %file:write(F2, Encoded),
            %file:close(F1),
            %file:close(F2),
            %?assertEqual(Email, Email),
            ok
        end},
        {"round trip quoted-printable email", fun() ->
            {ok, Email} = file:read_file("test/fixtures/testcase1"),
            Decoded = decode(Email),
            _Encoded = encode(Decoded),
            %{ok, F1} = file:open("f1", [write]),
            %{ok, F2} = file:open("f2", [write]),
            %file:write(F1, Email),
            %file:write(F2, Encoded),
            %file:close(F1),
            %file:close(F2),
            %?assertEqual(Email, Email),
            ok
        end}
    ].

dkim_canonicalization_test_() ->
    %% * canonicalization from #3.4.5
    Hdrs = [
        <<"A : X\r\n">>,
        <<"B : Y\t\r\n\tZ  \r\n">>
    ],
    Body = <<" C \r\nD \t E\r\n\r\n\r\n">>,
    [
        {"Simple body canonicalization", fun() ->
            ?assertEqual(<<" C \r\nD \t E\r\n">>, dkim_canonicalize_body(Body, simple)),
            ?assertEqual(<<"\r\n">>, dkim_canonicalize_body(<<>>, simple)),
            ?assertEqual(<<"\r\n">>, dkim_canonicalize_body(<<"\r\n\r\n\r\n">>, simple)),
            ?assertEqual(<<"A\r\n\r\nB\r\n">>, dkim_canonicalize_body(<<"A\r\n\r\nB\r\n\r\n">>, simple))
        end},
        {"Simple headers canonicalization", fun() ->
            ?assertEqual(
                [
                    <<"A : X\r\n">>,
                    <<"B : Y\t\r\n\tZ  \r\n">>
                ],
                dkim_canonicalize_headers(Hdrs, simple)
            )
        end},
        {"Relaxed headers canonicalization", fun() ->
            % \r\n's are stripped by current impl.
            ?assertEqual(
                [
                    <<"a:X">>,
                    <<"b:Y Z">>
                ],
                dkim_canonicalize_headers(Hdrs, relaxed)
            )
        end}
    ].

dkim_sign_rsa_test_() ->
    %% * sign using test/fixtures/dkim*.pem
    {ok, PrivKey} = file:read_file("test/fixtures/dkim-rsa-private.pem"),
    [
        {"Sign simple", fun() ->
            Email =
                {<<"text">>, <<"plain">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"Subject">>, <<"Hello world!">>},
                        {<<"Date">>, <<"Thu, 28 Nov 2013 04:15:44 +0400">>},
                        {<<"Message-ID">>, <<"the-id">>},
                        {<<"Content-Type">>, <<"text/plain; charset=utf-8">>}
                    ],
                    #{}, <<"123">>},
            Options = [
                {dkim, [
                    {s, <<"foo.bar">>},
                    {d, <<"example.com">>},
                    {c, {simple, simple}},
                    {t, {{2014, 2, 4}, {23, 15, 00}}},
                    {x, {{2114, 2, 4}, {23, 15, 00}}},
                    {private_key, {pem_plain, PrivKey}}
                ]}
            ],

            Enc = encode(Email, Options),
            %% This `Enc' value can be verified, for example, by Python script
            %% https://launchpad.net/dkimpy like:
            %% >>> pubkey = ''.join(open("test/fixtures/dkim-rsa-public.pem").read().splitlines()[1:-1])
            %% >>> dns_mock = lambda *args: 'v=DKIM1; g=*; k=rsa; p=' + pubkey
            %% >>> import dkim
            %% >>> d = dkim.DKIM(mime_message) % pass `Enc' value as 1'st argument
            %% >>> d.verify(dnsfunc=dns_mock)
            %% True
            {_, _, [{DkimHdrName, DkimHdrVal} | _], _, _} = decode(Enc),
            ?assertEqual(<<"DKIM-Signature">>, DkimHdrName),
            ?assertEqual(
                <<
                    "t=1391555700; x=4547229300; s=foo.bar; h=from:to:subject:date; d=example.com; c=simple/simple; "
                    "bh=Afm/S7SaxS19en1h955RwsupTF914DQUPqYU8Nh7kpw=; a=rsa-sha256; v=1; "
                    "b=Mtja7WpVvtOFT8rfzOS/2fRZ492jrgsHgD5YUl5zmPQ/NEEMjVhVX0JCkfZxWpxiKe"
                    "qwl7nTJy3xecdg12feGT1rGC+rV0vAX8LVc+AJ4T4A50hE8L4hpJ1Tv5rt2O2t0Xu1Wx"
                    "yH6Cmrhhh56istjL+ba+U1EHhV7uZXGpWXGa4="
                >>,
                DkimHdrVal
            )
        end},
        {"Sign relaxed headers, simple body", fun() ->
            Email =
                {<<"text">>, <<"plain">>,
                    [
                        {<<"From">>, <<"me@example.com">>},
                        {<<"Subject">>, <<"Hello world!">>},
                        {<<"Date">>, <<"Thu, 28 Nov 2013 04:15:44 +0400">>},
                        {<<"Message-ID">>, <<"the-id-relaxed">>},
                        {<<"Content-Type">>, <<"text/plain; charset=utf-8">>}
                    ],
                    #{}, <<"123">>},
            Options = [
                {dkim, [
                    {s, <<"foo.bar">>},
                    {d, <<"example.com">>},
                    {c, {relaxed, simple}},
                    {private_key, {pem_plain, PrivKey}}
                ]}
            ],

            Enc = encode(Email, Options),
            {_, _, [{DkimHdrName, DkimHdrVal} | _], _, _} = decode(Enc),
            ?assertEqual(<<"DKIM-Signature">>, DkimHdrName),
            ?assertEqual(
                <<
                    "s=foo.bar; h=from:to:subject:date; d=example.com; c=relaxed/simple; "
                    "bh=Afm/S7SaxS19en1h955RwsupTF914DQUPqYU8Nh7kpw=; a=rsa-sha256; v=1; "
                    "b=dXxKq6A7m4A3AoS90feuLP+IxOyXFTPIibja52E2JCAyOsxvIGlI51xR1LvmEaelv9"
                    "jJTH9iGyAC7RzTKxrWV1QXayvr05bsTy3vDw7P4vfZ1gmspuP/3Icw+J8KEn+p6+CRrf"
                    "T97QadH42PT6XmO2v01q5nhMgNE4yQyf9DBJs="
                >>,
                DkimHdrVal
            )
        end}
    ].

dkim_sign_ed25519_test_() ->
    case ed25519_supported() of
        true ->
            %% * sign using test/fixtures/dkim*.pem
            {ok, PrivKey} = file:read_file("test/fixtures/dkim-ed25519-private.pem"),
            [
                {"Sign simple", fun() ->
                    Email =
                        {<<"text">>, <<"plain">>,
                            [
                                {<<"From">>, <<"me@example.com">>},
                                {<<"Subject">>, <<"Hello world!">>},
                                {<<"Date">>, <<"Thu, 28 Nov 2013 04:15:44 +0400">>},
                                {<<"Message-ID">>, <<"the-id">>},
                                {<<"Content-Type">>, <<"text/plain; charset=utf-8">>}
                            ],
                            #{}, <<"123">>},
                    Options = [
                        {dkim, [
                            {s, <<"foo.bar">>},
                            {d, <<"example.com">>},
                            {c, {simple, simple}},
                            {a, 'ed25519-sha256'},
                            {t, {{2014, 2, 4}, {23, 15, 00}}},
                            {x, {{2114, 2, 4}, {23, 15, 00}}},
                            {private_key, {pem_plain, PrivKey}}
                        ]}
                    ],

                    Enc = encode(Email, Options),
                    %% This `Enc' value can be verified, for example, by Python script
                    %% https://launchpad.net/dkimpy like:
                    %% >>> pubkey = ''.join(open("test/fixtures/dkim-ed25519-public.pem").read().splitlines()[1:-1])
                    %% >>> dns_mock = lambda *args: 'v=DKIM1; g=*; k=ed25519; p=' + pubkey
                    %% >>> import dkim
                    %% >>> d = dkim.DKIM(mime_message) % pass `Enc' value as 1'st argument
                    %% >>> d.verify(dnsfunc=dns_mock)
                    %% True
                    {_, _, [{DkimHdrName, DkimHdrVal} | _], _, _} = decode(Enc),
                    ?assertEqual(<<"DKIM-Signature">>, DkimHdrName),
                    ?assertEqual(
                        <<
                            "t=1391555700; x=4547229300; s=foo.bar; h=from:to:subject:date; d=example.com; c=simple/simple; "
                            "bh=Afm/S7SaxS19en1h955RwsupTF914DQUPqYU8Nh7kpw=; a=ed25519-sha256; v=1; "
                            "b=bFPndkFlgpFbfVKBF9HiVkQQF/3ojOQT7ycrZYp0yYe4oyItUQexlvd+Q7BviiHv/seLVBESpBjLbthbfb5HDA=="
                        >>,
                        DkimHdrVal
                    )
                end},
                {"Sign relaxed headers, simple body", fun() ->
                    Email =
                        {<<"text">>, <<"plain">>,
                            [
                                {<<"From">>, <<"me@example.com">>},
                                {<<"Subject">>, <<"Hello world!">>},
                                {<<"Date">>, <<"Thu, 28 Nov 2013 04:15:44 +0400">>},
                                {<<"Message-ID">>, <<"the-id-relaxed">>},
                                {<<"Content-Type">>, <<"text/plain; charset=utf-8">>}
                            ],
                            #{}, <<"123">>},
                    Options = [
                        {dkim, [
                            {s, <<"foo.bar">>},
                            {d, <<"example.com">>},
                            {c, {relaxed, simple}},
                            {a, 'ed25519-sha256'},
                            {private_key, {pem_plain, PrivKey}}
                        ]}
                    ],

                    Enc = encode(Email, Options),
                    {_, _, [{DkimHdrName, DkimHdrVal} | _], _, _} = decode(Enc),
                    ?assertEqual(<<"DKIM-Signature">>, DkimHdrName),
                    ?assertEqual(
                        <<
                            "s=foo.bar; h=from:to:subject:date; d=example.com; c=relaxed/simple; "
                            "bh=Afm/S7SaxS19en1h955RwsupTF914DQUPqYU8Nh7kpw=; a=ed25519-sha256; v=1; "
                            "b=f7wORU/qmPr4q891m5zmZMadPm9n9e596mBJHBD6tE51PAl4pHdpw9xRC1kwLGmxPTEK5SiQluPVTbDHVhVZBQ=="
                        >>,
                        DkimHdrVal
                    )
                end}
            ];
        false ->
            []
    end.

dkim_sign_ed25519_encrypted_key_test_() ->
    case ed25519_supported() of
        true ->
            %% * sign using test/fixtures/dkim*.pem
            {ok, EncryptedPrivKey} =
                file:read_file("test/fixtures/dkim-ed25519-encrypted-private.pem"),
            [
                {"Sign encrypted", fun() ->
                    Email =
                        {<<"text">>, <<"plain">>,
                            [
                                {<<"From">>, <<"me@example.com">>},
                                {<<"Subject">>, <<"Hello world!">>},
                                {<<"Date">>, <<"Thu, 28 Nov 2013 04:15:44 +0400">>},
                                {<<"Message-ID">>, <<"the-id">>},
                                {<<"Content-Type">>, <<"text/plain; charset=utf-8">>}
                            ],
                            #{}, <<"123">>},
                    Options = [
                        {dkim, [
                            {s, <<"foo.bar">>},
                            {d, <<"example.com">>},
                            {c, {simple, simple}},
                            {a, 'ed25519-sha256'},
                            {t, {{2014, 2, 4}, {23, 15, 00}}},
                            {x, {{2114, 2, 4}, {23, 15, 00}}},
                            {private_key, {pem_encrypted, EncryptedPrivKey, "password"}}
                        ]}
                    ],

                    Enc = encode(Email, Options),
                    %% This `Enc' value can be verified, for example, by Python script
                    %% https://launchpad.net/dkimpy like:
                    %% >>> pubkey = ''.join(open("test/fixtures/dkim-ed25519-public.pem").read().splitlines()[1:-1])
                    %% >>> dns_mock = lambda *args: 'v=DKIM1; g=*; k=ed25519; p=' + pubkey
                    %% >>> import dkim
                    %% >>> d = dkim.DKIM(mime_message) % pass `Enc' value as 1'st argument
                    %% >>> d.verify(dnsfunc=dns_mock)
                    %% True
                    {_, _, [{DkimHdrName, DkimHdrVal} | _], _, _} = decode(Enc),
                    ?assertEqual(<<"DKIM-Signature">>, DkimHdrName),
                    ?assertEqual(
                        <<
                            "t=1391555700; x=4547229300; s=foo.bar; h=from:to:subject:date; d=example.com; c=simple/simple; "
                            "bh=Afm/S7SaxS19en1h955RwsupTF914DQUPqYU8Nh7kpw=; a=ed25519-sha256; v=1; "
                            "b=JgsuW5OmKPk188YRmxs1cLA8mrAf9FNC+s/PYK7Vat7HF4l7FglcoWWHqm0/Cg7o/V+8bP1RNwes1xDKS8/wDQ=="
                        >>,
                        DkimHdrVal
                    )
                end}
            ];
        false ->
            []
    end.

-endif.
