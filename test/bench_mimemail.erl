%% @doc Benchmarks for `mimemail' module
-module(bench_mimemail).


-export([parse_plain/1, bench_parse_plain/2,
		 parse_quoted_printable/1, bench_parse_quoted_printable/2,
		 parse_base64/1, bench_parse_base64/2,
		 parse_gamut/1, bench_parse_gamut/2
		]).
-export([encode_plain/1, bench_encode_plain/2,
		 encode_bin_attach/1, bench_encode_bin_attach/2,
		 encode_dkim_ss/1, bench_encode_dkim_ss/2,
		 encode_dkim_rs/1, bench_encode_dkim_rs/2]).

%% Parsing

%% @doc benchmark plaintext email decoding
parse_plain({input, _}) ->
	read_fixture("Plain-text-only.eml").

bench_parse_plain(Bin, _) ->
	{_, _, _, _, _} = mimemail:decode(Bin).


%% @doc bench email with quoted-printable body
parse_quoted_printable({input, _}) ->
	read_fixture("shift-jismail").

bench_parse_quoted_printable(Bin, _) ->
	{_, _, _, _, _} = mimemail:decode(Bin).


%% @doc bench decoding of email with only base64 content
parse_base64({input, _}) ->
	read_fixture("image-attachment-only.eml").

bench_parse_base64(Bin, _) ->
	{_, _, _, _, _} = mimemail:decode(Bin).


%% @doc bench decoding of email with many different bodies
parse_gamut({input, _}) ->
	read_fixture("the-gamut.eml").

bench_parse_gamut(Bin, _) ->
	{_, _, _, _, _} = mimemail:decode(Bin).


%% Encoding

%% @doc bench encoding of plain email
encode_plain({input, _}) ->
	mimemail:decode(read_fixture("Plain-text-only.eml")).

bench_encode_plain(Mimetuple, _) ->
	mimemail:encode(Mimetuple).


%% @doc bench encoding of email with binary attachment
encode_bin_attach({input, _}) ->
	mimemail:decode(read_fixture("image-attachment-only.eml")).

bench_encode_bin_attach(Mimetuple, _) ->
	mimemail:encode(Mimetuple).


%% @doc bench encoding with relaxed/simple dkim signature
encode_dkim_rs({input, _}) ->
	Mail = mimemail:decode(read_fixture("image-attachment-only.eml")),
	PrivKey = read_fixture("dkim-rsa-private.pem"),
	Opts = [{dkim, [{s, <<"foo.bar">>},
					{d, <<"example.com">>},
					{c, {relaxed, simple}},
					{private_key, {pem_plain, PrivKey}}]}],
	{Mail, Opts}.

bench_encode_dkim_rs({Mimetuple, Opts}, _) ->
	mimemail:encode(Mimetuple, Opts).


%% @doc bench encoding with simple/simple dkim signature
encode_dkim_ss({input, _}) ->
	Mail = mimemail:decode(read_fixture("image-attachment-only.eml")),
	PrivKey = read_fixture("dkim-rsa-private.pem"),
	Opts = [{dkim, [{s, <<"foo.bar">>},
					{d, <<"example.com">>},
					{c, {simple, simple}},
					{private_key, {pem_plain, PrivKey}}]}],
	{Mail, Opts}.

bench_encode_dkim_ss({Mimetuple, Opts}, _) ->
	mimemail:encode(Mimetuple, Opts).


%%
%% Helpers
%%
read_fixture(Name) ->
	{ok, B} = file:read_file(filename:join(["test", "fixtures", Name])),
	B.
