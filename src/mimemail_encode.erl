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
-module(mimemail_encode).

-export([encode/1]).

encode({ContentType1, ContentType2, Headers, ContentTypeParams, Parts}) ->
	{
		encode_headers(Headers),
		encode_component(Headers, ContentTypeParams, Parts) ++ [""]
	};

encode(_) ->
	io:format("Not a mime-decoded message~n"),
	erlang:error(non_mime).


encode_headers(Headers) ->
	encode_headers(Headers, []).
encode_headers([], EncodedHeaders) ->
	EncodedHeaders;
encode_headers([{Key, Value}|T] = Headers, EncodedHeaders) ->
	encode_headers(T, encode_folded_header(Key++": "++Value, EncodedHeaders)).

encode_folded_header(Header, HeaderLines) ->
  case string:str(Header, ";") of
		0 ->
			HeaderLines ++ [Header];
		Index ->
			Remainder = string:substr(Header, Index+1),
			TabbedRemainder = case Remainder of
				[$\t|_] -> Remainder;
				_       -> "\t"++Remainder
			end,
			HeaderLines ++
			[ string:substr(Header, 1, Index) ] ++
			encode_folded_header(TabbedRemainder, [])
	end.



encode_component(Headers, Params, Parts) ->
	case Params of
		% is this a multipart component?
		[	{"content-type-params", [{"boundary", Boundary}]},
			{"disposition", "inline"},
			{"disposition-params", []}
		] ->
			[""] ++  % blank line before start of component
			lists:flatmap(
				fun(PartLines) ->
					["--"++Boundary] ++ % start with the boundary
					PartLines
				end,
				encode_component_parts(Params, Parts)
			) ++ ["--"++Boundary++"--"]; % final boundary (with /--$/)
		% is this a simple inline component?
		[	{"content-type-params", ParamHeaders},
			{"disposition", "inline"},
			{"disposition-params", []}
		] ->
			% this is a string split by newlines
			string:tokens(Parts, "\r\n");
	  Other ->
		  [Parts]
	end.

encode_component_parts(Params, Parts) ->
	lists:map(
		fun(Part) -> encode_component_part(Part) end,
		Parts
	).

encode_component_part(Part) ->
	case Part of
		{"multipart", _, Headers, PartParams, Body} ->
			encode_headers(Headers) ++ encode_component(Headers, PartParams, Body);

		{"message", "rfc822", Headers,
		[{"content-type-params", TypeParams},
		 {"disposition", "attachment"}, _],
		Body} ->
			PartData = case Body of
				{_,_,_,_,_} -> encode_component_part(Body);
				String      -> [String]
			end,
			encode_headers(Headers) ++ [""] ++ PartData;

		{Type, SubType, Headers, PartParams, Body} ->
			PartData = case Body of
				{_,_,_,_,_} -> encode_component_part(Body);
				String      -> [String]
			end,
			encode_headers(Headers) ++ [""] ++ encode_body(
																						proplists:get_value("Content-Transfer-Encoding", Headers),
																						PartData
																				 );

		_ ->
			io:format("encode_component_part couldn't match Part to: ~p~n", [Part]),
			[]
	end.

encode_body(undefined, Body) ->
	Body;
encode_body(Type, Body) ->
	case string:to_lower(Type) of
		"quoted-printable" ->
			% TODO: examine whether this could be necessary to implement
			% encode_quoted_printable(Body);
			Body;
		"base64" ->
			[InnerBody] = Body,
			wrap_to_76(base64:encode_to_string(InnerBody));
		Other ->
			Body
	end.

wrap_to_76(String) ->
	wrap_to_76(String, []).
wrap_to_76([], Lines) ->
	Lines;
wrap_to_76(String, Lines) when length(String) >= 76 ->
	wrap_to_76(
		string:substr(String, 76+1),
		Lines ++ [string:substr(String, 1, 76)]
	);
wrap_to_76(String, Lines) ->
	wrap_to_76(
		[],
		Lines ++ [String]
	).

