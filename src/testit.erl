-module(testit).
-compile(export_all).

-define(TFILE, "otp_src_R13B02.tar.gz").

reverse(Bin) ->
	Size = size(Bin),
	<<T:Size/bitstring-little>> = Bin,
	<<T:Size/bitstring-big>>.

test1() ->
	{ok, Email} = file:read_file(?TFILE),
	String = binary_to_list(Email),
	{Time, _} = timer:tc(lists, reverse, [String]),
	io:format("test1 ran in ~B~n", [Time]).

reverse_str(String) ->
	binary_to_list(reverse(list_to_binary(String))).

test2() ->
	{ok, Email} = file:read_file(?TFILE),
	String = binary_to_list(Email),
	{Time, _} = timer:tc(?MODULE, reverse_str, [String]),
	io:format("test2 ran in ~B~n", [Time]).

test3() ->
	{ok, Email} = file:read_file(?TFILE),
	{Time, Value} = timer:tc(?MODULE, reverse, [Email]),
	io:format("test3 ran in ~B~n", [Time]),
	case reverse(Email) of
		Email ->
			io:format("round trip success~n");
		_ ->
			io:format("round trip failed~n")
	end.

