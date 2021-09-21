%% @doc Parser for [[https://datatracker.ietf.org/doc/html/rfc5322#section-3.4]] "mailbox-list" structure

Terminals
    qstring
    domain_literal
    atom
    '<'
    '>'
    ','
    '@'
    '.'
    ':'
    ';'.
Nonterminals
    root
    mailbox_list
    group
    mailbox
    name_addr
    addr_spec
    angle_addr
    display_name
    word
    local_part
    domain
    dot_atom.

Rootsymbol
    root.

root ->
	mailbox_list : {mailbox_list, '$1'}.
root ->
	group : {group, '$1'}.

group ->
	display_name ':' ';' : {'$1', []}.
group ->
	display_name ':' mailbox_list ';' : {'$1', '$3'}.

mailbox_list ->
	mailbox : ['$1'].
mailbox_list ->
	mailbox ',' mailbox_list : ['$1' | '$3'].

mailbox -> name_addr : '$1'.
mailbox -> addr_spec : {undefined, '$1'}.

name_addr ->
	angle_addr : {undefined, '$1'}.
name_addr ->
	display_name angle_addr : {'$1', '$2'}.

angle_addr ->
	'<' addr_spec '>' : '$2'.

addr_spec ->
	local_part '@' domain : {addr, '$1', '$3'}.

local_part ->
	dot_atom : '$1'.
local_part ->
	qstring : value_of('$1').

display_name ->
	word : '$1'.
display_name ->
	word display_name : '$1' ++ " " ++ '$2'.

word ->
	dot_atom : '$1'.
word ->
	qstring : unescape(value_of('$1')).	% same as local_part, but with unescaping (is it necessary?)

domain ->
	dot_atom : '$1'.
domain ->
	domain_literal : value_of('$1').

dot_atom ->
	atom : value_of('$1').
dot_atom ->
	atom '.' dot_atom : value_of('$1') ++ "." ++ '$3'.

Erlang code.
-ignore_xref([{smtp_rfc5322_parse, return_error, 2}]).

%% Unescaping
unescape([$\\, C | Tail]) ->
	%% unescaping
	[C | unescape(Tail)];
unescape([$" | Tail]) ->
	%% stripping quotes (only possible at start and end)
	unescape(Tail);
unescape([C | Tail]) ->
	[C | unescape(Tail)];
unescape([]) -> [].


value_of(Token) ->
    try element(3, Token)
    catch error:badarg ->
            error({badarg, Token})
    end.
