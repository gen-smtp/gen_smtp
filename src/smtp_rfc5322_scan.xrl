%% @doc Lexer for [[https://datatracker.ietf.org/doc/html/rfc5322#section-3.4]] "mailbox-list" structure
%% With unicode support from [[https://datatracker.ietf.org/doc/html/rfc6532]].
%% It's a bit more permissive compared to the one proposed in RFC.
%% It operates on codepoints! Not bytes! Use `unicode:characters_to_list/1'

Definitions.
%% Codepoint ranges which fit in 2/3/4 bytes of UTF-8; rfc3629#section-4
UTF8_2 = [\x{80}-\x{7FF}]
UTF8_3 = [\x{800}-\x{D7FF}\x{E000}-\x{FFFD}]
UTF8_4 = [\x{10000}-\x{10FFFF}]

Rules.

[\s\t]+ : skip_token.

%% rfc5322#section-3.2.5
%% Anything between double quotes, but double quotes inside should be escaped
"([^\"]|\\\")+" : {token, {qstring, TokenLine, TokenChars}}.

%% rfc5322#section-3.4.1
%% Anything between brackets, but closing bracket inside should be escaped
\[([^\]]|\\\])+\] : {token, {domain_literal, TokenLine, TokenChars}}.

%% rfc5322#section-3.2.3
([0-9a-zA-Z!#\$\%&\'*+\-/=?^_`\{|\}~]|{UTF8_2}|{UTF8_3}|{UTF8_4})+ : {token, {atom, TokenLine, TokenChars}}.

\< : {token, {'<', TokenLine}}.
\> : {token, {'>', TokenLine}}.
\, : {token, {',', TokenLine}}.
@ : {token, {'@', TokenLine}}.
\. : {token, {'.', TokenLine}}.
% mailbox group
\: : {token, {':', TokenLine}}.
\; : {token, {';', TokenLine}}.

Erlang code.
