#!/bin/sh
set -e

# Setup:
# mix escript.install hex ex_doc

# Usage:
# sh ./docs.sh

# Note:
# Source link inference (source-ref) will be set to the app version.
# Means a Git tag for the version must exist!

app_name="gen_smtp"

escript_get_app_vsn=$(cat <<EOF
{ok, [{_, _, App}]} = file:consult("src/${app_name}.app.src"),
io:format(proplists:get_value(vsn, App)),
halt(0)
EOF
)
app_vsn=$(erl -noshell -eval "$escript_get_app_vsn")

rebar3 compile
rebar3 edoc

~/.mix/escripts/ex_doc $app_name $app_vsn "_build/default/lib/$app_name/ebin" \
	--config docs.config \
	--source-ref $app_vsn \
	--paths "_build/default/lib/*/ebin"

echo "Generated docs v${app_vsn} (by $(~/.mix/escripts/ex_doc --version))"
