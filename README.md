# gen_smtp

[![Hex pm](http://img.shields.io/hexpm/v/gen_smtp.svg?style=flat)](https://hex.pm/packages/gen_smtp)
[![CI](https://github.com/gen-smtp/gen_smtp/actions/workflows/ci.yml/badge.svg)](https://github.com/gen-smtp/gen_smtp/actions/workflows/ci.yml)
[![Docs](https://github.com/gen-smtp/gen_smtp/actions/workflows/docs.yml/badge.svg)](https://github.com/gen-smtp/gen_smtp/actions/workflows/docs.yml)

The Erlang SMTP client and server library.

## Mission

Provide a generic Erlang SMTP server framework that can be extended via
callback modules in the OTP style. A pure Erlang SMTP client is also included.
The goal is to make it easy to send and receive email in Erlang without the
hassle of POP/IMAP. This is *not* a complete mailserver - although it includes
most of the parts you'd need to build one.

The SMTP server/client supports PLAIN, LOGIN, CRAM-MD5 authentication as well
as STARTTLS and SSL (port 465).

Also included is a MIME encoder/decoder, sorta according to RFC204{5,6,7}.

IPv6 is also supported (at least serverside).

SMTP server uses ranch as socket acceptor. It can use Ranch 1.7+, as well as 2.x.

I (Vagabond) have had a simple gen_smtp based SMTP server receiving and parsing
copies of all my email for several months and its been able to handle over 100
thousand emails without leaking any RAM or crashing the erlang virtual machine.

## Current Participants

+ Andrew Thompson (andrew AT hijacked.us)
+ Jack Danger Canty (code AT jackcanty.com)
+ Micah Warren (micahw AT lordnull.com)
+ Arjan Scherpenisse (arjan AT botsquad.com)
+ Marc Worrell (marc AT worrell.nl)

## Who is using it?

+ gen_smtp is used to provide the email functionality of [OpenACD](https://github.com/OpenACD/OpenACD)
+ gen_smtp is used as both the SMTP server and SMTP client for [Zotonic](http://zotonic.com)
+ [Chicago Boss](http://www.chicagoboss.org/) uses gen_smtp for its mail API.
+ [Gmailbox](https://www.gmailbox.org) uses gen_smtp to provide a free email forwarding service.
+ [JOSHMARTIN GmbH](https://joshmartin.ch/) uses gen_smtp to send emails in [Hygeia](https://covid19-tracing.ch/) to send emails for contact tracing of SARS-CoV-2.
+ many libraries [depend on gen_smtp](https://hex.pm/packages/gen_smtp) according to hex.pm

If you'd like to share your usage of gen_smtp, please submit a PR to this readme.

# Usage

## Client Example

Here's an example usage of the client:

```erlang
gen_smtp_client:send({"whatever@test.com", ["andrew@hijacked.us"],
 "Subject: testing\r\nFrom: Andrew Thompson <andrew@hijacked.us>\r\nTo: Some Dude <foo@bar.com>\r\n\r\nThis is the email body"},
  [{relay, "smtp.gmail.com"}, {username, "me@gmail.com"}, {password, "mypassword"}]).
```

The From and To addresses will be wrapped in &lt;&gt;s if they aren't already,
TLS will be auto-negotiated if available (unless you pass `{tls, never}`) and
authentication will by attempted by default since a username/password were
specified (`{auth, never}` overrides this).

If you want to mandate tls or auth, you can pass `{tls, always}` or `{auth,
always}` as one of the options. You can specify an alternate port with `{port,
2525}` (default is 25) or you can indicate that the server is listening for SSL
connections using `{ssl, true}` (port defaults to 465 with this option).

### Options

    send(Email, Options)
    send(Email, Options, Callback)
    send_blocking(Email, Options)

The `send` method variants `send/2, send/3, send_blocking/2` take an `Options` argument.
`Options` must be a proplist with the following valid values:

  * **relay** the smtp relay, e.g. `"smtp.gmail.com"`
  * **username** the username of the smtp relay e.g. `"me@gmail.com"`
  * **password** the password of the smtp relay e.g. `"mypassword"`
  * **auth** whether the smtp server needs authentication. Valid values are `if_available`, `always`, and `never`. Defaults to `if_available`. If your smtp relay requires authentication set it to `always`
  * **ssl** whether to connect on 465 in ssl mode. Defaults to `false`
  * **tls** valid values are `always`, `never`, `if_available`. Most modern smtp relays use tls, so set this to `always`. Defaults to `if_available`
  * **tls_options** used in `ssl:connect`, More info at http://erlang.org/doc/man/ssl.html . Defaults to `[{versions , ['tlsv1', 'tlsv1.1', 'tlsv1.2']}]`. This is merged with options listed at: https://github.com/gen-smtp/gen_smtp/blob/master/src/smtp_socket.erl#L46 . Any options not present in this list will be ignored.
  * **hostname** the hostname to be used by the smtp relay. Defaults to: `smtp_util:guess_FQDN()`. The hostname on your computer might not be correct, so set this to a valid value.
  * **retries** how many retries per smtp host on temporary failure. Defaults to 1, which means it will retry once if there is a failure.


### DKIM signing of outgoing emails

You may wish to configure DKIM signing [RFC6376](https://datatracker.ietf.org/doc/html/rfc5672) or [RFC8463](https://datatracker.ietf.org/doc/html/rfc8463) (Ed25519) of outgoing emails
for better security. To do that you need public and private keys, which can be generated by
following commands:

```bash
# RSA
openssl genrsa -out private-key.pem 1024
openssl rsa -in private-key.pem -out public-key.pem -pubout

# Ed25519 - Erlang/OTP 24.1+ only!
openssl genpkey -algorithm ed25519 -out private-key.pem
openssl pkey -in private-key.pem -out public-key.pem -pubout
```

To send DKIM-signed email:

```erlang
{ok, PrivKey} = file:read_file("private-key.pem"),
DKIMOptions = [
    {s, <<"foo.bar">>},
    {d, <<"example.com">>},
	{private_key, {pem_plain, PrivKey}}]}
    %{private_key, {pem_encrypted, EncryptedPrivKey, "password"}}
],
SignedMailBody = \
 mimemail:encode({<<"text">>, <<"plain">>,
                  [{<<"Subject">>, <<"DKIM testing">>},
                   {<<"From">>, <<"Andrew Thompson <andrew@hijacked.us>">>},
                   {<<"To">>, <<"Some Dude <foo@bar.com>">>}],
                  #{},
                  <<"This is the email body">>},
                  [{dkim, DKIMOptions}]),
gen_smtp_client:send({"whatever@example.com", ["andrew@hijacked.us"], SignedMailBody}, []).
```

For using Ed25519 you need to set the option `{a, 'ed25519-sha256'}`.

Don't forget to put your public key to `foo.bar._domainkey.example.com` TXT DNS record as something like

RSA:
```
v=DKIM1; g=*; k=rsa; p=MIGfMA0GCSqGSIb3DQEBA......
```

Ed25519:
```
v=DKIM1; g=*; k=ed25519; p=MIGfMA0GCSqGSIb3DQEBA......
```

See RFC6376 for more details.

## Server Example

`gen_smtp` ships with a simple callback server example, `smtp_server_example`. To start the SMTP server with this as the callback module, issue the following command:

```erlang
gen_smtp_server:start(smtp_server_example).
gen_smtp_server starting at nonode@nohost
listening on {0,0,0,0}:2525 via tcp
{ok,<0.33.0>}
```

By default it listens on 0.0.0.0 port 2525. You can telnet to it and test it:

```
^andrew@orz-dashes:: telnet localhost 2525                                                      [~]
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
220 localhost ESMTP smtp_server_example
EHLO example.com
250-orz-dashes
250-SIZE 10485670
250-8BITMIME
250-PIPELINING
250 WTF
MAIL FROM: andrew@hijacked.us
250 sender Ok
RCPT TO: andrew@hijacked.us
250 recipient Ok
DATA
354 enter mail, end with line containing only '.'
Good evening gentlemen, all your base are belong to us.
.
250 queued as #Ref<0.0.0.47>
QUIT
221 Bye
Connection closed by foreign host.
```

You can configure the server in general, each SMTP session, and the callback module, for example:

```erlang
gen_smtp_server:start(
    smtp_server_example,
    [{sessionoptions, [{allow_bare_newlines, fix},
                       {callbackoptions, [{parse, true}]}]}]).
```

This configures the session to fix bare newlines (other options are `strip`, `ignore` and `false`: `false` rejects emails with bare newlines, `ignore` passes them through unmodified and `strip` removes them) and tells the callback module to run the MIME decoder on the email once its been received. The example callback module also supports the following options: `relay` - whether to relay email on, `auth` - whether to do SMTP authentication and `parse` - whether to invoke the MIME parser. The example callback module is included mainly as an example and are not intended for serious usage. You could easily create your own callback options.
In general, following options can be specified `gen_smtp_server:options()`:

* `{domain, string()}` - is used as server hostname (it's placed to SMTP server banner and HELO/EHLO response), default - guess from machine hostname
* `{address, inet:ip4_address()}` - IP address to listen on, default `{0, 0, 0, 0}`
* `{port, inet:port_number()}` - port to listen on, default `2525`
* `{family, inet | inet6}` - IP address type (IPv4/IPv6), default `inet`
* `{protocol, tcp | ssl}` - listen in tcp or ssl mode, default `tcp`
* `{ranch_opts, ranch:opts()}` - format depends on ranch version. Consult Ranch documentation.
* `{sessionoptions, gen_smtp_server_session:options()}` - see below

Session options are:

* `{allow_bare_newlines, false | ignore | fix | strip}` - see above
* `{hostname, inet:hostname()}` - which hostname server should send in response
  to `HELO` / `EHLO` commands. Default: `inet:gethostname()`.
* `{tls_options, [ssl:server_option()]}` - options to pass to `ssl:handshake/3` (OTP-21+) / `ssl:ssl_accept/3`
  when `STARTTLS` command is sent by the client. Only needed if `STARTTLS` extension
  is enabled
* `{protocol, smtp | lmtp}` - when `lmtp` is passed, the control flow of the
  [Local Mail Transfer Protocol](https://tools.ietf.org/html/rfc2033) is applied.
  LMTP is derived from SMTP with just a few variations and is used by standard
  [Mail Transfer Agents (MTA)](https://en.wikipedia.org/wiki/Message_transfer_agent), like Postfix, Exim and OpenSMTPD to
  send incoming email to local mail-handling applications that usually don't have a delivery queue.
  The default value of this option is `smtp`.
* `{callbackoptions, any()}` - value will be passed as 4th argument to callback module's `init/4`

You can connect and test this using the `gen_smtp_client` via something like:

```erlang
gen_smtp_client:send(
    {"whatever@test.com", ["andrew@hijacked.us"], "Subject: testing\r\nFrom: Andrew Thompson \r\nTo: Some Dude \r\n\r\nThis is the email body"},
    [{relay, "localhost"}, {port, 2525}]).
```

If you want to listen on IPv6, you can use the `{family, inet6}` and `{address, "::"}` options to enable listening on IPv6.

Please notice that when using the LMTP protocol, the `handle_EHLO` callback will be used
to handle the `LHLO` command as defined in [RFC2033](https://tools.ietf.org/html/rfc2033),
due to their similarities. Although not used, the implementation of `handle_HELO` is still
mandatory for the general `gen_smtp_server_session` behaviour (you can simply
return a 500 error, e.g. `{error, "500 LMTP server, not SMTP"}`).

## Dependency on iconv

gen_smtp relies on iconv for text encoding and decoding when parsing is activated.

To use gen_smtp, a `eiconv` module must be loaded, with a `convert/3` function.

You can use [Zotonic/eiconv](https://github.com/zotonic/eiconv), which is used
for tests on the project.

For that, you can add the following line to your `rebar.config` file:

```
{deps, [
  {eiconv, "1.0.0"}
]}.
```
