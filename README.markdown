Mission
=======

Provide a generic SMTP server and client framework that can be extended via
callback modules in the OTP style. The goal is to make it easy to send and
receive email in Erlang without the hassle of POP/IMAP. This is *not* a true
mailserver - although you could build one with it.

The SMTP server/client supports PLAIN, LOGIN, CRAM-MD5 authentication as well
as STARTTLS and SSL (port 465).

Also included is a MIME encoder/decoder, sorta according to RFC204{5,6,7}.

I (Vagabond) have had a simple gen_smtp based SMTP server receiving and parsing
copies of all my email for several months and its been able to handle over 100
thousand emails without leaking any RAM or crashing the erlang virtual machine.

Current Participants
====================

+ Andrew Thompson (andrew@hijacked.us)
+ Jack Danger Canty (code@jackcanty.com)a

Example
=======

Here's an example usage of the client:

<pre>
gen_smtp_client:send({"whatever@test.com", ["andrew@hijacked.us"],
 "Subject: testing\r\nFrom: Andrew Thompson <andrew@hijacked.us>\r\nTo: Some Dude <foo@bar.com>\r\n\r\nThis is the email body"},
  [{relay, "smtp.gmail.com"}, {username, "me@gmail.com"}, {password, "mypassword"}]).
</pre>

The From and To addresses will be wrapped in &lt;&gt;s if they aren't already,
TLS will be auto-negotiated if available (unless you pass `{tls, never}`) and
authentication will by attempted by default since a username/password were
specified (`{auth, never}` overrides this).

If you want to mandate tls or auth, you can pass `{tls, always}` or `{auth,
always}` as one of the options. You can specify an alternate port with `{port,
2525}` (default is 25) or you can indicate that the server is listening for SSL
connections using `{ssl, true}` (port defaults to 465 with this option).
