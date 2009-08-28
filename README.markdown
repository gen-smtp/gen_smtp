Mission
=======

Provide a generic SMTP server and client framework that can be extended via
callback modules in the OTP style. The goal is to make it easy to send and
receive email in Erlang without the hassle of POP/IMAP. This is *not* a true
mailserver - although you could build one with it.

The SMTP server supports PLAIN, LOGIN, CRAM-MD5 authentication as well as TLS.

Also included is a MIME encoder/decoder, sorta according to RFC204{5,6,7}.

Current Participants
====================

+ Andrew Thompson (andrew@hijacked.us)
+ Jack Danger Canty (code@jackcanty.com)