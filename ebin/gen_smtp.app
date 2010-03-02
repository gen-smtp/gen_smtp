{application, gen_smtp,
	[
		{description, "An erlang SMTP server/client framework, also includes tools for working with MIME email."},
		{modules,
			[
				binstr,
				gen_smtp_client,
				gen_smtp_server,
				gen_smtp_server_session,
				mimemail,
				smtp_util,
				socket
			]
		},
		{applications, [kernel, stdlib]}
	]
}.
