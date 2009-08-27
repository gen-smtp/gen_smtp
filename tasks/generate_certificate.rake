require 'pty'
require 'expect'

$expect_verbose = false

file "server.key" do
	#print "Generating server.key..."
	#STDOUT.flush
	PTY.spawn("openssl genrsa -des3 -out server.key") do |reader, writer, pid|
		reader.expect(/^Enter pass phrase/) do |str|
			writer.puts "passphrase"
		end 
		reader.expect(/^Verifying/) do |str|
			writer.puts "passphrase"
		end 
	end
	#puts "ok"

	#print "Removing temporary passphrase from key..."
	#STDOUT.flush
	`cp server.key server.key.secure`
	PTY.spawn("openssl rsa -in server.key.secure -out server.key") do |reader, writer, pid|
		reader.expect(/^Enter pass phrase/) do |str|
			writer.puts "passphrase"
		end 
	end
	#puts "ok"
end

file "server.csr" => ["server.key"] do
	PTY.spawn("openssl req -new -key server.key -out server.csr") do |reader, writer, pid|
		9.times do 
			reader.expect(/.+?:$/) do |str|
				print str
				STDOUT.flush
				writer.puts STDIN.gets
			end
		end
	end
end

file "server.crt" => ["server.key", "server.csr"] do
	`openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt`
end

task :generate_self_signed_certificate => ["server.crt"]

