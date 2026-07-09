# frozen_string_literal: true
#
# Primary usage of the jwt gem from Ruby, running under go-embedded-ruby (rbgo).
# JWT.encode signs a payload into a compact JWS token; JWT.decode verifies it and
# returns [payload, header].

require "jwt"

secret = "s3cr3t"

# Sign a payload with HMAC-SHA256 (the default algorithm).
token = JWT.encode({ "user_id" => 42, "role" => "admin" }, secret, "HS256")
puts "token:  #{token}"

# Verify and decode; the algorithm must be allow-listed.
payload, header = JWT.decode(token, secret, true, { algorithm: "HS256" })
puts "payload: #{payload.inspect}"
puts "header:  #{header.inspect}"

# A wrong key fails verification with JWT::VerificationError.
begin
  JWT.decode(token, "wrong-key", true, { algorithm: "HS256" })
rescue JWT::VerificationError => e
  puts "rejected: #{e.message}"
end

# A past "exp" claim is enforced on decode, raising JWT::ExpiredSignature.
expired = JWT.encode({ "data" => "x", "exp" => 0 }, secret, "HS256")
begin
  JWT.decode(expired, secret, true, { algorithm: "HS256" })
rescue JWT::ExpiredSignature => e
  puts "expired:  #{e.message}"
end
