# Ruby examples

Pure-Ruby examples of the `jwt` gem — the Ruby face of this library — verified by
running under [go-embedded-ruby](https://github.com/go-embedded-ruby/ruby) (rbgo)
via its `require "jwt"` binding.

```sh
rbgo examples/jwt_usage.rb
```

| File | Shows |
| --- | --- |
| [`jwt_usage.rb`](jwt_usage.rb) | Sign a payload with `JWT.encode` (HS256), verify and read it back with `JWT.decode`, and rescue `JWT::VerificationError` / `JWT::ExpiredSignature`. |
