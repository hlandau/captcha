# Go CAPTCHA Library

[![godocs.io](https://godocs.io/github.com/hlandau/captcha?status.svg)](https://godocs.io/github.com/hlandau/captcha)

A stateless CAPTCHA library for Go. Currently supports only image CAPTCHAs.

![Image](https://github.com/hlandau/captcha/raw/master/examples/DELOWANE.gif)
![Image](https://github.com/hlandau/captcha/raw/master/examples/LDRONTIT.gif)
![Image](https://github.com/hlandau/captcha/raw/master/examples/WHEEDOKS.gif)

What does “stateless” mean in this context? Images are deterministically
generated and verified from an opaque key-string passed by the client. This
string is generated by the server, and is encrypted and authenticated via NaCl
secretbox. This means that you don't need to keep track of the CAPTCHAs you issue:

  - You generate a new Instance, which is serialized as a base64-encoded
    encrypted, authenticated data structure. This string is called the Key.

  - You direct the user to the appropriate image serving handler, e.g.
    `/captcha/{Key}.gif`.

  - In the response form, you include the Key as a hidden field.

  - When you receive the response, you use the passed Key to verify the
    correctness of the response.

  - The Key is added to a spent CAPTCHA store. By default, an in-memory
    store is used; you may optionally implement your own. Keys are expired
    from the store once their natural expiry time is reached.

Here's a usage example:

```go

cfg := captcha.Config{
  Leeway: 1,   // allow one wrong character
  Width:  200,
  Height: 100,

  // Default expiry time 1 hour

  // EncryptionKey will be generated automatically if it is unset.
  // You must therefore set it if you have multiple servers.
}

cfg.SetFontPath(".../fonts/")

http.Handle("/captcha/", cfg.Handler("/captcha/"))

inst := cfg.NewInstance()
key  := cfg.Key(&inst)
imageURL := "/captcha/" + key

// Later

inst2, err := cfg.DecodeInstance(key)
if err != nil {
  // ...
  return
}

if cfg.Verify(inst2, userInput) {
  // CAPTCHA response was valid
}
```

Licence
-------

Image warping code was taken from [dchest/captcha](https://github.com/dchest/captcha).

    © 2011-2014 Dmitry Chestnykh <dmitry@codingrobots.com>    MIT License
    © 2015 Hugo Landau <hlandau@devever.net>                  MIT License

