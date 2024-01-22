module github.com/kubewarden/container-resources-policy

go 1.20

require (
	github.com/francoispqt/onelog v0.0.0-20190306043706-8c2bb31b10a4
	github.com/google/go-cmp v0.6.0
	github.com/google/gofuzz v1.2.0
	github.com/kubewarden/k8s-objects v1.27.0-kw4
	github.com/kubewarden/policy-sdk-go v0.5.2
	github.com/spf13/pflag v1.0.5
	github.com/wapc/wapc-guest-tinygo v0.3.3
	gopkg.in/inf.v0 v0.9.1
)

require (
	github.com/francoispqt/gojay v0.0.0-20181220093123-f2cc13a668ca // indirect
	github.com/go-openapi/strfmt v0.21.3 // indirect
)

replace github.com/go-openapi/strfmt => github.com/kubewarden/strfmt v0.1.3
