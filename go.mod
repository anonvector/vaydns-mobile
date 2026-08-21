module vaydns-mobile

go 1.24.4

require (
	github.com/net2share/vaydns v0.0.0-00010101000000-000000000000
	github.com/refraction-networking/utls v1.8.2
	github.com/xtaci/kcp-go/v5 v5.6.61
	github.com/xtaci/smux v1.5.50
	golang.org/x/mobile v0.0.0-20260204172633-1dceadbbeea3
	golang.org/x/net v0.49.0
)

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/flynn/noise v1.1.0 // indirect
	github.com/klauspost/compress v1.18.3 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.13.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/mod v0.32.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.org/x/tools v0.41.0 // indirect
)

replace github.com/net2share/vaydns => ../vaydns

replace github.com/xtaci/kcp-go/v5 => github.com/net2share/kcp-go/v5 v5.0.0-20260325165956-416ba9d3856d
