# Go Library for PaSoRi and FeliCa Lite-S
[![Go Reference](https://pkg.go.dev/badge/github.com/tpc3/go-felica.svg)](https://pkg.go.dev/github.com/tpc3/go-felica)

## Introduction 
This library provides utility to interact with FeliCa Lite-S.

- To interact with card with PC/SC, use `felica_pcsc` which require CGO.
- To genearte Key or MAC, use `felica` which don't require PC/SC

## Installation

```
go get github.com/tpc3/go-felica
```

## Features
- Generate Card Key from Master Key
- Generate Session Key and MAC from Card Key
- Read, ReadWithMac, Write, and WriteWithMac to FeliCa Lite-S card with PaSoRi through PC/SC
