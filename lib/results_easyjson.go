// Code generated by easyjson for marshaling/unmarshaling. DO NOT EDIT.

package vegeta

import (
	json "encoding/json"
	time "time"

	easyjson "github.com/mailru/easyjson"
	jlexer "github.com/mailru/easyjson/jlexer"
	jwriter "github.com/mailru/easyjson/jwriter"
	"github.com/valyala/fasthttp"
)

// suppress unused package warning
var (
	_ *json.RawMessage
	_ *jlexer.Lexer
	_ *jwriter.Writer
	_ easyjson.Marshaler
)

func easyjsonBd1621b8DecodeGithubComTsenartVegetaLib(in *jlexer.Lexer, out *jsonResult) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeString()
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "attack":
			out.Attack = string(in.String())
		case "seq":
			out.Seq = uint64(in.Uint64())
		case "code":
			out.Code = uint16(in.Uint16())
		case "timestamp":
			if data := in.Raw(); in.Ok() {
				in.AddError((out.Timestamp).UnmarshalJSON(data))
			}
		case "latency":
			out.Latency = time.Duration(in.Int64())
		case "bytes_out":
			out.BytesOut = uint64(in.Uint64())
		case "bytes_in":
			out.BytesIn = uint64(in.Uint64())
		case "error":
			out.Error = string(in.String())
		case "body":
			if in.IsNull() {
				in.Skip()
				out.Body = nil
			} else {
				out.Body = in.Bytes()
			}
		case "method":
			out.Method = string(in.String())
		case "url":
			out.URL = string(in.String())
		case "headers":
			out.Headers = easyjsonUnmarshalHeaders(in)
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonBd1621b8EncodeGithubComTsenartVegetaLib(out *jwriter.Writer, in jsonResult) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"attack\":"
		out.RawString(prefix[1:])
		out.String(string(in.Attack))
	}
	{
		const prefix string = ",\"seq\":"
		out.RawString(prefix)
		out.Uint64(uint64(in.Seq))
	}
	{
		const prefix string = ",\"code\":"
		out.RawString(prefix)
		out.Uint16(uint16(in.Code))
	}
	{
		const prefix string = ",\"timestamp\":"
		out.RawString(prefix)
		out.Raw((in.Timestamp).MarshalJSON())
	}
	{
		const prefix string = ",\"latency\":"
		out.RawString(prefix)
		out.Int64(int64(in.Latency))
	}
	{
		const prefix string = ",\"bytes_out\":"
		out.RawString(prefix)
		out.Uint64(uint64(in.BytesOut))
	}
	{
		const prefix string = ",\"bytes_in\":"
		out.RawString(prefix)
		out.Uint64(uint64(in.BytesIn))
	}
	{
		const prefix string = ",\"error\":"
		out.RawString(prefix)
		out.String(string(in.Error))
	}
	{
		const prefix string = ",\"body\":"
		out.RawString(prefix)
		out.Base64Bytes(in.Body)
	}
	{
		const prefix string = ",\"method\":"
		out.RawString(prefix)
		out.String(string(in.Method))
	}
	{
		const prefix string = ",\"url\":"
		out.RawString(prefix)
		out.String(string(in.URL))
	}
	{
		const prefix string = ",\"headers\":"
		out.RawString(prefix)
		easyjsonMarshalHeaders(out, in.Headers)
	}
	out.RawByte('}')
}

func easyjsonUnmarshalHeaders(in *jlexer.Lexer) fasthttp.ResponseHeader {
	h := fasthttp.ResponseHeader{}
	in.Delim('[')
	for !in.IsDelim(']') {
		for in.IsDelim('{') {
			in.Delim('{')
			// var key string
			var values []string
			for !in.IsDelim('}') {
				k := in.UnsafeString()
				in.WantColon()
				if in.IsNull() {
					in.Skip()
					in.WantComma()
					continue
				}
				switch k {
				case "key":
					// key := in.String()
				case "value":
					values = append(values, in.String())
				}
				in.WantComma()
			}
			// h[key] = values

			in.Delim('}')
			in.WantComma()
		}
	}
	in.Delim(']')
	return h
}

func easyjsonMarshalHeaders(w *jwriter.Writer, h fasthttp.ResponseHeader) {
	w.RawByte('[')
	h.VisitAll(func(k, v []byte) {
		w.RawString(`{"key":`)
		w.String(string(k))
		w.RawString(`,"value":`)
		w.String(string(v))
		w.RawByte('}')
	})
	w.RawByte(']')
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v jsonResult) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonBd1621b8EncodeGithubComTsenartVegetaLib(w, v)
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *jsonResult) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonBd1621b8DecodeGithubComTsenartVegetaLib(l, v)
}
