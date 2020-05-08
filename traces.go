// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// Package elastic contains an opentelemetry-collector exporter
// for Elastic APM.
package elastic

import (
	"net"
	"net/url"
	"strconv"

	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	"github.com/open-telemetry/opentelemetry-collector/translator/conventions"
	otlptrace "github.com/open-telemetry/opentelemetry-proto/gen/go/trace/v1"
	"go.elastic.co/apm/model"
	"go.elastic.co/fastjson"
)

func encodeSpan(otelSpan *tracepb.Span, w *fastjson.Writer) error {
	var spanID, parentID model.SpanID
	var traceID model.TraceID
	copy(spanID[:], otelSpan.SpanId)
	copy(traceID[:], otelSpan.TraceId)
	root := copy(parentID[:], otelSpan.ParentSpanId) == 0

	startTime := parseTimestamp(otelSpan.StartTime)
	var duration float64
	if otelSpan.EndTime != nil && !startTime.IsZero() {
		duration = parseTimestamp(otelSpan.EndTime).Sub(startTime).Seconds() * 1000
	}

	name := otelSpan.GetName().GetValue()
	var transactionContext transactionContext
	if root || otelSpan.Kind == tracepb.Span_SERVER {
		transaction := model.Transaction{
			ID:        spanID,
			TraceID:   traceID,
			ParentID:  parentID,
			Name:      name,
			Timestamp: model.Time(startTime),
			Duration:  duration,
		}
		if err := setTransactionProperties(otelSpan, &transaction, &transactionContext); err != nil {
			return err
		}
		transaction.Context = transactionContext.modelContext()
		w.RawString(`{"transaction":`)
		if err := transaction.MarshalFastJSON(w); err != nil {
			return err
		}
		w.RawString("}\n")
	} else {
		span := model.Span{
			ID:        spanID,
			TraceID:   traceID,
			ParentID:  parentID,
			Timestamp: model.Time(startTime),
			Duration:  duration,
			Name:      name,
		}
		if err := setSpanProperties(otelSpan, &span); err != nil {
			return err
		}
		w.RawString(`{"span":`)
		if err := span.MarshalFastJSON(w); err != nil {
			return err
		}
		w.RawString("}\n")
	}

	// TODO(axw) we don't currently support sending arbitrary events
	// to Elastic APM Server. If/when we do, we should also transmit
	// otelSpan.TimeEvents. When there's a convention specified for
	// error events, we could send those.

	return nil
}

func setTransactionProperties(otelSpan *tracepb.Span, tx *model.Transaction, context *transactionContext) error {
	var (
		netHostName string
		netHostPort int
		netPeerIP   string
		netPeerPort int
	)

	for k, v := range otelSpan.GetAttributes().GetAttributeMap() {
		switch k {
		// http.*
		case conventions.AttributeHTTPMethod:
			context.setHTTPMethod(v.GetStringValue().GetValue())
		case conventions.AttributeHTTPURL:
			if err := context.setHTTPURL(v.GetStringValue().GetValue()); err != nil {
				return err
			}
		case conventions.AttributeHTTPTarget:
			if err := context.setHTTPURL(v.GetStringValue().GetValue()); err != nil {
				return err
			}
		case conventions.AttributeHTTPHost:
			if err := context.setHTTPHost(v.GetStringValue().GetValue()); err != nil {
				return err
			}
		case conventions.AttributeHTTPScheme:
			context.setHTTPScheme(v.GetStringValue().GetValue())
		case conventions.AttributeHTTPStatusCode:
			context.setHTTPStatusCode(int(v.GetIntValue()))
		case conventions.AttributeHTTPFlavor:
			context.setHTTPVersion(v.GetStringValue().GetValue())
		case conventions.AttributeHTTPServerName:
			context.setHTTPHostname(v.GetStringValue().GetValue())
		case conventions.AttributeHTTPClientIP:
			context.setHTTPRequestHeader("X-Forwarded-For", v.GetStringValue().GetValue())
		case conventions.AttributeHTTPUserAgent:
			context.setHTTPRequestHeader("User-Agent", v.GetStringValue().GetValue())
		case "http.remote_addr":
			// NOTE(axw) this is non-standard, sent by opentelemetry-go's othttp.
			// It's semantically equivalent to net.peer.ip+port.
			stringValue := v.GetStringValue().GetValue()
			ip, port, err := net.SplitHostPort(stringValue)
			if err != nil {
				ip = stringValue
			}
			if net.ParseIP(ip) != nil {
				netPeerIP = ip
				netPeerPort, _ = strconv.Atoi(port)
			}

		// net.*
		case conventions.AttributeNetPeerIP:
			netPeerIP = v.GetStringValue().GetValue()
		case conventions.AttributeNetPeerPort:
			netPeerPort = int(v.GetIntValue())
		case conventions.AttributeNetHostName:
			netHostName = v.GetStringValue().GetValue()
		case conventions.AttributeNetHostPort:
			netHostPort = int(v.GetIntValue())

		// other: record as a tag
		default:
			item := model.IfaceMapItem{Key: cleanLabelKey(k)}
			switch v := v.GetValue().(type) {
			case *tracepb.AttributeValue_StringValue:
				item.Value = truncate(v.StringValue.GetValue())
			case *tracepb.AttributeValue_IntValue:
				item.Value = v.IntValue
			case *tracepb.AttributeValue_DoubleValue:
				item.Value = v.DoubleValue
			case *tracepb.AttributeValue_BoolValue:
				item.Value = v.BoolValue
			}
			context.model.Tags = append(context.model.Tags, item)
		}
	}

	tx.Type = "unknown"
	if context.model.Request != nil {
		tx.Type = "request"
		if context.model.Request.URL.Protocol == "" {
			// A bit presumptuous, but OpenTelemetry clients
			// are expected to send the scheme; this is just
			// a failsafe.
			context.model.Request.URL.Protocol = "http"
		}
		if context.model.Request.URL.Hostname == "" {
			context.model.Request.URL.Hostname = netHostName
		}
		if context.model.Request.URL.Port == "" && netHostPort > 0 {
			context.model.Request.URL.Port = strconv.Itoa(netHostPort)
		}
		if netPeerIP != "" {
			remoteAddr := netPeerIP
			if netPeerPort > 0 {
				remoteAddr = net.JoinHostPort(remoteAddr, strconv.Itoa(netPeerPort))
			}
			context.setHTTPRemoteAddr(remoteAddr)
		}
	}

	if status := otelSpan.GetStatus(); status != nil {
		statusCode := status.GetCode()
		if statusCodeName, ok := otlptrace.Status_StatusCode_name[statusCode]; ok {
			tx.Result = statusCodeName
		} else {
			tx.Result = "unknown"
		}
	}
	return nil
}

func setSpanProperties(otelSpan *tracepb.Span, span *model.Span) error {
	var (
		context     spanContext
		netPeerName string
		netPeerIP   string
		netPeerPort int
	)

	for k, v := range otelSpan.GetAttributes().GetAttributeMap() {
		switch k {
		// http.*
		case conventions.AttributeHTTPURL:
			if err := context.setHTTPURL(v.GetStringValue().GetValue()); err != nil {
				return err
			}
		case conventions.AttributeHTTPTarget:
			if err := context.setHTTPURL(v.GetStringValue().GetValue()); err != nil {
				return err
			}
		case conventions.AttributeHTTPHost:
			context.setHTTPHost(v.GetStringValue().GetValue())
		case conventions.AttributeHTTPScheme:
			context.setHTTPScheme(v.GetStringValue().GetValue())
		case conventions.AttributeHTTPStatusCode:
			context.setHTTPStatusCode(int(v.GetIntValue()))

		// net.*
		case conventions.AttributeNetPeerName:
			netPeerIP = v.GetStringValue().GetValue()
		case conventions.AttributeNetPeerIP:
			netPeerIP = v.GetStringValue().GetValue()
		case conventions.AttributeNetPeerPort:
			netPeerPort = int(v.GetIntValue())

		// db.*
		case conventions.AttributeDBType:
			context.setDatabaseType(v.GetStringValue().GetValue())
		case conventions.AttributeDBInstance:
			context.setDatabaseInstance(v.GetStringValue().GetValue())
		case conventions.AttributeDBStatement:
			context.setDatabaseStatement(v.GetStringValue().GetValue())
		case conventions.AttributeDBUser:
			context.setDatabaseUser(v.GetStringValue().GetValue())

		// other: record as a tag
		default:
			item := model.IfaceMapItem{Key: cleanLabelKey(k)}
			switch v := v.GetValue().(type) {
			case *tracepb.AttributeValue_StringValue:
				item.Value = truncate(v.StringValue.GetValue())
			case *tracepb.AttributeValue_IntValue:
				item.Value = v.IntValue
			case *tracepb.AttributeValue_DoubleValue:
				item.Value = v.DoubleValue
			case *tracepb.AttributeValue_BoolValue:
				item.Value = v.BoolValue
			}
			context.model.Tags = append(context.model.Tags, item)
		}
	}

	span.Type = "app"
	if context.model.HTTP != nil {
		span.Type = "external"
		span.Subtype = "http"
		if context.http.URL != nil {
			if context.http.URL.Scheme == "" {
				// A bit presumptuous, but OpenTelemetry clients
				// are expected to send the scheme; this is just
				// a failsafe.
				context.http.URL.Scheme = "http"
			}
			if context.http.URL.Host == "" {
				hostname := netPeerName
				if hostname == "" {
					hostname = netPeerIP
				}
				if hostname != "" {
					host := hostname
					if netPeerPort > 0 {
						port := strconv.Itoa(netPeerPort)
						host = net.JoinHostPort(hostname, port)
					}
					context.http.URL.Host = host
				}
			}
		}
	}
	if context.model.Database != nil {
		span.Type = "db"
		span.Subtype = context.model.Database.Type
	}
	span.Context = context.modelContext()
	return nil
}

type transactionContext struct {
	model         model.Context
	request       model.Request
	requestSocket model.RequestSocket
	response      model.Response
	user          model.User
}

func (c *transactionContext) modelContext() *model.Context {
	switch {
	case c.model.Request != nil:
	case c.model.Response != nil:
	case c.model.User != nil:
	case len(c.model.Tags) != 0:
	default:
		return nil
	}
	return &c.model
}

func (c *transactionContext) setHTTPMethod(method string) {
	c.request.Method = truncate(method)
	c.model.Request = &c.request
}

func (c *transactionContext) setHTTPScheme(scheme string) {
	c.request.URL.Protocol = truncate(scheme)
	c.model.Request = &c.request
}

func (c *transactionContext) setHTTPURL(httpURL string) error {
	u, err := url.Parse(httpURL)
	if err != nil {
		return err
	}
	// http.url is typically a relative URL, i.e. missing
	// the scheme and host. Don't override those parts of
	// the URL if they're empty, as they may be set by
	// other attributes.
	if u.Scheme != "" {
		c.request.URL.Protocol = truncate(u.Scheme)
	}
	if hostname := u.Hostname(); hostname != "" {
		c.request.URL.Hostname = truncate(hostname)
	}
	if port := u.Port(); port != "" {
		c.request.URL.Port = truncate(u.Port())
	}
	c.request.URL.Path = truncate(u.Path)
	c.request.URL.Search = truncate(u.RawQuery)
	c.request.URL.Hash = truncate(u.Fragment)
	c.model.Request = &c.request
	return nil
}

func (c *transactionContext) setHTTPHost(hostport string) error {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return err
	}
	c.request.URL.Hostname = truncate(host)
	c.request.URL.Port = truncate(port)
	c.model.Request = &c.request
	return nil
}

func (c *transactionContext) setHTTPHostname(hostname string) {
	c.request.URL.Hostname = truncate(hostname)
	c.model.Request = &c.request
}

func (c *transactionContext) setHTTPVersion(version string) {
	c.request.HTTPVersion = truncate(version)
	c.model.Request = &c.request
}

func (c *transactionContext) setHTTPRemoteAddr(remoteAddr string) {
	c.requestSocket.RemoteAddress = truncate(remoteAddr)
	c.request.Socket = &c.requestSocket
	c.model.Request = &c.request
}

func (c *transactionContext) setHTTPRequestHeader(k string, v ...string) {
	for i := range v {
		v[i] = truncate(v[i])
	}
	c.request.Headers = append(c.request.Headers, model.Header{Key: truncate(k), Values: v})
	c.model.Request = &c.request
}

func (c *transactionContext) setHTTPStatusCode(statusCode int) {
	c.response.StatusCode = statusCode
	c.model.Response = &c.response
}

type spanContext struct {
	model   model.SpanContext
	http    model.HTTPSpanContext
	httpURL url.URL
	db      model.DatabaseSpanContext
}

func (c *spanContext) modelContext() *model.SpanContext {
	switch {
	case c.model.HTTP != nil:
	case c.model.Database != nil:
	case len(c.model.Tags) != 0:
	default:
		return nil
	}
	return &c.model
}

func (c *spanContext) setHTTPStatusCode(statusCode int) {
	c.http.StatusCode = statusCode
	// BUG(axw) apm-agent-go panics on marshalling if
	/// status code is set but URL is not.
	//
	// c.model.HTTP = &c.http
}

func (c *spanContext) setHTTPURL(httpURL string) error {
	u, err := url.Parse(httpURL)
	if err != nil {
		return err
	}
	// http.url may be a relative URL (http.target),
	// i.e. missing the scheme and host. Don't override
	// those parts of the URL if they're empty, as they
	// may be set by other attributes.
	if u.Scheme != "" {
		c.httpURL.Scheme = truncate(u.Scheme)
	}
	if u.Host != "" {
		c.httpURL.Host = truncate(u.Host)
	}
	c.httpURL.Path = truncate(u.Path)
	c.httpURL.RawQuery = truncate(u.RawQuery)
	c.httpURL.Fragment = truncate(u.Fragment)
	c.http.URL = &c.httpURL
	c.model.HTTP = &c.http
	return nil
}

func (c *spanContext) setHTTPScheme(httpScheme string) {
	c.httpURL.Scheme = truncate(httpScheme)
	c.http.URL = &c.httpURL
	c.model.HTTP = &c.http
}

func (c *spanContext) setHTTPHost(httpHost string) {
	c.httpURL.Host = truncate(httpHost)
	c.http.URL = &c.httpURL
	c.model.HTTP = &c.http
}

func (c *spanContext) setDatabaseType(dbType string) {
	c.db.Type = truncate(dbType)
	c.model.Database = &c.db
}

func (c *spanContext) setDatabaseInstance(dbInstance string) {
	c.db.Instance = truncate(dbInstance)
	c.model.Database = &c.db
}

func (c *spanContext) setDatabaseStatement(dbStatement string) {
	c.db.Statement = truncate(dbStatement)
	c.model.Database = &c.db
}

func (c *spanContext) setDatabaseUser(dbUser string) {
	c.db.User = truncate(dbUser)
	c.model.Database = &c.db
}
