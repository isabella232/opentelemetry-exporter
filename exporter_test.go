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

package elastic_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	elastic "github.com/elastic/opentelemetry-exporter"
	"github.com/golang/protobuf/ptypes/timestamp"
	"go.elastic.co/apm/transport/transporttest"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
)

var logLevel = zap.LevelFlag("log.level", zapcore.InfoLevel, "Set the exporter log level")

func newExporter(t *testing.T) (*elastic.Exporter, *transporttest.RecorderTransport) {
	var recorder transporttest.RecorderTransport
	srv := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/intake/v2/events" {
				http.Error(w, "unknown path", http.StatusNotFound)
				return
			}
			if err := recorder.SendStream(r.Context(), r.Body); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}),
	)
	t.Cleanup(srv.Close)

	exporter, err := elastic.NewExporter(elastic.Config{
		APMServerURLs: []string{srv.URL},
		HTTPClient:    srv.Client(),
		Logger:        zaptest.NewLogger(t, zaptest.Level(logLevel)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return exporter, &recorder
}

func toTimestamp(t time.Time) *timestamp.Timestamp {
	unixNano := t.UnixNano()
	return &timestamp.Timestamp{
		Seconds: unixNano / int64(time.Second),
		Nanos:   int32(unixNano % int64(time.Second)),
	}
}
