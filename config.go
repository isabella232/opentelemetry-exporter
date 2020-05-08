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

package elastic

import (
	"errors"
	"net/http"

	"go.uber.org/zap"
)

// Config holds configuration for NewExporter.
type Config struct {
	// APMServerURLs holds the APM Server URL(s).
	//
	// This is required.
	APMServerURLs []string

	// APIKey holds an API Key for authorization.
	//
	// This is required if APM Server has API Key authorization enabled.
	//
	// https://www.elastic.co/guide/en/apm/server/7.7/api-key-settings.html
	APIKey string

	// HTTPClient holds an *http.Client to use for communicating with the
	// APM Server(s).
	//
	// This is optional, and a new http.Client will be constructed if
	// unspecified.
	HTTPClient *http.Client

	// Logger holds a logger for logging the exporter's internal behaviour.
	//
	// This is optional, and zap.NewNop() will be used if Logger is nil.
	Logger *zap.Logger

	// SecretToken holds the secret token for authorization.
	//
	// This is required if APM Server has secret token authorization enabled.
	//
	// https://www.elastic.co/guide/en/apm/server/7.7/secret-token.html
	SecretToken string
}

// Validate validates the configuration.
func (cfg Config) Validate() error {
	if len(cfg.APMServerURLs) == 0 {
		return errors.New("APMServerURLs must be specified and non-empty")
	}
	return nil
}
