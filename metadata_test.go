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
	"context"
	"testing"

	commonpb "github.com/census-instrumentation/opencensus-proto/gen-go/agent/common/v1"
	resourcepb "github.com/census-instrumentation/opencensus-proto/gen-go/resource/v1"
	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	elastic "github.com/elastic/opentelemetry-exporter"
	"github.com/open-telemetry/opentelemetry-collector/translator/conventions"
	"github.com/stretchr/testify/assert"
	"go.elastic.co/apm/model"
)

func TestMetadataDefaults(t *testing.T) {
	assert.Equal(t, metadata{
		service: model.Service{
			Name: "unknown",
			Agent: &model.Agent{
				Name:    "OpenTelemetry",
				Version: "unknown",
			},
		},
	}, metadataWithNodeResource(t, nil, nil))
}

func TestMetadataServiceName(t *testing.T) {
	metadata := metadataWithNodeResource(t, &commonpb.Node{
		ServiceInfo: &commonpb.ServiceInfo{Name: "foo"},
	}, nil)
	assert.Equal(t, "foo", metadata.service.Name)
}

func TestMetadataServiceVersion(t *testing.T) {
	metadata := metadataWithNodeResource(t, nil, &resourcepb.Resource{
		Labels: map[string]string{"service.version": "1.2.3"},
	})
	assert.Equal(t, "1.2.3", metadata.service.Version)
}

func TestMetadataSystemHostname(t *testing.T) {
	metadata := metadataWithNodeResource(t, &commonpb.Node{
		Identifier: &commonpb.ProcessIdentifier{HostName: "foo"},
	}, nil)
	assert.Equal(t, "foo", metadata.system.Hostname)
}

func TestMetadataProcessID(t *testing.T) {
	metadata := metadataWithNodeResource(t, &commonpb.Node{
		Identifier: &commonpb.ProcessIdentifier{Pid: 123},
	}, nil)
	assert.Equal(t, 123, metadata.process.Pid)
}

func TestMetadataServiceLanguageName(t *testing.T) {
	metadata := metadataWithNodeResource(t, &commonpb.Node{
		LibraryInfo: &commonpb.LibraryInfo{Language: commonpb.LibraryInfo_JAVA},
	}, nil)
	assert.Equal(t, "Java", metadata.service.Language.Name)
}

func TestMetadataAgentName(t *testing.T) {
	metadata := metadataWithNodeResource(t, &commonpb.Node{
		LibraryInfo: &commonpb.LibraryInfo{ExporterVersion: "exporter-version"},
	}, nil)
	assert.Equal(t, &model.Agent{
		Name:    "exporter-version",
		Version: "unknown",
	}, metadata.service.Agent)
}

func TestMetadataLabels(t *testing.T) {
	metadata := metadataWithNodeResource(t, &commonpb.Node{
		Attributes: map[string]string{
			"a": "b",
			"b": "c",
		},
	}, &resourcepb.Resource{
		Labels: map[string]string{
			"b": "c!", // overrides node label with same name
			"c": "d",

			// well known resource label, not carried across
			conventions.AttributeServiceVersion: "...",
		},
	})
	assert.Equal(t, model.StringMap{
		{Key: "a", Value: "b"},
		{Key: "b", Value: "c!"},
		{Key: "c", Value: "d"},
	}, metadata.labels)
}

func metadataWithNodeResource(t *testing.T, node *commonpb.Node, resource *resourcepb.Resource) metadata {
	exporter, recorder := newExporter(t)
	_, err := exporter.PushTraceData(context.Background(), elastic.TraceData{
		Node:     node,
		Resource: resource,
		Spans:    []*tracepb.Span{{}},
	})
	assert.NoError(t, err)

	var out metadata
	out.system, out.process, out.service, out.labels = recorder.Metadata()
	return out
}

type metadata struct {
	system  model.System
	process model.Process
	service model.Service
	labels  model.StringMap
}
