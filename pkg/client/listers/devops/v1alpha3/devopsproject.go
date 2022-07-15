/*
Copyright 2020 The KubeSphere Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha3

import (
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	v1alpha3 "kubesphere.io/api/devops/v1alpha3"
)

// DevOpsProjectLister helps list DevOpsProjects.
// All objects returned here must be treated as read-only.
type DevOpsProjectLister interface {
	// List lists all DevOpsProjects in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha3.DevOpsProject, err error)
	// Get retrieves the DevOpsProject from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha3.DevOpsProject, error)
	DevOpsProjectListerExpansion
}

// devOpsProjectLister implements the DevOpsProjectLister interface.
type devOpsProjectLister struct {
	indexer cache.Indexer
}

// NewDevOpsProjectLister returns a new DevOpsProjectLister.
func NewDevOpsProjectLister(indexer cache.Indexer) DevOpsProjectLister {
	return &devOpsProjectLister{indexer: indexer}
}

// List lists all DevOpsProjects in the indexer.
func (s *devOpsProjectLister) List(selector labels.Selector) (ret []*v1alpha3.DevOpsProject, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha3.DevOpsProject))
	})
	return ret, err
}

// Get retrieves the DevOpsProject from the index for a given name.
func (s *devOpsProjectLister) Get(name string) (*v1alpha3.DevOpsProject, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha3.Resource("devopsproject"), name)
	}
	return obj.(*v1alpha3.DevOpsProject), nil
}
