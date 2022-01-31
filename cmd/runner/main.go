/*
Copyright 2021.

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

package main

import (
	"net"

	infrav1 "github.com/chanwit/tf-controller/api/v1alpha1"
	"github.com/chanwit/tf-controller/runner"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func main() {

	scheme := runtime.NewScheme()

	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		panic(err.Error())
	}
	if err := sourcev1.AddToScheme(scheme); err != nil {
		panic(err.Error())
	}
	if err := infrav1.AddToScheme(scheme); err != nil {
		panic(err.Error())
	}

	cfg := ctrl.GetConfigOrDie()
	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		panic(err.Error())
	}
	if k8sClient == nil {
		panic("k8sClient cannot be nil")
	}

	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		panic(err.Error())
	}

	server := grpc.NewServer()
	// local runner, use the same client as the manager
	runner.RegisterRunnerServer(server, &runner.TerraformRunnerServer{
		Client: k8sClient,
		Scheme: scheme,
	})

	if err := server.Serve(listener); err != nil {
		panic(err.Error())
	}

}
