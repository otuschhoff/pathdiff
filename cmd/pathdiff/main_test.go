package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestTrafficRecorder(t *testing.T) {
	server, client := net.Pipe()
	recorder, err := newTrafficRecorder(server, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("request"))
		done <- err
	}()
	buffer := make([]byte, len("request"))
	if _, err := recorder.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	done = make(chan error, 1)
	go func() {
		buffer := make([]byte, len("response"))
		_, err := client.Read(buffer)
		done <- err
	}()
	if _, err := recorder.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	inFiles, err := filepath.Glob(filepath.Join(filepath.Dir(recorder.in.Name()), "*.in"))
	if err != nil || len(inFiles) != 1 {
		t.Fatalf("in capture files = %v, err = %v", inFiles, err)
	}
	outFiles, err := filepath.Glob(filepath.Join(filepath.Dir(recorder.out.Name()), "*.out"))
	if err != nil || len(outFiles) != 1 {
		t.Fatalf("out capture files = %v, err = %v", outFiles, err)
	}
	in, err := os.ReadFile(inFiles[0])
	if err != nil || string(in) != "request" {
		t.Fatalf("in capture = %q, err = %v", in, err)
	}
	out, err := os.ReadFile(outFiles[0])
	if err != nil || string(out) != "response" {
		t.Fatalf("out capture = %q, err = %v", out, err)
	}
}
